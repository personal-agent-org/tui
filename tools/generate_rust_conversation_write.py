#!/usr/bin/env python3
"""Generate the two existing Conversation writes from their published OpenAPI closure."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

from generate_rust_conversation import ROOT, adapter_parameters, literal, require, session_cookie_alternative

OUTPUT = ROOT / "tui/crates/pa-tui/src/generated/rust_conversation_write.rs"
OPERATIONS = {"CreateConversation": "create_conversation", "SubmitTurn": "submit_turn"}


class Compiler:
    def __init__(self):
        self.declarations = []

    def compile(self, name, schema):
        if "oneOf" in schema:
            require(set(schema) == {"oneOf"})
            alternatives = schema["oneOf"]
            require(len(alternatives) == 2)
            # Untagged serde must represent exactly one match, never first-of-two.
            for a, b in [(alternatives[0], alternatives[1]), (alternatives[1], alternatives[0])]:
                require(a.get("additionalProperties") is False and
                        set(a["required"]) - set(b["properties"]), "union alternatives must be disjoint closed objects")
            variants = []
            checks = []
            for index, alternative in enumerate(alternatives):
                child = f"{name}Variant{index + 1}"
                self.compile(child, alternative)
                variants.append(f"Variant{index + 1}({child}),")
                checks.append(f"Self::Variant{index + 1}(value) => value.validate(),")
            self.declarations.append(f"#[derive(serde::Serialize, serde::Deserialize)]\n#[serde(untagged)]\npub enum {name} {{" +
                                     "".join(variants) + f"}}\nimpl {name} {{pub fn validate(&self)->Result<(),()> {{match self {{" +
                                     "".join(checks) + "}}}")
            return name
        kind = schema.get("type")
        allowed = {
            "object": {"type", "properties", "required", "additionalProperties", "description"},
            "string": {"type", "format", "pattern", "minLength", "maxLength", "x-pa-max-utf8-bytes", "description"},
            "integer": {"type", "minimum", "maximum", "description"},
            "boolean": {"type", "default", "description"},
            "array": {"type", "items", "maxItems", "description"},
        }
        require(kind in allowed and not set(schema) - allowed[kind], "unsupported semantic schema keyword")
        if kind == "object":
            require(type(schema["additionalProperties"]) is bool)
            required = set(schema["required"])
            require(required <= set(schema["properties"]))
            fields, checks = [], []
            for field, child in schema["properties"].items():
                require(field.isidentifier() and field.isascii() and not field.startswith("_"))
                ty = self.compile(name + "".join(x.capitalize() for x in field.split("_")), child)
                check = self.check("value", child)
                if field in required:
                    fields.append(f"pub {field}: {ty},")
                    checks.append(f"{{ let value = &self.{field}; {check} }}")
                else:
                    fields.append(f'#[serde(default, skip_serializing_if="Optional::is_absent")] pub {field}: Optional<{ty}>,')
                    checks.append(f"if let Optional::Value(value) = &self.{field} {{ {check} }}")
            self.declarations.append(f"#[derive(serde::Serialize, serde::Deserialize)]\n#[serde(deny_unknown_fields)]\npub struct {name} {{" +
                                     "".join(fields) + f"}}\nimpl {name} {{pub fn validate(&self)->Result<(),()> {{" +
                                     "".join(checks) + "Ok(())}}")
            return name
        if kind == "array":
            # A bounded list of closed values (e.g. SubmitTurn's `mentions`): the bound is
            # emitted and every element is validated, never only recorded in the digest.
            require(type(schema["maxItems"]) is int and 0 <= schema["maxItems"] <= 1024)
            return f"Vec<{self.compile(name + 'Item', schema['items'])}>"
        if kind == "boolean":
            require("default" not in schema or type(schema["default"]) is bool)
        if kind == "integer":
            require(all(type(schema[k]) is int for k in ("minimum", "maximum")))
            require(-9223372036854775808 <= schema["minimum"] <= schema["maximum"] <= 9223372036854775807)
        if kind == "string":
            require("format" not in schema or schema["format"] == "uuid")
            require("pattern" not in schema or schema["pattern"] == r"^conversation\.c[0-9a-f]{32}$")
            require(all(type(schema[k]) is int and 0 <= schema[k] <= 1048576
                        for k in ("minLength", "maxLength", "x-pa-max-utf8-bytes") if k in schema))
        return {"string": "String", "integer": "i64", "boolean": "bool"}[kind]

    @staticmethod
    def check(value, schema):
        checks = []
        kind = schema.get("type")
        if kind == "object" or "oneOf" in schema:
            return f"{value}.validate()?;"
        if kind == "array":
            item = Compiler.check("item", schema["items"])
            return (f"if {value}.len() > {schema['maxItems']} {{return Err(());}} "
                    f"for item in {value}.iter() {{ {item} }}")
        if kind == "integer":
            checks.append(f"!({schema['minimum']}..={schema['maximum']}).contains({value})")
        if kind == "string":
            if schema.get("format") == "uuid":
                checks.append(f"!super::rust_conversation::canonical_uuid({value})")
            if "pattern" in schema:
                checks.append(f'!({value}.strip_prefix("conversation.c").is_some_and(|tail| tail.len()==32 && tail.bytes().all(|b| b.is_ascii_digit() || (b\'a\'..=b\'f\').contains(&b))))')
            for key, expr, operator in [("minLength", "chars().count()", "<"), ("maxLength", "chars().count()", ">"),
                                        ("x-pa-max-utf8-bytes", "len()", ">")]:
                if key in schema:
                    checks.append(f"{value}.{expr} {operator} {schema[key]}")
        if checks:
            return "if " + " || ".join(checks) + " {return Err(());}"
        return f"let _ = {value};"


def generate(document):
    compiler = Compiler()
    adapters = []
    closure = {"openapi": document["openapi"], "info": document["info"], "operations": []}
    cookie = document["components"]["securitySchemes"]["sessionCookie"]
    require(set(cookie) == {"type", "in", "name"} and cookie["type"] == "apiKey" and cookie["in"] == "cookie")
    closure["cookie"] = cookie
    for operation_id, function in OPERATIONS.items():
        found = [(path, method, op) for path, methods in document["paths"].items()
                 for method, op in methods.items() if isinstance(op, dict) and op.get("operationId") == operation_id]
        require(len(found) == 1)
        path, method, operation = found[0]
        require(method == "post" and session_cookie_alternative(operation["security"]))
        require(path.count("{branch_id}") == (operation_id == "SubmitTurn") and path.count("{") == path.count("{branch_id}"))
        headers = []
        seen = set()
        for p in adapter_parameters(operation):
            require(set(p) == {"name", "in", "required", "schema"} and p["required"] is True)
            require((p["name"], p["in"]) not in seen)
            seen.add((p["name"], p["in"]))
            if p["in"] == "header":
                require(p["schema"] == {"type": "string"})
                headers.append(p["name"])
            else:
                require(p["in"] == "path" and p["name"] == "branch_id" and p["schema"] == {"type": "string", "format": "uuid"})
        require(len(headers) == 1 and len(seen) == 1 + (operation_id == "SubmitTurn"))
        require(set(operation["requestBody"]) == {"required", "content"})
        require(operation["requestBody"]["required"] is (operation_id == "SubmitTurn"))
        require(set(operation["requestBody"]["content"]) == {"application/json"})
        request = operation["requestBody"]["content"]["application/json"]["schema"]
        statuses = [status for status in operation["responses"] if status.startswith("2")]
        require(statuses == (["201"] if operation_id == "CreateConversation" else ["202"]))
        response = operation["responses"][statuses[0]]
        require(response["headers"] == {"Cache-Control": {"schema": {"const": "no-store"}}})
        require(set(response["content"]) == {"application/json"})
        compiler.compile(operation_id + "Request", request)
        compiler.compile(operation_id + "Response", response["content"]["application/json"]["schema"])
        if operation_id == "SubmitTurn":
            adapters.append(f"pub const MAX_TEXT_BYTES: usize = {request['properties']['text']['x-pa-max-utf8-bytes']};")
        branch_arg = "branch: &str," if "{branch_id}" in path else ""
        branch_check = "if !super::rust_conversation::canonical_uuid(branch) {return Err(());}" if branch_arg else ""
        url_path = f'&format!({literal(path.replace("{branch_id}", "{branch}"))})' if branch_arg else literal(path)
        adapters.append(f'''pub const {function.upper()}_STATUS: u16 = {statuses[0]};
pub fn {function}(http: &reqwest::Client, origin: &reqwest::Url, {branch_arg}
    body: &{operation_id}Request, cookie: reqwest::header::HeaderValue) -> Result<reqwest::RequestBuilder,()> {{
    {branch_check} body.validate()?;
    let mut url = origin.clone(); url.set_path({url_path});
    Ok(http.post(url).header(reqwest::header::ACCEPT,"application/json")
        .header(reqwest::header::COOKIE,cookie).header({literal(headers[0])},"1").json(body))
}}''')
        closure["operations"].append({"path": path, "method": method, "operation": operation})
    closure["schemas"] = {}
    def refs(value):
        if isinstance(value, dict):
            if "$ref" in value:
                ref = value["$ref"]
                require(ref.startswith("#/components/schemas/"))
                if ref not in closure["schemas"]:
                    closure["schemas"][ref] = document["components"]["schemas"][ref.rsplit("/", 1)[1]]
                    refs(closure["schemas"][ref])
            for child in value.values():
                refs(child)
        elif isinstance(value, list):
            for child in value:
                refs(child)
    refs(closure["operations"])
    digest = hashlib.sha256(json.dumps(closure, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    source = hashlib.sha256(Path(__file__).read_bytes() +
                            (ROOT / "tui/tools/generate_rust_conversation.py").read_bytes()).hexdigest()
    output = f'''// @generated by tui/tools/generate_rust_conversation_write.py; do not hand-edit.
// Published operation closure SHA-256: {digest}
// Generator and shared helper SHA-256: {source}
// Admission is not Run completion or authority to query a Run.
pub const SESSION_COOKIE: &str = {literal(cookie['name'])};
''' + '''
// Optional is deliberately not Option: present null cannot satisfy a non-null schema.
#[derive(Default)]
pub enum Optional<T> { #[default] Absent, Value(T) }
impl<T> Optional<T> {pub fn is_absent(&self)->bool {matches!(self,Self::Absent)}}
impl<'de,T:serde::Deserialize<'de>> serde::Deserialize<'de> for Optional<T> {
    fn deserialize<D:serde::Deserializer<'de>>(deserializer:D)->Result<Self,D::Error> {
        T::deserialize(deserializer).map(Self::Value)
    }
}
impl<T:serde::Serialize> serde::Serialize for Optional<T> {
    fn serialize<S:serde::Serializer>(&self,serializer:S)->Result<S::Ok,S::Error> {
        match self {Self::Value(value)=>value.serialize(serializer),Self::Absent=>serializer.serialize_none()}
    }
}
''' + "\n".join(compiler.declarations + adapters)
    return subprocess.run(["rustfmt", "--edition", "2021", "--emit", "stdout"], input=output,
                          text=True, check=True, capture_output=True).stdout


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--openapi-stdin", action="store_true")
    args = parser.parse_args()
    if args.openapi_stdin:
        document = json.load(sys.stdin)
    else:
        result = subprocess.run(["cargo", "run", "--offline", "--quiet", "--manifest-path",
                                 str(ROOT / "backend-rust/Cargo.toml"), "-p", "pa-server", "--example", "export_openapi"],
                                check=True, capture_output=True, text=True)
        document = json.loads(result.stdout)
    generated = generate(document)
    if args.check:
        require(OUTPUT.read_text() == generated, "Conversation write adapter is stale")
        print("Conversation write adapter matches published operations")
    else:
        OUTPUT.write_text(generated)
        print("Generated Conversation write adapter")


if __name__ == "__main__":
    main()
