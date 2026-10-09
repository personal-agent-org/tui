#!/usr/bin/env python3
"""Generate the narrow Rust Conversation reader from the published OpenAPI operation.

Default: export pa_server::document() through the release example. --check never writes.
--openapi-stdin lets server integration tests check their exact in-process document.
Unsupported schema constructs fail generation rather than weakening the client reader.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
OUTPUT = ROOT / "tui/crates/pa-tui/src/generated/rust_conversation.rs"
# The explicit generator extension for optional properties: each (declaring type, field)
# pair is admitted by name, only for a closed non-nullable object, and generated as an
# `Option` that is `None` when the field is absent and refuses an explicit `null`.
OPTIONAL_PROPERTIES = {("Parts", "artifact"), ("Parts", "action"), ("Action", "target")}


def literal(value):
    return json.dumps(value, ensure_ascii=True)


def name(value):
    return "".join(part.capitalize() for part in value.split("_"))


def require(condition, message="unsupported published operation shape"):
    # Do not disable schema checks under PYTHONOPTIMIZE/python -O.
    if not condition:
        raise AssertionError(message)


def session_cookie_alternative(security):
    """Whether `security` offers the bare session cookie, beside only known alternatives."""
    return (isinstance(security, list) and {"sessionCookie": []} in security
            and all(alternative in ({"sessionCookie": []}, {"bearerPat": []}) for alternative in security))


def adapter_parameters(operation):
    """The operation's parameters the cookie adapter sends.

    `pa-client-id` is published only for the `bearerPat` alternative (§5.2 line 1759: the
    client a PAT is bound to) and is optional; the cookie adapter never sends it. Any other
    optional header is a shape this generator does not know.
    """
    pat_only = [p for p in operation["parameters"]
                if p.get("in") == "header" and p.get("name") == "pa-client-id"
                and p.get("required") is False and {"bearerPat": []} in operation["security"]]
    return [p for p in operation["parameters"] if p not in pat_only]


def generate(document):
    operations = [(path, method, operation)
                  for path, methods in document["paths"].items()
                  for method, operation in methods.items()
                  if isinstance(operation, dict) and operation.get("operationId") == "ReadBranchMessages"]
    require(len(operations) == 1, "exactly one published ReadBranchMessages operation required")
    path, method, operation = operations[0]
    require(method == "get" and path.count("{branch_id}") == 1)
    # The adapter authenticates with the session cookie. Another published alternative (a
    # PAT's `bearerPat`, §5.2) is an OR the adapter simply does not take; anything else is a
    # shape this generator does not know.
    require(session_cookie_alternative(operation["security"]), "unsupported published operation shape")
    cookie = document["components"]["securitySchemes"]["sessionCookie"]
    require(cookie["type"] == "apiKey" and cookie["in"] == "cookie")
    sent = adapter_parameters(operation)
    parameters = {(p["in"], p["name"]): p for p in sent}
    require(len(parameters) == len(sent), "duplicate parameter identity")
    for parameter in sent:
        require(not set(parameter) - {"name", "in", "required", "schema", "description"}, "new parameter serialization requires generator support")
        spec = parameter["schema"]
        if parameter["in"] == "path":
            require(parameter.get("required") is True and spec.get("type") == "string" and spec.get("format") == "uuid")
            supported = {"type", "format", "description"}
        elif parameter["in"] == "header":
            require(parameter.get("required") is True and spec.get("type") == "string")
            supported = {"type", "description"}
        elif parameter["in"] == "query":
            require(spec.get("type") == "integer")
            supported = {"type", "minimum", "maximum", "default", "description"}
            require(all(type(spec[key]) is int for key in ("minimum", "maximum", "default")))
            require(-9223372036854775808 <= spec["minimum"] <= spec["default"] <= spec["maximum"] <= 9223372036854775807)
        else:
            raise AssertionError("unsupported parameter location")
        require(not set(spec) - supported, "new parameter constraints require generator support")
    headers = [p for p in sent if p["in"] == "header"]
    require(len(headers) == 1)
    require(set(parameters) == {("path", "branch_id"), ("query", "after_turn"), ("query", "limit"), ("header", headers[0]["name"])})
    schema = operation["responses"]["200"]["content"]["application/json"]["schema"]
    require(operation["responses"]["200"]["headers"]["Cache-Control"]["schema"]["const"] == "no-store")
    references = {}

    def collect_refs(value):
        if isinstance(value, dict):
            if "$ref" in value:
                ref = value["$ref"]
                require(ref.startswith("#/components/schemas/"), "only published local schema references supported")
                if ref not in references:
                    references[ref] = document["components"]["schemas"][ref.rsplit("/", 1)[1]]
                    collect_refs(references[ref])
            for child in value.values():
                collect_refs(child)
        elif isinstance(value, list):
            for child in value:
                collect_refs(child)

    collect_refs(operation)
    closure = {"openapi": document["openapi"], "info": document["info"], "path": path,
               "method": method, "operation": operation, "cookie": cookie, "referenced_schemas": references}
    digest = hashlib.sha256(json.dumps(closure, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    source_digest = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    declarations = []

    def rust_type(type_name, spec):
        kind = spec.get("type")
        if "enum" in spec:
            supported = {"enum", "description", "type"}
            require(spec.get("type", "string") == "string", "only string enums are supported")
        elif kind == "boolean":
            supported = {"type", "description"}
        elif isinstance(kind, list) or kind == "integer":
            supported = {"type", "description", "minimum", "maximum", "format"}
            require(spec.get("format", "int64") == "int64", "only the int64 integer format is supported")
        elif kind == "object":
            supported = {"type", "description", "additionalProperties", "required", "properties",
                         "x-pa-max-plaintext-bytes", "x-pa-max-source-parts"}
        elif kind == "array":
            supported = {"type", "description", "maxItems", "items"}
        elif kind == "string":
            supported = {"type", "description", "format"}
            require(spec.get("format", "uuid") == "uuid", "only the uuid string format is supported")
        else:
            raise AssertionError("unsupported schema kind")
        require(not set(spec) - supported, "new schema constraints require generator support")
        require(spec.get("maximum", 9223372036854775807) == 9223372036854775807, "non-i64 integer maximum requires generator support")
        if "enum" in spec:
            require(all(isinstance(v, str) for v in spec["enum"]))
            variants = "\n".join(f'    #[serde(rename = {literal(v)})]\n    {name(v)},' for v in spec["enum"])
            declarations.append(f"#[derive(Clone, Copy, serde::Deserialize)]\npub enum {type_name} {{\n{variants}\n}}")
            return type_name
        kind = spec["type"]
        if isinstance(kind, list):
            require(kind == ["integer", "null"])
            declarations.append(f"#[derive(Clone, serde::Deserialize)]\n#[serde(untagged)]\npub enum {type_name} {{ Value(i64), Null(()) }}")
            return type_name
        if kind == "object":
            require(spec["additionalProperties"] is False)
            require(set(spec["required"]) <= set(spec["properties"]))
            optional = set(spec["properties"]) - set(spec["required"])
            require(all((type_name, field) in OPTIONAL_PROPERTIES for field in optional),
                    "optional properties require an explicit generator extension")
            fields, checks = [], []
            for field, child in spec["properties"].items():
                require(field.replace("_", "").isalnum())
                child_name = "BranchMessage" if field == "messages" else name(field)
                ty = rust_type(child_name, child)
                if field in optional:
                    require(child.get("type") == "object" and "default" not in child,
                            "only a closed object may be an optional property")
                    fields.append(f'    #[serde(default, deserialize_with = "present")]\n    pub {field}: Option<{ty}>,')
                    checks.append(f"if let Some(value) = &self.{field} {{ value.validate()?; }}")
                    continue
                fields.append(f"    pub {field}: {ty},")
                if child.get("type") == "object":
                    checks.append(f"self.{field}.validate()?;")
                elif child.get("type") == "string" and child.get("format") == "uuid":
                    checks.append(f"if !canonical_uuid(&self.{field}) {{ return Err(()); }}")
                elif child.get("type") == "integer" and "minimum" in child:
                    checks.append(f"if self.{field} < {child.get('minimum', -9223372036854775808)} {{ return Err(()); }}")
                elif isinstance(child.get("type"), list):
                    checks.append(f"if let {ty}::Value(value) = self.{field} {{ if value < {child['minimum']} {{ return Err(()); }} }}")
                elif child.get("type") == "array":
                    checks.append(f"if self.{field}.len() > {child['maxItems']} {{ return Err(()); }}")
                    checks.append(f"for value in &self.{field} {{ value.validate()?; }}")
            # `#[serde(deny_unknown_fields)]` keeps the reader strict about the wire, and strictness
            # is the point: a field the client does not read today must still be *declared*, or a
            # newly added field would be rejected instead of ignored. `dead_code` then fires on
            # every declared-but-unread field, so the struct carries a reasoned allow -- the shape
            # `api.rs` and `agui.rs` already use for their wire DTOs. It is per struct and named,
            # never a crate-wide `-A dead_code`.
            declarations.append(f"#[allow(dead_code)] // the published wire contract, wider than the UI reads\n"
                                f"#[derive(Clone, serde::Deserialize)]\n#[serde(deny_unknown_fields)]\npub struct {type_name} {{\n" + "\n".join(fields) + "\n}\n" +
                                f"impl {type_name} {{ pub fn validate(&self) -> Result<(), ()> {{ " + " ".join(checks) + " Ok(()) } }")
            return type_name
        if kind == "array":
            return f"Vec<{rust_type(type_name, spec['items'])}>"
        return {"integer": "i64", "string": "String", "boolean": "bool"}[kind]

    require(rust_type("MessagePage", schema) == "MessagePage")
    after = parameters[("query", "after_turn")]["schema"]
    limit = parameters[("query", "limit")]["schema"]
    require(after["maximum"] == 9223372036854775807 and limit["minimum"] == 1)
    prefix, suffix = path.split("{branch_id}")
    output = f'''// @generated by tui/tools/generate_rust_conversation.py; do not hand-edit.
// Published operation closure SHA-256: {digest}
// Generator SHA-256: {source_digest}
// This is one read-only operation, not the complete generated TUI contract.
pub const SESSION_COOKIE: &str = {literal(cookie['name'])};
pub const CSRF_HEADER: &str = {literal(headers[0]['name'])};
pub const MAX_PLAINTEXT_BYTES: usize = {schema['x-pa-max-plaintext-bytes']};
pub const DEFAULT_LIMIT: i64 = {limit['default']};
pub const MAX_LIMIT: i64 = {limit['maximum']};
pub const DEFAULT_AFTER_TURN: i64 = {after['default']};
{chr(10).join(declarations)}

/// Construct only the generated method/path/query/security closure. No ambient credential.
pub fn read_branch_messages(
    http: &reqwest::Client,
    origin: &reqwest::Url,
    branch_id: &str,
    after_turn: i64,
    limit: i64,
    cookie: reqwest::header::HeaderValue,
) -> Result<reqwest::RequestBuilder, ()> {{
    if !canonical_uuid(branch_id) || after_turn < {after['minimum']} || !(1..=MAX_LIMIT).contains(&limit) {{ return Err(()); }}
    let mut url = origin.clone();
    url.set_path(&format!("{prefix}{{branch_id}}{suffix}"));
    Ok(http.get(url)
        .query(&[("after_turn", after_turn), ("limit", limit)])
        .header(reqwest::header::ACCEPT, "application/json")
        .header(reqwest::header::COOKIE, cookie)
        .header(CSRF_HEADER, "1"))
}}

/// An optional property is absent or a value; an explicit `null` is not a published answer.
fn present<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: serde::Deserialize<'de>,
{{
    T::deserialize(deserializer).map(Some)
}}

/// The client accepts the canonical hyphenated spelling of the published uuid format.
pub fn canonical_uuid(value: &str) -> bool {{
    value.len() == 36 && value.bytes().enumerate().all(|(index, byte)| {{
        if [8, 13, 18, 23].contains(&index) {{ byte == b'-' }} else {{ byte.is_ascii_hexdigit() }}
    }})
}}
'''
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
        if not OUTPUT.is_file() or OUTPUT.read_text() != generated:
            raise SystemExit("ReadBranchMessages generated adapter is stale; regenerate from release OpenAPI")
        print("ReadBranchMessages generated adapter matches published operation")
    else:
        OUTPUT.parent.mkdir(parents=True, exist_ok=True)
        OUTPUT.write_text(generated)
        print("Generated committed ReadBranchMessages adapter")


if __name__ == "__main__":
    main()
