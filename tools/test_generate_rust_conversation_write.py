"""Write-contract mutation tests use the real exported OpenAPI document."""
import copy
import json
import subprocess
import unittest

import generate_rust_conversation_write as generator


class WriteGenerator(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        output = subprocess.run(["cargo", "run", "--offline", "--quiet", "--manifest-path",
                                 str(generator.ROOT / "backend-rust/Cargo.toml"), "-p", "pa-server", "--example", "export_openapi"],
                                check=True, capture_output=True, text=True)
        cls.document = json.loads(output.stdout)

    def changed(self, operation_id="SubmitTurn"):
        document = copy.deepcopy(self.document)
        operation = next(op for methods in document["paths"].values() for op in methods.values()
                         if op.get("operationId") == operation_id)
        return document, operation

    def test_actual_contract_generates_typed_requests_and_disjoint_receipts(self):
        value = generator.generate(self.document)
        self.assertIn("pub enum SubmitTurnResponse", value)
        self.assertIn("pub enum Optional<T>", value)
        self.assertIn("pub fn submit_turn(", value)

    def test_unknown_schema_constraints_cannot_be_ignored(self):
        for field, change in [("text", {"pattern": "^allowed$"}), ("expected_turn", {"multipleOf": 2}),
                              ("text", {"contentEncoding": "base64"}), ("text", {"default": "invented text"})]:
            document, op = self.changed()
            op["requestBody"]["content"]["application/json"]["schema"]["properties"][field].update(change)
            with self.assertRaises(AssertionError):
                generator.generate(document)

    def test_bounds_are_emitted_not_just_recorded_in_a_digest(self):
        document, op = self.changed()
        schema = op["requestBody"]["content"]["application/json"]["schema"]
        schema["properties"]["expected_turn"]["maximum"] = 19
        schema["properties"]["text"]["x-pa-max-utf8-bytes"] = 17
        value = generator.generate(document)
        self.assertIn("(0..=19).contains(value)", value)
        self.assertIn("value.len() > 17", value)
        self.assertIn("MAX_TEXT_BYTES: usize = 17", value)

    def test_union_cannot_become_ambiguous_or_accept_unknown_fields(self):
        document, op = self.changed()
        schema = op["responses"]["202"]["content"]["application/json"]["schema"]
        schema["oneOf"][1] = copy.deepcopy(schema["oneOf"][0])
        with self.assertRaises(AssertionError):
            generator.generate(document)
        schema["oneOf"][1]["additionalProperties"] = True
        with self.assertRaises(AssertionError):
            generator.generate(document)

    def test_request_parameter_security_constraints_fail_closed(self):
        for field, value in [("const", "proof"), ("pattern", "^proof$"), ("maxLength", 1)]:
            document, op = self.changed()
            header = next(p for p in op["parameters"] if p["in"] == "header")
            header["schema"][field] = value
            with self.assertRaises(AssertionError):
                generator.generate(document)
        document, op = self.changed()
        op["parameters"].append({"name": "token", "in": "query", "required": True, "schema": {"type": "string"}})
        with self.assertRaises(AssertionError):
            generator.generate(document)

    def test_wrong_status_or_security_scheme_is_not_a_new_success(self):
        for kind in ("status", "security"):
            document, op = self.changed()
            if kind == "status":
                op["responses"]["200"] = op["responses"].pop("202")
            else:
                op["security"] = [{"bearerPat": []}]
            with self.assertRaises(AssertionError):
                generator.generate(document)


if __name__ == "__main__":
    unittest.main()
