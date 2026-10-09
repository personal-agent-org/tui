"""Mutation checks against the actual exported Rust release OpenAPI, not a parallel schema."""
import copy
import json
import subprocess
import unittest

import generate_rust_conversation as generator


class GeneratorConstraints(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        output = subprocess.run(
            ["cargo", "run", "--offline", "--quiet", "--manifest-path",
             str(generator.ROOT / "backend-rust/Cargo.toml"), "-p", "pa-server", "--example", "export_openapi"],
            check=True, capture_output=True, text=True,
        )
        cls.document = json.loads(output.stdout)

    def changed(self):
        document = copy.deepcopy(self.document)
        operation = next(operation for methods in document["paths"].values()
                         for operation in methods.values()
                         if operation.get("operationId") == "ReadBranchMessages")
        schema = operation["responses"]["200"]["content"]["application/json"]["schema"]
        message = schema["properties"]["messages"]["items"]
        return document, operation, schema, message

    def test_actual_contract_generates(self):
        generated = generator.generate(self.document)
        self.assertIn("pub struct MessagePage", generated)
        self.assertIn("#[serde(deny_unknown_fields)]", generated)
        self.assertIn("pub enum NextAfterTurn", generated)

    def test_lowered_response_maximum_is_not_silently_ignored(self):
        document, _, _, message = self.changed()
        message["properties"]["turn_sequence"]["maximum"] = 10
        with self.assertRaises(AssertionError):
            generator.generate(document)

    def test_string_max_length_is_not_silently_ignored(self):
        document, _, _, message = self.changed()
        message["properties"]["text"]["maxLength"] = 10
        with self.assertRaises(AssertionError):
            generator.generate(document)

    def test_string_pattern_is_not_silently_ignored(self):
        document, _, _, message = self.changed()
        message["properties"]["text"]["pattern"] = "^allowed$"
        with self.assertRaises(AssertionError):
            generator.generate(document)

    def test_optional_rendered_field_needs_explicit_support(self):
        document, _, _, message = self.changed()
        message["required"].remove("text")
        with self.assertRaises(AssertionError):
            generator.generate(document)

    def test_the_admitted_optional_artifact_is_generated_as_an_option(self):
        generated = generator.generate(self.document)
        self.assertIn("pub artifact: Option<Artifact>", generated)
        self.assertIn('#[serde(default, deserialize_with = "present")]', generated)
        self.assertIn("if !canonical_uuid(&self.artifact_id)", generated)

    def test_an_optional_property_outside_the_extension_is_refused(self):
        document, _, _, message = self.changed()
        part = message["properties"]["parts"]["items"]
        part["properties"]["extra"] = copy.deepcopy(part["properties"]["artifact"])
        with self.assertRaises(AssertionError):
            generator.generate(document)

    def test_the_admitted_optional_must_stay_a_closed_object(self):
        document, _, _, message = self.changed()
        message["properties"]["parts"]["items"]["properties"]["artifact"] = {"type": "string"}
        with self.assertRaises(AssertionError):
            generator.generate(document)

    def test_another_string_format_requires_generator_support(self):
        document, _, _, message = self.changed()
        artifact = message["properties"]["parts"]["items"]["properties"]["artifact"]
        artifact["properties"]["artifact_id"]["format"] = "uri"
        with self.assertRaises(AssertionError):
            generator.generate(document)

    def test_response_default_cannot_create_missing_text(self):
        document, _, _, message = self.changed()
        message["properties"]["text"]["default"] = "invented answer"
        with self.assertRaises(AssertionError):
            generator.generate(document)

    def test_nullable_property_cannot_become_optional_by_accident(self):
        document, _, schema, _ = self.changed()
        schema["required"].remove("next_after_turn")
        with self.assertRaises(AssertionError):
            generator.generate(document)

    def test_semantic_keywords_are_type_specific(self):
        document, _, _, message = self.changed()
        message["properties"]["text"]["minimum"] = 1
        with self.assertRaises(AssertionError):
            generator.generate(document)

    def test_csrf_cannot_disappear_from_generated_security_closure(self):
        document, operation, _, _ = self.changed()
        operation["parameters"] = [p for p in operation["parameters"] if p["in"] != "header"]
        with self.assertRaises(AssertionError):
            generator.generate(document)

    def test_query_multiple_of_is_not_silently_ignored(self):
        for key in ("after_turn", "limit"):
            document, operation, _, _ = self.changed()
            parameter = next(p for p in operation["parameters"] if p["name"] == key)
            parameter["schema"]["multipleOf"] = 2
            with self.assertRaises(AssertionError):
                generator.generate(document)

    def test_header_const_is_not_silently_replaced_by_one(self):
        document, operation, _, _ = self.changed()
        # The CSRF proof, not the optional PAT-only `pa-client-id` the cookie adapter omits.
        parameter = next(p for p in operation["parameters"]
                         if p["in"] == "header" and p.get("required") is True)
        parameter["schema"]["const"] = "different-proof"
        with self.assertRaises(AssertionError):
            generator.generate(document)

    def test_path_pattern_requires_generator_support(self):
        document, operation, _, _ = self.changed()
        parameter = next(p for p in operation["parameters"] if p["in"] == "path")
        parameter["schema"]["pattern"] = "^specific-uuid$"
        with self.assertRaises(AssertionError):
            generator.generate(document)

    def test_parameter_serialization_and_invalid_default_are_not_ignored(self):
        for field, value in [("style", "spaceDelimited"), ("invalid_default", -1)]:
            document, operation, _, _ = self.changed()
            parameter = next(p for p in operation["parameters"] if p["name"] == "after_turn")
            if field == "invalid_default":
                parameter["schema"]["default"] = value
            else:
                parameter[field] = value
            with self.assertRaises(AssertionError):
                generator.generate(document)


if __name__ == "__main__":
    unittest.main()
