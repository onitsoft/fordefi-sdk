#!/usr/bin/env python
from pathlib import Path
from typing import Any

import yaml


def extract_dependencies(
    schema_name: str,
    components: dict[str, Any],
) -> dict[str, Any]:
    dependencies: set[str] = set()
    to_visit = {schema_name}

    while to_visit:
        current = to_visit.pop()

        if current not in dependencies and current in components:
            dependencies.add(current)
            schema = components[current]
            referenced_schemas = find_referenced_schemas(schema)
            to_visit.update(referenced_schemas)

    return {name: components[name] for name in dependencies if name in components}


def find_referenced_schemas(schema: dict[str, Any]) -> set[str]:
    referenced: set[str] = set()

    if "$ref" in schema:
        ref = schema["$ref"]
        referenced.add(get_schema_name_from_ref(ref))

    else:
        for value in schema.values():
            if isinstance(value, dict):
                referenced.update(find_referenced_schemas(value))

            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        referenced.update(find_referenced_schemas(item))

    return referenced


def get_schema_name_from_ref(ref: str) -> str:
    return ref.split("/")[-1]


def main(
    schema_name: str,
    yaml_file_path: Path,
    output_file: Path | None = None,
) -> None:
    if output_file is None:
        output_file = yaml_file_path.with_name(f"{schema_name}.yaml")

    with yaml_file_path.open() as file:
        open_api_data = yaml.safe_load(file)

    components = open_api_data.get("components", {}).get("schemas", {})
    extracted_schemas = extract_dependencies(schema_name, components)

    doc = {
        "openapi": "3.1.0",
        "components": {
            "schemas": extracted_schemas,
        },
    }

    with output_file.open("w") as file:
        file.write(yaml.dump(doc, sort_keys=False))

    print(f"Written: {output_file}")  # noqa: T201


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 3:  # noqa: PLR2004
        print("Usage: python script.py <schema_name> <yaml_file_path>")  # noqa: T201

    else:
        _, schema_name, yaml_file_path = sys.argv
        main(schema_name, Path(yaml_file_path))
