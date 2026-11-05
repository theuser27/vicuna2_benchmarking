#!/usr/bin/env python3

import argparse
import re
from pathlib import Path


MAX_DATA_SIZE = 64
DATA_ALIGNMENT = 64


def hex_to_bytes(value):
    try:
        return bytes.fromhex(value.strip())
    except ValueError as e:
        raise ValueError(f"Invalid hexadecimal value: {value}") from e


def padded_bytes(data):
    if len(data) > MAX_DATA_SIZE:
        raise ValueError(
            f"Data is {len(data)} bytes; maximum is {MAX_DATA_SIZE}"
        )

    return data + bytes(MAX_DATA_SIZE - len(data))


def parse_rsp(path):
    tests = []
    current = {}
    section = None

    def finish_test():
        nonlocal current

        if current:
            if "COUNT" in current:
                tests.append({"section": section, **current})
            current = {}

    with path.open("r", encoding="ascii") as f:
        for raw_line in f:
            line = raw_line.strip()

            if not line or line.startswith("#"):
                if not line:
                    finish_test()
                continue

            if line.startswith("[") and line.endswith("]"):
                finish_test()
                section = line[1:-1].strip().upper()
                continue

            match = re.match(r"^([^=]+?)\s*=\s*(.*?)\s*$", line)
            if match:
                key = match.group(1).strip().upper()
                value = match.group(2).strip()
                current[key] = value

    finish_test()
    return tests


def cpp_identifier(filename):
    """Convert a filename stem into a valid C++ identifier."""
    name = re.sub(r"\W", "_", filename)

    if not name or name[0].isdigit():
        name = "_" + name

    return name


def format_byte_array(data, indent="            "):
    values = [f"0x{b:02x}" for b in padded_bytes(data)]

    lines = [
        indent + ", ".join(values[i:i + 8])
        for i in range(0, len(values), 8)
    ]

    return "{\n" + ",\n".join(lines) + "\n        }"


def make_test_initializer(test, source):
    section = test.get("section", "")

    if section not in ("ENCRYPT", "DECRYPT"):
        raise ValueError(
            f"{source}: unsupported section {section!r}"
        )

    decrypting = section == "DECRYPT"
    count = int(test["COUNT"])

    key = hex_to_bytes(test["KEY"])
    iv = hex_to_bytes(test["IV"]) if "IV" in test else b""

    plaintext = hex_to_bytes(test["PLAINTEXT"])
    ciphertext = hex_to_bytes(test["CIPHERTEXT"])

    input_data, output_data = (
        (ciphertext, plaintext)
        if decrypting
        else (plaintext, ciphertext)
    )

    if len(input_data) != len(output_data):
        raise ValueError(
            f"{source}: COUNT={count}: input/output size mismatch"
        )

    key_length = len(key)
    input_output_length = len(input_data)

    if key_length > MAX_DATA_SIZE:
        raise ValueError(
            f"{source}: COUNT={count}: length {key_length} exceeds "
            f"MAX_DATA_SIZE={MAX_DATA_SIZE}"
        )

    return f"""    {{
        {str(decrypting).lower()},
        {count},
        {key_length},
        {input_output_length},
        {format_byte_array(key)},
        {format_byte_array(iv)},
        {format_byte_array(input_data)},
        {format_byte_array(output_data)}
    }}"""


def generate_header(path, array_names):
    declarations = []

    for name in array_names:
        declarations.extend([
            f"extern const AESParameters {name}[];",
            f"extern const size_t {name}_count;",
            ""
        ])

    header = f"""// This file is generated. Do NOT edit!
#pragma once

#include <stddef.h>
#include <stdint.h>

#define AES_MAX_DATA_SIZE {MAX_DATA_SIZE}
#define AES_DATA_ALIGNMENT {DATA_ALIGNMENT}

struct AESParameters
{{
    bool is_decrypting;
    size_t count;
    size_t key_length;
    size_t input_output_length;

    alignas(AES_DATA_ALIGNMENT) uint8_t key[AES_MAX_DATA_SIZE];
    alignas(AES_DATA_ALIGNMENT) uint8_t init_vector[AES_MAX_DATA_SIZE];
    alignas(AES_DATA_ALIGNMENT) uint8_t input[AES_MAX_DATA_SIZE];
    alignas(AES_DATA_ALIGNMENT) uint8_t output[AES_MAX_DATA_SIZE];
}};

""" + "\n".join(declarations)

    path.write_text(header, encoding="utf-8")


def generate_source(path, header_name, file_tests):
    sections = []

    for name, (source_name, tests) in file_tests.items():
        initializers = [
            make_test_initializer(test, source_name)
            for test in tests
        ]

        joined = ",\n".join(initializers)

        sections.append(f"""// Generated from {source_name}
const AESParameters {name}[] =
{{
{joined}
}};

const size_t {name}_count =
    sizeof({name}) / sizeof({name}[0]);
""")

    source = f'This file is generated. Do NOT edit!\n#include "{header_name}"\n\n'
    source += "\n".join(sections)

    path.write_text(source, encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(
        description="Generate C++ AES KAT arrays from NIST .rsp files."
    )

    parser.add_argument(
        "input",
        type=Path,
        help="An .rsp file or directory containing .rsp files"
    )
    parser.add_argument(
        "-o", "--output",
        type=Path,
        default=Path("."),
        help="Output directory"
    )
    parser.add_argument(
        "--header",
        default="aes_kat.hpp",
        help="Generated header filename"
    )
    parser.add_argument(
        "--source",
        default="aes_kat.cpp",
        help="Generated source filename"
    )

    args = parser.parse_args()

    if args.input.is_file():
        files = [args.input] if args.input.suffix.lower() == ".rsp" else []
    elif args.input.is_dir():
        files = sorted(
            p for p in args.input.rglob("*")
            if p.is_file() and p.suffix.lower() == ".rsp"
        )
    else:
        files = []

    if not files:
        parser.error("No .rsp files found.")

    file_tests = {}

    for path in files:
        name = cpp_identifier(path.stem)

        if name in file_tests:
            raise SystemExit(
                f"Duplicate generated array name {name!r}; "
                f"multiple files have the same filename or sanitized name."
            )

        tests = parse_rsp(path)

        if not tests:
            print(f"Warning: no test vectors found in {path}")
            continue

        file_tests[name] = (str(path), tests)

    if not file_tests:
        raise SystemExit("No test vectors found.")

    args.output.mkdir(parents=True, exist_ok=True)

    generate_header(
        args.output / args.header,
        file_tests.keys()
    )

    generate_source(
        args.output / args.source,
        args.header,
        file_tests
    )

    total = sum(len(tests) for _, tests in file_tests.values())

    print(f"Generated {len(file_tests)} arrays containing {total} vectors.")
    print(f"Header: {args.output / args.header}")
    print(f"Source: {args.output / args.source}")


if __name__ == "__main__":
    main()