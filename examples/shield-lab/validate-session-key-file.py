#!/usr/bin/env python3

import base64
import binascii
import json
import sys
from typing import Any

U32_MAX = (1 << 32) - 1
ASCII_HEX = frozenset("0123456789abcdefABCDEF")


class InvalidKeyFile(ValueError):
    pass


def reject_duplicate_fields(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for name, value in pairs:
        if name in result:
            raise InvalidKeyFile
        result[name] = value
    return result


def reject_float(_value: str) -> None:
    raise InvalidKeyFile


def reject_constant(_value: str) -> None:
    raise InvalidKeyFile


def reject_booleans(value: Any) -> None:
    if isinstance(value, bool):
        raise InvalidKeyFile
    if isinstance(value, dict):
        for item in value.values():
            reject_booleans(item)
    elif isinstance(value, list):
        for item in value:
            reject_booleans(item)


def is_u32(value: Any) -> bool:
    return type(value) is int and 0 <= value <= U32_MAX


def validate_key_file(encoded: bytes) -> None:
    decoded = base64.b64decode(encoded, validate=True)
    document = decoded.decode("utf-8")
    value = json.loads(
        document,
        object_pairs_hook=reject_duplicate_fields,
        parse_float=reject_float,
        parse_constant=reject_constant,
    )
    reject_booleans(value)

    if not isinstance(value, dict):
        raise InvalidKeyFile
    active_version = value.get("active_key_version")
    keys = value.get("keys")
    if not is_u32(active_version) or not isinstance(keys, list) or not keys:
        raise InvalidKeyFile

    versions: set[int] = set()
    for entry in keys:
        if not isinstance(entry, dict):
            raise InvalidKeyFile
        version = entry.get("version")
        key_hex = entry.get("key_hex")
        if not is_u32(version):
            raise InvalidKeyFile
        if version in versions:
            raise InvalidKeyFile
        versions.add(version)
        if (
            not isinstance(key_hex, str)
            or len(key_hex) != 64
            or any(character not in ASCII_HEX for character in key_hex)
        ):
            raise InvalidKeyFile

    if active_version not in versions:
        raise InvalidKeyFile


def main() -> int:
    try:
        validate_key_file(sys.stdin.buffer.read())
    except (InvalidKeyFile, UnicodeDecodeError, binascii.Error, json.JSONDecodeError):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
