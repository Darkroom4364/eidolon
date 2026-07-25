#!/usr/bin/env python3

import base64
import json
from pathlib import Path
import subprocess
import sys
import unittest

HELPER = Path(__file__).with_name("validate-session-key-file.py")
KEY_A = "a" * 64
KEY_B = "B" * 64


def encoded(document: bytes) -> bytes:
    return base64.b64encode(document)


def run_helper(input_bytes: bytes) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [sys.executable, str(HELPER)],
        input=input_bytes,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


class SessionKeyFileValidatorTests(unittest.TestCase):
    def assert_valid(self, value: object) -> None:
        result = run_helper(encoded(json.dumps(value).encode("utf-8")))
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b"")
        self.assertEqual(result.stderr, b"")

    def assert_invalid_document(self, document: bytes) -> None:
        result = run_helper(encoded(document))
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, b"")
        self.assertEqual(result.stderr, b"")

    def test_accepts_single_and_overlapping_key_rings(self) -> None:
        self.assert_valid(
            {
                "active_key_version": 1,
                "keys": [{"version": 1, "key_hex": KEY_A}],
            }
        )
        self.assert_valid(
            {
                "active_key_version": 2,
                "keys": [
                    {"version": 1, "key_hex": KEY_A},
                    {"version": 2, "key_hex": KEY_B},
                ],
            }
        )

    def test_rejects_invalid_base64_and_utf8(self) -> None:
        for input_bytes in (b"not base64!", encoded(b"\xff")):
            result = run_helper(input_bytes)
            self.assertEqual(result.returncode, 1)
            self.assertEqual(result.stdout, b"")
            self.assertEqual(result.stderr, b"")

    def test_rejects_schema_and_json_edge_cases(self) -> None:
        cases = [
            b"not-json",
            b"[]",
            b'{"active_key_version":1,"keys":[]} trailing',
            (
                b'{"active_key_version":1,"active_key_version":1,'
                b'"keys":[{"version":1,"key_hex":"' + KEY_A.encode() + b'"}]}'
            ),
            (
                b'{"active_key_version":1,"keys":[{"version":1,"version":1,'
                b'"key_hex":"' + KEY_A.encode() + b'"}]}'
            ),
            (
                b'{"active_key_version":1.0,"keys":[{"version":1,"key_hex":"'
                + KEY_A.encode()
                + b'"}]}'
            ),
            (
                b'{"active_key_version":true,"keys":[{"version":1,"key_hex":"'
                + KEY_A.encode()
                + b'"}]}'
            ),
            (
                b'{"active_key_version":NaN,"keys":[{"version":1,"key_hex":"'
                + KEY_A.encode()
                + b'"}]}'
            ),
            b'{"keys":[{"version":1,"key_hex":"' + KEY_A.encode() + b'"}]}',
            b'{"active_key_version":1}',
            b'{"active_key_version":1,"keys":[]}',
            (
                b'{"active_key_version":1,"keys":[{"key_hex":"'
                + KEY_A.encode()
                + b'"}]}'
            ),
            b'{"active_key_version":1,"keys":[{"version":1}]}',
            (
                b'{"active_key_version":1,"keys":[{"version":1.0,"key_hex":"'
                + KEY_A.encode()
                + b'"}]}'
            ),
            (
                b'{"active_key_version":1,"keys":[{"version":true,"key_hex":"'
                + KEY_A.encode()
                + b'"}]}'
            ),
            (
                b'{"active_key_version":4294967296,"keys":[{"version":1,"key_hex":"'
                + KEY_A.encode()
                + b'"}]}'
            ),
            (
                b'{"active_key_version":1,"keys":[{"version":4294967296,"key_hex":"'
                + KEY_A.encode()
                + b'"}]}'
            ),
            (
                b'{"active_key_version":1,"keys":[{"version":1,"key_hex":"'
                + KEY_A.encode()
                + b'"},{"version":1,"key_hex":"'
                + KEY_B.encode()
                + b'"}]}'
            ),
            (
                b'{"active_key_version":2,"keys":[{"version":1,"key_hex":"'
                + KEY_A.encode()
                + b'"}]}'
            ),
            b'{"active_key_version":1,"keys":[{"version":1,"key_hex":"short"}]}',
            (
                b'{"active_key_version":1,"keys":[{"version":1,"key_hex":"'
                + ("a" * 63 + "é").encode("utf-8")
                + b'"}]}'
            ),
            (
                b'{"active_key_version":1,"keys":[{"version":1,"key_hex":"'
                + KEY_A.encode()
                + b'\\n"}]}'
            ),
        ]
        for document in cases:
            with self.subTest(document=document):
                self.assert_invalid_document(document)


if __name__ == "__main__":
    unittest.main()
