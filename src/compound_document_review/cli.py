"""Sanitized local read-only CFB review command."""

import argparse
import json

from .cfb import review
from .files import read_local
from .model import Issue


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise Issue("arguments")


def main(argv=None):
    parser = Parser(
        description="Read-only bounded CFB structure review. Names are redacted by default; stream contents are never decoded."
    )
    parser.add_argument("file")
    parser.add_argument("--reveal-names", action="store_true")
    try:
        args = parser.parse_args(argv)
        result = review(read_local(args.file), args.reveal_names)
    except (Issue, OSError, UnicodeError, ValueError) as error:
        code = error.code if isinstance(error, Issue) else "input_error"
        result = {
            "schema_version": 1,
            "status": "OPEN",
            "issues": [{"code": code, "offset": None}],
            "directory": [],
            "cvp_eligibility": "OPEN",
            "ai_assisted": True,
        }
    print(json.dumps(result, ensure_ascii=True, sort_keys=True, separators=(",", ":")))
    return 0 if result["status"] == "PASS" else 2
