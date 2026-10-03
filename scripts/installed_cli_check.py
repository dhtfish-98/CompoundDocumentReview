"""Exercise an installed wheel CLI on harmless synthetic CFBs away from the source tree."""

import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))


def main():
    from fixtures import Builder
    import compound_document_review

    assert ROOT / "src" not in Path(compound_document_review.__file__).parents
    binary = Path(sys.executable).parent / "compound-document-review"
    with tempfile.TemporaryDirectory() as name:
        folder = Path(name).resolve()
        sample = folder / "PRIVATE_INPUT_PATH.cfb"
        builder = Builder()
        builder.add(("PRIVATE_DIRECTORY_NAME",), b"PRIVATE_PAYLOAD_SENTINEL")
        builder.add(("VBA", "dir"))
        raw = builder.build()
        sample.write_bytes(raw)
        before = hashlib.sha256(sample.read_bytes()).hexdigest()
        damaged = folder / "damaged.cfb"
        damaged.write_bytes(raw[:-1])
        link = folder / "link.cfb"
        link.symlink_to(sample)
        cases = [
            ([str(sample)], 0, False),
            ([str(sample), "--reveal-names"], 0, True),
            ([str(damaged), "--reveal-names"], 2, False),
            ([str(folder / "PRIVATE_INPUT_PATH_MISSING")], 2, False),
            ([str(sample), "--PRIVATE_ARGUMENT"], 2, False),
            ([str(link)], 2, False),
            ([str(folder) + "/../" + folder.name + "/" + sample.name], 2, False),
        ]
        for args, expected, reveal in cases:
            child = subprocess.run(
                [str(binary), *args],
                cwd=folder,
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            assert child.returncode == expected and not child.stderr
            result = json.loads(child.stdout)
            assert result["status"] == ("PASS" if expected == 0 else "OPEN")
            for private in (
                "PRIVATE_INPUT_PATH",
                "PRIVATE_ARGUMENT",
                "PRIVATE_PAYLOAD_SENTINEL",
                str(folder),
            ):
                assert private not in child.stdout
            assert ("PRIVATE_DIRECTORY_NAME" in child.stdout) == reveal
            if expected == 0:
                assert result["macro_name_indicators"] == 2
            assert (
                result["cvp_eligibility"] == "OPEN"
                and result["implementation_author"] == "dhtfish98"
            )
        assert before == hashlib.sha256(sample.read_bytes()).hexdigest()
    print(
        json.dumps(
            {
                "status": "PASS",
                "CLI_cases": len(cases),
                "input_unchanged": True,
                "installed_module": str(compound_document_review.__file__),
            }
        )
    )


if __name__ == "__main__":
    main()
