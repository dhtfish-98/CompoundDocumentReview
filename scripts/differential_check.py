"""Fixed source oracle on synthetic content; not a public runtime dependency."""

import argparse
import hashlib
import io
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))


def main():
    from fixtures import Builder
    from compound_document_review import review

    arguments = argparse.ArgumentParser()
    arguments.add_argument("source", type=Path)
    args = arguments.parse_args()
    audit = json.loads((ROOT / "SOURCE_AUDIT.json").read_text())
    identities = {}
    for row in audit["selected_full_files"]:
        path = args.source / row["path"]
        if not path.is_file():
            path = ROOT / "validation-local/upstream" / row["path"]
        raw = path.read_bytes()
        digest = hashlib.sha256(raw).hexdigest()
        blob = hashlib.sha1(
            b"blob " + str(len(raw)).encode() + b"\0" + raw, usedforsecurity=False
        ).hexdigest()
        assert digest == row["sha256"] and blob == row["git_blob"], row["path"]
        identities[path] = digest
    sys.path.insert(0, str(args.source.resolve()))
    import olefile

    count = 0
    streams_compared = 0
    for major in (3, 4):
        for fat in (0, 110, 240):
            for size in (0, 1, 63, 64, 65, 511, 512, 513, 4095, 4096, 4097, 20000):
                builder = Builder(major, fat)
                payload = (b"SYNTHETIC_VALUE" * ((size + 14) // 15))[:size]
                builder.add(("Nested", "Sample"), payload)
                builder.add(("Empty",))
                builder.add(("VBA", "dir"))
                raw = builder.build()
                before = hashlib.sha256(raw).hexdigest()
                result = review(raw, True)
                assert result["status"] == "PASS", result["issues"]
                rows = {tuple(row["path"]): row for row in result["directory"]}
                with olefile.OleFileIO(io.BytesIO(raw)) as old:
                    assert set(rows) == set(
                        tuple(path) for path in old.listdir(streams=True, storages=True)
                    )
                    for path, row in rows.items():
                        assert row["kind"] == (
                            "STREAM" if old.get_type(list(path)) == 2 else "STORAGE"
                        )
                        sid = old._find(list(path))
                        assert row["directory_id"] == sid
                        assert row["directory_entry_offset"] == builder.entry_offsets[sid]
                        if row["kind"] == "STREAM":
                            streams_compared += 1
                            assert (
                                row["size"]
                                == old.get_size(list(path))
                                == len(builder.nodes[sid]["data"])
                            )
                            with old.openstream(list(path)) as stream:
                                assert stream.read() == builder.nodes[sid]["data"]
                            reconstructed = b"".join(
                                raw[extent["offset"] : extent["offset"] + extent["length"]]
                                for extent in row["data_extents"]
                            )
                            assert reconstructed == builder.nodes[sid]["data"]
                        else:
                            assert (
                                row["created"]["utc"] == old.getctime(list(path)).isoformat() + "Z"
                            )
                            assert (
                                row["modified"]["utc"] == old.getmtime(list(path)).isoformat() + "Z"
                            )
                assert hashlib.sha256(raw).hexdigest() == before
                count += 1
    assert all(
        hashlib.sha256(path.read_bytes()).hexdigest() == digest
        for path, digest in identities.items()
    )
    print(
        json.dumps(
            {
                "status": "PASS",
                "complete_containers": count,
                "stream_payload_oracle_comparisons": streams_compared,
                "fixed_source_files_verified_unchanged": len(identities),
                "input_unchanged": True,
                "upstream_commit": audit["commit"],
                "domain": "v3/v4, 0/110/240 forced FAT counts with real DIFAT, nested storage, small/empty/multi-sector/cutoff streams, empty VBA indicators. Malformed, unsupported Unicode case ordering, transaction and property decoding not differential claims.",
                "normalization": "None",
                "compared": [
                    "directory paths/types/IDs/physical offsets",
                    "size",
                    "storage timestamps",
                    "oracle actual harmless stream bytes vs synthetic facts and new source extents",
                ],
                "public_runtime_content": "NOT_DECODED",
            }
        )
    )


if __name__ == "__main__":
    main()
