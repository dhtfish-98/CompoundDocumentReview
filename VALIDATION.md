# Validation and limits

Local verification uses Python 3.14.6 on macOS. The 52 independent test methods pass,
including complete version-3/version-4 containers, actual extended DIFAT chains with
110/240 FAT sectors, normal/mini/empty streams across sector/cutoff boundaries, nested
storages, real fragmented normal/root-mini chains and independently reconstructed
source extents. Tests also run 1,000 fixed-seed three-byte malformed mutations.

Focused negatives cover header reserved fields/counts/versions, truncation, wrong
FAT/DIFAT/MiniFAT ownership/markers/capacity/slack, out-of-range references, cycles,
sharing, exact chain length/termination, directory types/fields/name encoding/NUL,
sibling order/color/duplicate references, unreachable active entries, unclaimed
allocations, FILETIME and every documented budget. Source-position assertions locate
the exact altered header/directory fields. File tests cover held no-follow path
components, special files, sparse size refusal, short reads, every observed metadata
identity field, absent paths, arguments and default/explicit metadata privacy.

```sh
python -m pip install -r requirements-dev.txt
PYTHONPATH=src python -m unittest discover -s tests -v
ruff check src tests scripts
ruff format --check src tests scripts
python -m build --no-isolation
python -m venv .install-check
.install-check/bin/python -m pip install --no-index --no-deps dist/compound_document_review-0.1.0-py3-none-any.whl
.install-check/bin/python -m pip check
# Use absolute project/tool paths from a separate working directory:
/path/to/.install-check/bin/python -I -m unittest discover -s /path/to/CompoundDocumentReview/tests -v
/path/to/.install-check/bin/python -I /path/to/CompoundDocumentReview/scripts/installed_cli_check.py
/path/to/.install-check/bin/python -I /path/to/CompoundDocumentReview/scripts/verify_package.py /path/to/CompoundDocumentReview --installed /path/to/consumer/site-packages
```

The isolated consumer repeats all 52 methods and seven actual installed CLI cases:
default redaction, explicit name reveal, truncated file, absent file, unknown argument,
leaf symlink and raw dot-dot spelling. Original content/digest remain unchanged.
The artifact verifier checks every wheel RECORD hash/size, entry points, metadata,
runtime bytes against source and installed files, complete license bytes, and all
public source files in the sdist. It does not extract either archive. Local virtual
environments, upstream downloads, caches, private evidence and build artifacts are
excluded from the public source archive.

Test-only fixed upstream differential reproduction:

```sh
PYTHONPATH=src python scripts/differential_check.py /path/to/verified/olefile
```

It checks all ten selected source SHA256/Git blob identities before importing the
fixed test-only oracle, then compares 72 complete synthetic CFBs and 216 declared
streams. Directory paths/types/IDs/physical offsets, size and storage timestamps are
compared without normalization. Known harmless synthetic payload bytes read by the
oracle equal the fixture facts and the new parser's independently reconstructed
extents. Input and fixed source remain unchanged; public runtime never decodes those
payloads. Malformed files, Unicode ordering, transactions and property decoding are
outside this differential domain. Agreement is not universal format equivalence.

The CI matrix repeats source tests/build, full isolated consumer tests, CLI and
artifact checks on Linux/macOS, Python 3.11/3.14. This local evidence does not claim
exact-commit remote CI, remote source identity or publication: those require separate
parent observation. Real Office loading, complete document/macro semantics, authentic
forensic datasets, source authenticity and CVP qualification remain OPEN.
