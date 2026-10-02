# CompoundDocumentReview

A bounded, read-only Python library and CLI for actual CFB/OLE compound file
allocation and directory structures. It parses version 3 and 4 headers, FAT, DIFAT,
MiniFAT, the root mini stream, all active directory records, sibling/containment
references, and every declared normal or mini stream chain. Reports contain sizes,
source offsets, allocation ownership, timestamps and macro-related name indicators.

`PASS` means the documented finite structural profile completed. It does not prove
that stream content is safe, macros are absent, the file is authentic, or Office would
load it. Stream content is never decoded or exported. Macro name presence is metadata;
macro behavior and maliciousness remain `OPEN`. CVP eligibility and human applicant
contribution remain `OPEN`. AI assistance is stated in every report and [ORIGIN.md](ORIGIN.md).

## Use

Python 3.11+ and POSIX no-follow directory-relative file access; no runtime dependencies.
Install a locally built wheel:

```sh
pip install compound_document_review-0.1.0-py3-none-any.whl
compound-document-review /trusted/local/document.cfb
```

By default directory names are represented by SHA256 of their exact UTF-16 encoding,
length and numeric directory IDs/parent links. Add `--reveal-names` to explicitly
include names and paths after the complete profile passes. Any unknown, damaged or
unsupported case suppresses all revealed names; stream content is always absent.
Invalid input and arguments produce fixed JSON issue codes with numeric positions,
without echoing the host path or underlying exception. Exit 0 is profile PASS; 2 is OPEN.

```python
from compound_document_review import Limits, review

result = review(immutable_bytes, reveal_names=False,
                limits=Limits(directory_depth=32, stream_bytes=1048576))
```

The API accepts exact immutable `bytes`; it does not open or change files. Limits can
only be reduced. There is no stream read/extract/write interface, macro execution,
Office automation, object activation, password handling, network retrieval or property
value decoder. Source extents describe payload positions without returning bytes.

See [DEFENSIVE_SCOPE.md](DEFENSIVE_SCOPE.md), [VALIDATION.md](VALIDATION.md), and
[SOURCE_AUDIT.json](SOURCE_AUDIT.json) for the finite profile and reproducible evidence.
Names, CLSIDs and presence indicators cannot authenticate the file or its contents.
