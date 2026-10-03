# Finite read-only CFB profile

The input is an immutable complete CFB file. Header signature, class-ID/reserved bytes,
major/sector/mini-sector shift, byte order, cutoff, aligned whole-file size, declared
allocation counts and version-4 header padding are checked. Versions 3/4 use 512/4096-byte
sectors and 64-byte mini sectors. Minor versions other than 0x3E and transaction states
stay OPEN. These rules reference the [MS-CFB header](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cfb/05060311-bfce-4b12-874d-71fd4ce63aea).

Header DIFAT slots and actual DIFAT chains yield every FAT sector with precise pointer
locations, exact counts, distinct ownership, markers and final termination. All FAT
and MiniFAT entries are examined. Non-addressable table slack must be FREE; slack is
checked one sector at a time and is not retained. Each allocated regular/mini sector
must belong to a reviewed chain or known table; unclaimed allocations remain OPEN.
Every stream chain must end exactly at its declared length with no cycle, shared sector,
free/reserved target or invalid reference. Payload bytes are not interpreted or returned.
The source mechanisms are specified by [FAT](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cfb/30e1013a-a0ff-4404-9ccf-d75d835ff404),
[DIFAT](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cfb/0afa4e43-b18f-432a-9917-4f276eca7a73)
and [MiniFAT](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cfb/c5d235f7-b73c-4ec5-bf8d-5c08306cd023).

The normal directory chain is parsed completely, including active records not reachable
from the root. Active entries must have known types, strict bounded UTF-16 terminated
names, permitted name characters, color values, and valid type-specific metadata.
Root ID/name/sibling/creation fields, storage zero-size/start fields and stream child/
CLSID/timestamps are checked. Storage times retain integer FILETIME ticks and remainder;
zero is UNSET, out-of-range dates are OPEN, and times are unauthenticated. Version-3
stream/root sizes deliberately ignore the historical uninitialized high DWORD while
reporting its raw numeric value. Version-4 sizes use all 64 bits. These checks reference
[directory entries](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cfb/60fe8611-66c3-496b-b70d-a504c94c9ace),
[root entries](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cfb/026fde6e-143d-41bf-a7da-c08b2130d50e)
and the documented [legacy size behavior](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cfb/b37413bb-f3ef-4adc-b18e-29bddd62c26e).

Containment and sibling trees are walked iteratively. Duplicate references, sibling/
storage cycles, unreachable active nodes, sorted bounds and duplicate ASCII names are
checked. Each child-tree top is black; consecutive red sibling nodes are refused.
The MS-CFB constraints permit an all-black binary tree; equal black height is not imposed.
Ordering uses UTF-16 name length and ASCII uppercase. Unicode names are decoded without
repair, but their simple uppercase ordering remains OPEN rather than using Python's full
Unicode folding as proof. See [MS-CFB sibling tree rules](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cfb/d30e462c-5f8a-435b-9c4c-cc0b9ea89956).

All active stream chains are reviewed, even if directory reachability is unknown.
Small nonempty streams use the MiniFAT/root mini stream; size >=4096 uses the normal FAT.
Empty streams require ENDOFCHAIN. The finite mini-stream profile requires its declared
length to comprise complete 64-byte mini sectors. Irregular mini lengths, unsupported
name case mapping, transactions, stale allocated records or strict stream-state flags
may exclude documents accepted by permissive readers. OPEN is not a maliciousness or
universal corruption verdict. No CFB property set, embedded file, decrypted data, Office
application or VBA binary semantics are parsed.

Rows provide numeric directory IDs, source positions, parent/sibling/child links,
size and sector count, chain-ID hash and merged ordered byte extents excluding final
padding. Root mini-stream metadata is separately located. Macro-related names (VBA,
PROJECT, PROJECTwm, _VBA_PROJECT and dir/__SRP_ names under VBA) are literal name indicators,
including empty streams. They do not prove VBA code is present, valid, executed or
malicious. Absence within this limited list does not prove the absence of all macros.

Default lower-only limits: 64 MiB file and individual stream, 131,072 physical sectors,
4,096 FAT sectors, 1,024 DIFAT sectors, 16,384 directory slots, 96 containment levels,
96 sibling levels, 8,192 streams, 1,048,576 mini sectors, 500,000 followed references,
8,192 merged extents, 64 issues and 1 MiB encoded JSON. Minimum report budget is 256 bytes.
Table slack is scanned through fixed-size sectors, with only addressable table entries
retained. Budget or parse failure is OPEN; revealed names and clean prefix reports are
never returned. The parser has finite data limits, not an OS memory/time isolation proof.

The CLI holds each directory descriptor and opens every path component NOFOLLOW.
Symlinks, dot/dot-dot/empty components, devices, FIFOs, sockets and directories are refused.
POSIX O_NOFOLLOW/O_DIRECTORY/O_NONBLOCK and true os.open dirfd support are required. Before/after
regular-file state, device/inode/size/mtime/ctime and exact read length must match.
This is an observation on held descriptors, not an atomic snapshot or enduring pathname
identity. The original file is never changed.

Default output hashes names; explicit reveal allows names/paths only for a complete
profile PASS. No content bytes, property values, private source paths or exception
messages are emitted. Names/hash/timestamps may themselves be sensitive metadata.
Only synthetic inputs are shipped. Authenticity, application behavior, macro semantics,
maliciousness, complete Unicode ordering, researcher credentials and CVP remain OPEN.
