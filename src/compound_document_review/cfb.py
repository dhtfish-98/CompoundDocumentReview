"""Independent read-only CFB allocation graph, directory and stream provenance."""

from dataclasses import dataclass
from hashlib import sha256
import json
import struct

from .model import DEFAULT_LIMITS, Issue, check_limits, time_evidence

MAGIC = bytes.fromhex("d0cf11e0a1b11ae1")
FREE = 0xFFFFFFFF
END = 0xFFFFFFFE
FAT = 0xFFFFFFFD
DIFAT = 0xFFFFFFFC


def number(raw, offset, fmt="<I"):
    if offset < 0 or offset + struct.calcsize(fmt) > len(raw):
        raise Issue("field_bounds", offset)
    return struct.unpack_from(fmt, raw, offset)[0]


@dataclass(frozen=True)
class Entry:
    sid: int
    offset: int
    name: str
    name_length: int
    kind: int
    color: int
    left: int
    right: int
    child: int
    start: int
    size: int
    high_size: int
    created: dict
    modified: dict


class CFB:
    def __init__(self, data, limits):
        self.raw = memoryview(data)
        self.limits = limits
        self.issues = []
        self.owners = {}
        self.mini_owners = {}
        self.references = 0
        self.fat = []
        self.fat_sources = []
        self.fat_locations = []
        self.difat_locations = []
        self.minifat = []
        self.entries = {}
        self.paths = {}
        self.parents = {0: None}
        self.rows = []
        self.header = {}
        self.normal_count = 0
        self.directory_slots = 0
        self.extent_count = 0
        self.row_bytes = 0
        self.mini_slots = 0
        self.root_chain = []

    def issue(self, code, offset=None):
        if len(self.issues) >= self.limits.issues:
            raise Issue("issue_budget", offset)
        self.issues.append({"code": code, "offset": offset})

    def reference(self, offset):
        self.references += 1
        if self.references > self.limits.references:
            raise Issue("reference_budget", offset)

    def sector(self, sid, source=None):
        self.reference(source)
        if not 0 <= sid < self.normal_count:
            raise Issue("sector_reference_bounds", source)
        start = (sid + 1) * self.sector_size
        return self.raw[start : start + self.sector_size]

    def claim(self, sid, role, source):
        raw = self.sector(sid, source)
        if sid in self.owners:
            raise Issue("sector_cycle_or_shared_role", source)
        self.owners[sid] = role
        return raw

    def fat_offset(self, sid):
        return (self.fat_locations[sid // self.words] + 1) * self.sector_size + 4 * (
            sid % self.words
        )

    def header_read(self):
        if len(self.raw) < 512 or bytes(self.raw[:8]) != MAGIC:
            raise Issue("header_signature_or_size", 0)
        major = number(self.raw, 26, "<H")
        shift = number(self.raw, 30, "<H")
        if major not in (3, 4):
            raise Issue("version_or_sector_shift", 26)
        if shift != {3: 9, 4: 12}[major]:
            raise Issue("version_or_sector_shift", 30)
        self.major = major
        self.sector_size = 1 << shift
        self.words = self.sector_size // 4
        if len(self.raw) < 3 * self.sector_size or len(self.raw) % self.sector_size:
            raise Issue("file_sector_extent", len(self.raw))
        self.normal_count = len(self.raw) // self.sector_size - 1
        if self.normal_count > self.limits.sectors:
            raise Issue("sector_budget", 0)
        if any(self.raw[8:24]):
            raise Issue("header_reserved", 8)
        if any(self.raw[34:40]):
            raise Issue("header_reserved", 34)
        if number(self.raw, 28, "<H") != 0xFFFE:
            raise Issue("byte_order_or_mini_shift", 28)
        if number(self.raw, 32, "<H") != 6:
            raise Issue("byte_order_or_mini_shift", 32)
        if major == 4 and any(self.raw[512 : self.sector_size]):
            raise Issue("version4_header_padding", 512)
        if number(self.raw, 56) != 4096:
            raise Issue("mini_cutoff", 56)
        self.dir_declared = number(self.raw, 40)
        if major == 3 and self.dir_declared:
            raise Issue("version3_directory_count", 40)
        self.nfat = number(self.raw, 44)
        self.dir_start = number(self.raw, 48)
        self.mini_start = number(self.raw, 60)
        self.nmini = number(self.raw, 64)
        self.difat_start = number(self.raw, 68)
        self.ndifat = number(self.raw, 72)
        if not 0 < self.nfat <= min(self.limits.fat_sectors, self.normal_count):
            raise Issue("fat_sector_budget", 44)
        if self.ndifat > self.limits.difat_sectors or self.ndifat > self.normal_count:
            raise Issue("difat_sector_budget", 72)
        if self.nmini > self.normal_count:
            raise Issue("minifat_sector_budget", 64)
        if self.dir_declared > self.limits.directory_entries // (self.sector_size // 128):
            raise Issue("directory_entry_budget", 40)
        minor = number(self.raw, 24, "<H")
        transaction = number(self.raw, 52)
        self.header = {
            "major": major,
            "minor": minor,
            "sector_size": self.sector_size,
            "transaction_sequence": transaction,
            "physical_sectors": self.normal_count,
            "declared_fat_sectors": self.nfat,
            "declared_difat_sectors": self.ndifat,
            "declared_minifat_sectors": self.nmini,
        }
        if minor != 0x3E:
            self.issue("minor_version_profile", 24)
        if transaction:
            self.issue("transaction_state_not_implemented", 52)

    def allocation(self):
        initial = min(109, self.nfat)
        for index in range(109):
            pointer = number(self.raw, 76 + 4 * index)
            if index < initial:
                self.fat_locations.append(pointer)
                self.fat_sources.append(76 + 4 * index)
            elif pointer != FREE:
                raise Issue("unused_header_difat_entry", 76 + 4 * index)
        needed = max(0, (self.nfat - 109 + self.words - 2) // (self.words - 1))
        if self.ndifat != needed:
            raise Issue("difat_count_mismatch", 72)
        pointer = self.difat_start
        remaining = self.nfat - initial
        for index in range(self.ndifat):
            source = (
                68
                if index == 0
                else (self.difat_locations[-1] + 1) * self.sector_size + self.sector_size - 4
            )
            raw = self.claim(pointer, "DIFAT", source)
            self.difat_locations.append(pointer)
            take = min(remaining, self.words - 1)
            for slot in range(self.words - 1):
                location = number(raw, slot * 4)
                if slot < take:
                    self.fat_locations.append(location)
                    self.fat_sources.append((pointer + 1) * self.sector_size + slot * 4)
                elif location != FREE:
                    raise Issue(
                        "unused_difat_entry",
                        (pointer + 1) * self.sector_size + 4 * slot,
                    )
            remaining -= take
            pointer = number(raw, self.sector_size - 4)
        if pointer != END:
            raise Issue(
                "difat_chain_termination",
                68
                if not self.difat_locations
                else (self.difat_locations[-1] + 2) * self.sector_size - 4,
            )
        seen = set()
        for pointer, source in zip(self.fat_locations, self.fat_sources):
            if pointer in seen:
                raise Issue("duplicate_fat_sector", source)
            seen.add(pointer)
            raw = self.claim(pointer, "FAT", source)
            base = len(self.fat) if len(self.fat) < self.normal_count else self.normal_count
            # Retain only file-addressable entries; still validate all table slack.
            for slot, value in enumerate(struct.unpack("<" + "I" * self.words, raw)):
                if base + slot < self.normal_count:
                    self.fat.append(value)
                elif value != FREE:
                    raise Issue(
                        "fat_allocation_past_eof",
                        (pointer + 1) * self.sector_size + slot * 4,
                    )
        if len(self.fat) < self.normal_count:
            raise Issue("fat_table_capacity", 44)
        for sid, value in enumerate(self.fat[: self.normal_count]):
            if value not in (FREE, END, FAT, DIFAT) and not 0 <= value < self.normal_count:
                raise Issue("fat_next_reference_bounds", self.fat_offset(sid))
            if (
                value == FAT
                and self.owners.get(sid) != "FAT"
                or value == DIFAT
                and self.owners.get(sid) != "DIFAT"
            ):
                raise Issue("undeclared_metadata_sector", self.fat_offset(sid))
        for sid in self.fat_locations:
            if self.fat[sid] != FAT:
                raise Issue("fat_sector_marker", self.fat_offset(sid))
        for sid in self.difat_locations:
            if self.fat[sid] != DIFAT:
                raise Issue("difat_sector_marker", self.fat_offset(sid))

    def chain(self, start, role, source, expected=None, max_count=None):
        if expected is not None and expected > self.normal_count:
            raise Issue("chain_capacity", source)
        maximum = self.normal_count if max_count is None else min(max_count, self.normal_count)
        pointers = []
        pointer = start
        while pointer != END:
            if len(pointers) >= maximum:
                raise Issue("chain_budget", source)
            if expected is not None and len(pointers) >= expected:
                raise Issue("chain_longer_than_size", source)
            self.claim(pointer, role, source)
            pointers.append(pointer)
            source = self.fat_offset(pointer)
            pointer = self.fat[pointer]
            if pointer in (FREE, FAT, DIFAT):
                raise Issue("chain_terminal_marker", source)
        if expected is not None and len(pointers) != expected:
            raise Issue("chain_shorter_than_size", source)
        return pointers

    def directory(self):
        max_sectors = self.limits.directory_entries // (self.sector_size // 128)
        chain = self.chain(
            self.dir_start,
            "DIRECTORY",
            48,
            expected=self.dir_declared if self.major == 4 else None,
            max_count=max_sectors,
        )
        if not chain:
            raise Issue("empty_directory_chain", 48)
        self.directory_slots = len(chain) * self.sector_size // 128
        self.header.update(
            directory_sector_count=len(chain),
            first_directory_offset=(chain[0] + 1) * self.sector_size,
        )
        for sid in range(self.directory_slots):
            absolute = (chain[(sid * 128) // self.sector_size] + 1) * self.sector_size + (
                sid * 128
            ) % self.sector_size
            raw = self.raw[absolute : absolute + 128]
            kind = raw[66]
            if kind == 0:
                continue
            if kind not in (1, 2, 5):
                raise Issue("directory_type", absolute + 66)
            if (sid == 0) != (kind == 5):
                raise Issue("root_entry_identity", absolute + 66)
            length = number(raw, 64, "<H")
            if not 4 <= length <= 64 or length % 2 or bytes(raw[length - 2 : length]) != b"\0\0":
                raise Issue("directory_name_length_or_terminator", absolute + 64)
            try:
                name = bytes(raw[: length - 2]).decode("utf-16le", "strict")
            except UnicodeError:
                raise Issue("directory_name_encoding", absolute) from None
            if "\0" in name or any(c in name for c in "/\\:!"):
                raise Issue("directory_name_character", absolute)
            if not name.isascii():
                self.issue("unicode_simple_uppercase_open", absolute)
            color = raw[67]
            if color not in (0, 1):
                raise Issue("directory_color", absolute + 67)
            left, right, child = struct.unpack_from("<III", raw, 68)
            start = number(raw, 116)
            fullsize = number(raw, 120, "<Q")
            high = number(raw, 124)
            size = fullsize if self.major == 4 else fullsize & 0xFFFFFFFF
            created, modified = number(raw, 100, "<Q"), number(raw, 108, "<Q")
            if size > self.limits.stream_bytes:
                raise Issue("stream_byte_budget", absolute + 120)
            if kind == 5:
                for bad, field in [
                    (name != "Root Entry", 0),
                    (left != FREE, 68),
                    (right != FREE, 72),
                    (bool(created), 100),
                ]:
                    if bad:
                        raise Issue("root_entry_fields", absolute + field)
            if kind == 1:
                if start:
                    raise Issue("storage_entry_fields", absolute + 116)
                if fullsize:
                    raise Issue("storage_entry_fields", absolute + 120)
            if kind == 2:
                for bad, field in [
                    (child != FREE, 76),
                    (any(raw[80:96]), 80),
                    (bool(created), 100),
                    (bool(modified), 108),
                ]:
                    if bad:
                        raise Issue("stream_entry_fields", absolute + field)
            if kind == 2 and number(raw, 96):
                self.issue("stream_state_bits_profile", absolute + 96)
            self.entries[sid] = Entry(
                sid,
                absolute,
                name,
                length,
                kind,
                color,
                left,
                right,
                child,
                start,
                size,
                high,
                time_evidence(created, absolute + 100),
                time_evidence(modified, absolute + 108),
            )
        if 0 not in self.entries:
            raise Issue("missing_root_entry", 48)

    def tree(self):
        used = {0}
        self.paths[0] = ()
        storage = [(0, 0)]
        while storage:
            parent, depth = storage.pop()
            entry = self.entries[parent]
            if depth > self.limits.directory_depth:
                raise Issue("directory_depth_budget", entry.offset)
            top = entry.child
            if top == FREE:
                continue
            candidate = self.entries.get(top)
            if candidate is None:
                raise Issue("directory_reference_bounds", entry.offset + 76)
            if candidate.color != 1:
                raise Issue("sibling_tree_root_red", candidate.offset + 67)
            pending = [(top, None, None, False, 1, entry.offset + 76)]
            names = set()
            while pending:
                sid, low, high, parent_red, tree_depth, source = pending.pop()
                self.reference(source)
                if tree_depth > self.limits.sibling_depth:
                    raise Issue("sibling_depth_budget", source)
                child = self.entries.get(sid)
                if child is None:
                    raise Issue("directory_reference_bounds", source)
                if sid in used:
                    raise Issue("directory_cycle_or_shared_reference", source)
                used.add(sid)
                if child.kind == 5:
                    raise Issue("root_in_sibling_tree", source)
                key = (child.name_length, child.name.upper()) if child.name.isascii() else None
                if key is not None:
                    if key in names:
                        raise Issue("duplicate_sibling_name", child.offset)
                    if low is not None and key <= low or high is not None and key >= high:
                        raise Issue("sibling_name_order", child.offset)
                    names.add(key)
                if parent_red and child.color == 0:
                    raise Issue("consecutive_red_siblings", child.offset + 67)
                path = self.paths[parent] + (child.name,)
                if len(path) > self.limits.directory_depth:
                    raise Issue("directory_depth_budget", child.offset)
                self.paths[sid] = path
                self.parents[sid] = parent
                if child.kind == 1:
                    storage.append((sid, depth + 1))
                if child.right != FREE:
                    pending.append(
                        (
                            child.right,
                            key if key is not None else low,
                            high,
                            child.color == 0,
                            tree_depth + 1,
                            child.offset + 72,
                        )
                    )
                if child.left != FREE:
                    pending.append(
                        (
                            child.left,
                            low,
                            key if key is not None else high,
                            child.color == 0,
                            tree_depth + 1,
                            child.offset + 68,
                        )
                    )
        if len(used) != len(self.entries):
            missing = min(sid for sid in self.entries if sid not in used)
            self.issue("unreachable_active_directory_entry", self.entries[missing].offset)

    def mini_allocation(self):
        root = self.entries[0]
        self.root_chain = self.chain(
            root.start,
            "MINISTREAM",
            root.offset + 116,
            expected=(root.size + self.sector_size - 1) // self.sector_size,
        )
        digest = sha256()
        for sid in self.root_chain:
            digest.update(struct.pack("<I", sid))
        self.root_evidence = {
            "directory_entry_offset": root.offset,
            "child_id": None if root.child == FREE else root.child,
            "size": root.size,
            "starting_sector": root.start,
            "sector_count": len(self.root_chain),
            "chain_sha256": digest.hexdigest(),
            "created": root.created,
            "modified": root.modified,
            "raw_size_high_dword": root.high_size,
            "version3_size_high_dword_ignored": self.major == 3,
            "content": "NOT_DECODED",
        }
        if root.size % 64:
            raise Issue("partial_mini_sector_profile", root.offset + 120)
        self.mini_slots = root.size // 64
        if self.mini_slots > self.limits.mini_sectors:
            raise Issue("mini_sector_budget", root.offset + 120)
        chain = self.chain(self.mini_start, "MINIFAT", 60, expected=self.nmini)
        self.mini_locations = chain
        for sid in chain:
            base = min(len(self.minifat), self.mini_slots)
            raw = self.raw[(sid + 1) * self.sector_size : (sid + 2) * self.sector_size]
            for slot, value in enumerate(struct.unpack("<" + "I" * self.words, raw)):
                if base + slot < self.mini_slots:
                    self.minifat.append(value)
                elif value != FREE:
                    raise Issue(
                        "minifat_allocation_past_ministream",
                        (sid + 1) * self.sector_size + slot * 4,
                    )
        if len(self.minifat) < self.mini_slots:
            raise Issue("minifat_capacity", 64)
        for sid, value in enumerate(self.minifat[: self.mini_slots]):
            if value not in (FREE, END) and not 0 <= value < self.mini_slots:
                raise Issue("minifat_next_reference_bounds", self.mini_offset(sid))

    def mini_offset(self, sid):
        return (self.mini_locations[sid // self.words] + 1) * self.sector_size + (
            sid % self.words
        ) * 4

    def mini_chain(self, entry):
        count = (entry.size + 63) // 64
        pointer = entry.start
        result = []
        source = entry.offset + 116
        while pointer != END:
            self.reference(source)
            if len(result) >= count:
                raise Issue("mini_chain_longer_than_size", source)
            if not 0 <= pointer < self.mini_slots:
                raise Issue("mini_reference_bounds", source)
            if pointer in self.mini_owners:
                raise Issue("mini_cycle_or_shared_reference", source)
            self.mini_owners[pointer] = entry.sid
            result.append(pointer)
            source = self.mini_offset(pointer)
            pointer = self.minifat[pointer]
            if pointer == FREE:
                raise Issue("mini_chain_free_reference", source)
        if len(result) != count:
            raise Issue("mini_chain_shorter_than_size", source)
        return result

    def stream_row(self, entry, chain, mini):
        extents = []
        remaining = entry.size
        digest = sha256()
        for sid in chain:
            digest.update(struct.pack("<I", sid))
            logical = sid * 64 if mini else 0
            offset = (
                (self.root_chain[logical // self.sector_size] + 1) * self.sector_size
                + logical % self.sector_size
                if mini
                else (sid + 1) * self.sector_size
            )
            take = min(remaining, 64 if mini else self.sector_size)
            remaining -= take
            if extents and extents[-1]["offset"] + extents[-1]["length"] == offset:
                extents[-1]["length"] += take
            else:
                self.extent_count += 1
                if self.extent_count > self.limits.extents:
                    raise Issue("extent_budget", entry.offset)
                extents.append({"offset": offset, "length": take})
        path = self.paths.get(entry.sid)
        rawname = entry.name.encode("utf-16le")
        row = {
            "directory_id": entry.sid,
            "directory_entry_offset": entry.offset,
            "parent_directory_id": self.parents.get(entry.sid),
            "left_sibling_id": None if entry.left == FREE else entry.left,
            "right_sibling_id": None if entry.right == FREE else entry.right,
            "child_id": None if entry.child == FREE else entry.child,
            "kind": "STREAM" if entry.kind == 2 else "STORAGE",
            "name_sha256": sha256(rawname).hexdigest(),
            "name_utf16_bytes": entry.name_length - 2,
            "hierarchy": "REACHABLE" if path is not None else "OPEN_UNREACHABLE",
            "size": entry.size,
            "raw_size_high_dword": entry.high_size,
            "version3_size_high_dword_ignored": self.major == 3 and entry.kind in (2, 5),
            "sector_space": "MINIFAT" if mini else "FAT" if entry.kind == 2 else "NONE",
            "sector_count": len(chain),
            "chain_sha256": digest.hexdigest(),
            "data_extents": extents,
            "created": entry.created,
            "modified": entry.modified,
            "content": "NOT_DECODED",
        }
        row["macro_name_indicator"] = (
            entry.name.lower() in ("vba", "_vba_project", "project", "projectwm")
            or path is not None
            and any(part.lower() == "vba" for part in path[:-1])
            and (entry.name.lower() == "dir" or entry.name.lower().startswith("__srp_"))
        )
        if self.reveal_names and not self.issues:
            row["name"] = entry.name
            if path is not None:
                row["path"] = list(path)
        encoded = json.dumps(row, ensure_ascii=True, separators=(",", ":")).encode()
        self.row_bytes += len(encoded) + 1
        if self.row_bytes > self.limits.report_bytes:
            raise Issue("report_budget", entry.offset)
        self.rows.append(row)

    def streams(self, reveal_names):
        self.reveal_names = reveal_names
        streams = 0
        for sid, entry in sorted(self.entries.items()):
            if sid == 0:
                continue
            chain = []
            mini = False
            if entry.kind == 2:
                streams += 1
                if streams > self.limits.streams:
                    raise Issue("stream_count_budget", entry.offset)
                mini = 0 < entry.size < 4096
                chain = (
                    self.mini_chain(entry)
                    if mini
                    else self.chain(
                        entry.start,
                        "STREAM:" + str(sid),
                        entry.offset + 116,
                        expected=(entry.size + self.sector_size - 1) // self.sector_size,
                    )
                )
            self.stream_row(entry, chain, mini)
        leftover = next(
            (sid for sid, value in enumerate(self.fat) if value != FREE and sid not in self.owners),
            None,
        )
        if leftover is not None:
            self.issue("unclaimed_allocated_sector", self.fat_offset(leftover))
        leftover = next(
            (
                sid
                for sid, value in enumerate(self.minifat)
                if value != FREE and sid not in self.mini_owners
            ),
            None,
        )
        if leftover is not None:
            self.issue("unclaimed_allocated_mini_sector", self.mini_offset(leftover))
        if self.issues:
            for row in self.rows:
                row.pop("name", None)
                row.pop("path", None)


def review(data, reveal_names=False, limits=DEFAULT_LIMITS):
    """Review exact immutable CFB bytes, without decoding or exporting stream payloads."""
    result = {
        "schema_version": 1,
        "status": "OPEN",
        "issues": [],
        "directory": [],
        "stream_content": "NOT_DECODED",
        "macro_execution": "NOT_IMPLEMENTED",
        "macro_maliciousness": "OPEN",
        "input_authenticity": "OPEN",
        "office_runtime": "OPEN",
        "cvp_eligibility": "OPEN",
        "implementation_author": "dhtfish98",
    }
    parser = None
    report_limit = DEFAULT_LIMITS.report_bytes
    try:
        check_limits(limits)
        report_limit = limits.report_bytes
        if type(data) is not bytes or len(data) > limits.file_bytes:
            raise Issue("input_type_or_byte_budget")
        if type(reveal_names) is not bool:
            raise Issue("reveal_names_type")
        result.update(input_bytes=len(data), input_sha256=sha256(data).hexdigest())
        parser = CFB(data, limits)
        parser.header_read()
        result["header"] = parser.header
        parser.allocation()
        parser.directory()
        parser.tree()
        parser.mini_allocation()
        parser.streams(reveal_names)
        result["root_ministream"] = parser.root_evidence
        result["directory"] = parser.rows
        result["status"] = "OPEN" if parser.issues else "PASS"
        result["macro_name_indicators"] = sum(row["macro_name_indicator"] for row in parser.rows)
    except Issue as error:
        issue = {"code": error.code, "offset": error.offset}
        if parser is not None:
            parser.issues = parser.issues[: max(0, limits.issues - 1)] + [issue]
        else:
            result["issues"] = [issue]
        result["directory"] = []
    if parser is not None:
        result["issues"] = parser.issues
        result["counts"] = {
            "physical_sectors": parser.normal_count,
            "claimed_sectors": len(parser.owners),
            "directory_slots": parser.directory_slots,
            "active_directory_entries": len(parser.entries),
            "reachable_directory_entries": len(parser.paths),
            "mini_sectors": parser.mini_slots,
            "claimed_mini_sectors": len(parser.mini_owners),
            "references": parser.references,
        }
    if len(json.dumps(result, ensure_ascii=True, separators=(",", ":")).encode()) > report_limit:
        return {
            "schema_version": 1,
            "status": "OPEN",
            "issues": [{"code": "report_budget", "offset": None}],
            "directory": [],
            "cvp_eligibility": "OPEN",
            "implementation_author": "dhtfish98",
        }
    return result
