import dataclasses
import hashlib
import json
import random
import unittest

from compound_document_review import Limits, review
from fixtures import Builder, END, FAT, FREE, DIF, example, put


class Structure(unittest.TestCase):
    def change(self, raw, offset, value, fmt="<I"):
        output = bytearray(raw)
        put(output, offset, value, fmt)
        return bytes(output)

    def assert_open(self, raw, code=None, limits=Limits()):
        before = hashlib.sha256(raw).digest()
        result = review(raw, True, limits)
        self.assertEqual(result["status"], "OPEN", result)
        self.assertEqual(before, hashlib.sha256(raw).digest())
        for row in result["directory"]:
            self.assertNotIn("name", row)
            self.assertNotIn("path", row)
        if code:
            self.assertIn(code, [i["code"] for i in result["issues"]])
        return result

    def test_versions_header_and_extended_difat(self):
        for major in (3, 4):
            for fats in (0, 110, 240):
                with self.subTest(major=major, fats=fats):
                    raw, b, *_ = example(major, fats)
                    r = review(raw, True)
                    self.assertEqual(r["status"], "PASS", r)
                    self.assertEqual(
                        r["counts"]["claimed_sectors"], r["counts"]["physical_sectors"]
                    )
                    self.assertEqual(r["header"]["declared_difat_sectors"], len(b.difat_ids))
                    self.assertEqual(r["input_sha256"], hashlib.sha256(raw).hexdigest())

    def test_stream_sizes_names_and_actual_offsets(self):
        for major in (3, 4):
            raw, b, short, long, empty = example(major)
            result = review(raw, True)
            rows = {r["directory_id"]: r for r in result["directory"]}
            self.assertEqual(rows[short]["path"], ["Synthetic", "Small"])
            self.assertEqual(rows[short]["size"], 15)
            self.assertEqual(rows[short]["sector_space"], "MINIFAT")
            self.assertEqual(rows[long]["path"], ["Large"])
            self.assertEqual(rows[long]["size"], 6000)
            self.assertEqual(rows[long]["sector_count"], 12 if major == 3 else 2)
            self.assertEqual(rows[empty]["data_extents"], [])
            for sid in (short, long, empty):
                self.assertEqual(rows[sid]["directory_entry_offset"], b.entry_offsets[sid])
                self.assertEqual(
                    sum(e["length"] for e in rows[sid]["data_extents"]),
                    rows[sid]["size"],
                )
            small = rows[short]["data_extents"][0]
            self.assertEqual(
                small,
                {
                    "offset": (b.chains["root_mini"][0] + 1) * b.sector_size,
                    "length": 15,
                },
            )

    def test_fragmented_regular_extents_follow_chain_order(self):
        raw, b, _short, long, *_ = example()
        data = bytearray(raw)
        chain = b.chains[("stream", long)]
        permutation = chain[2:4] + chain[:2] + chain[4:]
        # Reorder physical payload blocks to preserve the independent source value.
        chunks = [raw[(sid + 1) * 512 : (sid + 2) * 512] for sid in chain]
        for idx, sid in enumerate(permutation):
            data[(sid + 1) * 512 : (sid + 2) * 512] = chunks[idx]
            put(
                data,
                b.fat_offset(sid),
                permutation[idx + 1] if idx + 1 < len(permutation) else END,
            )
        put(data, b.entry_offsets[long] + 116, permutation[0])
        result = review(bytes(data), True)
        self.assertEqual(result["status"], "PASS", result)
        row = next(r for r in result["directory"] if r["directory_id"] == long)
        self.assertEqual(len(row["data_extents"]), 3)
        reconstructed = b"".join(
            bytes(data[e["offset"] : e["offset"] + e["length"]]) for e in row["data_extents"]
        )
        self.assertEqual(reconstructed, b.nodes[long]["data"])

    def test_fragmented_ministream_source_extents(self):
        b = Builder()
        sid = b.add(("Small",), b"XYZ" * 700)
        raw = b.build()
        data = bytearray(raw)
        chain = b.chains["root_mini"]
        permutation = chain[2:] + chain[:2]
        chunks = [raw[(i + 1) * 512 : (i + 2) * 512] for i in chain]
        for idx, target in enumerate(permutation):
            data[(target + 1) * 512 : (target + 2) * 512] = chunks[idx]
            put(
                data,
                b.fat_offset(target),
                permutation[idx + 1] if idx + 1 < len(permutation) else END,
            )
        put(data, b.entry_offsets[0] + 116, permutation[0])
        result = review(bytes(data), True)
        self.assertEqual(result["status"], "PASS", result)
        row = result["directory"][0]
        self.assertEqual(len(row["data_extents"]), 2)
        self.assertEqual(row["parent_directory_id"], 0)
        self.assertEqual(
            b"".join(
                bytes(data[e["offset"] : e["offset"] + e["length"]]) for e in row["data_extents"]
            ),
            b.nodes[sid]["data"],
        )

    def test_empty_container_both_versions(self):
        for major in (3, 4):
            raw = Builder(major).build()
            r = review(raw)
            self.assertEqual(r["status"], "PASS")
            self.assertEqual(r["directory"], [])

    def test_default_name_and_all_content_privacy(self):
        b = Builder()
        b.add(("PRIVATE_DIRECTORY_NAME",), b"PRIVATE_PAYLOAD_SENTINEL")
        raw = b.build()
        before = hashlib.sha256(raw).digest()
        r = review(raw)
        self.assertEqual(r["status"], "PASS")
        text = json.dumps(r)
        self.assertNotIn("PRIVATE_DIRECTORY_NAME", text)
        self.assertNotIn("PRIVATE_PAYLOAD_SENTINEL", text)
        r = review(raw, True)
        self.assertIn("PRIVATE_DIRECTORY_NAME", json.dumps(r))
        self.assertNotIn("PRIVATE_PAYLOAD_SENTINEL", json.dumps(r))
        self.assertEqual(before, hashlib.sha256(raw).digest())

    def test_payload_change_does_not_decode_or_classify(self):
        raw, b, *_ = example()
        changed = bytearray(raw)
        sector = (
            b.chains[("stream", 3)][0]
            if ("stream", 3) in b.chains
            else next(v[0] for k, v in b.chains.items() if type(k) is tuple and k[0] == "stream")
        )
        start = (sector + 1) * b.sector_size
        changed[start : start + 100] = b"PRIVATE_MACRO_BYTES_NO_EXECUTION".ljust(100, b"X")
        before = review(raw)
        after = review(bytes(changed))
        self.assertEqual(after["status"], "PASS")
        self.assertEqual(before["directory"], after["directory"])
        self.assertNotEqual(before["input_sha256"], after["input_sha256"])
        self.assertNotIn("PRIVATE_MACRO_BYTES", json.dumps(after))

    def test_empty_vba_name_only_indication(self):
        b = Builder()
        b.add(("VBA", "dir"))
        b.add(("PROJECT",))
        b.add(("VBA", "_VBA_PROJECT"))
        result = review(b.build(), True)
        self.assertEqual(result["status"], "PASS")
        self.assertGreaterEqual(result["macro_name_indicators"], 3)
        self.assertEqual(result["macro_maliciousness"], "OPEN")
        self.assertEqual(result["macro_execution"], "NOT_IMPLEMENTED")

    def test_header_signature_versions_shifts_order_reserved(self):
        raw, _b, *_ = example()
        for offset, value, fmt, code in [
            (0, 0, "<Q", "header_signature_or_size"),
            (26, 5, "<H", "version_or_sector_shift"),
            (30, 12, "<H", "version_or_sector_shift"),
            (30, 65535, "<H", "version_or_sector_shift"),
            (28, 0, "<H", "byte_order_or_mini_shift"),
            (32, 7, "<H", "byte_order_or_mini_shift"),
            (8, 1, "<I", "header_reserved"),
            (34, 1, "<H", "header_reserved"),
            (56, 1, "<I", "mini_cutoff"),
            (40, 1, "<I", "version3_directory_count"),
        ]:
            self.assert_open(self.change(raw, offset, value, fmt), code)

    def test_version4_padding_and_directory_count(self):
        raw, b, *_ = example(4)
        self.assert_open(self.change(raw, 512, 1), "version4_header_padding")
        self.assert_open(self.change(raw, 40, 0), "chain_longer_than_size")
        self.assert_open(self.change(raw, 40, 2), "chain_shorter_than_size")

    def test_diagnostics_locate_exact_source_field(self):
        raw, b, short, *_ = example()
        fields = [
            (26, 5, "<H"),
            (30, 12, "<H"),
            (8, 1, "<I"),
            (34, 1, "<H"),
            (28, 0, "<H"),
            (32, 7, "<H"),
        ]
        fields += [(b.entry_offsets[0] + field, 1, "<I") for field in (68, 72, 100)]
        fields += [(b.entry_offsets[1] + field, 1, "<I") for field in (116, 120)]
        fields += [(b.entry_offsets[short] + field, 1, "<I") for field in (76, 80, 100, 108)]
        for offset, value, fmt in fields:
            with self.subTest(offset=offset):
                result = self.assert_open(self.change(raw, offset, value, fmt))
                self.assertEqual(result["issues"][-1]["offset"], offset)
        detached = self.change(raw, b.entry_offsets[1] + 76, FREE)
        result = self.assert_open(detached, "unreachable_active_directory_entry")
        issue = next(
            i for i in result["issues"] if i["code"] == "unreachable_active_directory_entry"
        )
        self.assertEqual(issue["offset"], b.entry_offsets[short])

    def test_minor_and_transaction_are_open_without_name_leak(self):
        raw, b, *_ = example()
        self.assert_open(self.change(raw, 24, 0, "<H"), "minor_version_profile")
        self.assert_open(self.change(raw, 52, 1), "transaction_state_not_implemented")

    def test_truncation_and_partial_extra_sector(self):
        raw, b, *_ = example()
        for size in (0, 1, 7, 8, 511, 512, 1024, len(raw) - 1):
            self.assert_open(raw[:size])
        self.assert_open(raw + b"X", "file_sector_extent")

    def test_fat_sector_count_and_unused_difat_slots(self):
        raw, b, *_ = example()
        for count in (0, 4097, 0xFFFFFFFF):
            self.assert_open(self.change(raw, 44, count), "fat_sector_budget")
        self.assert_open(self.change(raw, 80, 0), "unused_header_difat_entry")
        self.assert_open(self.change(raw, 76, 0xFFFFFFFF), "sector_reference_bounds")
        self.assert_open(self.change(raw, 68, FREE), "difat_chain_termination")

    def test_difat_count_bounds_cycle_duplicate_and_termination(self):
        raw, b, *_ = example(3, 240)
        self.assertEqual(len(b.difat_ids), 2)
        self.assert_open(self.change(raw, 72, 1), "difat_count_mismatch")
        self.assert_open(self.change(raw, 68, 0xFFFFFFFF), "sector_reference_bounds")
        first, last = b.difat_ids
        self.assert_open(
            self.change(raw, (first + 2) * 512 - 4, first),
            "sector_cycle_or_shared_role",
        )
        self.assert_open(self.change(raw, (last + 2) * 512 - 4, 0), "difat_chain_termination")
        self.assert_open(self.change(raw, (last + 1) * 512 + 4 * 4, 0), "unused_difat_entry")
        self.assert_open(self.change(raw, (first + 1) * 512, b.fat_ids[0]), "duplicate_fat_sector")

    def test_fat_difat_marker_identity_and_no_metadata_alias(self):
        raw, b, *_ = example(3, 110)
        self.assert_open(self.change(raw, b.fat_offset(b.fat_ids[0]), END), "fat_sector_marker")
        self.assert_open(self.change(raw, b.fat_offset(b.difat_ids[0]), END), "difat_sector_marker")
        self.assert_open(self.change(raw, 76, b.difat_ids[0]), "sector_cycle_or_shared_role")
        raw, b, *_ = example()
        stream = b.chains[("stream", 3)][0]
        self.assert_open(self.change(raw, b.fat_offset(stream), FAT), "undeclared_metadata_sector")

    def test_fat_slots_beyond_eof_and_invalid_next(self):
        raw, b, *_ = example()
        self.assert_open(
            self.change(raw, b.fat_offset(len(raw) // 512 - 1), END),
            "fat_allocation_past_eof",
        )
        first = b.chains[("stream", 3)][0]
        for next_id in (0xFFFFFFFB, 0xFFFFFFFA, 0xFFFFFFF0, 65536):
            self.assert_open(
                self.change(raw, b.fat_offset(first), next_id),
                "fat_next_reference_bounds",
            )

    def test_regular_chain_self_cycle_sharing_and_roles(self):
        raw, b, _short, long, _empty = example()
        first = b.chains[("stream", long)][0]
        self.assert_open(
            self.change(raw, b.fat_offset(first), first), "sector_cycle_or_shared_role"
        )
        self.assert_open(
            self.change(raw, b.entry_offsets[long] + 116, b.chains["directory"][0]),
            "sector_cycle_or_shared_role",
        )
        self.assert_open(
            self.change(raw, b.entry_offsets[long] + 116, b.chains["root_mini"][0]),
            "sector_cycle_or_shared_role",
        )

    def test_chain_short_long_and_non_end_terminal(self):
        raw, b, _short, long, _empty = example()
        chain = b.chains[("stream", long)]
        self.assert_open(self.change(raw, b.fat_offset(chain[0]), END), "chain_shorter_than_size")
        self.assert_open(
            self.change(raw, b.entry_offsets[long] + 120, 4096, "<Q"),
            "chain_longer_than_size",
        )
        for value in (FREE, FAT, DIF):
            self.assert_open(self.change(raw, b.fat_offset(chain[0]), value))
        self.assert_open(self.change(raw, 48, END), "empty_directory_chain")

    def test_directory_loop_nonboundary_bounds(self):
        raw, b, *_ = example()
        first = b.chains["directory"][0]
        self.assert_open(
            self.change(raw, b.fat_offset(first), first), "sector_cycle_or_shared_role"
        )
        self.assert_open(self.change(raw, 48, FREE), "sector_reference_bounds")

    def test_directory_name_length_termination_forbidden_and_surrogate(self):
        raw, b, short, *_ = example()
        offset = b.entry_offsets[short]
        for value in (0, 1, 2, 3, 65, 0xFFFF):
            self.assert_open(
                self.change(raw, offset + 64, value, "<H"),
                "directory_name_length_or_terminator",
            )
        data = bytearray(raw)
        data[offset + 10 : offset + 12] = b"X\0"
        self.assert_open(bytes(data), "directory_name_length_or_terminator")
        for char in "/\\:!\0":
            self.assert_open(self.change(raw, offset, ord(char), "<H"), "directory_name_character")
        self.assert_open(self.change(raw, offset, 0xD800, "<H"), "directory_name_encoding")

    def test_unicode_simple_uppercase_open(self):
        b = Builder()
        b.add(("合成",), b"private")
        self.assert_open(b.build(), "unicode_simple_uppercase_open")

    def test_object_types_and_root_location(self):
        raw, b, short, *_ = example()
        self.assert_open(self.change(raw, b.entry_offsets[0] + 66, 2, "<B"), "root_entry_identity")
        for value in (3, 4, 6, 255):
            self.assert_open(
                self.change(raw, b.entry_offsets[short] + 66, value, "<B"),
                "directory_type",
            )
        self.assert_open(
            self.change(raw, b.entry_offsets[short] + 66, 5, "<B"),
            "root_entry_identity",
        )
        self.assert_open(self.change(raw, b.entry_offsets[0] + 66, 0, "<B"), "missing_root_entry")

    def test_root_name_siblings_and_creation(self):
        raw, b, *_ = example()
        offset = b.entry_offsets[0]
        for where, value, fmt in [
            (0, ord("R") + 1, "<H"),
            (68, 1, "<I"),
            (72, 1, "<I"),
            (100, 1, "<Q"),
        ]:
            self.assert_open(self.change(raw, offset + where, value, fmt), "root_entry_fields")

    def test_storage_and_stream_fields(self):
        raw, b, short, *_ = example()
        storage = b.entry_offsets[1]
        stream = b.entry_offsets[short]
        for where in (116, 120):
            self.assert_open(self.change(raw, storage + where, 1), "storage_entry_fields")
        for where in (76, 80, 100, 108):
            self.assert_open(self.change(raw, stream + where, 1), "stream_entry_fields")
        self.assert_open(self.change(raw, stream + 96, 1), "stream_state_bits_profile")

    def test_colors_red_roots_and_consecutive_red(self):
        b = Builder()
        for name in ("a", "b", "c", "d", "e", "f", "g"):
            b.add((name,))
        raw = b.build()
        top = b.nodes[0]["child"]
        left = b.nodes[top]["left"]
        grand = b.nodes[left]["left"]
        self.assert_open(
            self.change(raw, b.entry_offsets[top] + 67, 0, "<B"),
            "sibling_tree_root_red",
        )
        self.assert_open(self.change(raw, b.entry_offsets[left] + 67, 2, "<B"), "directory_color")
        data = self.change(raw, b.entry_offsets[left] + 67, 0, "<B")
        self.assert_open(
            self.change(data, b.entry_offsets[grand] + 67, 0, "<B"),
            "consecutive_red_siblings",
        )
        self.assertEqual(
            review(self.change(raw, b.entry_offsets[0] + 67, 0, "<B"))["status"], "PASS"
        )

    def test_sibling_cycle_multiple_parent_and_free_slot(self):
        raw, b, short, *_ = example()
        top = b.nodes[0]["child"]
        self.assert_open(
            self.change(raw, b.entry_offsets[top] + 68, top),
            "directory_cycle_or_shared_reference",
        )
        self.assert_open(
            self.change(raw, b.entry_offsets[1] + 76, top),
            "directory_cycle_or_shared_reference",
        )
        self.assert_open(self.change(raw, b.entry_offsets[1] + 76, 7), "directory_reference_bounds")
        self.assert_open(
            self.change(raw, b.entry_offsets[1] + 76, 0xFFFFFFFF - 1),
            "directory_reference_bounds",
        )

    def test_sibling_sort_and_case_ambiguity(self):
        b = Builder()
        b.add(("aaa",))
        b.add(("bbb",))
        raw = b.build()
        self.assert_open(self.change(raw, b.entry_offsets[1], ord("z"), "<H"), "sibling_name_order")
        data = bytearray(raw)
        data[b.entry_offsets[1] : b.entry_offsets[1] + 6] = "BBB".encode("utf-16le")
        self.assert_open(bytes(data), "duplicate_sibling_name")

    def test_active_orphan_is_open(self):
        raw, b, short, *_ = example()
        self.assert_open(
            self.change(raw, b.entry_offsets[1] + 76, FREE),
            "unreachable_active_directory_entry",
        )

    def test_unallocated_sector_and_unclaimed_allocation(self):
        raw, b, *_ = example()
        data = raw + bytes(512)
        sid = len(raw) // 512 - 1
        self.assertEqual(review(data)["status"], "PASS")
        self.assert_open(self.change(data, b.fat_offset(sid), END), "unclaimed_allocated_sector")

    def test_minifat_header_chain_and_capacity(self):
        raw, b, *_ = example()
        self.assert_open(self.change(raw, 60, END), "chain_shorter_than_size")
        self.assert_open(self.change(raw, 64, 0), "chain_longer_than_size")
        self.assert_open(self.change(raw, 64, 99999), "minifat_sector_budget")
        root = b.entry_offsets[0]
        self.assert_open(self.change(raw, root + 120, 65, "<Q"), "partial_mini_sector_profile")
        self.assert_open(self.change(self.change(raw, 64, 0), 60, END), "minifat_capacity")

    def test_ministream_chain_and_mini_allocation_extent(self):
        raw, b, short, *_ = example()
        root = b.entry_offsets[0]
        self.assert_open(self.change(raw, root + 116, END), "chain_shorter_than_size")
        mini = (b.chains["minifat"][0] + 1) * 512
        self.assert_open(self.change(raw, mini + 4, END), "minifat_allocation_past_ministream")
        self.assert_open(self.change(raw, mini, FAT), "minifat_next_reference_bounds")
        self.assert_open(self.change(raw, b.entry_offsets[short] + 116, 1), "mini_reference_bounds")

    def test_minifat_self_cycle_free_and_short_chain(self):
        b = Builder()
        sid = b.add(("Short",), b"X" * 100)
        raw = b.build()
        mini = (b.chains["minifat"][0] + 1) * 512
        self.assert_open(self.change(raw, mini, 0), "mini_cycle_or_shared_reference")
        self.assert_open(self.change(raw, mini, FREE), "mini_chain_free_reference")
        self.assert_open(self.change(raw, mini, END), "mini_chain_shorter_than_size")
        self.assert_open(
            self.change(raw, b.entry_offsets[sid] + 120, 1, "<Q"),
            "mini_chain_longer_than_size",
        )

    def test_shared_mini_chain_and_unclaimed_mini(self):
        b = Builder()
        one = b.add(("One",), b"x")
        two = b.add(("Two",), b"y")
        raw = b.build()
        self.assert_open(
            self.change(raw, b.entry_offsets[two] + 116, b.nodes[one]["start"]),
            "mini_cycle_or_shared_reference",
        )
        # Leave a valid chain allocated but detach its directory entry as an empty stream.
        data = self.change(raw, b.entry_offsets[two] + 116, END)
        self.assert_open(
            self.change(data, b.entry_offsets[two] + 120, 0, "<Q"),
            "unclaimed_allocated_mini_sector",
        )

    def test_empty_stream_requires_end_and_cutoff_boundary(self):
        raw, b, short, long, empty = example()
        self.assert_open(
            self.change(raw, b.entry_offsets[empty] + 116, 0), "chain_longer_than_size"
        )
        for size in (0, 1, 63, 64, 65, 4095, 4096, 4097, 8192):
            builder = Builder()
            builder.add(("Value",), b"X" * size)
            result = review(builder.build())
            self.assertEqual(result["status"], "PASS", result)
            self.assertEqual(result["directory"][0]["size"], size)

    def test_v3_high_dword_ignored_but_v4_used(self):
        raw, b, _short, long, *_ = example()
        changed = self.change(raw, b.entry_offsets[long] + 124, 0xFFFFFFFF)
        result = review(changed)
        self.assertEqual(result["status"], "PASS")
        row = next(r for r in result["directory"] if r["directory_id"] == long)
        self.assertEqual(row["size"], 6000)
        self.assertEqual(row["raw_size_high_dword"], 0xFFFFFFFF)
        raw, b, _short, long, *_ = example(4)
        self.assert_open(self.change(raw, b.entry_offsets[long] + 124, 1), "stream_byte_budget")

    def test_storage_filetime_zero_exact_and_overflow(self):
        raw, b, *_ = example()
        offset = b.entry_offsets[1]
        row = next(r for r in review(raw)["directory"] if r["directory_id"] == 1)
        self.assertEqual(row["created"]["utc"], "1970-01-01T00:00:00Z")
        self.assertEqual(row["modified"]["submicrosecond_nanoseconds"], 900)
        result = review(self.change(raw, offset + 100, 0, "<Q"))
        self.assertEqual(
            next(r for r in result["directory"] if r["directory_id"] == 1)["created"]["status"],
            "UNSET",
        )
        self.assert_open(self.change(raw, offset + 100, 0xFFFFFFFFFFFFFFFF, "<Q"), "filetime_range")

    def test_api_limits_types_and_every_fixed_budget(self):
        raw, b, *_ = example()
        for value in (
            None,
            {},
            dataclasses.replace(Limits(), sectors=True),
            dataclasses.replace(Limits(), references=0),
            dataclasses.replace(Limits(), file_bytes=64 * 1024 * 1024 + 1),
            dataclasses.replace(Limits(), report_bytes=255),
        ):
            self.assert_open(raw, limits=value)
        for data in (None, "text", bytearray(raw), memoryview(raw)):
            self.assertEqual(review(data)["status"], "OPEN")
        self.assertEqual(review(raw, reveal_names=1)["status"], "OPEN")
        cases = [
            ("file_bytes", 1535, raw),
            ("sectors", 1, raw),
            ("fat_sectors", 1, example(3, 110)[0]),
            ("difat_sectors", 1, example(3, 240)[0]),
            ("directory_entries", 4, raw),
            ("directory_depth", 1, raw),
            ("sibling_depth", 1, raw),
            ("streams", 1, raw),
            ("stream_bytes", 10, raw),
            ("references", 1, raw),
            ("extents", 1, raw),
            ("report_bytes", 256, raw),
        ]
        for field, value, sample in cases:
            with self.subTest(field=field):
                self.assert_open(sample, limits=dataclasses.replace(Limits(), **{field: value}))
        b = Builder()
        b.add(("Short",), b"X" * 100)
        sample = b.build()
        self.assert_open(
            sample, "mini_sector_budget", dataclasses.replace(Limits(), mini_sectors=1)
        )
        sample = self.change(self.change(raw, 24, 0, "<H"), 52, 1)
        self.assert_open(sample, "issue_budget", dataclasses.replace(Limits(), issues=1))

    def test_late_error_does_not_return_early_revealed_names(self):
        b = Builder()
        b.add(("PRIVATE_NAME_SENTINEL",), b"x")
        late = b.add(("Later",), b"X" * 5000)
        raw = b.build()
        result = self.assert_open(self.change(raw, b.entry_offsets[late] + 116, 0xFFFFFFFB))
        self.assertEqual(result["directory"], [])
        self.assertNotIn("PRIVATE_NAME_SENTINEL", json.dumps(result))

    def test_fixed_random_malformed_smoke(self):
        raw, b, *_ = example()
        rng = random.Random(20261002)
        for _ in range(1000):
            data = bytearray(raw)
            for _ in range(3):
                data[rng.randrange(len(data))] = rng.randrange(256)
            result = review(bytes(data))
            self.assertIn(result["status"], ("PASS", "OPEN"))
            self.assertLessEqual(len(json.dumps(result).encode()), 1024 * 1024)


if __name__ == "__main__":
    unittest.main()
