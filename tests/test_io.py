import contextlib
import io
import json
import os
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from compound_document_review.cli import main
from compound_document_review.files import read_local
from compound_document_review.model import Issue
from fixtures import Builder, example


class InputAndCLI(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.folder = Path(temporary.name).resolve()
        self.path = self.folder / "PRIVATE_FILE_PATH.cfb"
        self.data, _b, *_ = example()
        self.path.write_bytes(self.data)

    def call(self, options):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(options)
        self.assertEqual(err.getvalue(), "")
        self.assertNotIn(str(self.folder), out.getvalue())
        self.assertNotIn("PRIVATE_FILE_PATH", out.getvalue())
        return code, json.loads(out.getvalue())

    def test_byte_exact_no_modify_and_default_redaction(self):
        self.assertEqual(read_local(str(self.path)), self.data)
        self.assertEqual(self.call([str(self.path)])[0], 0)
        self.assertEqual(self.call([str(self.path), "--reveal-names"])[0], 0)
        self.assertEqual(self.path.read_bytes(), self.data)

    def test_absolute_path_parent_and_leaf_links_are_refused(self):
        for level in ("leaf", "parent"):
            link = self.folder / level
            link.symlink_to(
                self.path if level == "leaf" else self.folder,
                target_is_directory=level == "parent",
            )
            target = link if level == "leaf" else link / self.path.name
            with self.assertRaises(Issue):
                read_local(str(target))
        nested = self.folder / "nested"
        nested.mkdir()
        (nested / "link").symlink_to(self.folder, target_is_directory=True)
        with self.assertRaises(Issue):
            read_local(str(nested / "link" / self.path.name))

    def test_relative_paths_and_original_components(self):
        previous = os.getcwd()
        try:
            os.chdir(self.folder)
            self.assertEqual(read_local(self.path.name), self.data)
            for spelling in (
                ".",
                "..",
                "./" + self.path.name,
                "../" + self.path.name,
                "nested//x",
            ):
                with self.assertRaises(Issue):
                    read_local(spelling)
        finally:
            os.chdir(previous)

    def test_nonregular_objects_never_wait_for_data(self):
        import socket

        fifo = self.folder / "fifo"
        os.mkfifo(fifo)
        handle = socket.socket(socket.AF_UNIX)
        self.addCleanup(handle.close)
        socket_path = self.folder / "socket"
        handle.bind(str(socket_path))
        for path in (self.folder, fifo, socket_path, Path("/dev/null")):
            with self.assertRaises(Issue):
                read_local(str(path))

    def test_platform_without_dirfd_is_open(self):
        with patch("compound_document_review.files.os.supports_dir_fd", set()):
            with self.assertRaises(Issue) as result:
                read_local(str(self.path))
        self.assertEqual(result.exception.code, "safe_file_platform_not_supported")

    def test_path_type_nul_surrogate_and_byte_budgets(self):
        for spelling in (None, self.path, "", "/", "\0", "\ud800", "x" * 8193):
            with self.assertRaises(Issue):
                read_local(spelling)
        code, result = self.call([str(self.folder / "PRIVATE_FILE_PATH_MISSING")])
        self.assertEqual(code, 2)
        self.assertEqual(result["status"], "OPEN")

    def test_short_read_is_rejected_even_with_unchanged_stat(self):
        calls = []
        original = os.read

        def incomplete(fd, count):
            calls.append(fd)
            return original(fd, 1) if len(calls) == 1 else b""

        with patch("compound_document_review.files.os.read", incomplete):
            with self.assertRaises(Issue) as result:
                read_local(str(self.path))
        self.assertEqual(result.exception.code, "file_changed_or_short_read")

    def test_regular_and_every_identity_field_rechecked(self):
        original = os.fstat
        fields = (
            "st_dev",
            "st_ino",
            "st_size",
            "st_mtime_ns",
            "st_ctime_ns",
            "st_mode",
        )
        for field in fields:
            calls = []

            def replacement(fd):
                actual = original(fd)
                calls.append(fd)
                data = {name: getattr(actual, name) for name in fields}
                if len(calls) == 2:
                    data[field] = stat.S_IFIFO if field == "st_mode" else data[field] + 1
                return SimpleNamespace(**data)

            with (
                self.subTest(field=field),
                patch("compound_document_review.files.os.fstat", replacement),
            ):
                with self.assertRaises(Issue) as result:
                    read_local(str(self.path))
                self.assertEqual(result.exception.code, "file_changed_or_short_read")

    def test_sparse_input_refused_before_read(self):
        with self.path.open("wb") as out:
            out.truncate(64 * 1024 * 1024 + 1)
        with patch(
            "compound_document_review.files.os.read",
            side_effect=AssertionError("No data read"),
        ):
            with self.assertRaises(Issue):
                read_local(str(self.path))

    def test_cli_unknown_and_invalid_options_are_not_echoed(self):
        for arguments in (
            [],
            [str(self.path), "--PRIVATE_FILE_PATH_OPTION"],
            ["PRIVATE_FILE_PATH_MISSING"],
        ):
            code, result = self.call(arguments)
            self.assertEqual(code, 2)
            self.assertEqual(result["status"], "OPEN")
            self.assertEqual(result["directory"], [])

    def test_only_explicit_names_never_content(self):
        b = Builder()
        b.add(("PRIVATE_NAME",), b"PRIVATE_STREAM_CONTENT")
        self.path.write_bytes(b.build())
        code, result = self.call([str(self.path)])
        self.assertEqual(code, 0)
        self.assertNotIn("PRIVATE_NAME", json.dumps(result))
        self.assertNotIn("PRIVATE_STREAM_CONTENT", json.dumps(result))
        code, result = self.call([str(self.path), "--reveal-names"])
        self.assertEqual(code, 0)
        self.assertIn("PRIVATE_NAME", json.dumps(result))
        self.assertNotIn("PRIVATE_STREAM_CONTENT", json.dumps(result))

    def test_public_runtime_requires_no_network_or_subprocess(self):
        with (
            patch("socket.socket", side_effect=AssertionError("Network forbidden")),
            patch("subprocess.Popen", side_effect=AssertionError("Execution forbidden")),
        ):
            self.assertEqual(self.call([str(self.path)])[0], 0)


if __name__ == "__main__":
    unittest.main()
