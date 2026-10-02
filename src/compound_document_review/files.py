"""Stable bounded reads from a regular file with all path components held no-follow."""

from contextlib import ExitStack
import os
import stat

from .model import DEFAULT_LIMITS, Issue


def read_local(path):
    if type(path) is not str or "\0" in path:
        raise Issue("file_path_input")
    try:
        encoded = path.encode("utf-8", "strict")
    except UnicodeError:
        raise Issue("file_path_input") from None
    if len(encoded) > 8192:
        raise Issue("file_path_input")
    if (
        not hasattr(os, "O_NOFOLLOW")
        or not hasattr(os, "O_DIRECTORY")
        or not hasattr(os, "O_NONBLOCK")
        or os.open not in os.supports_dir_fd
    ):
        raise Issue("safe_file_platform_not_supported")
    absolute = path.startswith("/")
    parts = path.split("/")[1:] if absolute else path.split("/")
    if not parts or any(p in ("", ".", "..") for p in parts):
        raise Issue("file_path_components")
    try:
        with ExitStack() as closing:
            folder = os.open("/" if absolute else ".", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            closing.callback(os.close, folder)
            for component in parts[:-1]:
                folder = os.open(
                    component,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                    dir_fd=folder,
                )
                closing.callback(os.close, folder)
            handle = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=folder)
            closing.callback(os.close, handle)
            before = os.fstat(handle)
            if not stat.S_ISREG(before.st_mode) or before.st_size > DEFAULT_LIMITS.file_bytes:
                raise Issue("file_not_regular_or_byte_budget")
            blocks = []
            size = 0
            while True:
                block = os.read(handle, min(65536, DEFAULT_LIMITS.file_bytes + 1 - size))
                if not block:
                    break
                size += len(block)
                if size > DEFAULT_LIMITS.file_bytes:
                    raise Issue("file_byte_budget")
                blocks.append(block)
            after = os.fstat(handle)
            keys = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
            if (
                not stat.S_ISREG(after.st_mode)
                or size != after.st_size
                or any(getattr(before, k) != getattr(after, k) for k in keys)
            ):
                raise Issue("file_changed_or_short_read")
            return b"".join(blocks)
    except (OSError, UnicodeError):
        raise Issue("file_input_error") from None
