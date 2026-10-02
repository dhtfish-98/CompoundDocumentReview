"""Fixed budgets and source-local diagnostic codes."""

from dataclasses import dataclass, fields
from datetime import datetime, timedelta, timezone


class Issue(Exception):
    def __init__(self, code, offset=None):
        self.code, self.offset = code, offset
        super().__init__(code)


@dataclass(frozen=True)
class Limits:
    file_bytes: int = 64 * 1024 * 1024
    sectors: int = 131072
    fat_sectors: int = 4096
    difat_sectors: int = 1024
    directory_entries: int = 16384
    directory_depth: int = 96
    sibling_depth: int = 96
    streams: int = 8192
    stream_bytes: int = 64 * 1024 * 1024
    mini_sectors: int = 1048576
    references: int = 500000
    extents: int = 8192
    issues: int = 64
    report_bytes: int = 1024 * 1024


DEFAULT_LIMITS = Limits()


def check_limits(limits):
    if type(limits) is not Limits:
        raise Issue("limits_type")
    for field in fields(Limits):
        value = getattr(limits, field.name)
        if type(value) is not int or not 0 < value <= getattr(DEFAULT_LIMITS, field.name):
            raise Issue("limits_range")
    if limits.report_bytes < 256:
        raise Issue("minimum_report_budget")


def time_evidence(ticks, offset):
    if ticks == 0:
        return {"ticks_100ns": 0, "utc": None, "status": "UNSET"}
    try:
        value = datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=ticks // 10)
    except OverflowError:
        raise Issue("filetime_range", offset) from None
    return {
        "ticks_100ns": ticks,
        "utc": value.isoformat().replace("+00:00", "Z"),
        "submicrosecond_nanoseconds": ticks % 10 * 100,
        "status": "UNAUTHENTICATED",
    }
