"""Dissect ESE database tooling.

Names from :mod:`dissect.esedb.tools.sru` are lazily re-exported for convenient
cross-database SRUM identity provenance and merging access.
"""

from __future__ import annotations

from typing import Any

_LAZY_SRU_NAMES = {
    "SRU",
    "Entry",
    "Identity",
    "AppIdentity",
    "UserIdentity",
    "IdentityList",
    "IdentityConflict",
    "IdentityConflictError",
    "IdentityStatus",
    "MappingCategory",
    "UsageRecord",
    "MergedUsage",
    "merge_records",
    "merge_identities",
    "merge_sru",
    "same_subject",
    "subject_key",
    "build_identity",
    "build_usage_record",
    "open_sru",
}


def __getattr__(name: str) -> Any:
    if name in _LAZY_SRU_NAMES or name[:1].isupper() or name.startswith(("merge", "build", "trace")):
        from dissect.esedb.tools import sru  # noqa: PLC0415

        return getattr(sru, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__() -> list[str]:
    from dissect.esedb.tools import sru  # noqa: PLC0415

    return sorted(set(globals()) | set(dir(sru)))
