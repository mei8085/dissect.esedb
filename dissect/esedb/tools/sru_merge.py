"""Cross-database identity provenance for SRUM records.

Thin namespace over :mod:`dissect.esedb.tools.sru`, where the source-scoped
:class:`~dissect.esedb.tools.sru.Identity` model and merge helpers live.
"""

from __future__ import annotations

from dissect.esedb.tools import sru as _sru

__all__ = list(getattr(_sru, "__all__", []))


def __getattr__(name: str):  # noqa: ANN202
    return getattr(_sru, name)


def __dir__() -> list[str]:
    return dir(_sru)
