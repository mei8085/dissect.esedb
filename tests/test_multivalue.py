from __future__ import annotations

import struct
from typing import TYPE_CHECKING, BinaryIO

from dissect.esedb.c_esedb import PAGE_FLAG, TAGFLD_HEADER, JET_coltyp
from dissect.esedb.compression import decompress
from dissect.esedb.esedb import EseDB
from dissect.esedb.record import Record
from dissect.esedb.table import Column, Table

if TYPE_CHECKING:
    from collections.abc import Sequence

    from dissect.esedb.record import TagField

SEPARATED_FLAG = 0x8000


def _split_members(blob: bytes, *, two_values: bool) -> list[tuple[bytes, bool]]:
    """Split a raw tagged multi-value blob into its members, in stored order.

    Returns a list of ``(member bytes, is separated long value key)`` tuples.
    """
    if two_values:
        # Optimized storage: the first value is length-prefixed, the second value is the remainder
        first_size = blob[0]
        return [(blob[1 : 1 + first_size], False), (blob[1 + first_size :], False)]

    first_offset = struct.unpack("<H", blob[:2])[0] & 0x7FFF
    count = first_offset // 2
    offsets = struct.unpack(f"<{count}H", blob[:first_offset])
    bounds = [offset & 0x7FFF for offset in offsets] + [len(blob)]

    return [(blob[bounds[i] : bounds[i + 1]], bool(offsets[i] & SEPARATED_FLAG)) for i in range(count)]


def _parse_member(column: Column, member: bytes) -> object:
    ctype = column.ctype
    if column.is_text:
        return ctype.parse(member, encoding=column.encoding)
    return ctype.parse(member)


def _resolve_members(record: Record, column: Column, tag_field: TagField, blob: bytes) -> list[object]:
    """Resolve a raw tagged multi-value blob to parsed members, position by position."""
    result = []
    members = _split_members(blob, two_values=bool(tag_field.flags & TAGFLD_HEADER.TwoValues))

    for index, (member, separated) in enumerate(members):
        if separated:
            member = record._table.get_long_value(member)
        if index == 0 and tag_field.flags & TAGFLD_HEADER.Compressed:
            member = decompress(member)
        result.append(_parse_member(column, member))

    return result


class _FakePage:
    def __init__(self, flags: int) -> None:
        self.flags = flags


class _FakeTag:
    def __init__(self, page: _FakePage) -> None:
        self.page = page


class _FakeNode:
    """Minimal node that satisfies the parts of :class:`RecordData` used for tagged fields."""

    def __init__(self, data: bytes) -> None:
        self.data = data
        self.tag = _FakeTag(_FakePage(PAGE_FLAG.NewRecordFormat))


class _FakeEseDB:
    has_small_pages = False
    impacket_compat = False


class _SyntheticTable(Table):
    """Table with a fixed set of long values so separated multi-values can be resolved."""

    def __init__(self, columns: Sequence[Column], long_values: dict[bytes, bytes]) -> None:
        super().__init__(_FakeEseDB(), "synthetic", 1, columns=list(columns))
        self._long_values = long_values

    def get_long_value(self, key: bytes) -> bytes:
        return self._long_values[bytes(key)]


def _multivalue_blob(members: Sequence[tuple[bytes, bool]]) -> bytes:
    """Build a regular multi-value blob (offset table followed by the member data)."""
    offsets = []
    body = b""
    position = 2 * len(members)

    for payload, separated in members:
        offsets.append(position | (SEPARATED_FLAG if separated else 0))
        body += payload
        position += len(payload)

    return b"".join(struct.pack("<H", offset) for offset in offsets) + body


def _two_values_blob(first: bytes, second: bytes) -> bytes:
    return bytes([len(first)]) + first + second


def _record_data(fields: Sequence[tuple[int, int, bytes]]) -> bytes:
    """Build a record that only has tagged fields.

    ``fields`` is a sequence of ``(column identifier, tag flags, raw tagged data)``.
    """
    array_size = 4 * len(fields)
    offset = array_size
    offsets = []

    for _, _, payload in fields:
        offsets.append(offset)
        offset += 1 + len(payload)

    tag_array = b"".join(
        struct.pack("<HH", identifier, field_offset)
        for (identifier, _, _), field_offset in zip(fields, offsets, strict=True)
    )
    tagged_data = b"".join(bytes([flags]) + payload for _, flags, payload in fields)

    # Header with no fixed and no variable columns, so the tagged data starts right after it
    return struct.pack("<BBH", 0, 127, 4) + tag_array + tagged_data


def _synthetic_record(fields: Sequence[tuple[int, int, bytes]], long_values: dict[bytes, bytes]) -> Record:
    columns = [Column(identifier, f"Column{identifier}", JET_coltyp.LongBinary) for identifier, _, _ in fields]
    table = _SyntheticTable(columns, long_values)
    return Record(table, _FakeNode(_record_data(fields)))


def test_tagged_multivalue_members_map_to_raw_slices(multi_db: BinaryIO) -> None:
    """Every parsed member must correspond one to one to its raw member, in stored order."""
    db = EseDB(multi_db)
    table = db.table("multi")

    records = list(table.records())
    assert len(records) == 2

    checked = 0
    for record in records:
        for column in table.columns:
            if not column.is_tagged:
                continue

            tag_field, _ = record._data._get_tagged(column)
            if tag_field is None or not tag_field.flags & TAGFLD_HEADER.MultiValues:
                continue

            raw = record.get(column.name, raw=True)
            parsed = record.get(column.name)
            assert isinstance(parsed, list), f"{column.name} should be parsed as a list of members"

            members = _split_members(raw, two_values=bool(tag_field.flags & TAGFLD_HEADER.TwoValues))
            assert len(parsed) == len(members)
            assert parsed == _resolve_members(record, column, tag_field, raw)
            checked += 1

    # 21 multi-value columns on the first record, 6 on the second one
    assert checked == 27


def test_separated_members_are_traceable_in_stored_order(multi_db: BinaryIO) -> None:
    """Members that live in the long value page must resolve to the same ordered list."""
    db = EseDB(multi_db)
    table = db.table("multi")
    record = next(table.records())

    column = table.column("LongBinary")
    _, raw = record._data._get_tagged(column)
    members = _split_members(bytes(raw), two_values=False)

    # All members are separated and the raw view contains their long value keys, in order
    assert all(separated for _, separated in members)
    keys = [member for member, _ in members]
    assert keys == sorted(keys)

    parsed = record.get("LongBinary")
    assert parsed == [table.get_long_value(key) for key in keys]
    assert parsed[0].startswith(b"Some very long binary data that has multiple values, this is value 1")
    assert parsed[1].startswith(b"Some very long binary data that has multiple values, this is value 2")
    assert parsed[2].startswith(b"Some very long binary data that has multiple values, this is value 3")

    # The same correspondence holds for the exported record
    assert record.as_dict()["LongBinary"] == parsed
    assert record.as_dict(raw=True)["LongBinary"] == bytes(raw)


def test_inline_and_separated_members_share_one_ordered_list() -> None:
    long_values = {b"KEY-BETA": b"beta-long-value", b"KEY-GAMMA": b"gamma-long-value"}
    blob = _multivalue_blob(
        [
            (b"alpha", False),
            (b"KEY-BETA", True),
            (b"", False),
            (b"alpha", False),
            (b"KEY-GAMMA", True),
        ]
    )
    record = _synthetic_record([(256, TAGFLD_HEADER.MultiValues, blob)], long_values)

    assert record.get("Column256") == [b"alpha", b"beta-long-value", b"", b"alpha", b"gamma-long-value"]

    # The raw view still exposes the original inline payloads and separated keys, in order
    raw = record.get("Column256", raw=True)
    members = _split_members(raw, two_values=False)
    assert [member for member, separated in members if separated] == [b"KEY-BETA", b"KEY-GAMMA"]
    assert [member for member, separated in members if not separated] == [b"alpha", b"", b"alpha"]


def test_empty_and_duplicate_members_are_preserved() -> None:
    long_values: dict[bytes, bytes] = {}
    fields = [
        (256, TAGFLD_HEADER.MultiValues | TAGFLD_HEADER.TwoValues, _two_values_blob(b"twin", b"twin")),
        (257, TAGFLD_HEADER.MultiValues | TAGFLD_HEADER.TwoValues, _two_values_blob(b"", b"tail")),
        (258, TAGFLD_HEADER.MultiValues, _multivalue_blob([(b"", False)])),
        (
            259,
            TAGFLD_HEADER.MultiValues,
            _multivalue_blob([(b"z", False), (b"a", False), (b"m", False), (b"a", False)]),
        ),
    ]
    record = _synthetic_record(fields, long_values)

    # Duplicates survive as separate members
    assert record.get("Column256") == [b"twin", b"twin"]

    # An empty member is a member of its own, it does not disappear or become None
    assert record.get("Column257") == [b"", b"tail"]
    assert record.get("Column258") == [b""]

    # Member order is the stored order, not a sorted or deduplicated view
    order = record.get("Column259")
    assert order == [b"z", b"a", b"m", b"a"]
    assert order != sorted(order)
    assert order.count(b"a") == 2


def test_raw_and_parsed_views_do_not_overwrite_each_other() -> None:
    long_values = {b"KEY-BETA": b"beta-long-value"}
    blob = _multivalue_blob([(b"alpha", False), (b"KEY-BETA", True), (b"alpha", False), (b"", False)])
    two_values = _two_values_blob(b"dup", b"dup")
    record = _synthetic_record(
        [
            (256, TAGFLD_HEADER.MultiValues, blob),
            (257, TAGFLD_HEADER.MultiValues | TAGFLD_HEADER.TwoValues, two_values),
        ],
        long_values,
    )

    expected_parsed = [b"alpha", b"beta-long-value", b"alpha", b""]

    # The raw view is the untouched stored bytes, not the parsed member list
    assert record.get("Column256", raw=True) == blob

    # Reading the parsed view multiple times and then the raw view leaves both untouched
    assert record.get("Column256") == expected_parsed
    assert record.get("Column256", raw=True) == blob
    assert record.get("Column256") == expected_parsed
    assert record.get("Column256", raw=True) == blob

    # Splitting the raw bytes again still yields the original members
    members = _split_members(record.get("Column256", raw=True), two_values=False)
    assert [member for member, _ in members] == [b"alpha", b"KEY-BETA", b"alpha", b""]

    # Same for two-values storage
    assert record.get("Column257") == [b"dup", b"dup"]
    assert record.get("Column257", raw=True) == two_values
    assert record.get("Column257") == [b"dup", b"dup"]
    assert record.get("Column257", raw=True) == two_values


def test_export_restores_member_order() -> None:
    long_values = {b"KEY-BETA": b"beta-long-value", b"KEY-GAMMA": b"gamma-long-value"}
    blob = _multivalue_blob(
        [
            (b"alpha", False),
            (b"KEY-BETA", True),
            (b"", False),
            (b"alpha", False),
            (b"KEY-GAMMA", True),
        ]
    )
    record = _synthetic_record([(256, TAGFLD_HEADER.MultiValues, blob)], long_values)

    exported = record.as_dict()
    exported_raw = record.as_dict(raw=True)

    assert exported["Column256"] == [b"alpha", b"beta-long-value", b"", b"alpha", b"gamma-long-value"]
    assert exported_raw["Column256"] == blob

    # Re-splitting the exported raw bytes and resolving them gives back the exported members, in order
    column = record._table.column("Column256")
    tag_field, raw = record._data._get_tagged(column)
    resolved = _resolve_members(record, column, tag_field, exported_raw["Column256"])
    assert resolved == exported["Column256"]
    assert bytes(raw) == exported_raw["Column256"]
