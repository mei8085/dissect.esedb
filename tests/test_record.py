from __future__ import annotations

from typing import BinaryIO

from dissect.esedb.c_esedb import CODEPAGE_MAP, TAGFLD_HEADER
from dissect.esedb.esedb import EseDB
from dissect.esedb.record import LongText, LongValue, Record


def test_as_dict(basic_db: BinaryIO) -> None:
    db = EseDB(basic_db)
    table = db.table("basic")

    records = list(table.records())
    assert len(records) == 2

    assert [r.as_dict() for r in records] == [
        {
            "Id": 1,
            "Bit": False,
            "UnsignedByte": 213,
            "Short": -1337,
            "Long": -13371337,
            "Currency": 1337133713371337,
            "IEEESingle": 1.0,
            "IEEEDouble": 13371337.13371337,
            "DateTime": 4675210852477960192,
            "UnsignedLong": 13371337,
            "LongLong": -13371337,
            "GUID": "3f360af1-6766-46dc-9af2-0dacf295c2a1",
            "UnsignedShort": 1337,
        },
        {
            "Id": 2,
            "Bit": True,
            "UnsignedByte": 255,
            "Short": 1339,
            "Long": 13391339,
            "Currency": -1339133913391339,
            "IEEESingle": -2.0,
            "IEEEDouble": -13391339.13391339,
            "DateTime": -4537072128574357504,
        },
    ]


def test_comparison(basic_db: BinaryIO) -> None:
    db = EseDB(basic_db)
    table = db.table("basic")

    records = list(table.records())
    assert len(records) == 2

    assert records[0] == records[0]
    assert records[0] != records[1]

    obj = Record(table, records[0]._node)
    assert records[0] == obj
    assert records[0] is not obj

    assert records[0] < records[1]
    assert records[0] <= records[1]
    assert records[0] <= records[0]

    assert set(records) == {records[0], records[1]}
    assert set(records) | {obj} == {records[0], records[1]}


def test_parse_value_encoding(windows_search_db: BinaryIO) -> None:
    """Test if we can parse invalid utf-16-le (Long)Text columns.

    Resources:
        - https://github.com/fox-it/dissect.esedb/pull/48
    """

    db = EseDB(windows_search_db)
    table = db.table("SystemIndex_PropertyStore")

    record = table.search(WorkID=1017)
    auto_summary = record.get("4625-System_Search_AutoSummary")
    assert auto_summary.startswith("Hong Kong SCS AdobeMingStd-Light-Acro-HKscs-B5-H ASCII")
    assert auto_summary.endswith("\\x4c\\xd8")


def test_separated_long_value_completeness_and_consistency(text_db: BinaryIO) -> None:
    """Separated long values expose completeness info and consistent raw/parsed bytes."""
    db = EseDB(text_db)
    table = db.table("text")
    record = next(table.records())

    for column_name in ("LongASCII", "LongUnicode", "LongCompressedASCII", "LongCompressedUnicode"):
        column = table.column(column_name)
        tag_field, _ = record._data._get_tagged(column)
        assert tag_field.flags & TAGFLD_HEADER.Separated

        raw_value = record.get(column_name, raw=True)
        parsed_value = record.get(column_name)

        # The raw read is a LongValue carrying reassembly metadata
        assert isinstance(raw_value, LongValue)
        assert raw_value.is_complete
        assert raw_value.gaps == ()
        assert len(raw_value) == raw_value.declared_size

        # The parsed read keeps the same metadata, in a text-specific wrapper
        assert isinstance(parsed_value, LongText)
        assert parsed_value.is_complete
        assert parsed_value.gaps == raw_value.gaps
        assert parsed_value.declared_size == raw_value.declared_size

        # The decoded text must match the raw reassembled bytes interpreted with the column encoding
        encoding = CODEPAGE_MAP[column.encoding]
        assert parsed_value == bytes(raw_value).decode(encoding)


def test_separated_binary_long_value_stays_bytes(binary_db: BinaryIO) -> None:
    """Separated binary long values stay a bytes subclass in both raw and parsed reads."""
    db = EseDB(binary_db)
    table = db.table("binary")
    record = next(table.records())

    raw_value = record.get("LongCompressedBinary", raw=True)
    parsed_value = record.get("LongCompressedBinary")

    assert isinstance(raw_value, LongValue)
    assert isinstance(parsed_value, LongValue)
    assert raw_value == parsed_value
    assert raw_value.is_complete
    assert parsed_value.is_complete
    assert parsed_value == b"test long compressed binary data " + (b"a" * 1000)


def test_multivalue_separated_instances_carry_metadata(multi_db: BinaryIO) -> None:
    """Separated instances inside a multi-value keep their per-value completeness metadata."""
    db = EseDB(multi_db)
    table = db.table("multi")
    record = next(table.records())

    binary_values = record.get("LongBinary")
    text_values = record.get("LongASCII")

    assert len(binary_values) == 3
    assert all(isinstance(value, LongValue) and value.is_complete for value in binary_values)

    assert len(text_values) == 3
    assert all(isinstance(value, LongText) and value.is_complete for value in text_values)
    assert all(value.gaps == () for value in text_values)
