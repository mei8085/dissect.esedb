from __future__ import annotations

import datetime
from typing import BinaryIO

from dissect.util.ts import wintimestamp

from dissect.esedb.tools.ual import UAL

EPOCH_1601 = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)


def to_filetime(timestamp: datetime.datetime) -> int:
    """Convert an aware datetime to the raw Windows FILETIME integer stored in an ESE record."""
    return int((timestamp - EPOCH_1601).total_seconds() * 10_000_000)


def expected_day_date(year: int, day_num: int) -> datetime.datetime:
    """Reference conversion of a UAL day ordinal to a calendar date, independent of the parser."""
    year_start = datetime.datetime(year, 1, 1, tzinfo=datetime.timezone.utc)
    return EPOCH_1601.fromordinal(year_start.toordinal() + day_num - 1).replace(tzinfo=datetime.timezone.utc)


class FakeColumn:
    """Minimal stand-in for an ESE column descriptor at the EseDB boundary."""

    def __init__(self, name: str):
        self.name = name


class FakeRecord:
    """Minimal stand-in for an ESE record, returning raw stored values by column name."""

    def __init__(self, values: dict[str, object]):
        self._values = values

    def get(self, column_name: str) -> object:
        return self._values[column_name]


class FakeTable:
    """Minimal stand-in for an ESE table exposing columns and records."""

    def __init__(self, name: str, columns: list[FakeColumn], records: list[FakeRecord]):
        self.name = name
        self.columns = columns
        self._records = records

    def records(self) -> list[FakeRecord]:
        return self._records


class FakeEseDB:
    """Minimal stand-in for an EseDB database, resolving tables by name like the real parser."""

    def __init__(self, tables: list[FakeTable]):
        self._tables = {table.name: table for table in tables}

    def table(self, name: str) -> FakeTable:
        return self._tables[name]


def build_ual(table_name: str, columns: list[FakeColumn], records: list[FakeRecord]) -> UAL:
    """Wire a UAL parser to an in-memory table without touching an on-disk database."""
    ual = UAL.__new__(UAL)
    ual.esedb = FakeEseDB([FakeTable(table_name, columns, records)])
    return ual


def day_columns(day_nums: list[int]) -> list[FakeColumn]:
    return [FakeColumn(f"Day{day_num}") for day_num in day_nums]


def test_ual(ual_db: BinaryIO) -> None:
    db = UAL(ual_db)

    assert len(list(db.get_table_records("CLIENTS"))) == 19
    assert len(list(db.get_table_records("ROLE_ACCESS"))) == 3
    assert len(list(db.get_table_records("VIRTUALMACHINES"))) == 0
    assert len(list(db.get_table_records("DNS"))) == 12
    assert len(list(db.get_table_records("SYSTEM_IDENTITY"))) == 0


def test_ual_activity_counts_land_in_last_access_calendar_year(ual_db: BinaryIO) -> None:
    db = UAL(ual_db)
    table = db.esedb.table("CLIENTS")
    day_column_names = [column.name for column in table.columns if column.name.startswith("Day")]

    for raw_record, view_record in zip(table.records(), db.get_table_records("CLIENTS"), strict=True):
        last_access_year = wintimestamp(raw_record.get("LastAccess")).year

        # A determinable activity day is attributed to the LastAccess calendar year using its day ordinal.
        expected = {
            expected_day_date(last_access_year, int(name[3:])): raw_record.get(name)
            for name in day_column_names
            if raw_record.get(name)
        }
        assert dict(view_record["activity_counts"]) == expected

        for activity_day, _count in view_record["activity_counts"]:
            assert isinstance(activity_day, datetime.datetime)
            assert activity_day.year == last_access_year

        # Days without any recorded access must not be presented as days on which access happened.
        zero_days = {int(name[3:]) for name in day_column_names if not raw_record.get(name)}
        represented_ordinals = {activity_day.timetuple().tm_yday for activity_day, _ in view_record["activity_counts"]}
        assert zero_days.isdisjoint(represented_ordinals)


def test_ual_raw_record_keeps_day_evidence_without_year(ual_db: BinaryIO) -> None:
    db = UAL(ual_db)
    table = db.esedb.table("CLIENTS")
    day_column_names = [column.name for column in table.columns if column.name.startswith("Day")]

    for raw_record, view_record in zip(table.records(), db.get_table_records("CLIENTS"), strict=True):
        # Even after date attribution, the original day ordinals and counts remain available in the raw record.
        raw_nonzero = {int(name[3:]): raw_record.get(name) for name in day_column_names if raw_record.get(name)}
        view_ordinals = {
            activity_day.timetuple().tm_yday: count for activity_day, count in view_record["activity_counts"]
        }
        assert view_ordinals == raw_nonzero

        # Days omitted from the activity view for having no visits are still evidence in the raw ESE record,
        # stored there as an explicit zero or as a NULL (unset) value rather than disappearing entirely.
        zero_columns = [name for name in day_column_names if not raw_record.get(name)]
        assert all(raw_record.get(name) in (0, None) for name in zero_columns)
        assert {activity_day.timetuple().tm_yday for activity_day, _count in view_record["activity_counts"]}.isdisjoint(
            int(name[3:]) for name in zero_columns
        )


def test_ual_undeterminable_year_keeps_original_day_ordinals_and_counts() -> None:
    # A FILETIME of zero means no calendar year can be derived from LastAccess.
    columns = [FakeColumn("LastAccess"), *day_columns([1, 60, 200])]
    record = FakeRecord({"LastAccess": 0, "Day1": 5, "Day60": 0, "Day200": 42})
    ual = build_ual("CLIENTS", columns, [record])

    (view_record,) = ual.get_table_records("CLIENTS")

    # The counts keep their original day ordinals and values; nothing is projected onto a guessed date.
    assert view_record["activity_counts"] == ((1, 5), (200, 42))
    assert all(isinstance(day_num, int) for day_num, _count in view_record["activity_counts"])
    assert not any(isinstance(day_num, datetime.datetime) for day_num, _count in view_record["activity_counts"])


def test_ual_all_zero_day_counts_are_not_reported_as_activity() -> None:
    columns = [FakeColumn("LastAccess"), *day_columns([1, 2, 3])]
    record = FakeRecord(
        {
            "LastAccess": to_filetime(datetime.datetime(2021, 6, 15, 12, 0, tzinfo=datetime.timezone.utc)),
            "Day1": 0,
            "Day2": 0,
            "Day3": 0,
        }
    )
    ual = build_ual("CLIENTS", columns, [record])

    (view_record,) = ual.get_table_records("CLIENTS")

    assert view_record["activity_counts"] == ()


def test_ual_day_ordinal_conversion_respects_leap_years() -> None:
    # 2020 is a leap year: day 60 is February 29th and day 366 stays inside 2020.
    columns = [FakeColumn("LastAccess"), *day_columns([60, 366])]
    record = FakeRecord(
        {
            "LastAccess": to_filetime(datetime.datetime(2020, 12, 31, 23, 59, tzinfo=datetime.timezone.utc)),
            "Day60": 7,
            "Day366": 9,
        }
    )
    ual = build_ual("CLIENTS", columns, [record])

    (view_record,) = ual.get_table_records("CLIENTS")

    assert dict(view_record["activity_counts"]) == {
        expected_day_date(2020, 60): 7,
        expected_day_date(2020, 366): 9,
    }
    assert all(activity_day.year == 2020 for activity_day, _count in view_record["activity_counts"])
