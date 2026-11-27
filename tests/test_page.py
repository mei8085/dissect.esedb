from __future__ import annotations

import struct
from typing import TYPE_CHECKING
from unittest.mock import Mock

from dissect.esedb.c_esedb import PAGE_FLAG, TAG_FLAG, c_esedb
from dissect.esedb.esedb import EseDB
from dissect.esedb.page import Page, TagStatus

if TYPE_CHECKING:
    from typing import BinaryIO


def _build_page(
    has_small_pages: bool,
    tags: list[tuple[bytes, int]],
    tag_reserved: int = 1,
    flags: PAGE_FLAG = PAGE_FLAG.Leaf | PAGE_FLAG.Root,
) -> bytes:
    """Build a synthetic page with the given tag data and tag flags."""
    page_size = 4096 if has_small_pages else 32768
    header_size = len(c_esedb.PGHDR)
    data_start = header_size + (0 if has_small_pages else len(c_esedb.PGHDR2))

    buf = bytearray(page_size)

    tag_entries = []
    data_end = 0
    for data, tag_flags in tags:
        start = data_start + data_end
        buf[start : start + len(data)] = data

        if has_small_pages:
            # Small pages encode the flags in the 3 MSB of the tag offset
            entry = (len(data), data_end | (tag_flags << 13))
        else:
            # Large pages encode the flags in the 3 MSB of the first USHORT of the tag data
            if tag_flags and len(data) >= 2:
                buf[start + 1] = (buf[start + 1] & 0x1F) | (tag_flags << 5)
            entry = (len(data), data_end)

        tag_entries.append(entry)
        data_end += len(data)

    header = c_esedb.PGHDR(
        objidFDP=0,
        cbFree=0,
        cbUncommittedFree=0,
        ibMicFree=data_end,
        itagState=(tag_reserved << 12) | len(tags),
        fFlags=flags,
    ).dumps()
    buf[:header_size] = header

    # Tag array grows backwards from the end of the page
    for i, entry in enumerate(tag_entries):
        struct.pack_into("<HH", buf, page_size - 4 * (i + 1), *entry)

    return bytes(buf)


def test_tag_state() -> None:
    mock_esedb = Mock()
    mock_esedb.has_small_pages = True

    mock_header = c_esedb.PGHDR(
        itagState=0x2069,
    ).dumps()

    page = Page(mock_esedb, 0, mock_header)
    assert page.tag_reserved == 2
    assert page.tag_count == 0x69

    mock_header = c_esedb.PGHDR(
        itagState=0x0069,
    ).dumps()

    page = Page(mock_esedb, 0, mock_header)
    assert page.tag_reserved == 1
    assert page.tag_count == 0x69


def test_tag_source_small_page() -> None:
    """Tag provenance on small pages reports tag number, deletion status and traceable node position."""
    mock_esedb = Mock()
    mock_esedb.has_small_pages = True

    key_tag = b"\x00" * 16
    active_data = b"\x05\x00" + b"key" + b"\x00" * 4
    deleted_data = b"\x04\x00" + b"old" + b"\x00" * 4
    tags = [
        (key_tag, 0),
        (active_data, int(TAG_FLAG.Version)),
        (deleted_data, int(TAG_FLAG.Version | TAG_FLAG.Deleted)),
    ]

    page = Page(mock_esedb, 69, _build_page(True, tags))

    sources = list(page.tag_sources())

    assert len(sources) == 3
    assert sources[0].tag_num == 0
    assert sources[0].node_num is None
    assert sources[0].status is TagStatus.Reserved
    assert sources[0].reserved is True
    assert sources[0].node_position is None

    assert sources[1].tag_num == 1
    assert sources[1].node_num == 0
    assert sources[1].status is TagStatus.Active
    assert sources[1].active is True
    assert sources[1].node_position == (69, 0)

    assert sources[2].tag_num == 2
    assert sources[2].node_num == 1
    assert sources[2].status is TagStatus.Deleted
    assert sources[2].deleted is True
    assert sources[2].node_position == (69, 1)

    assert [s.tag_num for s in page.node_tag_sources()] == [1, 2]
    assert [s.node_num for s in page.active_tag_sources()] == [0]
    assert [s.node_num for s in page.deleted_tag_sources()] == [1]

    assert page.tag(2).deleted is True
    assert page.tag(2).source == sources[2]
    assert sources[2].to_dict()["status"] == "deleted"


def test_tag_source_large_page() -> None:
    """Large pages give the same deletion status meaning as small pages."""
    mock_esedb = Mock()
    mock_esedb.has_small_pages = False

    key_tag = b"\x08\x00" + b"prefix"
    active_data = b"\xa0\x05" + b"key" + b"\x00" * 4
    deleted_data = b"\xa0\x05" + b"old" + b"\x00" * 4
    tags = [
        (key_tag, 0),
        (active_data, int(TAG_FLAG.Version)),
        (deleted_data, int(TAG_FLAG.Version | TAG_FLAG.Deleted)),
    ]

    page = Page(mock_esedb, 69, _build_page(False, tags))

    active = page.tag(1)
    deleted = page.tag(2)

    assert active.status is TagStatus.Active
    assert deleted.status is TagStatus.Deleted
    assert deleted.deleted is True

    deleted_source = page.tag_source(2)
    assert deleted_source.page_num == 69
    assert deleted_source.tag_num == 2
    assert deleted_source.node_num == 1
    assert deleted_source.status is TagStatus.Deleted
    assert deleted_source.node_position == (69, 1)
    assert deleted_source.size == len(deleted_data)


def test_reserved_tags_have_no_node() -> None:
    """Reserved tags occupy physical space but never represent a node."""
    mock_esedb = Mock()
    mock_esedb.has_small_pages = True

    # One leading key tag and one trailing reserved tag, with a single node in between
    tags = [
        (b"\x00" * 16, 0),
        (b"\x05\x00" + b"key" + b"\x00" * 4, int(TAG_FLAG.Version)),
        (b"\x00" * 16, 0),
    ]

    page = Page(mock_esedb, 69, _build_page(True, tags, tag_reserved=2))

    assert page.tag_reserved == 2
    assert page.tag_count == 3
    assert page.node_count == 1

    sources = list(page.tag_sources())
    assert [s.tag_num for s in sources] == [0, 1, 2]
    assert [s.node_num for s in sources] == [None, 0, None]

    # Both reserved tags are included in the physical inventory, but neither is a node
    assert [s.node_num for s in page.node_tag_sources()] == [0]
    assert [s.node_num for s in page.deleted_tag_sources()] == []


def test_deleted_tag_not_in_active_leaf_nodes() -> None:
    """Deleted leaf tags are residual evidence and are excluded from the active node set."""
    mock_esedb = Mock()
    mock_esedb.has_small_pages = True

    tags = [
        (b"\x00" * 16, 0),
        (b"\x05\x00" + b"key" + b"\x00" * 4, int(TAG_FLAG.Version)),
        (b"\x04\x00" + b"old" + b"\x00" * 4, int(TAG_FLAG.Version | TAG_FLAG.Deleted)),
    ]

    page = Page(mock_esedb, 69, _build_page(True, tags))

    # The physical layout still contains both leaf nodes
    assert [node.num for node in page.iter_leaf_nodes()] == [0, 1]
    assert [node.num for node in page.iter_leaf_nodes(include_deleted=False)] == [0]
    assert [node.num for node in page.iter_active_leaf_nodes()] == [0]
    assert [node.num for node in page.nodes()] == [0, 1]
    assert [source.tag_num for source in page.deleted_tag_sources()] == [2]


def test_deleted_records_are_residual_evidence(windows_search_db: BinaryIO) -> None:
    """Active rows and residual deleted records are reported separately."""
    db = EseDB(windows_search_db)
    table = db.table("SystemIndex_PropertyStore")

    records = list(table.records())
    deleted = list(table.deleted_records())
    all_records = list(table.records_with_source(include_deleted=True))

    assert len(records) == 1182
    assert len(deleted) == 1
    assert len(all_records) == len(records) + len(deleted)

    for record in records:
        assert record.deleted is False

    deleted_record = deleted[0]
    source = deleted_record.source
    assert source.page_num == 570
    assert source.tag_num == 15
    assert source.node_num == 14
    assert source.status is TagStatus.Deleted
    assert source.node_position == (570, 14)
    assert deleted_record.deleted is True

    # The page reports the deleted tag as part of the physical inventory
    page = db.page(570)
    page_sources = list(page.deleted_tag_sources())
    assert [s.node_position for s in page_sources] == [(570, 14)]
    assert len(list(page.node_tag_sources())) == page.node_count


def test_cursor_skips_deleted_records(windows_search_db: BinaryIO) -> None:
    """Index iteration only yields active entries, unless deleted entries are requested."""
    db = EseDB(windows_search_db)
    table = db.table("SystemIndex_PropertyStore")
    cursor = table.primary_index.cursor()

    # Position the cursor on the first leaf entry of the (multi-level) primary index
    cursor.seek_key(b"\x00")
    active = list(cursor)
    assert len(active) == 1182
    assert all(record.deleted is False for record in active)

    cursor.reset()
    cursor.seek_key(b"\x00")
    residual = list(cursor.iter_records(include_deleted=True))
    assert len(residual) == 1183
    assert [record.deleted for record in residual].count(True) == 1
