from __future__ import annotations

import struct
from typing import TYPE_CHECKING
from unittest.mock import MagicMock, patch

import pytest
from dissect.util.compression import sevenbit

from dissect.esedb.c_esedb import COMPRESSION_SCHEME
from dissect.esedb.exceptions import NoNeighbourPageError
from dissect.esedb.record import LongText, LongValue
from dissect.esedb.table import Table

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator


class FakeNode:
    """Minimal stand-in for a long value tree node."""

    def __init__(self, key: bytes, data: bytes):
        self.key = key
        self.data = data


class FakeBTree:
    """Controllable replacement for :class:`dissect.esedb.btree.BTree` used in long value tests."""

    def __init__(self, header: FakeNode, chunks: list[FakeNode], fail_after: bool = False):
        self._header = header
        self._chunks = chunks
        self._fail_after = fail_after
        self._index = 0

    def search(self, key: bytes) -> FakeNode:
        self._index = 0
        return self._header

    def next(self) -> FakeNode:
        if self._index >= len(self._chunks):
            if self._fail_after:
                raise NoNeighbourPageError("no next page")
            # Signal the end of this long value with an unrelated key
            return FakeNode(b"different-key", b"")
        node = self._chunks[self._index]
        self._index += 1
        return node


def make_header(rkey: bytes, size: int) -> FakeNode:
    return FakeNode(rkey, struct.pack("<2I", 1, size))


def make_chunk(rkey: bytes, offset: int, data: bytes) -> FakeNode:
    return FakeNode(rkey + struct.pack(">I", offset), data)


def compress_7bit(data: bytes) -> bytes:
    """Produce a chunk in the 7-bit ASCII format understood by ``compression.decompress``."""
    return bytes([int(COMPRESSION_SCHEME.COMPRESS_7BITASCII) << 3]) + sevenbit.compress(data)


@pytest.fixture
def table_factory() -> Iterator[Callable[[FakeBTree], Table]]:
    patchers = []

    def _factory(btree: FakeBTree) -> Table:
        esedb = MagicMock()
        table = Table(esedb, "lv-table", root_page=1)
        table._long_value_record = MagicMock()
        # Bypass the cached lv_page property with a plain instance attribute
        table.__dict__["lv_page"] = MagicMock(name="lv_page")

        patcher = patch("dissect.esedb.table.BTree", return_value=btree)
        patcher.start()
        patchers.append(patcher)
        return table

    yield _factory

    for patcher in patchers:
        patcher.stop()


def test_long_value_complete_single_chunk(table_factory: Callable[[FakeBTree], Table]) -> None:
    rkey = b"rkey"
    data = b"complete long value"
    btree = FakeBTree(make_header(rkey, len(data)), [make_chunk(rkey, 0, data)])
    table = table_factory(btree)

    result = table.get_long_value(rkey[::-1])

    assert isinstance(result, LongValue)
    assert result.is_complete
    assert result.declared_size == len(data)
    assert result.gaps == ()
    assert bytes(result) == data


def test_long_value_complete_multiple_chunks(table_factory: Callable[[FakeBTree], Table]) -> None:
    rkey = b"rkey"
    first = b"A" * 100
    second = b"B" * 50
    third = b"C" * 25
    chunks = [
        make_chunk(rkey, 0, first),
        make_chunk(rkey, 100, second),
        make_chunk(rkey, 150, third),
    ]
    btree = FakeBTree(make_header(rkey, 175), chunks)
    table = table_factory(btree)

    result = table.get_long_value(rkey[::-1])

    assert result.is_complete
    assert result.gaps == ()
    assert bytes(result) == first + second + third
    assert len(result) == result.declared_size == 175


def test_long_value_missing_middle_chunk(table_factory: Callable[[FakeBTree], Table]) -> None:
    rkey = b"rkey"
    first = b"A" * 100
    third = b"C" * 25
    # The chunk covering logical range [100, 150) is missing
    chunks = [
        make_chunk(rkey, 0, first),
        make_chunk(rkey, 150, third),
    ]
    btree = FakeBTree(make_header(rkey, 175), chunks)
    table = table_factory(btree)

    result = table.get_long_value(rkey[::-1])

    assert isinstance(result, LongValue)
    assert not result.is_complete
    assert result.declared_size == 175
    assert result.gaps == ((100, 150),)
    # Surviving chunks are concatenated without any fabricated filler bytes
    assert bytes(result) == first + third
    assert len(result) == 125


def test_long_value_missing_first_chunk(table_factory: Callable[[FakeBTree], Table]) -> None:
    rkey = b"rkey"
    second = b"B" * 50
    chunks = [make_chunk(rkey, 100, second)]
    btree = FakeBTree(make_header(rkey, 150), chunks)
    table = table_factory(btree)

    result = table.get_long_value(rkey[::-1])

    assert not result.is_complete
    assert result.gaps == ((0, 100),)
    assert bytes(result) == second


def test_long_value_truncated_tail(table_factory: Callable[[FakeBTree], Table]) -> None:
    rkey = b"rkey"
    first = b"A" * 100
    chunks = [make_chunk(rkey, 0, first)]
    btree = FakeBTree(make_header(rkey, 175), chunks, fail_after=True)
    table = table_factory(btree)

    result = table.get_long_value(rkey[::-1])

    assert not result.is_complete
    assert result.gaps == ((100, 175),)
    assert bytes(result) == first


def test_long_value_no_chunks(table_factory: Callable[[FakeBTree], Table]) -> None:
    rkey = b"rkey"
    btree = FakeBTree(make_header(rkey, 175), [])
    table = table_factory(btree)

    result = table.get_long_value(rkey[::-1])

    assert not result.is_complete
    assert result.gaps == ((0, 175),)
    assert bytes(result) == b""


def test_long_value_compressed_chunks(table_factory: Callable[[FakeBTree], Table]) -> None:
    rkey = b"rkey"
    plain_first = b"A" * 100
    plain_second = b"B" * 100
    stored_second = compress_7bit(plain_second)
    assert len(stored_second) != len(plain_second)

    chunks = [
        make_chunk(rkey, 0, plain_first),
        make_chunk(rkey, 100, stored_second),
    ]
    btree = FakeBTree(make_header(rkey, 200), chunks)
    table = table_factory(btree)

    result = table.get_long_value(rkey[::-1])

    assert result.is_complete
    assert bytes(result) == plain_first + plain_second


def test_long_value_compressed_chunk_after_gap(table_factory: Callable[[FakeBTree], Table]) -> None:
    rkey = b"rkey"
    plain_third = b"C" * 100
    stored_third = compress_7bit(plain_third)

    # Chunks for [0, 100) and [100, 200) are missing; the compressed chunk at offset 200 remains.
    # Its computed span (size - 200) cannot be compared against its stored length to detect
    # compression once neighbouring chunks are gone, so the scheme identifier must be used.
    chunks = [make_chunk(rkey, 200, stored_third)]
    btree = FakeBTree(make_header(rkey, 300), chunks)
    table = table_factory(btree)

    result = table.get_long_value(rkey[::-1])

    assert not result.is_complete
    assert result.gaps == ((0, 200),)
    assert bytes(result) == plain_third


def test_long_value_plain_chunk_after_gap_not_misdetected(table_factory: Callable[[FakeBTree], Table]) -> None:
    rkey = b"rkey"
    # Plain data whose first byte does not encode a known compression scheme
    plain = b"Z" * 100
    chunks = [make_chunk(rkey, 50, plain)]
    btree = FakeBTree(make_header(rkey, 150), chunks)
    table = table_factory(btree)

    result = table.get_long_value(rkey[::-1])

    assert not result.is_complete
    # The surviving chunk at offset 50 holds 100 bytes and ends exactly at the declared size
    assert result.gaps == ((0, 50),)
    # Plain bytes must be returned verbatim, never fed to a decompressor
    assert bytes(result) == plain


def test_long_value_invalid_scheme_byte_after_gap_kept_raw(table_factory: Callable[[FakeBTree], Table]) -> None:
    rkey = b"rkey"
    # The first byte encodes a known 7-bit ASCII scheme (0x08), but the remaining bytes are not a
    # valid compressed blob. Across a gap the scheme byte cannot be trusted, so decompression must be
    # best-effort: the raw chunk survives instead of raising.
    raw_blob = bytes([int(COMPRESSION_SCHEME.COMPRESS_7BITASCII) << 3]) + b"not really compressed" * 4
    chunks = [make_chunk(rkey, 50, raw_blob)]
    btree = FakeBTree(make_header(rkey, 50 + len(raw_blob)), chunks)
    table = table_factory(btree)

    result = table.get_long_value(rkey[::-1])

    assert not result.is_complete
    assert result.gaps == ((0, 50),)
    assert bytes(result) == raw_blob


def test_long_value_wrapper_is_bytes_subclass(table_factory: Callable[[FakeBTree], Table]) -> None:
    rkey = b"rkey"
    data = b"abc"
    btree = FakeBTree(make_header(rkey, 3), [make_chunk(rkey, 0, data)])
    table = table_factory(btree)

    result = table.get_long_value(rkey[::-1])

    assert isinstance(result, bytes)
    assert result == b"abc"
    assert result.hex() == b"abc".hex()
    assert result + b"d" == b"abcd"


def test_long_text_wrapper_preserves_completeness(table_factory: Callable[[FakeBTree], Table]) -> None:
    rkey = b"rkey"
    text = b"hello world"
    btree = FakeBTree(make_header(rkey, len(text)), [make_chunk(rkey, 0, text)])
    table = table_factory(btree)

    long_value = table.get_long_value(rkey[::-1])
    long_text = LongText(text.decode("ascii"), long_value)

    assert isinstance(long_text, str)
    assert long_text == "hello world"
    assert long_text.is_complete
    assert long_text.declared_size == long_value.declared_size
    assert long_text.gaps == long_value.gaps

    fragmented = LongValue(b"hello", 11, ((5, 11),))
    fragmented_text = LongText("hello", fragmented)
    assert not fragmented_text.is_complete
    assert fragmented_text.gaps == ((5, 11),)
    assert isinstance(fragmented_text, str)
    assert fragmented_text == "hello"


def test_long_value_repr_matches_base_types() -> None:
    # The wrappers keep the bytes/str repr so record serialization output is unchanged
    complete = LongValue(b"abc", 3)
    assert repr(complete) == repr(b"abc")

    fragmented = LongValue(b"a", 3, ((1, 3),))
    assert repr(fragmented) == repr(b"a")

    long_text = LongText("hello", fragmented)
    assert repr(long_text) == repr("hello")
