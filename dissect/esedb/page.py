from __future__ import annotations

import struct
from enum import Enum
from functools import cached_property
from typing import TYPE_CHECKING, NamedTuple

from dissect.esedb.c_esedb import PAGE_FLAG, TAG_FLAG, c_esedb

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.esedb.esedb import EseDB


class TagStatus(Enum):
    """The logical visibility of a physical page tag.

    A tag that still occupies space in a page is not necessarily an active record. Both small pages
    (<= 8K) and large pages (> 8K) encode the :attr:`~dissect.esedb.c_esedb.TAG_FLAG.Deleted` bit,
    only the physical location of that bit differs. Decoding it here gives the same meaning for
    every page specification.

    ``Reserved`` tags (such as the page key tag) occupy physical space but never represent a node,
    so they are neither active rows nor deleted records.
    """

    Active = "active"
    Deleted = "deleted"
    Reserved = "reserved"


class TagSource(NamedTuple):
    """The provenance of a physical page tag.

    This combines the raw trace (where the tag and its data physically live in the database) with
    the logical visibility (whether the tag still represents an active record). Keeping both
    allows a forensic inventory to distinguish residual evidence from live rows.

    Attributes:
        page_num: The logical page number the tag lives in.
        tag_num: The index of the tag within the page tag array.
        node_num: The index of the node derived from this tag, or ``None`` for reserved tags.
        offset: The offset of the tag data relative to the start of the page data area.
        size: The size of the tag data in bytes.
        status: The logical visibility of the tag.
    """

    page_num: int
    tag_num: int
    node_num: int | None
    offset: int
    size: int
    status: TagStatus

    @property
    def deleted(self) -> bool:
        """Return whether this tag is logically deleted."""
        return self.status is TagStatus.Deleted

    @property
    def active(self) -> bool:
        """Return whether this tag is logically active."""
        return self.status is TagStatus.Active

    @property
    def reserved(self) -> bool:
        """Return whether this tag is reserved and does not represent a node."""
        return self.status is TagStatus.Reserved

    @property
    def node_position(self) -> tuple[int, int] | None:
        """Return the traceable ``(page_num, node_num)`` position of this tag, if it is a node."""
        if self.node_num is None:
            return None

        return self.page_num, self.node_num

    def to_dict(self) -> dict[str, int | str | None]:
        """Serialize this tag source to a dictionary."""
        return {
            "page_num": self.page_num,
            "tag_num": self.tag_num,
            "node_num": self.node_num,
            "offset": self.offset,
            "size": self.size,
            "status": self.status.value,
        }

    def __repr__(self) -> str:
        return (
            f"<TagSource page={self.page_num} tag={self.tag_num} node={self.node_num} "
            f"offset={self.offset:#x} size={self.size:#x} status={self.status.value}>"
        )


class Page:
    """Represents a logical page of an ESE database.

    Args:
        esedb: An instance of :class:`~dissect.esedb.esedb.EseDB`.
        num: The logical page number.
        buf: The physical page data.
    """

    def __init__(self, esedb: EseDB, num: int, buf: bytes):
        self.esedb = esedb
        self.num = num
        self.buf = memoryview(buf)

        data_start = len(c_esedb.PGHDR)
        self.header = c_esedb.PGHDR(self.buf)
        self.header2 = None
        if not self.is_small_page:
            # Large pages have some additional header fields
            self.header2 = c_esedb.PGHDR2(self.buf[data_start:])
            data_start += len(c_esedb.PGHDR2)

        self.flags = self.header.fFlags
        self.previous_page = self.header.pgnoPrev
        self.next_page = self.header.pgnoNext

        data_end = self.header.ibMicFree
        self.data = self.buf[data_start : data_start + data_end]

        # On newer versions, itagMicFree was renamed to itagState and
        # now includes a reserved tag count in the upper 4 bits
        self.tag_reserved = (self.header.itagState >> 12) or 1
        self.tag_count = self.header.itagState & 0x0FFF
        self.node_count = self.tag_count - self.tag_reserved
        self._node_cls = LeafNode if self.is_leaf else BranchNode
        self._node_cache = {}

    @cached_property
    def is_small_page(self) -> bool:
        return self.esedb.has_small_pages

    @cached_property
    def is_root(self) -> bool:
        return bool(self.flags & PAGE_FLAG.Root)

    @cached_property
    def is_leaf(self) -> bool:
        return bool(self.flags & PAGE_FLAG.Leaf)

    @cached_property
    def is_parent(self) -> bool:
        return bool(self.flags & PAGE_FLAG.ParentOfLeaf)

    @cached_property
    def is_empty(self) -> bool:
        return bool(self.flags & PAGE_FLAG.Empty)

    @cached_property
    def is_space_tree(self) -> bool:
        return bool(self.flags & PAGE_FLAG.SpaceTree)

    @cached_property
    def is_index(self) -> bool:
        return bool(self.flags & PAGE_FLAG.Index)

    @cached_property
    def is_long_value(self) -> bool:
        return bool(self.flags & PAGE_FLAG.LongValue)

    @cached_property
    def is_branch(self) -> bool:
        return not self.is_leaf

    @cached_property
    def key_prefix(self) -> bytes | None:
        if not self.is_root:
            return bytes(self.tag(0).data)

        return None

    def tag(self, num: int) -> Tag:
        """Retrieve a tag by index.

        Args:
            num: The tag number to retrieve.

        Raises:
            IndexError: If the tag number is out of bounds.
        """
        if num < 0 or num > self.tag_count - 1:
            raise IndexError(f"Tag number exceeds boundaries: 0-{self.tag_count - 1}")

        return Tag(self, num)

    def tags(self) -> Iterator[Tag]:
        """Yield all tags."""
        for i in range(1, self.tag_count):
            yield self.tag(i)

    def node(self, num: int) -> BranchNode | LeafNode:
        """Retrieve a node by index.

        Nodes are just tags, but indexed from the first tag. Tag 0 (the page key tag) and the trailing
        reserved tags beyond ``node_count`` are not nodes.

        Args:
            num: The node number to retrieve.

        Raises:
            IndexError: If the node number is out of bounds.
        """
        if num < 0 or num > self.node_count - 1:
            raise IndexError(f"Node number exceeds boundaries: 0-{self.node_count - 1}")

        if num not in self._node_cache:
            self._node_cache[num] = self._node_cls(self.tag(num + 1))

        return self._node_cache[num]

    def nodes(self) -> Iterator[BranchNode | LeafNode]:
        """Yield all nodes."""
        for i in range(self.node_count):
            yield self.node(i)

    def tag_source(self, num: int) -> TagSource:
        """Return the provenance of the tag with index ``num``.

        This includes reserved tags (see :attr:`Tag.is_reserved`), which have no node.

        Args:
            num: The tag number to describe.

        Raises:
            IndexError: If the tag number is out of bounds.
        """
        tag = self.tag(num)
        return TagSource(
            page_num=self.num,
            tag_num=tag.num,
            node_num=tag.node_num,
            offset=tag.offset,
            size=tag.size,
            status=tag.status,
        )

    def tag_sources(self) -> Iterator[TagSource]:
        """Yield the provenance of all physical tags, including reserved tags.

        Reserved tags are included because they also occupy physical space in the page, even though
        they never represent a record.
        """
        for i in range(self.tag_count):
            yield self.tag_source(i)

    def node_tag_sources(self) -> Iterator[TagSource]:
        """Yield the provenance of all nodes, excluding reserved tags."""
        for i in range(self.tag_count):
            source = self.tag_source(i)
            if source.node_num is not None:
                yield source

    def deleted_tag_sources(self) -> Iterator[TagSource]:
        """Yield the provenance of all logically deleted tags."""
        for source in self.tag_sources():
            if source.deleted:
                yield source

    def active_tag_sources(self) -> Iterator[TagSource]:
        """Yield the provenance of all logically active node tags, excluding reserved tags."""
        for source in self.node_tag_sources():
            if source.active:
                yield source

    def iter_leaf_pages(self) -> Iterator[Page]:
        """Walk the page tree and yield leaf pages in key order.

        Two methods can be used, one is to travel down to the first leaf, and keep reading ``next_page``'s,
        the other is to traverse the tree branches.

        Impacket uses the first method, but gets caught in an infinite loop on some dirty databases.
        Traversing the branches seems safer, at the risk of missing a couple (possibly corrupt) pages.

        For this reason, we also explicitly check for a ``next_page`` after the last branch we descend, and
        parse that chain as well. This method seems to work so far.

        Unlike :meth:`nodes`, this does not skip deleted branch entries: a deleted branch entry can still
        reference a child page with active records.
        """
        seen = set()
        pages = list(self._walk_leaf_pages(seen))

        # Check if the last leaf we descended to has a ``next_page`` and parse that chain as well.
        # This only applies to root branch pages, matching the historical traversal behaviour.
        if self.is_root and not self.is_leaf and pages and pages[-1].next_page:
            pages.extend(self.esedb.page(pages[-1].next_page)._walk_leaf_pages(seen))

        yield from pages

    def _walk_leaf_pages(self, seen: set[int]) -> Iterator[Page]:
        """Recursively descend a page, yielding leaf pages exactly once."""
        if self.num in seen:
            return

        seen.add(self.num)

        if self.is_leaf:
            yield self
            return

        for node in self.nodes():
            yield from self.esedb.page(node.child)._walk_leaf_pages(seen)

    def iter_leaf_nodes(self, include_deleted: bool = True) -> Iterator[LeafNode]:
        """Walk the page tree and yield leaf nodes.

        By default this yields every leaf node that still occupies physical space, including logically
        deleted ones, since this method exposes the physical layout. Pass ``include_deleted=False`` to get
        only active leaf nodes.

        Deleted tags can also be inspected through :meth:`deleted_tag_sources`.

        See :meth:`iter_leaf_pages` for the page traversal strategy.

        Args:
            include_deleted: Whether to also yield logically deleted leaf nodes.
        """
        for page in self.iter_leaf_pages():
            for source in page.node_tag_sources():
                if source.deleted and not include_deleted:
                    continue

                yield page.node(source.node_num)

    def iter_active_leaf_nodes(self) -> Iterator[LeafNode]:
        """Walk the page tree and yield only logically active leaf nodes."""
        return self.iter_leaf_nodes(include_deleted=False)

    def __repr__(self) -> str:
        return f"<Page num={self.num:d}>"


class Tag:
    """A tag is the "physical" data entry of a page.

    Args:
        page: The :class:`Page` this tag is in.
        num: The tag number to parse.
    """

    __slots__ = ("data", "flags", "num", "offset", "page", "size", "tag")

    def __init__(self, page: Page, num: int):
        self.page = page
        self.num = num

        tag_offset = len(page.buf) + ((num + 1) * -4)
        tag_buf = page.buf[tag_offset : tag_offset + 4]

        self.tag = c_esedb.TAG(tag_buf)

        mask = 0x1FFF if page.is_small_page else 0x7FFF
        self.size = self.tag.cb_ & mask
        self.offset = self.tag.ib_ & mask

        if self.size == 0 and self.num != 0:
            raise ValueError("Invalid TAG data, corrupt database?")

        self.data = self.page.data[self.offset : self.offset + self.size]

        flags = 0
        if self.is_reserved:
            # Reserved tags (such as the page key tag) are not record headers. On large pages the first
            # USHORT of their data is a key length, not a flag word, so any decoded flags would be bogus.
            flags = 0
        elif page.is_small_page:
            # Small pages have the flag in the tag
            flags = self.tag.ib_ >> 13
        elif len(self.data) >= 2:
            # Large pages have the flag in the first USHORT
            # Also in the 3 MSB, just like the small page, but we know it'll be little endian so do a shortcut on
            # the second byte.
            flags = self.data[1] >> 5

        self.flags = TAG_FLAG(flags)

    @property
    def is_reserved(self) -> bool:
        """Return whether this tag is reserved and does not represent a node."""
        return self.node_num is None

    @property
    def node_num(self) -> int | None:
        """Return the node number derived from this tag, or ``None`` for reserved tags.

        Nodes occupy tags ``1`` up to ``node_count``, matching :meth:`Page.node`. Tag ``0`` (the page key
        tag) and any trailing tags beyond ``node_count`` are reserved: they still occupy physical space in
        the page but are never records.
        """
        if self.num < 1 or self.num > self.page.node_count:
            return None

        return self.num - 1

    @property
    def status(self) -> TagStatus:
        """Return the logical visibility of this tag.

        The :attr:`~dissect.esedb.c_esedb.TAG_FLAG.Deleted` bit has the same meaning for every page
        specification, only its physical location differs (see :class:`Tag`). Reserved tags never
        represent a record, so they are reported as ``Reserved`` regardless of their decoded bits.
        """
        if self.is_reserved:
            return TagStatus.Reserved

        if self.flags & TAG_FLAG.Deleted:
            return TagStatus.Deleted

        return TagStatus.Active

    @property
    def deleted(self) -> bool:
        """Return whether this tag is logically deleted."""
        return self.status is TagStatus.Deleted

    @property
    def active(self) -> bool:
        """Return whether this tag is a logically active node."""
        return self.status is TagStatus.Active

    @property
    def reserved(self) -> bool:
        """Return whether this tag is reserved and does not represent a node."""
        return self.status is TagStatus.Reserved

    @property
    def source(self) -> TagSource:
        """Return the provenance of this tag."""
        return TagSource(
            page_num=self.page.num,
            tag_num=self.num,
            node_num=self.node_num,
            offset=self.offset,
            size=self.size,
            status=self.status,
        )

    def __repr__(self) -> str:
        return f"<Tag offset={self.offset:#x} size={self.size:#x} status={self.status.value}>"


class Node:
    """A node is the "logical" data entry of a page.

    Args:
        tag: The :class:`Tag` to parse a node from.
    """

    __slots__ = ("data", "key", "key_prefix", "key_suffix", "num", "tag")

    def __init__(self, tag: Tag):
        self.tag = tag
        self.num = tag.num - 1

        buf = tag.data
        offset = 0

        key_prefix = b""
        key_prefix_size = None

        # Large pages have the tag flags encoded in the 3 MSB of the first word, so we have to mask the first 13 bits
        # See also the Tag class
        if len(buf) >= offset + 2 and tag.flags & TAG_FLAG.Compressed:
            key_prefix_size = struct.unpack("<H", buf[:2])[0] & 0x1FFF
            key_prefix = self.tag.page.key_prefix[:key_prefix_size].ljust(key_prefix_size, b"\x00")
            offset += 2

        key_suffix = b""
        key_suffix_size = None

        if len(buf) >= offset + 2:
            key_suffix_size = struct.unpack("<H", buf[offset : offset + 2])[0] & 0x1FFF
            offset += 2
            key_suffix = buf[offset : offset + key_suffix_size]
            offset += key_suffix_size

        self.key = key_prefix + key_suffix
        self.key_prefix = key_prefix
        self.key_suffix = key_suffix
        self.data = buf[offset:]


class LeafNode(Node):
    """Special leaf node."""

    def __repr__(self) -> str:
        return f"<LeafNode key={self.key}>"


class BranchNode(Node):
    """Special branch node. Parses the child page information."""

    __slots__ = ("child",)

    def __init__(self, tag: Tag):
        super().__init__(tag)
        self.child = struct.unpack("<I", self.data[:4])[0]

    def __repr__(self) -> str:
        return f"<BranchNode key={self.key} child={self.child}>"
