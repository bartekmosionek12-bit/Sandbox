"""Metadata reader for legacy Keras HDF5 files (``.h5``). Standard library only.

It runs INSIDE the WASI sandbox (``kind == "h5_meta"``): the host never parses an
HDF5 file. libhdf5 and h5py are not involved anywhere.

What it reads (HDF5 file format specification 3.0, the parts libhdf5 writes):

* the superblock (versions 0-3);
* object headers (versions 1 and 2, continuation blocks, lookup3 checksums);
* old-style groups (symbol table: v1 B-tree, symbol nodes, local heap) and
  new-style compact groups (link messages);
* the root group's attribute messages (versions 1-3), with fixed-length and
  variable-length strings (global heap).

What it never reads: dataset contents. Datasets are visited only for their object
header, to refuse layouts that make a loader read other files (external data
files, virtual datasets). Every address and length is checked against the file
size, every structure has a count limit, and anything this reader does not model
exactly is a *problem*: the caller turns problems into a SUSPICIOUS verdict. A
structure it cannot parse at all raises :class:`Refused`.

Not supported (problem, never guessed): dense storage (fractal heap) for the
root's attributes or for any group's links, shared root attributes, external and
user-defined links, superblock driver info (multi-file drivers), a user block
(base address other than 0).
"""

ROOT_ATTRS = ("model_config", "training_config", "keras_version", "backend")
SIGNATURE = b"\x89HDF\r\n\x1a\n"

LIMITS = {
    "max_attr_bytes": 16 * 1024 * 1024,  # one root attribute value
    "max_objects": 100_000,  # object headers visited
    "max_messages": 2_000_000,  # header messages, all objects
    "max_chunks": 1_000,  # continuation chunks per object header
    "max_btree_nodes": 200_000,
    "max_btree_depth": 64,
    "max_links": 1_000_000,
    "max_root_attrs": 10_000,
    "max_read_bytes": 512 * 1024 * 1024,  # all reads together
    "max_heap_bytes": 64 * 1024 * 1024,  # one local or global heap
}

UNDEF = None

MSG_NIL = 0x00
MSG_DATASPACE = 0x01
MSG_LINK_INFO = 0x02
MSG_DATATYPE = 0x03
MSG_FILL_OLD = 0x04
MSG_FILL = 0x05
MSG_LINK = 0x06
MSG_EXTERNAL = 0x07
MSG_LAYOUT = 0x08
MSG_BOGUS = 0x09
MSG_GROUP_INFO = 0x0A
MSG_FILTERS = 0x0B
MSG_ATTRIBUTE = 0x0C
MSG_COMMENT = 0x0D
MSG_MTIME_OLD = 0x0E
MSG_SHARED_TABLE = 0x0F
MSG_CONTINUATION = 0x10
MSG_SYMBOL_TABLE = 0x11
MSG_MTIME = 0x12
MSG_BTREE_K = 0x13
MSG_DRIVER_INFO = 0x14
MSG_ATTR_INFO = 0x15
MSG_REFCOUNT = 0x16
MSG_FSINFO = 0x17
KNOWN_MESSAGES = frozenset(range(0x00, 0x18))

MASK32 = 0xFFFFFFFF


class Refused(ValueError):
    """The file cannot be parsed as the HDF5 this reader models."""


def _rot(x, k):
    return ((x << k) | (x >> (32 - k))) & MASK32


def lookup3(data, initval=0):
    """Bob Jenkins' lookup3 ``hashlittle`` as used by HDF5 (H5_checksum_lookup3)."""
    length = len(data)
    a = b = c = (0xDEADBEEF + length + initval) & MASK32
    i = 0
    while length > 12:
        a = (a + int.from_bytes(data[i:i + 4], "little")) & MASK32
        b = (b + int.from_bytes(data[i + 4:i + 8], "little")) & MASK32
        c = (c + int.from_bytes(data[i + 8:i + 12], "little")) & MASK32
        a = (a - c) & MASK32; a ^= _rot(c, 4); c = (c + b) & MASK32  # noqa: E702
        b = (b - a) & MASK32; b ^= _rot(a, 6); a = (a + c) & MASK32  # noqa: E702
        c = (c - b) & MASK32; c ^= _rot(b, 8); b = (b + a) & MASK32  # noqa: E702
        a = (a - c) & MASK32; a ^= _rot(c, 16); c = (c + b) & MASK32  # noqa: E702
        b = (b - a) & MASK32; b ^= _rot(a, 19); a = (a + c) & MASK32  # noqa: E702
        c = (c - b) & MASK32; c ^= _rot(b, 4); b = (b + a) & MASK32  # noqa: E702
        length -= 12
        i += 12
    if length == 0:
        return c
    tail = data[i:i + length] + bytes(12 - length)
    a = (a + int.from_bytes(tail[0:4], "little")) & MASK32
    b = (b + int.from_bytes(tail[4:8], "little")) & MASK32
    c = (c + int.from_bytes(tail[8:12], "little")) & MASK32
    c ^= b; c = (c - _rot(b, 14)) & MASK32  # noqa: E702
    a ^= c; a = (a - _rot(c, 11)) & MASK32  # noqa: E702
    b ^= a; b = (b - _rot(a, 25)) & MASK32  # noqa: E702
    c ^= b; c = (c - _rot(b, 16)) & MASK32  # noqa: E702
    a ^= c; a = (a - _rot(c, 4)) & MASK32  # noqa: E702
    b ^= a; b = (b - _rot(a, 14)) & MASK32  # noqa: E702
    c ^= b; c = (c - _rot(b, 24)) & MASK32  # noqa: E702
    return c


class _Buf:
    """Bounds-checked little-endian cursor over one structure's bytes."""

    def __init__(self, data, where):
        self.data = data
        self.pos = 0
        self.where = where

    def take(self, n):
        if n < 0 or self.pos + n > len(self.data):
            raise Refused(f"{self.where}: structure ends early (need {n} bytes at {self.pos})")
        out = self.data[self.pos:self.pos + n]
        self.pos += n
        return out

    def uint(self, n):
        return int.from_bytes(self.take(n), "little")

    def skip(self, n):
        self.take(n)

    def left(self):
        return len(self.data) - self.pos


class Reader:
    def __init__(self, fh, size, limits=None):
        self.fh = fh
        self.size = size
        self.limits = dict(LIMITS)
        if limits:
            self.limits.update(limits)
        self.read_bytes = 0
        self.messages = 0
        self.btree_nodes = 0
        self.links = 0
        self.problems = []
        self.notes = []
        self.offsets = 8
        self.lengths = 8
        self.superblock_version = None
        self.counts = {"groups": 0, "datasets": 0, "datatypes": 0, "other_objects": 0,
                       "soft_links": 0, "hard_links": 0}

    # -- raw access ---------------------------------------------------------

    def read(self, addr, n, what):
        if addr is UNDEF:
            raise Refused(f"{what}: undefined address")
        if n < 0 or addr < 0 or addr + n > self.size:
            raise Refused(f"{what}: {n} bytes at {addr} lie outside the {self.size}-byte file")
        self.read_bytes += n
        if self.read_bytes > self.limits["max_read_bytes"]:
            raise Refused(f"metadata reads exceed {self.limits['max_read_bytes']} bytes")
        self.fh.seek(addr)
        data = self.fh.read(n)
        if len(data) != n:
            raise Refused(f"{what}: short read at {addr}")
        return data

    def addr(self, buf):
        value = buf.uint(self.offsets)
        return UNDEF if value == (1 << (8 * self.offsets)) - 1 else value

    def length(self, buf):
        return buf.uint(self.lengths)

    def _note(self, text):
        if len(self.notes) < 200:
            self.notes.append(text)

    def problem(self, text):
        if text not in self.problems and len(self.problems) < 200:
            self.problems.append(text)

    # -- superblock -----------------------------------------------------------

    def superblock(self):
        head = self.read(0, min(self.size, 256), "superblock")
        if not head.startswith(SIGNATURE):
            raise Refused("no HDF5 signature at offset 0")
        buf = _Buf(head, "superblock")
        buf.skip(8)
        version = buf.uint(1)
        self.superblock_version = version
        if version in (0, 1):
            free_ver, root_ver, _, shared_ver = buf.uint(1), buf.uint(1), buf.uint(1), buf.uint(1)
            self.offsets, self.lengths = buf.uint(1), buf.uint(1)
            self._check_sizes()
            buf.skip(1)
            buf.skip(4)  # group leaf / internal node K
            buf.skip(4)  # file consistency flags
            if version == 1:
                buf.skip(4)  # indexed storage K + reserved
            if (free_ver, root_ver, shared_ver) != (0, 0, 0):
                raise Refused(f"unsupported superblock sub-versions {(free_ver, root_ver, shared_ver)}")
            base = self.addr(buf)
            self.addr(buf)  # free-space info (always undefined)
            eof = self.addr(buf)
            driver = self.addr(buf)
            entry = self._symbol_entry(buf)
            if driver is not UNDEF:
                self.problem("superblock has a driver info block (multi-file or family driver): "
                             "the file refers to other files")
            root = entry["header"]
        elif version in (2, 3):
            self.offsets, self.lengths = buf.uint(1), buf.uint(1)
            self._check_sizes()
            buf.skip(1)  # flags
            base = self.addr(buf)
            extension = self.addr(buf)
            eof = self.addr(buf)
            root = self.addr(buf)
            end = buf.pos
            stored = buf.uint(4)
            if lookup3(head[:end]) != stored:
                raise Refused("superblock checksum mismatch")
            if extension is not UNDEF:
                self._extension(extension)
            entry = None
        else:
            raise Refused(f"unsupported superblock version {version}")
        if base not in (0, UNDEF):
            self.problem(f"superblock base address {base} (user block); not supported")
        if eof is UNDEF or eof > self.size:
            raise Refused(f"file is truncated: superblock says {eof} bytes, file has {self.size}")
        if eof < self.size:
            self.notes.append(f"{self.size - eof} bytes after the end of the HDF5 data")
        if root is UNDEF:
            raise Refused("superblock has no root group")
        return root, entry

    def _check_sizes(self):
        if self.offsets not in (2, 4, 8) or self.lengths not in (2, 4, 8):
            raise Refused(f"unsupported offset/length sizes {self.offsets}/{self.lengths}")

    def _extension(self, address):
        for mtype, _flags, _body in self.object_messages(address, "superblock extension"):
            if mtype == MSG_DRIVER_INFO:
                self.problem("superblock extension has driver info (multi-file or family driver)")
            elif mtype == MSG_SHARED_TABLE:
                self.notes.append("file uses shared object header messages")

    def _symbol_entry(self, buf):
        name_offset = self.length_or_offset(buf)
        header = self.addr(buf)
        cache = buf.uint(4)
        buf.skip(4)
        scratch = _Buf(buf.take(16), "symbol table entry scratch")
        entry = {"name_offset": name_offset, "header": header, "cache": cache}
        if cache == 1:
            entry["btree"] = self.addr(scratch)
            entry["heap"] = self.addr(scratch)
        elif cache == 2:
            entry["link_offset"] = scratch.uint(4)
        elif cache != 0:
            raise Refused(f"unknown symbol table cache type {cache}")
        return entry

    def length_or_offset(self, buf):
        return buf.uint(self.offsets)

    # -- object headers -------------------------------------------------------

    def object_messages(self, address, what):
        """All messages of one object header as (type, flags, body bytes)."""
        if address is UNDEF:
            raise Refused(f"{what}: object header address is undefined")
        prefix = self.read(address, min(16, self.size - address), f"{what} object header")
        if prefix[:4] == b"OHDR":
            return self._messages_v2(address, what)
        if prefix[:1] == b"\x01":
            return self._messages_v1(address, what)
        raise Refused(f"{what}: unknown object header version at {address}")

    def _count(self):
        self.messages += 1
        if self.messages > self.limits["max_messages"]:
            raise Refused(f"more than {self.limits['max_messages']} object header messages")

    def _messages_v1(self, address, what):
        head = _Buf(self.read(address, 16, f"{what} object header"), what)
        head.skip(2)
        expected = head.uint(2)
        head.skip(4)  # reference count
        size = head.uint(4)
        chunks = [(address + 16, size)]
        out = []
        seen = set()
        while chunks:
            start, length = chunks.pop(0)
            if (start, length) in seen:
                raise Refused(f"{what}: object header continuation loop")
            seen.add((start, length))
            if len(seen) > self.limits["max_chunks"]:
                raise Refused(f"{what}: more than {self.limits['max_chunks']} header chunks")
            buf = _Buf(self.read(start, length, f"{what} header chunk"), what)
            while buf.left() >= 8:
                mtype = buf.uint(2)
                msize = buf.uint(2)
                flags = buf.uint(1)
                buf.skip(3)
                body = buf.take(msize)
                self._count()
                out.append((mtype, flags, body))
                if mtype == MSG_CONTINUATION:
                    cbuf = _Buf(body, f"{what} continuation")
                    chunks.append((self.addr(cbuf), self.length(cbuf)))
            if buf.left():
                raise Refused(f"{what}: {buf.left()} stray bytes at the end of a v1 header chunk")
        if len(out) != expected:
            raise Refused(f"{what}: object header says {expected} messages, found {len(out)}")
        return self._checked(out, what)

    def _messages_v2(self, address, what):
        first = self.read(address, min(64, self.size - address), f"{what} object header")
        head = _Buf(first, what)
        head.skip(4)
        version = head.uint(1)
        if version != 2:
            raise Refused(f"{what}: unsupported object header version {version}")
        flags = head.uint(1)
        if flags & 0x20:
            head.skip(16)  # access / modification / change / birth times
        if flags & 0x10:
            head.skip(4)  # max compact / min dense attributes
        size_len = 1 << (flags & 0x03)
        chunk0 = head.uint(size_len)
        prefix_len = head.pos
        track_order = bool(flags & 0x04)
        chunks = [(address, prefix_len, chunk0, False)]
        out = []
        seen = set()
        while chunks:
            start, skip, length, is_cont = chunks.pop(0)
            if start in seen:
                raise Refused(f"{what}: object header continuation loop")
            seen.add(start)
            if len(seen) > self.limits["max_chunks"]:
                raise Refused(f"{what}: more than {self.limits['max_chunks']} header chunks")
            if is_cont:
                raw = self.read(start, length, f"{what} header continuation")
                if raw[:4] != b"OCHK" or length < 8:
                    raise Refused(f"{what}: continuation block without OCHK signature")
                body_bytes, stored = raw[4:-4], int.from_bytes(raw[-4:], "little")
                if lookup3(raw[:-4]) != stored:
                    raise Refused(f"{what}: header continuation checksum mismatch")
            else:
                raw = self.read(start, skip + length + 4, f"{what} object header")
                body_bytes, stored = raw[skip:skip + length], int.from_bytes(raw[-4:], "little")
                if lookup3(raw[:-4]) != stored:
                    raise Refused(f"{what}: object header checksum mismatch")
            buf = _Buf(body_bytes, what)
            header_len = 4 + (2 if track_order else 0)
            while buf.left() >= header_len:
                mtype = buf.uint(1)
                msize = buf.uint(2)
                mflags = buf.uint(1)
                if track_order:
                    buf.skip(2)
                body = buf.take(msize)
                self._count()
                out.append((mtype, mflags, body))
                if mtype == MSG_CONTINUATION:
                    cbuf = _Buf(body, f"{what} continuation")
                    chunks.append((self.addr(cbuf), 0, self.length(cbuf), True))
            # A gap shorter than a message header may end a v2 chunk.
        return self._checked(out, what)

    def _checked(self, messages, what):
        for mtype, _flags, _ in messages:
            if mtype not in KNOWN_MESSAGES:
                self.problem(f"{what}: unknown object header message type {mtype:#x}")
            if mtype == MSG_BOGUS:
                self.problem(f"{what}: 'bogus' test message present")
        return messages

    # -- groups -----------------------------------------------------------------

    def local_heap(self, address):
        head = _Buf(self.read(address, 8 + 2 * self.lengths + self.offsets, "local heap"), "local heap")
        if head.take(4) != b"HEAP" or head.uint(1) != 0:
            raise Refused(f"no local heap at {address}")
        head.skip(3)
        size = self.length(head)
        self.length(head)  # free list offset
        data_addr = self.addr(head)
        if size > self.limits["max_heap_bytes"]:
            raise Refused(f"local heap of {size} bytes exceeds the limit")
        return self.read(data_addr, size, "local heap data")

    @staticmethod
    def heap_string(heap, offset):
        if offset >= len(heap):
            raise Refused(f"name offset {offset} outside the local heap")
        end = heap.find(b"\x00", offset)
        if end < 0:
            raise Refused("unterminated name in the local heap")
        return heap[offset:end].decode("utf-8", "replace")

    def symbol_table_children(self, btree, heap_addr, where):
        """(name, entry) for every entry of an old-style group."""
        heap = self.local_heap(heap_addr)
        out = []
        stack = [(btree, 0)]
        visited = set()
        while stack:
            node, depth = stack.pop()
            if node in visited:
                raise Refused(f"{where}: B-tree cycle")
            visited.add(node)
            self.btree_nodes += 1
            if self.btree_nodes > self.limits["max_btree_nodes"]:
                raise Refused(f"more than {self.limits['max_btree_nodes']} B-tree nodes")
            if depth > self.limits["max_btree_depth"]:
                raise Refused(f"{where}: B-tree deeper than {self.limits['max_btree_depth']}")
            head = _Buf(self.read(node, 8 + 2 * self.offsets, "group B-tree node"), where)
            if head.take(4) != b"TREE":
                raise Refused(f"{where}: no B-tree node at {node}")
            if head.uint(1) != 0:
                raise Refused(f"{where}: B-tree node is not a group node")
            level = head.uint(1)
            used = head.uint(2)
            body_len = (used + 1) * self.lengths + used * self.offsets
            body = _Buf(self.read(node + head.pos + 2 * self.offsets, body_len, "group B-tree keys"), where)
            for _ in range(used):
                self.length(body)  # key
                child = self.addr(body)
                if level > 0:
                    stack.append((child, depth + 1))
                else:
                    out.extend(self.symbol_node(child, heap, where))
            if len(out) > self.limits["max_links"]:
                raise Refused(f"{where}: too many group entries")
        return out

    def symbol_node(self, address, heap, where):
        head = _Buf(self.read(address, 8, "symbol table node"), where)
        if head.take(4) != b"SNOD" or head.uint(1) != 1:
            raise Refused(f"{where}: no symbol table node at {address}")
        head.skip(1)
        count = head.uint(2)
        entry_size = 2 * self.offsets + 24
        buf = _Buf(self.read(address + 8, count * entry_size, "symbol table entries"), where)
        out = []
        for _ in range(count):
            entry = self._symbol_entry(buf)
            out.append((self.heap_string(heap, entry["name_offset"]), entry))
        return out

    def link_message(self, body, where):
        buf = _Buf(body, f"{where} link")
        if buf.uint(1) != 1:
            raise Refused(f"{where}: unsupported link message version")
        flags = buf.uint(1)
        ltype = buf.uint(1) if flags & 0x08 else 0
        if flags & 0x04:
            buf.skip(8)
        if flags & 0x10:
            buf.skip(1)
        name_len = buf.uint(1 << (flags & 0x03))
        name = buf.take(name_len).decode("utf-8", "replace")
        if ltype == 0:
            return name, "hard", self.addr(buf)
        if ltype == 1:
            return name, "soft", None
        if ltype == 64:
            return name, "external", None
        return name, f"user-defined type {ltype}", None

    # -- the walk ----------------------------------------------------------------

    def walk(self, root, root_entry):
        """Visit every object reachable by hard links; return the root's messages."""
        root_messages = None
        queue = [("/", root, root_entry)]
        visited = set()
        while queue:
            path, address, entry = queue.pop()
            if address in visited:
                continue  # a second hard link to an object already checked
            visited.add(address)
            if len(visited) > self.limits["max_objects"]:
                self.problem(f"more than {self.limits['max_objects']} objects; not all were checked")
                break
            messages = self.object_messages(address, path)
            if root_messages is None:
                root_messages = messages
            types = {m[0] for m in messages}
            children = []
            # libhdf5 reads a group's B-tree and heap from its Symbol Table message and
            # ignores the copy cached in the parent's entry, which goes stale when a
            # group is converted to links; so does this reader.
            cached = (entry["btree"], entry["heap"]) if entry is not None and entry.get("cache") == 1 else None
            tables = [m for m in messages if m[0] == MSG_SYMBOL_TABLE]
            if len(tables) > 1:
                self.problem(f"{path}: more than one symbol table message")
            if cached is not None and not tables:
                self._note(f"{path}: stale cached symbol table (group uses link messages)")
            for mtype, _, body in messages:
                if mtype == MSG_SYMBOL_TABLE:
                    sbuf = _Buf(body, path)
                    btree, heap = self.addr(sbuf), self.addr(sbuf)
                    if cached is not None and cached != (btree, heap):
                        self._note(f"{path}: cached symbol table differs from the object header")
                    children.extend(self.symbol_table_children(btree, heap, path))
                elif mtype == MSG_LINK_INFO:
                    lbuf = _Buf(body, path)
                    lbuf.skip(1)
                    lflags = lbuf.uint(1)
                    if lflags & 0x01:
                        lbuf.skip(8)
                    if self.addr(lbuf) is not UNDEF:
                        self.problem(f"{path}: dense link storage (fractal heap) is not supported")
                elif mtype == MSG_LINK:
                    name, kind, target = self.link_message(body, path)
                    child_path = path.rstrip("/") + "/" + name
                    if kind == "hard":
                        children.append((name, {"header": target, "cache": 0}))
                    elif kind == "soft":
                        self.counts["soft_links"] += 1
                    else:
                        self.problem(f"{child_path}: {kind} link (points outside this file)")
                elif mtype == MSG_EXTERNAL:
                    self.problem(f"{path}: dataset stores its data in external files")
                elif mtype == MSG_LAYOUT:
                    self._layout(body, path)
            if MSG_SYMBOL_TABLE in types or MSG_LINK_INFO in types or MSG_GROUP_INFO in types \
                    or MSG_LINK in types or path == "/":
                self.counts["groups"] += 1
            elif MSG_LAYOUT in types:
                self.counts["datasets"] += 1
            elif MSG_DATATYPE in types:
                self.counts["datatypes"] += 1
            else:
                self.counts["other_objects"] += 1
            for name, child in children:
                if child.get("cache") == 2:
                    self.counts["soft_links"] += 1
                    continue
                self.counts["hard_links"] += 1
                self.links += 1
                if self.links > self.limits["max_links"]:
                    raise Refused(f"more than {self.limits['max_links']} links")
                queue.append((path.rstrip("/") + "/" + name, child["header"], child))
        return root_messages

    def _layout(self, body, path):
        if not body:
            raise Refused(f"{path}: empty data layout message")
        version = body[0]
        if version in (1, 2):
            return
        if version in (3, 4):
            if len(body) < 2:
                raise Refused(f"{path}: short data layout message")
            if body[1] == 3:
                self.problem(f"{path}: virtual dataset (maps data from other files)")
            elif body[1] not in (0, 1, 2):
                self.problem(f"{path}: unknown data layout class {body[1]}")
            return
        self.problem(f"{path}: unsupported data layout message version {version}")

    # -- root attributes ---------------------------------------------------------

    def root_attributes(self, messages, wanted):
        names = []
        values = {}
        for mtype, flags, body in messages:
            if mtype == MSG_ATTR_INFO:
                abuf = _Buf(body, "/ attribute info")
                abuf.skip(1)
                aflags = abuf.uint(1)
                if aflags & 0x01:
                    abuf.skip(2)
                if self.addr(abuf) is not UNDEF:
                    self.problem("root attributes use dense storage (fractal heap); not supported")
            if mtype != MSG_ATTRIBUTE:
                continue
            if flags & 0x02:
                self.problem("root attribute stored as a shared message; not supported")
                continue
            name, info = self.attribute(body, wanted)
            if len(names) >= self.limits["max_root_attrs"]:
                raise Refused("too many root attributes")
            if name in names:
                self.problem(f"root attribute {name!r} appears more than once")
            names.append(name)
            if info is not None:
                values[name] = info
        return names, values

    def attribute(self, body, wanted):
        buf = _Buf(body, "attribute")
        version = buf.uint(1)
        if version == 1:
            buf.skip(1)
            name_size, type_size, space_size = buf.uint(2), buf.uint(2), buf.uint(2)
            name = buf.take(_pad8(name_size))[:name_size]
            dtype = buf.take(_pad8(type_size))[:type_size]
            space = buf.take(_pad8(space_size))[:space_size]
        elif version in (2, 3):
            aflags = buf.uint(1)
            name_size, type_size, space_size = buf.uint(2), buf.uint(2), buf.uint(2)
            if version == 3:
                buf.skip(1)  # name character set
            name = buf.take(name_size)
            dtype = buf.take(type_size)
            space = buf.take(space_size)
            if aflags & 0x03:
                self.problem("root attribute with a shared datatype or dataspace; not supported")
                return _attr_name(name), None
        else:
            raise Refused(f"unsupported attribute message version {version}")
        name = _attr_name(name)
        if name not in wanted:
            return name, None
        where = f"root attribute {name!r}"
        count = self.dataspace(space, where)
        if count is None:
            self.problem(f"{where} has a null dataspace (no value)")
            return name, None
        if count != 1:
            self.problem(f"{where} is an array of {count} values, not a scalar")
            return name, None
        kind, info = self.string_type(dtype, where)
        if kind is None:
            self.problem(f"{where} is not a string ({info})")
            return name, None
        data = buf.data[buf.pos:]
        if kind == "fixed":
            size = info
            if size > self.limits["max_attr_bytes"]:
                self.problem(f"{where} is {size} bytes (limit {self.limits['max_attr_bytes']})")
                return name, None
            if len(data) < size:
                raise Refused(f"{where}: value shorter than its datatype")
            value = data[:size].rstrip(b"\x00")
        else:
            value = self.vlen_value(data, where)
            if value is None:
                return name, None
        if b"\x00" in value:
            self.problem(f"{where} contains NUL bytes (readers would disagree on its end)")
            return name, None
        return name, value

    def dataspace(self, space, where):
        """Number of elements, or None for a null dataspace."""
        buf = _Buf(space, f"{where} dataspace")
        version = buf.uint(1)
        rank = buf.uint(1)
        flags = buf.uint(1)
        if version == 1:
            buf.skip(5)
            kind = 1 if rank else 0
        elif version == 2:
            kind = buf.uint(1)
        else:
            raise Refused(f"{where}: unsupported dataspace version {version}")
        if kind == 2:
            return None
        if kind == 0:
            return 1
        if rank > 32:
            raise Refused(f"{where}: dataspace rank {rank}")
        count = 1
        for _ in range(rank):
            count *= self.length(buf)
        if flags & 0x01:
            buf.skip(rank * self.lengths)
        return count

    def string_type(self, dtype, where):
        buf = _Buf(dtype, f"{where} datatype")
        class_version = buf.uint(1)
        cls = class_version & 0x0F
        bits = buf.uint(3)
        size = buf.uint(4)
        if cls == 3:
            return "fixed", size
        if cls == 9 and (bits & 0x0F) == 1:
            return "vlen", size
        return None, f"datatype class {cls}"

    def vlen_value(self, data, where):
        buf = _Buf(data, f"{where} value")
        length = buf.uint(4)
        collection = self.addr(buf)
        index = buf.uint(4)
        if length > self.limits["max_attr_bytes"]:
            self.problem(f"{where} is {length} bytes (limit {self.limits['max_attr_bytes']})")
            return None
        if collection is UNDEF or (length == 0 and collection == 0):
            return b""
        obj = self.global_heap_object(collection, index, where)
        if len(obj) != length:
            self.problem(f"{where}: global heap object is {len(obj)} bytes, attribute says {length}")
            return None
        return obj

    def global_heap_object(self, address, index, where):
        head = _Buf(self.read(address, 8 + self.lengths, "global heap"), where)
        if head.take(4) != b"GCOL" or head.uint(1) != 1:
            raise Refused(f"{where}: no global heap collection at {address}")
        head.skip(3)
        size = self.length(head)
        if size > self.limits["max_heap_bytes"] + 4096:
            self.problem(f"{where}: global heap collection of {size} bytes exceeds the limit")
            return b""
        buf = _Buf(self.read(address, size, "global heap collection"), where)
        buf.skip(8 + self.lengths)
        object_head = 8 + self.lengths
        found = None
        while buf.left() >= object_head:
            obj_index = buf.uint(2)
            buf.skip(6)  # reference count, reserved
            obj_size = self.length(buf)
            if obj_index == 0:
                break  # free space runs to the end of the collection
            obj = buf.take(obj_size)
            buf.skip(min(buf.left(), _pad8(obj_size) - obj_size))
            if obj_index == index:
                if found is not None:
                    raise Refused(f"{where}: global heap object {index} appears twice")
                found = obj
        if found is None:
            raise Refused(f"{where}: global heap object {index} not found")
        return found


def _pad8(n):
    return (n + 7) // 8 * 8


def _attr_name(raw):
    end = raw.find(b"\x00")
    return (raw if end < 0 else raw[:end]).decode("utf-8", "replace")


def read_metadata(fh, size, wanted=ROOT_ATTRS, limits=None):
    """Metadata of one HDF5 file. ``values`` maps each wanted root attribute that is
    a scalar string to its bytes; everything doubtful is listed in ``problems``."""
    reader = Reader(fh, size, limits)
    root, entry = reader.superblock()
    root_messages = reader.walk(root, entry)
    names, values = reader.root_attributes(root_messages or [], frozenset(wanted))
    return {
        "superblock_version": reader.superblock_version,
        "root_attr_names": names,
        "values": values,
        "counts": reader.counts,
        "problems": reader.problems,
        "notes": reader.notes,
    }
