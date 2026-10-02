"""Independent synthetic CFB writer for exact structural fixture facts."""

import struct

FREE = 0xFFFFFFFF
END = 0xFFFFFFFE
FAT = 0xFFFFFFFD
DIF = 0xFFFFFFFC
STAMP = 116444736000000000


def put(raw, offset, value, fmt="<I"):
    struct.pack_into(fmt, raw, offset, value)


class Builder:
    def __init__(self, major=3, forced_fat=0):
        self.major = major
        self.sector_size = {3: 512, 4: 4096}[major]
        self.nodes = [{"name": "Root Entry", "kind": 5, "children": {}, "data": b""}]
        self.forced_fat = forced_fat
        self.sectors = []
        self.chains = {}
        self.entry_offsets = {}
        self.difat_ids = []

    def storage(self, path):
        parent = 0
        for name in path:
            node = self.nodes[parent]
            if name not in node["children"]:
                sid = len(self.nodes)
                node["children"][name] = sid
                self.nodes.append({"name": name, "kind": 1, "children": {}, "data": b""})
            parent = node["children"][name]
        return parent

    def add(self, path, data=b""):
        path = tuple(path)
        parent = self.storage(path[:-1])
        sid = len(self.nodes)
        assert path[-1] not in self.nodes[parent]["children"]
        self.nodes[parent]["children"][path[-1]] = sid
        self.nodes.append({"name": path[-1], "kind": 2, "children": {}, "data": data})
        return sid

    def allocate(self, data, label):
        chain = []
        for offset in range(0, len(data), self.sector_size):
            chain.append(len(self.sectors))
            self.sectors.append(
                bytes(data[offset : offset + self.sector_size]).ljust(self.sector_size, b"\0")
            )
        self.chains[label] = chain
        return chain[0] if chain else END

    def build(self):
        mini = bytearray()
        mini_fat = []
        for sid, node in enumerate(self.nodes):
            node.update(left=FREE, right=FREE, child=FREE, start=0, size=0)
            if node["kind"] == 2:
                data = node["data"]
                node["size"] = len(data)
                if 0 < len(data) < 4096:
                    start = len(mini_fat)
                    count = (len(data) + 63) // 64
                    mini_fat.extend([start + i + 1 for i in range(count - 1)] + [END])
                    mini += data + bytes(count * 64 - len(data))
                    node["start"] = start
                    self.chains[("mini", sid)] = list(range(start, start + count))
                else:
                    node["start"] = self.allocate(data, ("stream", sid))
        self.nodes[0]["size"] = len(mini)
        self.nodes[0]["start"] = self.allocate(mini, "root_mini")
        mini_bytes = b"".join(struct.pack("<I", v) for v in mini_fat)
        if mini_bytes:
            mini_bytes += struct.pack("<I", FREE) * ((-len(mini_bytes)) % self.sector_size // 4)
        mini_start = self.allocate(mini_bytes, "minifat")

        def siblings(ids):
            if not ids:
                return FREE
            middle = len(ids) // 2
            sid = ids[middle]
            self.nodes[sid]["left"] = siblings(ids[:middle])
            self.nodes[sid]["right"] = siblings(ids[middle + 1 :])
            return sid

        for node in self.nodes:
            ids = sorted(
                node["children"].values(),
                key=lambda i: (
                    len(self.nodes[i]["name"].encode("utf-16le")),
                    self.nodes[i]["name"].upper(),
                ),
            )
            node["child"] = siblings(ids)
        directory = bytearray()
        for sid, node in enumerate(self.nodes):
            raw = bytearray(128)
            name = (node["name"] + "\0").encode("utf-16le")
            assert len(name) <= 64
            raw[: len(name)] = name
            put(raw, 64, len(name), "<H")
            raw[66] = node["kind"]
            raw[67] = 1
            for offset, value in [
                (68, node["left"]),
                (72, node["right"]),
                (76, node["child"]),
                (116, node["start"]),
            ]:
                put(raw, offset, value)
            if node["kind"] == 1:
                put(raw, 100, STAMP, "<Q")
                put(raw, 108, STAMP + 9, "<Q")
            put(raw, 120, node["size"], "<Q")
            directory += raw
        directory += bytes((-len(directory)) % self.sector_size)
        directory_start = self.allocate(directory, "directory")
        words = self.sector_size // 4
        nfat = max(1, self.forced_fat)
        while True:
            ndif = max(0, (nfat - 109 + words - 2) // (words - 1))
            need = (len(self.sectors) + nfat + ndif + words - 1) // words
            if need <= nfat:
                break
            nfat = need
        fat_ids = list(range(len(self.sectors), len(self.sectors) + nfat))
        self.difat_ids = list(range(len(self.sectors) + nfat, len(self.sectors) + nfat + ndif))
        self.sectors.extend([bytes(self.sector_size)] * (nfat + ndif))
        values = [FREE] * (nfat * words)
        for label, chain in self.chains.items():
            if type(label) is tuple and label[0] == "mini":
                continue
            for i, sid in enumerate(chain):
                values[sid] = chain[i + 1] if i + 1 < len(chain) else END
        for sid in fat_ids:
            values[sid] = FAT
        for sid in self.difat_ids:
            values[sid] = DIF
        for i, sid in enumerate(fat_ids):
            self.sectors[sid] = struct.pack("<" + "I" * words, *values[i * words : (i + 1) * words])
        for i, sid in enumerate(self.difat_ids):
            group = fat_ids[109 + i * (words - 1) : 109 + (i + 1) * (words - 1)]
            group += [FREE] * (words - 1 - len(group))
            group += [self.difat_ids[i + 1] if i + 1 < len(self.difat_ids) else END]
            self.sectors[sid] = struct.pack("<" + "I" * words, *group)
        header = bytearray(self.sector_size)
        header[:8] = bytes.fromhex("d0cf11e0a1b11ae1")
        for offset, value in [
            (24, 0x3E),
            (26, self.major),
            (28, 0xFFFE),
            (30, 9 if self.major == 3 else 12),
            (32, 6),
        ]:
            put(header, offset, value, "<H")
        for offset, value in [
            (40, len(self.chains["directory"]) if self.major == 4 else 0),
            (44, nfat),
            (48, directory_start),
            (56, 4096),
            (60, mini_start),
            (64, len(self.chains["minifat"])),
            (68, self.difat_ids[0] if ndif else END),
            (72, ndif),
        ]:
            put(header, offset, value)
        for i in range(109):
            put(header, 76 + 4 * i, fat_ids[i] if i < len(fat_ids) else FREE)
        self.fat_ids = fat_ids
        self.fat_values = values
        for sid in range(len(self.nodes)):
            self.entry_offsets[sid] = (
                self.chains["directory"][sid * 128 // self.sector_size] + 1
            ) * self.sector_size + sid * 128 % self.sector_size
        return bytes(header) + b"".join(self.sectors)

    def fat_offset(self, sid):
        words = self.sector_size // 4
        return (self.fat_ids[sid // words] + 1) * self.sector_size + 4 * (sid % words)


def example(major=3, forced_fat=0):
    b = Builder(major, forced_fat)
    short = b.add(("Synthetic", "Small"), b"SYNTHETIC_SMALL")
    long = b.add(("Large",), b"ABCD" * 1500)
    empty = b.add(("Empty",), b"")
    return b.build(), b, short, long, empty
