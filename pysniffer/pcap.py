"""Read/write libpcap files (openable in Wireshark / tcpdump)."""
from __future__ import annotations

import struct
from typing import BinaryIO, Iterator, Tuple

LINKTYPE_ETHERNET, LINKTYPE_RAW = 1, 101


class PcapWriter:
    def __init__(self, path: str, link: str = "eth", snaplen: int = 65535):
        self.f: BinaryIO = open(path, "wb")
        lt = LINKTYPE_ETHERNET if link == "eth" else LINKTYPE_RAW
        self.f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, snaplen, lt))
        self.snaplen = snaplen

    def write(self, ts: float, data: bytes) -> None:
        sec = int(ts); usec = int((ts - sec) * 1_000_000)
        cap = data[:self.snaplen]
        self.f.write(struct.pack("<IIII", sec, usec, len(cap), len(data)) + cap)

    def close(self): self.f.close()
    def __enter__(self): return self
    def __exit__(self, *a): self.close()


class PcapReader:
    """Iterate (timestamp, bytes) and expose .link ('eth' or 'raw')."""

    def __init__(self, path: str):
        self.f = open(path, "rb")
        magic = self.f.read(4)
        fmts = {b"\xd4\xc3\xb2\xa1": ("<", 1e-6), b"\xa1\xb2\xc3\xd4": (">", 1e-6),
                b"\x4d\x3c\xb2\xa1": ("<", 1e-9), b"\xa1\xb2\x3c\x4d": (">", 1e-9)}
        if magic not in fmts:
            raise ValueError("not a classic pcap file (pcapng is not supported)")
        self.end, self.res = fmts[magic]
        _, _, _, _, _, lt = struct.unpack(self.end + "HHiIII", self.f.read(20))
        if lt not in (LINKTYPE_ETHERNET, LINKTYPE_RAW):
            raise ValueError(f"unsupported link type {lt}")
        self.link = "eth" if lt == LINKTYPE_ETHERNET else "raw"

    def __iter__(self) -> Iterator[Tuple[float, bytes]]:
        while True:
            h = self.f.read(16)
            if len(h) < 16:
                return
            sec, frac, cap, _ = struct.unpack(self.end + "IIII", h)
            data = self.f.read(cap)
            if len(data) < cap:
                return
            yield sec + frac * self.res, data

    def close(self): self.f.close()
    def __enter__(self): return self
    def __exit__(self, *a): self.close()
