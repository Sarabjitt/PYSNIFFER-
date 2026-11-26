"""Packet dissection: Ethernet, VLAN, ARP, IPv4, IPv6, TCP, UDP, ICMP/ICMPv6,
DNS, HTTP (plain text) and TLS (ClientHello SNI)."""
from __future__ import annotations

import socket
import struct
import time
from dataclasses import dataclass, field
from typing import Optional

ETH_IPV4, ETH_ARP, ETH_IPV6, ETH_VLAN = 0x0800, 0x0806, 0x86DD, 0x8100

IP_PROTOS = {1: "ICMP", 2: "IGMP", 6: "TCP", 17: "UDP", 47: "GRE", 50: "ESP",
             51: "AH", 58: "ICMPv6", 89: "OSPF", 132: "SCTP"}
ICMP_TYPES = {0: "Echo Reply", 3: "Destination Unreachable", 5: "Redirect",
              8: "Echo Request", 11: "Time Exceeded", 12: "Parameter Problem"}
ICMP6_TYPES = {1: "Destination Unreachable", 2: "Packet Too Big", 3: "Time Exceeded",
               128: "Echo Request", 129: "Echo Reply", 133: "Router Solicitation",
               134: "Router Advertisement", 135: "Neighbor Solicitation",
               136: "Neighbor Advertisement"}
UDP_PORT_LABELS = {67: "DHCP", 68: "DHCP", 123: "NTP", 1900: "SSDP", 5353: "mDNS",
                   5355: "LLMNR", 137: "NBNS", 443: "QUIC"}
DNS_TYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX",
             16: "TXT", 28: "AAAA", 33: "SRV", 65: "HTTPS", 255: "ANY"}
HTTP_METHODS = (b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ", b"OPTIONS ",
                b"PATCH ", b"CONNECT ")


def fmt_mac(b: bytes) -> str:
    return ":".join(f"{x:02x}" for x in b)


@dataclass
class Packet:
    ts: float
    raw: bytes
    ethertype: Optional[int] = None
    src_mac: Optional[str] = None
    dst_mac: Optional[str] = None
    vlan: Optional[int] = None
    ip_version: Optional[int] = None
    src: Optional[str] = None          # IP (or ARP sender) address
    dst: Optional[str] = None
    ttl: Optional[int] = None
    ip_proto: Optional[int] = None
    l4: Optional[str] = None           # TCP / UDP / ICMP / ...
    sport: Optional[int] = None
    dport: Optional[int] = None
    flags: str = ""
    seq: Optional[int] = None
    ack: Optional[int] = None
    window: Optional[int] = None
    app: Optional[str] = None          # DNS / HTTP / TLS / ...
    info: str = ""
    payload: bytes = b""
    error: Optional[str] = None
    extra: dict = field(default_factory=dict)

    @property
    def length(self) -> int:
        return len(self.raw)

    @property
    def proto(self) -> str:
        """Highest-layer protocol label."""
        if self.app:
            return self.app
        if self.l4:
            return self.l4
        if self.ethertype == ETH_ARP:
            return "ARP"
        if self.ip_version:
            return f"IPv{self.ip_version}"
        return "ETH" if self.ethertype is not None else "RAW"

    def to_dict(self) -> dict:
        d = {"time": self.ts, "length": self.length, "protocol": self.proto,
             "src_mac": self.src_mac, "dst_mac": self.dst_mac, "src": self.src,
             "dst": self.dst, "sport": self.sport, "dport": self.dport,
             "ttl": self.ttl, "flags": self.flags or None, "info": self.info or None,
             "payload_len": len(self.payload), "error": self.error}
        d.update(self.extra)
        return {k: v for k, v in d.items() if v is not None}

    def summary(self, relative_to: Optional[float] = None) -> str:
        t = self.ts - relative_to if relative_to is not None else self.ts
        ts = f"{t:10.6f}" if relative_to is not None else time.strftime(
            "%H:%M:%S", time.localtime(self.ts)) + f".{int(self.ts % 1 * 1e6):06d}"
        s = f"{self.src}:{self.sport}" if self.sport is not None else (self.src or self.src_mac or "?")
        d = f"{self.dst}:{self.dport}" if self.dport is not None else (self.dst or self.dst_mac or "?")
        if self.ip_version == 6 and self.sport is not None:
            s, d = f"[{self.src}]:{self.sport}", f"[{self.dst}]:{self.dport}"
        err = f" [malformed: {self.error}]" if self.error else ""
        return f"{ts}  {self.proto:<7} {s} -> {d}  len={self.length}  {self.info}{err}".rstrip()

    def detail(self) -> str:
        lines = [self.summary()]
        if self.src_mac:
            v = f" vlan={self.vlan}" if self.vlan is not None else ""
            lines.append(f"    Ethernet : {self.src_mac} -> {self.dst_mac} type=0x{self.ethertype:04x}{v}")
        if self.ip_version:
            lines.append(f"    IPv{self.ip_version}     : {self.src} -> {self.dst} ttl/hop={self.ttl} proto={IP_PROTOS.get(self.ip_proto, self.ip_proto)}")
        if self.l4 == "TCP":
            lines.append(f"    TCP      : {self.sport} -> {self.dport} flags=[{self.flags}] seq={self.seq} ack={self.ack} win={self.window}")
        elif self.l4 == "UDP":
            lines.append(f"    UDP      : {self.sport} -> {self.dport}")
        elif self.l4:
            lines.append(f"    {self.l4:<9}: {self.info}")
        if self.app:
            lines.append(f"    {self.app:<9}: {self.info}")
        if self.payload:
            lines.append(f"    Payload  : {len(self.payload)} bytes")
        return "\n".join(lines)


# --------------------------------------------------------------------------- #
def parse_packet(raw: bytes, ts: Optional[float] = None, link: str = "eth") -> Packet:
    """Dissect a raw frame. link='eth' (Ethernet frame) or 'raw' (starts at IP)."""
    p = Packet(ts=time.time() if ts is None else ts, raw=bytes(raw))
    try:
        off = 0
        if link == "eth":
            off = _eth(p)
        elif raw:
            p.ethertype = ETH_IPV4 if raw[0] >> 4 == 4 else ETH_IPV6
        if p.ethertype == ETH_ARP:
            _arp(p, off)
        elif p.ethertype == ETH_IPV4:
            _ipv4(p, off)
        elif p.ethertype == ETH_IPV6:
            _ipv6(p, off)
    except (struct.error, IndexError, ValueError, OSError) as e:
        p.error = str(e) or type(e).__name__
    return p


def _eth(p: Packet) -> int:
    d = p.raw
    p.dst_mac, p.src_mac = fmt_mac(d[0:6]), fmt_mac(d[6:12])
    et, off = struct.unpack("!H", d[12:14])[0], 14
    while et in (ETH_VLAN, 0x88A8):          # 802.1Q / QinQ
        tci, et = struct.unpack("!HH", d[off:off + 4])
        p.vlan, off = tci & 0x0FFF, off + 4
    p.ethertype = et
    return off


def _arp(p: Packet, off: int) -> None:
    d = p.raw
    _, _, hl, pl, op = struct.unpack("!HHBBH", d[off:off + 8])
    if hl != 6 or pl != 4:
        raise ValueError("unsupported ARP format")
    smac, sip = fmt_mac(d[off + 8:off + 14]), socket.inet_ntoa(d[off + 14:off + 18])
    dip = socket.inet_ntoa(d[off + 24:off + 28])
    p.src, p.dst = sip, dip
    p.extra["arp_op"] = "request" if op == 1 else "reply" if op == 2 else str(op)
    p.info = (f"Who has {dip}? Tell {sip}" if op == 1 else f"{sip} is at {smac}" if op == 2 else f"op={op}")


def _ipv4(p: Packet, off: int) -> None:
    d = p.raw
    vihl, _, total, _, ff, ttl, proto = struct.unpack("!BBHHHBB", d[off:off + 10])
    ihl = (vihl & 0x0F) * 4
    if vihl >> 4 != 4 or ihl < 20:
        raise ValueError("bad IPv4 header")
    p.ip_version, p.ttl, p.ip_proto = 4, ttl, proto
    p.src, p.dst = socket.inet_ntoa(d[off + 12:off + 16]), socket.inet_ntoa(d[off + 16:off + 20])
    end = min(len(d), off + total) if total >= ihl else len(d)   # strip Ethernet padding
    frag_off, mf = (ff & 0x1FFF), bool(ff & 0x2000)
    if frag_off or mf:
        p.extra["fragment"] = True
        p.info = f"fragment offset={frag_off * 8}{' MF' if mf else ''}"
    if frag_off:
        p.l4 = IP_PROTOS.get(proto, f"IP-{proto}")
        p.payload = d[off + ihl:end]
        return
    _transport(p, proto, d[off + ihl:end])


_EXT_HDRS = {0, 43, 60}


def _ipv6(p: Packet, off: int) -> None:
    d = p.raw
    vtf, plen, nxt, hop = struct.unpack("!IHBB", d[off:off + 8])
    if vtf >> 28 != 6:
        raise ValueError("bad IPv6 header")
    p.ip_version, p.ttl = 6, hop
    p.src, p.dst = socket.inet_ntop(socket.AF_INET6, d[off + 8:off + 24]), socket.inet_ntop(socket.AF_INET6, d[off + 24:off + 40])
    pos, end = off + 40, min(len(d), off + 40 + plen) if plen else len(d)
    while nxt in _EXT_HDRS or nxt == 44:
        if nxt == 44:
            nxt = d[pos]; pos += 8
            p.extra["fragment"] = True
        else:
            n, ln = d[pos], d[pos + 1]; nxt = n; pos += 8 + ln * 8
    p.ip_proto = nxt
    _transport(p, nxt, d[pos:end])


def _transport(p: Packet, proto: int, seg: bytes) -> None:
    p.l4 = IP_PROTOS.get(proto, f"IP-{proto}")
    if proto == 6:
        _tcp(p, seg)
    elif proto == 17:
        _udp(p, seg)
    elif proto == 1:
        t, c = seg[0], seg[1]
        p.info = ICMP_TYPES.get(t, f"type={t}") + (f" code={c}" if c else "")
        p.extra.update(icmp_type=t, icmp_code=c)
        if t in (0, 8) and len(seg) >= 8:
            p.info += f" id={struct.unpack('!H', seg[4:6])[0]} seq={struct.unpack('!H', seg[6:8])[0]}"
        p.payload = seg[8:]
    elif proto == 58:
        t = seg[0]
        p.info = ICMP6_TYPES.get(t, f"type={t}")
        p.extra.update(icmp_type=t)
        p.payload = seg[4:]
    else:
        p.payload = seg


def _tcp(p: Packet, seg: bytes) -> None:
    sport, dport, seq, ack, off_flags, win = struct.unpack("!HHIIHH", seg[:16])
    doff = (off_flags >> 12) * 4
    if doff < 20:
        raise ValueError("bad TCP header")
    names = ["FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECE", "CWR"]
    p.flags = ",".join(n for i, n in enumerate(names) if off_flags & (1 << i))
    p.sport, p.dport, p.seq, p.ack, p.window = sport, dport, seq, ack, win
    p.payload = seg[doff:]
    p.info = f"[{p.flags}] seq={seq} ack={ack} win={win}"
    if p.payload:
        _tcp_app(p)


def _tcp_app(p: Packet) -> None:
    d = p.payload
    if d.startswith(HTTP_METHODS) or d.startswith(b"HTTP/1."):
        line = d.split(b"\r\n", 1)[0][:120].decode("latin-1")
        p.app, p.info = "HTTP", line
        host = _http_header(d, b"host")
        if host:
            p.extra["http_host"] = host
        return
    if len(d) > 5 and d[0] in (0x16, 0x17, 0x15, 0x14) and d[1] == 3 and d[2] <= 4:
        p.app = "TLS"
        kinds = {0x14: "ChangeCipherSpec", 0x15: "Alert", 0x16: "Handshake", 0x17: "ApplicationData"}
        p.info = kinds[d[0]]
        if d[0] == 0x16:
            hs = d[5]
            names = {1: "ClientHello", 2: "ServerHello", 11: "Certificate", 14: "ServerHelloDone", 16: "ClientKeyExchange"}
            p.info = names.get(hs, f"Handshake({hs})")
            if hs == 1:
                sni = _tls_sni(d)
                if sni:
                    p.info += f" SNI={sni}"
                    p.extra["tls_sni"] = sni


def _http_header(data: bytes, name: bytes) -> Optional[str]:
    head = data.split(b"\r\n\r\n", 1)[0]
    for line in head.split(b"\r\n")[1:]:
        k, _, v = line.partition(b":")
        if k.strip().lower() == name:
            return v.strip().decode("latin-1")
    return None


def _tls_sni(d: bytes) -> Optional[str]:
    try:
        pos = 5 + 4 + 2 + 32                         # record hdr, hs hdr, version, random
        pos += 1 + d[pos]                            # session id
        pos += 2 + struct.unpack("!H", d[pos:pos + 2])[0]   # cipher suites
        pos += 1 + d[pos]                            # compression
        end = pos + 2 + struct.unpack("!H", d[pos:pos + 2])[0]
        pos += 2
        while pos + 4 <= min(end, len(d)):
            et, el = struct.unpack("!HH", d[pos:pos + 4])
            pos += 4
            if et == 0:                              # server_name
                nl = struct.unpack("!H", d[pos + 3:pos + 5])[0]
                return d[pos + 5:pos + 5 + nl].decode("ascii", "replace")
            pos += el
    except (struct.error, IndexError):
        pass
    return None


def _udp(p: Packet, seg: bytes) -> None:
    sport, dport, ln, _ = struct.unpack("!HHHH", seg[:8])
    p.sport, p.dport, p.payload = sport, dport, seg[8:ln] if ln >= 8 else seg[8:]
    p.info = f"len={len(p.payload)}"
    if 53 in (sport, dport) or 5353 in (sport, dport):
        try:
            p.info = _dns(p, p.payload)
            p.app = "mDNS" if 5353 in (sport, dport) else "DNS"
            return
        except (struct.error, IndexError, ValueError):
            pass
    label = UDP_PORT_LABELS.get(dport) or UDP_PORT_LABELS.get(sport)
    if label:
        p.app = label


def _dns_name(d: bytes, off: int) -> tuple[str, int]:
    labels, end, hops = [], None, 0
    while True:
        ln = d[off]
        if ln == 0:
            off += 1
            break
        if ln & 0xC0 == 0xC0:
            if end is None:
                end = off + 2
            off = ((ln & 0x3F) << 8) | d[off + 1]
            hops += 1
            if hops > 20:
                raise ValueError("DNS compression loop")
            continue
        labels.append(d[off + 1:off + 1 + ln].decode("ascii", "replace"))
        off += 1 + ln
    return ".".join(labels) or ".", (end if end is not None else off)


def _dns(p: Packet, d: bytes) -> str:
    tid, flags, qd, an, _, _ = struct.unpack("!HHHHHH", d[:12])
    off, qs, ans = 12, [], []
    for _ in range(qd):
        name, off = _dns_name(d, off)
        qt = struct.unpack("!H", d[off:off + 2])[0]
        off += 4
        qs.append(f"{DNS_TYPES.get(qt, qt)} {name}")
    for _ in range(an):
        name, off = _dns_name(d, off)
        rt, _, _, rl = struct.unpack("!HHIH", d[off:off + 10])
        off += 10
        rd = d[off:off + rl]
        if rt == 1 and rl == 4:
            ans.append(socket.inet_ntoa(rd))
        elif rt == 28 and rl == 16:
            ans.append(socket.inet_ntop(socket.AF_INET6, rd))
        elif rt in (2, 5, 12):
            ans.append(_dns_name(d, off)[0])
        else:
            ans.append(DNS_TYPES.get(rt, str(rt)))
        off += rl
    is_resp = bool(flags & 0x8000)
    rcode = flags & 0xF
    p.extra.update(dns_id=tid, dns_query=qs[0].split(" ", 1)[1] if qs else None)
    if not is_resp:
        return f"Query 0x{tid:04x} " + ", ".join(qs)
    out = f"Response 0x{tid:04x} " + ", ".join(qs)
    if rcode:
        out += f" rcode={rcode}"
    return out + (" -> " + ", ".join(ans) if ans else "")


def hexdump(data: bytes, width: int = 16) -> str:
    rows = []
    for i in range(0, len(data), width):
        chunk = data[i:i + width]
        hx = " ".join(f"{b:02x}" for b in chunk).ljust(width * 3 - 1)
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        rows.append(f"    {i:04x}  {hx}  {asc}")
    return "\n".join(rows)
