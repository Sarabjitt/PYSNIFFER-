from __future__ import annotations

from collections import Counter

from .protocols import Packet


class Stats:
    def __init__(self):
        self.count = self.bytes = 0
        self.proto, self.proto_bytes = Counter(), Counter()
        self.talkers, self.ports, self.dns = Counter(), Counter(), Counter()
        self.first = self.last = None

    def add(self, p: Packet) -> None:
        self.count += 1; self.bytes += p.length
        self.proto[p.proto] += 1; self.proto_bytes[p.proto] += p.length
        if p.src and p.dst:
            self.talkers[(p.src, p.dst)] += p.length
        if p.dport is not None and p.l4 in ("TCP", "UDP"):
            self.ports[(p.l4, min(p.sport or 65535, p.dport))] += 1
        q = p.extra.get("dns_query")
        if q and p.app == "DNS" and "Query" in p.info:
            self.dns[q] += 1
        self.first = p.ts if self.first is None else self.first
        self.last = p.ts

    def report(self, top: int = 8) -> str:
        if not self.count:
            return "No packets captured."
        dur = max((self.last - self.first), 1e-9)
        out = [f"\n=== Capture statistics ===",
               f"Packets: {self.count}   Bytes: {self.bytes}   Duration: {dur:.2f}s   "
               f"Rate: {self.count / dur:.1f} pkt/s, {self.bytes * 8 / dur / 1000:.1f} kbit/s",
               "\nProtocols:"]
        for k, v in self.proto.most_common():
            out.append(f"  {k:<8} {v:>7} pkts  {self.proto_bytes[k]:>10} bytes  {v * 100 / self.count:5.1f}%")
        out.append("\nTop talkers (by bytes):")
        for (s, d), b in self.talkers.most_common(top):
            out.append(f"  {s} -> {d}  {b} bytes")
        if self.ports:
            out.append("\nTop service ports:")
            for (pr, port), n in self.ports.most_common(top):
                out.append(f"  {pr}/{port:<6} {n} pkts")
        if self.dns:
            out.append("\nTop DNS queries:")
            for q, n in self.dns.most_common(top):
                out.append(f"  {q}  x{n}")
        return "\n".join(out)
