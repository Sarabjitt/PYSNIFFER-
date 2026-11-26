"""A small BPF-like display/capture filter language.

Examples:
    tcp and port 443
    host 192.168.1.5 and not udp
    (src host 10.0.0.1 or dst net 10.0.0.0/8) and dns
    tcp and (dst port 80 or dst port 8080)
    http, tls, dns, arp, icmp, icmp6, ip, ip6, syn, vlan 10, len > 100  (len < N / len >= N too)
"""
from __future__ import annotations

import ipaddress
import re
from typing import Callable

from .protocols import Packet

Pred = Callable[[Packet], bool]


class FilterError(ValueError):
    pass


def _tokenize(expr: str) -> list[str]:
    toks = re.findall(r"\(|\)|>=|<=|[<>=]|[^\s()<>=]+", expr)
    return [t.lower() if t.lower() in ("and", "or", "not", "src", "dst", "host", "net", "port") else t for t in toks]


class _Parser:
    def __init__(self, toks): self.t, self.i = toks, 0

    def peek(self): return self.t[self.i] if self.i < len(self.t) else None

    def next(self):
        if self.i >= len(self.t):
            raise FilterError("unexpected end of filter")
        self.i += 1
        return self.t[self.i - 1]

    def parse(self) -> Pred:
        f = self.or_()
        if self.peek() is not None:
            raise FilterError(f"unexpected token {self.peek()!r}")
        return f

    def or_(self):
        l = self.and_()
        while self.peek() == "or":
            self.next(); r = self.and_(); l = (lambda a, b: lambda p: a(p) or b(p))(l, r)
        return l

    def and_(self):
        l = self.not_()
        while self.peek() not in (None, "or", ")"):       # explicit "and" or implicit (tcpdump style)
            if self.peek() == "and":
                self.next()
            r = self.not_(); l = (lambda a, b: lambda p: a(p) and b(p))(l, r)
        return l

    def not_(self):
        if self.peek() == "not":
            self.next(); f = self.not_(); return lambda p: not f(p)
        if self.peek() == "(":
            self.next(); f = self.or_()
            if self.next() != ")":
                raise FilterError("missing ')'")
            return f
        return self.prim()

    def prim(self) -> Pred:
        t = self.next()
        lt = t.lower()
        simple = {
            "tcp": lambda p: p.l4 == "TCP", "udp": lambda p: p.l4 == "UDP",
            "icmp": lambda p: p.l4 == "ICMP", "icmp6": lambda p: p.l4 == "ICMPv6",
            "arp": lambda p: p.proto == "ARP", "ip": lambda p: p.ip_version == 4,
            "ip6": lambda p: p.ip_version == 6,
            "dns": lambda p: p.app in ("DNS", "mDNS"), "http": lambda p: p.app == "HTTP",
            "tls": lambda p: p.app == "TLS", "dhcp": lambda p: p.app == "DHCP",
            "syn": lambda p: "SYN" in p.flags and "ACK" not in p.flags,
            "rst": lambda p: "RST" in p.flags, "fin": lambda p: "FIN" in p.flags,
        }
        if lt in simple:
            return simple[lt]
        direction = None
        if t in ("src", "dst"):
            direction, t = t, self.next()
        if t == "host":
            addr = self._addr(self.next())
            return lambda p: self._side(direction, p.src, p.dst, lambda a: a == addr)
        if t == "net":
            try:
                net = ipaddress.ip_network(self.next(), strict=False)
            except ValueError as e:
                raise FilterError(str(e))
            def in_net(a):
                try: return ipaddress.ip_address(a) in net
                except ValueError: return False
            return lambda p: self._side(direction, p.src, p.dst, in_net)
        if t == "port":
            tok = self.next()
            try:
                if "-" in tok:
                    lo, hi = map(int, tok.split("-")); test = lambda n: lo <= n <= hi
                else:
                    n = int(tok); test = lambda x: x == n
            except ValueError:
                raise FilterError(f"bad port {tok!r}")
            return lambda p: self._side(direction, p.sport, p.dport, test)
        if direction:
            raise FilterError(f"expected host/net/port after {direction}")
        if lt == "vlan":
            v = int(self.next()); return lambda p: p.vlan == v
        if lt == "mac":
            m = self.next().lower(); return lambda p: m in (p.src_mac, p.dst_mac)
        if lt == "len":
            op, n = self.next(), int(self.next())
            ops = {">": lambda a: a > n, "<": lambda a: a < n, ">=": lambda a: a >= n,
                   "<=": lambda a: a <= n, "=": lambda a: a == n}
            if op not in ops:
                raise FilterError(f"bad operator {op!r}")
            f = ops[op]; return lambda p: f(p.length)
        if lt == "contains":
            s = self.next().encode(); return lambda p: s in p.payload
        raise FilterError(f"unknown filter term {t!r}")

    @staticmethod
    def _addr(s):
        try: return str(ipaddress.ip_address(s))
        except ValueError: raise FilterError(f"bad IP address {s!r}")

    @staticmethod
    def _side(direction, a, b, test):
        va = a is not None and test(a)
        vb = b is not None and test(b)
        return va if direction == "src" else vb if direction == "dst" else (va or vb)


def compile_filter(expr: str | None) -> Pred:
    if not expr or not expr.strip():
        return lambda p: True
    return _Parser(_tokenize(expr)).parse()
