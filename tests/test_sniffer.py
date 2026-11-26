import os, socket, struct, tempfile, unittest
from pysniffer.protocols import parse_packet
from pysniffer.filters import compile_filter, FilterError
from pysniffer.pcap import PcapWriter, PcapReader

def mac(s): return bytes(int(x, 16) for x in s.split(":"))
def eth(payload, et=0x0800, dst="aa:bb:cc:dd:ee:ff", src="11:22:33:44:55:66"):
    return mac(dst) + mac(src) + struct.pack("!H", et) + payload
def ipv4(proto, seg, src="10.0.0.1", dst="10.0.0.2"):
    return struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(seg), 1, 0, 64, proto, 0,
                       socket.inet_aton(src), socket.inet_aton(dst)) + seg
def tcp(sport, dport, flags, payload=b""):
    return struct.pack("!HHIIHHHH", sport, dport, 100, 200, (5 << 12) | flags, 1024, 0, 0) + payload
def udp(sport, dport, payload):
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload

def dns_query(name):
    q = b"".join(bytes([len(l)]) + l.encode() for l in name.split(".")) + b"\0"
    return struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + q + struct.pack("!HH", 1, 1)

def dns_response(name, ip):
    q = b"".join(bytes([len(l)]) + l.encode() for l in name.split(".")) + b"\0"
    hdr = struct.pack("!HHHHHH", 0x1234, 0x8180, 1, 1, 0, 0)
    ans = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton(ip)
    return hdr + q + struct.pack("!HH", 1, 1) + ans

class Tests(unittest.TestCase):
    def test_tcp_syn(self):
        p = parse_packet(eth(ipv4(6, tcp(5555, 80, 0x02))))
        self.assertEqual((p.proto, p.src, p.dst, p.sport, p.dport, p.flags), ("TCP", "10.0.0.1", "10.0.0.2", 5555, 80, "SYN"))
        self.assertTrue(compile_filter("syn and tcp port 80")(p))

    def test_http(self):
        req = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"
        p = parse_packet(eth(ipv4(6, tcp(5555, 80, 0x18, req))))
        self.assertEqual(p.proto, "HTTP"); self.assertEqual(p.info, "GET /index.html HTTP/1.1")
        self.assertEqual(p.extra["http_host"], "example.com")

    def test_dns_query_and_response(self):
        q = parse_packet(eth(ipv4(17, udp(4000, 53, dns_query("www.example.com")))))
        self.assertEqual(q.proto, "DNS"); self.assertIn("A www.example.com", q.info)
        r = parse_packet(eth(ipv4(17, udp(53, 4000, dns_response("www.example.com", "93.184.216.34")))))
        self.assertIn("93.184.216.34", r.info)

    def test_icmp_ping(self):
        p = parse_packet(eth(ipv4(1, struct.pack("!BBHHH", 8, 0, 0, 7, 1) + b"x" * 8)))
        self.assertEqual(p.proto, "ICMP"); self.assertIn("Echo Request", p.info)

    def test_arp(self):
        arp = struct.pack("!HHBBH", 1, 0x0800, 6, 4, 1) + mac("11:22:33:44:55:66") + socket.inet_aton("10.0.0.1") \
              + b"\0" * 6 + socket.inet_aton("10.0.0.2")
        p = parse_packet(eth(arp, 0x0806, dst="ff:ff:ff:ff:ff:ff"))
        self.assertEqual(p.proto, "ARP"); self.assertIn("Who has 10.0.0.2", p.info)

    def test_ipv6_udp(self):
        seg = udp(1000, 2000, b"hi")
        ip6 = struct.pack("!IHBB", 6 << 28, len(seg), 17, 64) + socket.inet_pton(socket.AF_INET6, "fe80::1") + socket.inet_pton(socket.AF_INET6, "fe80::2") + seg
        p = parse_packet(eth(ip6, 0x86DD))
        self.assertEqual((p.l4, p.src, p.dport), ("UDP", "fe80::1", 2000))

    def test_tls_sni(self):
        name = b"secure.example.org"
        sni = struct.pack("!HHHBH", 0, len(name) + 5, len(name) + 3, 0, len(name)) + name
        exts = struct.pack("!H", len(sni)) + sni
        body = b"\x03\x03" + b"\0" * 32 + b"\0" + struct.pack("!H", 2) + b"\x13\x01" + b"\x01\x00" + exts
        hs = b"\x01" + struct.pack("!I", len(body))[1:] + body
        rec = b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs
        p = parse_packet(eth(ipv4(6, tcp(5555, 443, 0x18, rec))))
        self.assertEqual(p.proto, "TLS"); self.assertIn("SNI=secure.example.org", p.info)

    def test_truncated_is_safe(self):
        p = parse_packet(eth(ipv4(6, b"\x00\x01"))); self.assertIsNotNone(p.error)

    def test_filters(self):
        p = parse_packet(eth(ipv4(17, udp(4000, 53, dns_query("a.b")))))
        for expr, want in [("udp", True), ("tcp", False), ("not tcp", True), ("host 10.0.0.1", True),
                           ("src host 10.0.0.2", False), ("dst net 10.0.0.0/24", True),
                           ("port 53 and dns", True), ("dst port 50-60", True), ("udp and (port 1 or port 53)", True),
                           ("len > 1000", False), ("", True)]:
            self.assertEqual(compile_filter(expr)(p), want, expr)
        for bad in ["tcp and", "host", "(tcp", "bogus", "host 1.2.3"]:
            with self.assertRaises(FilterError): compile_filter(bad)

    def test_pcap_roundtrip(self):
        raw = eth(ipv4(6, tcp(1, 2, 0x10)))
        path = os.path.join(tempfile.mkdtemp(), "t.pcap")
        with PcapWriter(path) as w: w.write(1700000000.5, raw)
        with PcapReader(path) as r:
            pk = list(r); self.assertEqual(r.link, "eth")
        self.assertEqual(pk[0][1], raw); self.assertAlmostEqual(pk[0][0], 1700000000.5, 3)

if __name__ == "__main__":
    unittest.main()
