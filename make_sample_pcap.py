"""Generate a small sample.pcap (DNS, TCP handshake, HTTP, ICMP, ARP) so you can
try the tool without root privileges:   python3 make_sample_pcap.py && python3 -m pysniffer -r sample.pcap -s"""
import sys; sys.path.insert(0, "tests")
from test_sniffer import *   # reuse the packet builders
from pysniffer.pcap import PcapWriter
import time

t = time.time()
c, s = "192.168.1.10", "93.184.216.34"
frames = [
    eth(ipv4(17, udp(51000, 53, dns_query("example.com")), c, "192.168.1.1")),
    eth(ipv4(17, udp(53, 51000, dns_response("example.com", s)), "192.168.1.1", c)),
    eth(ipv4(6, tcp(52000, 80, 0x02), c, s)),
    eth(ipv4(6, tcp(80, 52000, 0x12), s, c)),
    eth(ipv4(6, tcp(52000, 80, 0x10), c, s)),
    eth(ipv4(6, tcp(52000, 80, 0x18, b"GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: demo\r\n\r\n"), c, s)),
    eth(ipv4(1, struct.pack("!BBHHH", 8, 0, 0, 1, 1) + b"abcdefgh", c, "8.8.8.8")),
]
with PcapWriter("sample.pcap") as w:
    for i, f in enumerate(frames):
        w.write(t + i * 0.02, f)
print(f"wrote sample.pcap with {len(frames)} packets")
