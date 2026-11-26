"""Raw-socket capture backends (Linux AF_PACKET, Windows SIO_RCVALL)."""
from __future__ import annotations

import socket
import sys
import time
from typing import Iterator, Optional, Tuple


class CaptureError(RuntimeError):
    pass


def list_interfaces() -> list[str]:
    try:
        return [name for _, name in socket.if_nameindex()]
    except (AttributeError, OSError):
        return []


def open_socket(iface: Optional[str] = None) -> Tuple[socket.socket, str]:
    """Returns (socket, link) where link is 'eth' or 'raw' (starts at IP header)."""
    try:
        if sys.platform.startswith("linux"):
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))  # ETH_P_ALL
            if iface:
                s.bind((iface, 0))
            return s, "eth"
        if sys.platform == "win32":
            host = socket.gethostbyname(socket.gethostname())
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            s.bind((host, 0))
            s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            return s, "raw"
    except PermissionError:
        raise CaptureError("permission denied - run as root/Administrator "
                           "(or: sudo setcap cap_net_raw+eip $(readlink -f $(which python3)))")
    except OSError as e:
        raise CaptureError(f"cannot open capture socket: {e}")
    raise CaptureError(f"live capture not supported on {sys.platform} with raw sockets "
                       "(use Linux/Windows, or analyze a pcap with -r)")


def sniff(iface: Optional[str] = None, timeout: float = 1.0) -> Iterator[Tuple[float, bytes, str]]:
    """Yield (timestamp, frame, link). Yields (ts, b'', link) on timeout so callers can check deadlines."""
    sock, link = open_socket(iface)
    sock.settimeout(timeout)
    try:
        while True:
            try:
                data, _ = sock.recvfrom(65535)
            except socket.timeout:
                yield time.time(), b"", link
                continue
            yield time.time(), data, link
    finally:
        if sys.platform == "win32":
            try: sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            except OSError: pass
        sock.close()
