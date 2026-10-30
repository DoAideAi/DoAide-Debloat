"""Who did the phone talk to? A small PCAP reader for the X-ray.

Reads a capture written by PCAPdroid (or any raw-IP / Ethernet PCAP) and returns, per TCP or UDP
flow: the server name (TLS ClientHello SNI, HTTP Host, or the DNS answer that pointed at the
server's address), the Android UID that owned the socket (from PCAPdroid's per-packet trailer,
written when the capture was started with dump_extensions=true), and packet and byte counts.
DNS queries are listed separately.

Nothing is decrypted. Of each flow only the first client bytes are looked at, to find the server
name, and they are dropped as soon as it is found.

Stdlib only, Python 3.9+.
"""
from __future__ import annotations

import ipaddress
import struct
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Union

LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101
LINKTYPE_IPV4 = 228
LINKTYPE_IPV6 = 229
LINKTYPE_LINUX_SLL = 113
SUPPORTED_LINKTYPES = (LINKTYPE_ETHERNET, LINKTYPE_RAW, LINKTYPE_IPV4, LINKTYPE_IPV6, LINKTYPE_LINUX_SLL)

# PCAPdroid's trailer (docs/app_api.md, jni/core/pcap_dump.c): it ends every record when the
# capture runs with dump_extensions, after a fake Ethernet header, the IP packet and padding:
#   magic 0x01072021 (4, big-endian) | uid (4, big-endian, signed) | app name (20) | FCS (4)
TRAILER_MAGIC = b"\x01\x07\x20\x21"
TRAILER_LEN = 32
UNKNOWN_UID = -1

CLIENT_BYTES = 16384        # how much of a client stream is kept while looking for a server name
MAX_RECORD = 262144         # a record longer than this means the file is not what it claims
SERVER_PORTS = {53, 80, 123, 443, 853, 3478, 5228, 5229, 5230, 8080, 8443, 19302}
HTTP_METHODS = (b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ", b"OPTIONS ", b"PATCH ", b"CONNECT ")


class ScanError(ValueError):
    pass


@dataclass
class DnsQuery:
    ts: float
    name: str
    qtype: int
    uid: int


@dataclass
class Flow:
    proto: str                  # "tcp" or "udp"
    client: str
    client_port: int
    server: str
    server_port: int
    first_ts: float
    last_ts: float = 0.0
    packets: int = 0
    bytes: int = 0              # IP bytes, both directions
    sni: Optional[str] = None
    http_host: Optional[str] = None
    dns_name: Optional[str] = None
    uids: Counter = field(default_factory=Counter)
    _isn: Optional[int] = None
    _segments: Dict[int, bytes] = field(default_factory=dict)
    _done: bool = False

    @property
    def uid(self) -> int:
        known = [(count, uid) for uid, count in self.uids.items() if uid >= 0]
        return max(known)[1] if known else UNKNOWN_UID

    @property
    def name(self) -> Optional[str]:
        return self.sni or self.http_host or self.dns_name

    @property
    def via(self) -> str:
        if self.sni:
            return "sni"
        if self.http_host:
            return "http"
        return "dns" if self.dns_name else ""


@dataclass
class Capture:
    linktype: int
    packets: int = 0
    bytes: int = 0
    first_ts: Optional[float] = None
    last_ts: Optional[float] = None
    flows: List[Flow] = field(default_factory=list)
    queries: List[DnsQuery] = field(default_factory=list)
    answers: Dict[str, List[Tuple[float, str]]] = field(default_factory=dict)   # ip -> [(ts, name)]
    cnames: Dict[str, Set[str]] = field(default_factory=dict)                  # name -> CNAME targets
    trailer_packets: int = 0
    app_names: Dict[int, str] = field(default_factory=dict)                    # uid -> trailer name
    skipped: int = 0
    warnings: List[str] = field(default_factory=list)

    @property
    def seconds(self) -> float:
        if self.first_ts is None or self.last_ts is None:
            return 0.0
        return max(0.0, self.last_ts - self.first_ts)


# --------------------------------------------------------------------------- names


def clean_host(name: str) -> Optional[str]:
    """A lower-case DNS name, or None for IP literals, single labels and garbage."""
    name = (name or "").strip().rstrip(".").lower()
    if not name or len(name) > 253 or "." not in name:
        return None
    try:
        ipaddress.ip_address(name)
        return None
    except ValueError:
        pass
    for label in name.split("."):
        if not label or len(label) > 63 or label[0] == "-" or label[-1] == "-":
            return None
        if any(not (c.isascii() and (c.isalnum() or c in "-_")) for c in label):
            return None
    return name


LOCAL_NETWORKS = tuple(ipaddress.ip_network(n) for n in (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
    "192.168.0.0/16", "224.0.0.0/4", "255.255.255.255/32",
    "::/128", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8",
))


def is_local(ip: str) -> bool:
    """LAN, VPN-internal, CGNAT, loopback, link-local or multicast: not a server on the internet.

    An explicit list rather than ipaddress.is_private, whose meaning differs between Python versions.
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr.version == net.version and addr in net for net in LOCAL_NETWORKS)


# --------------------------------------------------------------------------- layers


def link_payload(linktype: int, data: bytes) -> Tuple[bytes, Optional[int], Optional[str]]:
    """(IP packet, uid or None, trailer app name or None) for one record."""
    if linktype == LINKTYPE_ETHERNET:
        if len(data) >= 14 + TRAILER_LEN and data[-TRAILER_LEN:-TRAILER_LEN + 4] == TRAILER_MAGIC:
            uid = struct.unpack(">i", data[-28:-24])[0]
            app = data[-24:-4].split(b"\0", 1)[0].decode("ascii", "replace")
            return data[14:-TRAILER_LEN], uid, app
        if data[12:14] in (b"\x08\x00", b"\x86\xdd"):
            return data[14:], None, None
        # PCAPdroid drops the Ethernet header and trailer when they would not fit the snaplen
        return data, None, None
    if linktype == LINKTYPE_LINUX_SLL:
        return data[16:], None, None
    return data, None, None


def parse_ip(pkt: bytes) -> Optional[Tuple[str, str, int, bytes, int]]:
    """(src, dst, protocol, transport bytes, IP length); transport is empty for later fragments."""
    if not pkt:
        return None
    version = pkt[0] >> 4
    if version == 4:
        if len(pkt) < 20:
            return None
        ihl = (pkt[0] & 0x0F) * 4
        total = struct.unpack(">H", pkt[2:4])[0]
        if ihl < 20 or total < ihl:
            return None
        frag_offset = struct.unpack(">H", pkt[6:8])[0] & 0x1FFF
        src = str(ipaddress.IPv4Address(pkt[12:16]))
        dst = str(ipaddress.IPv4Address(pkt[16:20]))
        payload = b"" if frag_offset else pkt[ihl:min(total, len(pkt))]
        return src, dst, pkt[9], payload, total
    if version == 6:
        if len(pkt) < 40:
            return None
        plen = struct.unpack(">H", pkt[4:6])[0]
        nxt = pkt[6]
        src = str(ipaddress.IPv6Address(pkt[8:24]))
        dst = str(ipaddress.IPv6Address(pkt[24:40]))
        end = min(len(pkt), 40 + plen)
        off = 40
        while nxt in (0, 43, 44, 60) and off + 8 <= end:
            if nxt == 44:                                   # fragment header
                later = struct.unpack(">H", pkt[off + 2:off + 4])[0] >> 3
                nxt = pkt[off]
                off += 8
                if later:
                    return src, dst, nxt, b"", 40 + plen
                continue
            nxt, off = pkt[off], off + (pkt[off + 1] + 1) * 8
        return src, dst, nxt, pkt[off:end], 40 + plen
    return None


# --------------------------------------------------------------------------- DNS


def read_name(msg: bytes, pos: int) -> Tuple[Optional[str], int]:
    """A (possibly compressed) DNS name at `pos`; returns (name, position after it)."""
    labels: List[str] = []
    jumps = 0
    end: Optional[int] = None
    while True:
        if pos >= len(msg):
            return None, pos
        length = msg[pos]
        if length == 0:
            pos += 1
            break
        if length & 0xC0 == 0xC0:
            if pos + 1 >= len(msg):
                return None, pos
            pointer = ((length & 0x3F) << 8) | msg[pos + 1]
            if end is None:
                end = pos + 2
            jumps += 1
            if jumps > 32 or pointer >= len(msg):
                return None, pos
            pos = pointer
            continue
        if length & 0xC0:
            return None, pos
        pos += 1
        labels.append(msg[pos:pos + length].decode("ascii", "replace"))
        pos += length
        if len(labels) > 127:
            return None, pos
    return ".".join(labels), (end if end is not None else pos)


# --------------------------------------------------------------------------- TLS and HTTP


def _client_hello(buf: bytes) -> Tuple[Optional[bytes], bool]:
    """(ClientHello body, final). final=False means more bytes are needed."""
    handshake = bytearray()
    pos = 0
    while pos + 5 <= len(buf):
        if buf[pos] != 22:                                  # not a handshake record
            return None, True
        length = struct.unpack(">H", buf[pos + 3:pos + 5])[0]
        handshake += buf[pos + 5:pos + 5 + length]
        pos += 5 + length
        if len(handshake) >= 4 and len(handshake) >= 4 + int.from_bytes(handshake[1:4], "big"):
            break
    if len(handshake) < 4:
        return None, False
    if handshake[0] != 1:                                   # not a ClientHello
        return None, True
    need = 4 + int.from_bytes(handshake[1:4], "big")
    if len(handshake) < need:
        return None, False
    return bytes(handshake[4:need]), True


def sni_from_hello(body: bytes) -> Optional[str]:
    try:
        pos = 2 + 32                                        # client_version, random
        pos += 1 + body[pos]                                # session id
        pos += 2 + int.from_bytes(body[pos:pos + 2], "big")  # cipher suites
        pos += 1 + body[pos]                                # compression methods
        if pos + 2 > len(body):
            return None
        end = min(len(body), pos + 2 + int.from_bytes(body[pos:pos + 2], "big"))
        pos += 2
        while pos + 4 <= end:
            ext_type = int.from_bytes(body[pos:pos + 2], "big")
            ext_len = int.from_bytes(body[pos + 2:pos + 4], "big")
            pos += 4
            if ext_type == 0:                               # server_name
                item = pos + 2
                while item + 3 <= pos + ext_len:
                    name_type = body[item]
                    name_len = int.from_bytes(body[item + 1:item + 3], "big")
                    item += 3
                    if name_type == 0:
                        return clean_host(body[item:item + name_len].decode("ascii", "replace"))
                    item += name_len
                return None
            pos += ext_len
    except IndexError:
        return None
    return None


def http_host(head: bytes) -> Optional[str]:
    for line in head.split(b"\r\n")[1:]:
        if not line:
            break
        if line[:5].lower() == b"host:":
            host = line[5:].strip().decode("ascii", "replace")
            if host.startswith("["):
                return None
            if host.count(":") == 1:
                host = host.split(":", 1)[0]
            return clean_host(host)
    return None


def server_name(buf: bytes) -> Tuple[Optional[str], Optional[str], bool]:
    """(name, "sni" | "http" | None, final) for the start of a client byte stream."""
    if not buf:
        return None, None, False
    if buf[0] == 22:
        hello, final = _client_hello(buf)
        if hello is None:
            return None, None, final
        return sni_from_hello(hello), "sni", True
    if buf.startswith(HTTP_METHODS):
        end = buf.find(b"\r\n\r\n")
        if end < 0 and len(buf) < 8192:
            return None, None, False
        return http_host(buf[:end if end >= 0 else 8192]), "http", True
    if len(buf) < 8 and any(m.startswith(buf) for m in HTTP_METHODS):
        return None, None, False
    return None, None, True


def _assemble(segments: Dict[int, bytes]) -> bytes:
    out = bytearray()
    pos = 0
    while True:
        chunk = segments.get(pos)
        if chunk is None:
            covering = [(start, data) for start, data in segments.items() if start < pos < start + len(data)]
            if not covering:
                break
            start, data = covering[0]
            chunk = data[pos - start:]
        if not chunk:
            break
        out += chunk
        pos += len(chunk)
    return bytes(out)


# --------------------------------------------------------------------------- scanner


class _Scanner:
    def __init__(self, cap: Capture) -> None:
        self.cap = cap
        self.flows: Dict[Tuple[str, str, int, str, int], Flow] = {}

    def packet(self, ts: float, data: bytes) -> None:
        cap = self.cap
        cap.packets += 1
        if cap.first_ts is None:
            cap.first_ts = ts
        cap.last_ts = ts
        ip, uid, app = link_payload(cap.linktype, data)
        if uid is not None:
            cap.trailer_packets += 1
            if app and uid >= 0:
                cap.app_names.setdefault(uid, app)
        parsed = parse_ip(ip)
        if not parsed:
            cap.skipped += 1
            return
        src, dst, proto, payload, length = parsed
        cap.bytes += length
        if proto == 17:
            self.udp(ts, src, dst, payload, length, uid)
        elif proto == 6:
            self.tcp(ts, src, dst, payload, length, uid)

    def flow(self, proto: str, src: str, sport: int, dst: str, dport: int, ts: float,
             syn: bool) -> Tuple[Flow, bool]:
        key = (proto, src, sport, dst, dport)
        found = self.flows.get(key)
        if found:
            return found, True
        rkey = (proto, dst, dport, src, sport)
        found = self.flows.get(rkey)
        if found:
            return found, False
        if _src_is_client(src, sport, dst, dport, syn):
            new = Flow(proto, src, sport, dst, dport, ts)
            self.flows[key] = new
            from_client = True
        else:
            new = Flow(proto, dst, dport, src, sport, ts)
            self.flows[rkey] = new
            from_client = False
        self.cap.flows.append(new)
        return new, from_client

    @staticmethod
    def account(flow: Flow, ts: float, length: int, uid: Optional[int]) -> None:
        flow.packets += 1
        flow.bytes += length
        flow.last_ts = ts
        if uid is not None:
            flow.uids[uid] += 1

    def udp(self, ts: float, src: str, dst: str, seg: bytes, length: int, uid: Optional[int]) -> None:
        if len(seg) < 8:
            return
        sport, dport = struct.unpack(">HH", seg[:4])
        flow, _ = self.flow("udp", src, sport, dst, dport, ts, syn=False)
        self.account(flow, ts, length, uid)
        if 53 in (sport, dport):
            self.dns(ts, seg[8:], uid)

    def tcp(self, ts: float, src: str, dst: str, seg: bytes, length: int, uid: Optional[int]) -> None:
        if len(seg) < 20:
            return
        sport, dport, seq = struct.unpack(">HHI", seg[:8])
        offset = (seg[12] >> 4) * 4
        flags = seg[13]
        syn = bool(flags & 0x02) and not flags & 0x10
        flow, from_client = self.flow("tcp", src, sport, dst, dport, ts, syn=syn)
        self.account(flow, ts, length, uid)
        if not from_client or flow._done:
            return
        if syn:
            if not flow._segments:
                flow._isn = (seq + 1) & 0xFFFFFFFF
            return
        data = seg[offset:]
        if data:
            self.client_data(flow, seq, data)

    @staticmethod
    def client_data(flow: Flow, seq: int, data: bytes) -> None:
        if flow._isn is None:
            flow._isn = seq
        rel = (seq - flow._isn) & 0xFFFFFFFF
        if rel >= CLIENT_BYTES:
            return
        flow._segments.setdefault(rel, data)
        buf = _assemble(flow._segments)
        name, kind, final = server_name(buf)
        if name:
            if kind == "sni":
                flow.sni = name
            else:
                flow.http_host = name
        if name or final or len(buf) >= CLIENT_BYTES:
            flow._done = True
            flow._segments = {}

    def dns(self, ts: float, msg: bytes, uid: Optional[int]) -> None:
        if len(msg) < 12:
            return
        _, flags, qdcount, ancount = struct.unpack(">HHHH", msg[:8])
        pos = 12
        questions: List[Tuple[str, int]] = []
        for _ in range(min(qdcount, 16)):
            name, pos = read_name(msg, pos)
            if name is None or pos + 4 > len(msg):
                return
            questions.append((name, int.from_bytes(msg[pos:pos + 2], "big")))
            pos += 4
        if not flags & 0x8000:                              # a query
            for name, qtype in questions:
                host = clean_host(name)
                if host:
                    self.cap.queries.append(DnsQuery(ts, host, qtype, UNKNOWN_UID if uid is None else uid))
            return
        cnames: Dict[str, str] = {}
        addresses: List[Tuple[str, str]] = []
        for _ in range(min(ancount, 64)):
            owner, pos = read_name(msg, pos)
            if owner is None or pos + 10 > len(msg):
                break
            rtype, _, _, rdlength = struct.unpack(">HHIH", msg[pos:pos + 10])
            pos += 10
            rdata = msg[pos:pos + rdlength]
            start = pos
            pos += rdlength
            if pos > len(msg):
                break
            owner = owner.lower().rstrip(".")
            if rtype == 1 and rdlength == 4:
                addresses.append((owner, str(ipaddress.IPv4Address(rdata))))
            elif rtype == 28 and rdlength == 16:
                addresses.append((owner, str(ipaddress.IPv6Address(rdata))))
            elif rtype == 5:
                target, _ = read_name(msg, start)
                if target:
                    cnames[owner] = target.lower().rstrip(".")
        for qname, _ in questions:
            host = clean_host(qname)
            if not host:
                continue
            chain = [host]
            while chain[-1] in cnames and len(chain) < 16 and cnames[chain[-1]] not in chain:
                chain.append(cnames[chain[-1]])
            if len(chain) > 1:
                self.cap.cnames.setdefault(host, set()).update(c for c in chain[1:] if clean_host(c))
            names = set(chain)
            for owner, ip in addresses:
                if owner in names:
                    self.cap.answers.setdefault(ip, []).append((ts, host))

    def finish(self) -> None:
        for flow in self.cap.flows:
            flow._segments = {}
            if flow.sni or flow.http_host:
                continue
            answers = self.cap.answers.get(flow.server)
            if not answers:
                continue
            before = [a for a in answers if a[0] <= flow.first_ts + 1.0]
            flow.dns_name = (before[-1] if before else answers[0])[1]


def _src_is_client(src: str, sport: int, dst: str, dport: int, syn: bool) -> bool:
    if syn:
        return True
    if dport in SERVER_PORTS and sport not in SERVER_PORTS:
        return True
    if sport in SERVER_PORTS and dport not in SERVER_PORTS:
        return False
    src_local, dst_local = is_local(src), is_local(dst)
    if src_local != dst_local:
        return src_local
    return sport >= dport


def _header(head: bytes) -> Tuple[str, bool]:
    if len(head) < 24:
        raise ScanError("not a PCAP file (too short)")
    magic = head[:4]
    if magic == b"\x0a\x0d\x0d\x0a":
        raise ScanError("this is a PCAPNG file; save the capture as PCAP (in PCAPdroid: Settings > "
                        "PCAPNG format off)")
    if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        return "<", magic == b"\x4d\x3c\xb2\xa1"
    if magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        return ">", magic == b"\xa1\xb2\x3c\x4d"
    raise ScanError("not a PCAP file")


def scan(path: Union[str, Path]) -> Capture:
    with open(path, "rb") as fh:
        head = fh.read(24)
        endian, nano = _header(head)
        linktype = struct.unpack(endian + "I", head[20:24])[0] & 0x0FFFFFFF
        if linktype not in SUPPORTED_LINKTYPES:
            raise ScanError(f"unsupported PCAP link type {linktype}")
        cap = Capture(linktype=linktype)
        scanner = _Scanner(cap)
        while True:
            record = fh.read(16)
            if not record:
                break
            if len(record) < 16:
                cap.warnings.append("the capture ends in the middle of a packet (it was cut short)")
                break
            sec, frac, incl, _ = struct.unpack(endian + "IIII", record)
            if incl > MAX_RECORD:
                raise ScanError(f"corrupt PCAP: a {incl}-byte record")
            data = fh.read(incl)
            if len(data) < incl:
                cap.warnings.append("the capture ends in the middle of a packet (it was cut short)")
                break
            scanner.packet(sec + frac / (1e9 if nano else 1e6), data)
        scanner.finish()
    return cap
