"""Behaviour tests for the X-ray: PCAP parsing, tracker lists, analysis, the public summary, the
card, the capture over a scripted phone, and the Phone-Home Index.

Run:  python3 -m unittest discover -s tests -v     (stdlib only; no network, no device)
"""
from __future__ import annotations

import contextlib
import io
import ipaddress
import json
import os
import shlex
import struct
import sys
import tempfile
import unittest
import urllib.parse
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import debloat  # noqa: E402
import pcapscan  # noqa: E402
import trackerdb  # noqa: E402
import xray  # noqa: E402
import xray_index  # noqa: E402
from test_debloat import BASE_PACKAGES, FakeDevice  # noqa: E402

PHONE, RESOLVER = "10.215.173.1", "10.215.173.2"
PHONE6 = "fd00:2:fd00:1:fd00:1:fd00:1"
UID_SYSTEM, UID_GLANCE, UID_USER, UID_PCAPDROID = 1000, 10050, 10200, 10300
UID_LIST = (
    "package:android uid:1000\n"
    "package:com.android.settings uid:1000\n"
    "package:com.glance.internet uid:10050\n"
    "package:com.example.thirdparty uid:10200\n"
    "package:com.emanuelef.remote_capture uid:10300\n"
)

# --------------------------------------------------------------------------- packet builders


def ip4(src, dst, proto, payload):
    header = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 0, 0, 64, proto, 0,
                         ipaddress.IPv4Address(src).packed, ipaddress.IPv4Address(dst).packed)
    return header + payload


def ip6(src, dst, nxt, payload):
    return struct.pack(">IHBB16s16s", 6 << 28, len(payload), nxt, 64, ipaddress.IPv6Address(src).packed,
                       ipaddress.IPv6Address(dst).packed) + payload


def udp(sport, dport, data):
    return struct.pack(">HHHH", sport, dport, 8 + len(data), 0) + data


def tcp(sport, dport, seq, flags, data=b""):
    bits = sum(bit for flag, bit in (("F", 1), ("S", 2), ("P", 8), ("A", 16)) if flag in flags)
    return struct.pack(">HHIIBBHHH", sport, dport, seq, 0, 5 << 4, bits, 65535, 0, 0) + data


def dns_name(name):
    return b"".join(bytes([len(label)]) + label.encode() for label in name.split(".")) + b"\0"


def dns_query(qid, name, qtype=1):
    return struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0) + dns_name(name) + struct.pack(">HH", qtype, 1)


def dns_response(qid, name, answers, qtype=1):
    out = struct.pack(">HHHHHH", qid, 0x8180, 1, len(answers), 0, 0) + dns_name(name) + struct.pack(">HH", qtype, 1)
    for owner, rtype, value in answers:
        owner_bytes = b"\xc0\x0c" if owner == name else dns_name(owner)    # compression pointer
        if rtype == "A":
            code, rdata = 1, ipaddress.IPv4Address(value).packed
        elif rtype == "AAAA":
            code, rdata = 28, ipaddress.IPv6Address(value).packed
        else:
            code, rdata = 5, dns_name(value)
        out += owner_bytes + struct.pack(">HHIH", code, 1, 60, len(rdata)) + rdata
    return out


def client_hello(sni, pad=1400):
    name = sni.encode()
    padding = struct.pack(">HH", 21, pad) + b"\0" * pad          # padding first: SNI lands in a later segment
    server_name = struct.pack(">HHHBH", 0, len(name) + 5, len(name) + 3, 0, len(name)) + name
    extensions = padding + server_name
    body = (b"\x03\x03" + b"\x11" * 32 + b"\x00" + struct.pack(">H", 2) + b"\x13\x01" + b"\x01\x00" +
            struct.pack(">H", len(extensions)) + extensions)
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack(">H", len(handshake)) + handshake


def with_trailer(packet, uid, app="app"):
    ethertype = b"\x08\x00" if packet[0] >> 4 == 4 else b"\x86\xdd"
    padding = b"\0" * ((-(14 + len(packet))) % 4)
    trailer = pcapscan.TRAILER_MAGIC + struct.pack(">i", uid) + app.encode()[:19].ljust(20, b"\0")
    return b"\0" * 12 + ethertype + packet + padding + trailer + b"\0\0\0\0"


def pcap_file(records, linktype=1, endian="<"):
    out = struct.pack(endian + "IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, linktype)
    for ts, data in records:
        sec = int(ts)
        out += struct.pack(endian + "IIII", sec, int(round((ts - sec) * 1e6)), len(data), len(data)) + data
    return out


class Traffic:
    """A phone's traffic, written as PCAPdroid would (Ethernet + trailer) unless raw=True."""

    def __init__(self, raw=False):
        self.raw = raw
        self.records = []
        self.ts = 1_790_000_000.0
        self.port = 40000

    def add(self, packet, uid=-1, app="app"):
        self.records.append((self.ts, packet if self.raw else with_trailer(packet, uid, app)))
        self.ts += 0.01

    def next_port(self):
        self.port += 1
        return self.port

    def dns(self, name, answers, qtype=1):
        port = self.next_port()
        self.add(ip4(PHONE, RESOLVER, 17, udp(port, 53, dns_query(port, name, qtype))))
        self.add(ip4(RESOLVER, PHONE, 17, udp(53, port, dns_response(port, name, answers, qtype))))

    def tls(self, server, sni, uid, pieces=2, reverse=False, v6=False, reply=1200):
        ip, phone, port = (ip6, PHONE6, self.next_port()) if v6 else (ip4, PHONE, self.next_port())
        self.add(ip(phone, server, 6, tcp(port, 443, 1000, "S")), uid)
        self.add(ip(server, phone, 6, tcp(443, port, 5000, "SA")), uid)
        hello = client_hello(sni)
        size = -(-len(hello) // pieces)
        chunks = [(1001 + i, hello[i:i + size]) for i in range(0, len(hello), size)]
        for seq, chunk in (reversed(chunks) if reverse else chunks):
            self.add(ip(phone, server, 6, tcp(port, 443, seq, "PA", chunk)), uid)
        self.add(ip(server, phone, 6, tcp(443, port, 5001, "PA", b"\x16\x03\x03" + b"\0" * reply)), uid)

    def http(self, server, host, uid):
        port = self.next_port()
        self.add(ip4(PHONE, server, 6, tcp(port, 80, 7000, "S")), uid)
        request = f"GET /beacon?id=1 HTTP/1.1\r\nHost: {host}:80\r\nUser-Agent: t\r\n\r\n".encode()
        self.add(ip4(PHONE, server, 6, tcp(port, 80, 7001, "PA", request)), uid)
        self.add(ip4(server, PHONE, 6, tcp(80, port, 9000, "PA", b"HTTP/1.1 204 No Content\r\n\r\n")), uid)

    def udp(self, server, dport, uid, size=600):
        port = self.next_port()
        self.add(ip4(PHONE, server, 17, udp(port, dport, b"\xc3" + b"\0" * size)), uid)
        self.add(ip4(server, PHONE, 17, udp(dport, port, b"\0" * size)), uid)

    def bytes(self, linktype=None, endian="<"):
        return pcap_file(self.records, linktype or (pcapscan.LINKTYPE_RAW if self.raw else 1), endian)


def before_traffic():
    t = Traffic()
    t.dns("lock.glanceapis.example", [("lock.glanceapis.example", "A", "203.0.113.10")])
    t.tls("203.0.113.10", "lock.glanceapis.example", UID_GLANCE)
    t.dns("cdn.partner.example", [("cdn.partner.example", "CNAME", "ads.adnet.example"),
                                  ("ads.adnet.example", "A", "203.0.113.20")])
    t.tls("203.0.113.20", "cdn.partner.example", UID_GLANCE, pieces=3, reverse=True)
    t.http("198.51.100.7", "metrics.oemtelemetry.example", UID_SYSTEM)
    t.tls("198.51.100.50", "telemetry.datingapp.example", UID_USER)
    t.tls("198.51.100.60", "www.bank.example", UID_USER)
    t.dns("events.glanceapis.example", [("events.glanceapis.example", "A", "203.0.113.30")])
    t.udp("203.0.113.30", 443, UID_GLANCE)                  # QUIC: named by the DNS answer
    t.udp("192.168.1.20", 8009, UID_USER)                    # LAN: left out
    t.tls("203.0.113.99", "geo.pcapdroid.example", UID_PCAPDROID)   # PCAPdroid itself: left out
    t.tls("2001:db8::5", "ipv6.trackme.example", UID_SYSTEM, v6=True)
    t.dns("beacon.adnet.example", [])                        # looked up, never contacted
    return t


def after_traffic():
    t = Traffic()
    t.http("198.51.100.7", "metrics.oemtelemetry.example", UID_SYSTEM)
    t.tls("198.51.100.60", "www.bank.example", UID_USER)
    return t


PSL_TEXT = "// test list\n// ===BEGIN ICANN DOMAINS===\nexample\ncom\nnet\nin\nco.in\n*.ck\n!www.ck\n"
EXODUS = {"trackers": {
    "1": {"id": 1, "name": "AdNet Ads", "network_signature": "adnet\\.example"},
    "2": {"id": 2, "name": "Adjustish", "network_signature": "go\\.link"},
    "5": {"id": 5, "name": "BigCo Ads", "network_signature": "\\.bigco\\.example"},
    "3": {"id": 3, "name": "No Network", "network_signature": ""},
    "4": {"id": 4, "name": "Broken", "network_signature": "(unclosed"},
}}
PRO = ["glanceapis.example", "datingapp.example", "trackme.example", "adnet.example", "go.link"] + \
    [f"filler{i}.example" for i in range(10)]
NATIVE = ["oemtelemetry.example"] + [f"native{i}.example" for i in range(10)]


def test_db():
    exodus, _ = trackerdb.parse_exodus(json.dumps(EXODUS))
    return trackerdb.TrackerDB(exodus=exodus, native={"Xiaomi": set(NATIVE)}, pro=set(PRO),
                               psl=trackerdb.PublicSuffixList(PSL_TEXT),
                               sources={"exodus": {"entries": 2}, "pro": {"entries": len(PRO)}})


def write_cache(folder: Path):
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "exodus-trackers.json").write_text(json.dumps(EXODUS))
    (folder / "hagezi-native.xiaomi.txt").write_text("# HaGeZi test\n" + "\n".join(NATIVE) + "\n")
    (folder / "hagezi-pro.txt").write_text("# HaGeZi test\n" + "\n".join(PRO) + "\n")
    (folder / "public_suffix_list.dat").write_text(PSL_TEXT)


def scan_bytes(data: bytes) -> pcapscan.Capture:
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "t.pcap"
        path.write_bytes(data)
        return pcapscan.scan(path)


def report_for(traffic, label, created=None):
    cap = scan_bytes(traffic.bytes())
    device = {"serial_hash": "abc123", "manufacturer": "OnePlus", "brand": "OnePlus", "model": "CPH2487",
              "android": "16", "build": "CPH2487_16.0.1"}
    report = xray.analyze(cap, test_db(), xray.parse_uid_list(UID_LIST), {"com.example.thirdparty"},
                          device, {"minutes": 10.0, "wakes": 10}, label)
    if created:
        report["created"] = created
    return report


# --------------------------------------------------------------------------- tests


class PcapScanTests(unittest.TestCase):
    def test_names_uids_and_reassembly(self):
        cap = scan_bytes(before_traffic().bytes())
        self.assertEqual(cap.warnings, [])
        self.assertGreater(cap.trailer_packets, 0)
        by_name = {f.name: f for f in cap.flows if f.name}
        self.assertEqual(by_name["lock.glanceapis.example"].via, "sni")
        self.assertEqual(by_name["lock.glanceapis.example"].uid, UID_GLANCE)
        self.assertEqual(by_name["cdn.partner.example"].via, "sni")          # 3 segments, out of order
        self.assertEqual(by_name["metrics.oemtelemetry.example"].via, "http")
        self.assertEqual(by_name["events.glanceapis.example"].via, "dns")     # QUIC, named by DNS
        self.assertEqual(by_name["ipv6.trackme.example"].server, "2001:db8::5")
        self.assertEqual(cap.cnames["cdn.partner.example"], {"ads.adnet.example"})
        self.assertIn("beacon.adnet.example", {q.name for q in cap.queries})
        quic = by_name["events.glanceapis.example"]
        self.assertEqual((quic.client, quic.server_port), (PHONE, 443))

    def test_raw_big_endian_capture_without_trailer(self):
        t = Traffic(raw=True)
        t.tls("203.0.113.10", "plain.example", UID_GLANCE)
        cap = scan_bytes(t.bytes(endian=">"))
        self.assertEqual(cap.linktype, pcapscan.LINKTYPE_RAW)
        self.assertEqual(cap.trailer_packets, 0)
        flow = next(f for f in cap.flows if f.name)
        self.assertEqual((flow.name, flow.uid), ("plain.example", pcapscan.UNKNOWN_UID))

    def test_cut_short_capture_is_a_warning(self):
        data = before_traffic().bytes()
        cap = scan_bytes(data[:-7])
        self.assertTrue(any("cut short" in w for w in cap.warnings))
        self.assertGreater(len(cap.flows), 5)

    def test_rejects_pcapng_and_garbage(self):
        with self.assertRaisesRegex(pcapscan.ScanError, "PCAPNG"):
            scan_bytes(b"\x0a\x0d\x0d\x0a" + b"\0" * 40)
        with self.assertRaisesRegex(pcapscan.ScanError, "not a PCAP"):
            scan_bytes(b"hello world, this is not a capture")

    def test_clean_host(self):
        self.assertEqual(pcapscan.clean_host("Ads.Example.COM."), "ads.example.com")
        for bad in ("localhost", "1.2.3.4", "::1", "-bad.example", "sp ace.example", ""):
            self.assertIsNone(pcapscan.clean_host(bad), bad)


class TrackerDbTests(unittest.TestCase):
    def test_exodus_signatures_match_whole_labels(self):
        exodus, bad = trackerdb.parse_exodus(json.dumps(EXODUS))
        self.assertEqual(bad, 1)
        self.assertEqual([n for n, _ in exodus], ["Adjustish", "AdNet Ads", "BigCo Ads"])
        go = dict(exodus)["Adjustish"]
        self.assertTrue(trackerdb.signature_hits(go, "go.link"))
        self.assertTrue(trackerdb.signature_hits(go, "x.go.link"))
        self.assertFalse(trackerdb.signature_hits(go, "ago.linkedin.com"))
        import re as _re
        fb = _re.compile("\\.facebook\\.com", _re.I)
        self.assertTrue(trackerdb.signature_hits(fb, "graph.facebook.com"))
        self.assertFalse(trackerdb.signature_hits(fb, "notfacebook.com"))
        wild = _re.compile("adservice\\.google\\..*", _re.I)
        self.assertTrue(trackerdb.signature_hits(wild, "adservice.google.co.in"))

    def test_exodus_names_but_hagezi_decides(self):
        db = test_db()
        self.assertEqual(db.classify("www.bigco.example"), [])                  # Exodus alone: not counted
        self.assertEqual(db.classify("x.go.link"), [{"source": "exodus", "name": "Adjustish"},
                                                     {"source": "hagezi-pro", "name": "HaGeZi Pro"}])
        self.assertFalse(trackerdb.TrackerDB(exodus=db.exodus).available)

    def test_domain_lists_cover_subdomains_only(self):
        domains = {"glanceapis.example"}
        self.assertEqual(trackerdb.in_domains("a.b.glanceapis.example", domains), "glanceapis.example")
        self.assertIsNone(trackerdb.in_domains("glanceapis.example.evil", domains))
        self.assertIsNone(trackerdb.in_domains("example", {"example"}))

    def test_public_suffix_list(self):
        psl = trackerdb.PublicSuffixList(PSL_TEXT)
        self.assertEqual(psl.registrable("a.b.shop.co.in"), "shop.co.in")
        self.assertEqual(psl.registrable("x.y.com"), "y.com")
        self.assertEqual(psl.registrable("www.foo.ck"), "www.foo.ck")       # *.ck
        self.assertEqual(psl.registrable("a.www.ck"), "www.ck")             # !www.ck
        self.assertEqual(psl.registrable("co.in"), "co.in")
        self.assertEqual(trackerdb.guess_registrable("ads.shop.co.in"), "shop.co.in")
        self.assertEqual(trackerdb.guess_registrable("a.b.c.com"), "c.com")

    def test_load_uses_cache_offline_and_tolerates_missing_lists(self):
        with tempfile.TemporaryDirectory() as tmp:
            old = os.environ.get("DOAIDE_DEBLOAT_CACHE")
            os.environ["DOAIDE_DEBLOAT_CACHE"] = tmp
            try:
                err = io.StringIO()
                with contextlib.redirect_stderr(err):
                    empty = trackerdb.load(offline=True)
                self.assertFalse(empty.available)
                write_cache(Path(tmp) / "xray")
                db = trackerdb.load(offline=True)
                self.assertTrue(db.available)
                self.assertEqual(set(db.sources), {"exodus", "native.xiaomi", "pro", "psl"})
                self.assertEqual(db.classify("cdn.ads.adnet.example")[0]["name"], "AdNet Ads")
                self.assertEqual(db.classify("x.oemtelemetry.example"), [{"source": "hagezi-native", "name": "Xiaomi"}])
                self.assertEqual(db.registrable("lock.glanceapis.example"), "glanceapis.example")
                self.assertNotIn("pro", trackerdb.load(offline=True, pro=False).sources)
            finally:
                if old is None:
                    os.environ.pop("DOAIDE_DEBLOAT_CACHE", None)
                else:
                    os.environ["DOAIDE_DEBLOAT_CACHE"] = old


class AnalysisTests(unittest.TestCase):
    def test_totals_attribution_and_exclusions(self):
        report = report_for(before_traffic(), "before")
        totals = report["totals"]
        hosts = {h["host"]: h for h in report["hosts"]}
        self.assertEqual(set(hosts), {"lock.glanceapis.example", "cdn.partner.example", "metrics.oemtelemetry.example",
                                      "telemetry.datingapp.example", "www.bank.example", "events.glanceapis.example",
                                      "ipv6.trackme.example"})
        self.assertEqual(totals["tracker_hosts"], 6)
        self.assertEqual(totals["tracker_domains"], 5)
        self.assertEqual(totals["local_flows"], 1)
        self.assertEqual(totals["pcapdroid_flows"], 1)
        self.assertEqual(totals["dns_flows"], 4)
        self.assertEqual(totals["tracker_lookups_without_connection"], 1)
        self.assertEqual(hosts["cdn.partner.example"]["trackers"],                                  # via its CNAME
                         [{"source": "exodus", "name": "AdNet Ads"}, {"source": "hagezi-pro", "name": "HaGeZi Pro"}])
        self.assertEqual(hosts["cdn.partner.example"]["cname"], ["ads.adnet.example"])
        self.assertEqual(hosts["www.bank.example"]["trackers"], [])
        apps = {a["label"]: a for a in report["apps"]}
        self.assertEqual(apps["com.glance.internet"]["tracker_hosts"],
                         ["cdn.partner.example", "events.glanceapis.example", "lock.glanceapis.example"])
        self.assertTrue(apps["com.glance.internet"]["system"])
        self.assertIn("android (+1 more sharing uid 1000)", apps)
        self.assertFalse(apps["com.example.thirdparty"]["system"])
        self.assertEqual(report["warnings"], [])

    def test_without_lists_the_counts_are_flagged(self):
        cap = scan_bytes(after_traffic().bytes())
        report = xray.analyze(cap, trackerdb.TrackerDB(), {}, set(), {}, {}, "x")
        self.assertFalse(report["lists_available"])
        self.assertTrue(any("no tracker list" in w for w in report["warnings"]))


class ShareAndCardTests(unittest.TestCase):
    def setUp(self):
        self.before = report_for(before_traffic(), "before", "2026-10-30T10:00:00+0530")
        self.after = report_for(after_traffic(), "after", "2026-10-30T11:00:00+0530")

    def test_share_summary_keeps_only_counts_and_preinstalled_names(self):
        share = xray.share_summary(self.before, self.after, disabled=7)
        self.assertEqual(share["before"]["tracker_hosts"], 6)
        self.assertEqual(share["after"]["tracker_hosts"], 1)
        self.assertEqual(share["packages_disabled"], 7)
        self.assertEqual([d["domain"] for d in share["before"]["top_tracker_domains"]],
                         ["glanceapis.example", "oemtelemetry.example", "partner.example", "trackme.example"])
        self.assertEqual(share["before"]["system_apps"],
                         [{"package": "com.glance.internet", "tracker_hosts": 3}, {"package": "android", "tracker_hosts": 2}])
        text = json.dumps(share)
        for secret in ("datingapp", "bank", "thirdparty", "abc123", "10.215.", "203.0.113", "198.51.100",
                       "2001:db8", "serial", "pcapdroid"):
            self.assertNotIn(secret, text)
        self.assertEqual(xray_index.validate(json.loads(text))["before"]["tracker_hosts"], 6)  # the index accepts it

    def test_issue_url_carries_the_report(self):
        share = xray.share_summary(self.before, self.after, disabled=7)
        url = xray.issue_url(share)
        self.assertTrue(url.startswith(xray.REPO_URL + "/issues/new?template=xray-report.yml&"))
        query = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
        self.assertEqual(json.loads(query["report"][0]), share)
        self.assertEqual(query["title"][0], "[x-ray] OnePlus CPH2487: 6 → 1 tracker servers")
        self.assertLessEqual(len(url), xray.URL_LIMIT)

    def test_card_is_valid_svg_with_the_numbers(self):
        share = xray.share_summary(self.before, self.after, disabled=7)
        share["device"]["model"] = "A&B <5G>"
        svg = xray.card_svg(share)
        root = ET.fromstring(svg)
        texts = [t.text for t in root.iter("{http://www.w3.org/2000/svg}text")]
        self.assertIn("6", texts)
        self.assertIn("1", texts)
        self.assertIn("7 preinstalled apps turned off by a coding agent", texts)
        self.assertIn("OnePlus A&B <5G> · Android 16", texts)
        single = ET.fromstring(xray.card_svg(xray.share_summary(self.before)))
        self.assertIn("What does yours send home?", [t.text for t in single.iter("{http://www.w3.org/2000/svg}text")])

    def test_comparable(self):
        self.assertEqual(xray.comparable(self.before, self.after), [])
        other = json.loads(json.dumps(self.after))
        other["device"]["serial_hash"] = "zzz"
        other["protocol"]["minutes"] = 5
        problems = xray.comparable(self.before, other)
        self.assertTrue(any("different phones" in p for p in problems))
        self.assertTrue(any("minutes" in p for p in problems))
        self.assertTrue(xray.comparable(self.after, self.before))     # reversed order


class FakePhone(FakeDevice):
    """FakeDevice plus PCAPdroid's intent API, stat, input, rm and adb pull."""

    def __init__(self, pcaps, version=81, installed=True):
        packages = BASE_PACKAGES + ([xray.PCAPDROID] if installed else [])
        super().__init__(packages=packages)
        self.pcaps = list(pcaps)
        self.version = version
        self.running = False
        self.files = {}
        self.started = []

    def __call__(self, args):
        args = list(args)
        if args[:2] == ["-s", self.serial]:
            args = args[2:]
        if args and args[0] == "pull":
            if args[1] not in self.files:
                return 1, f"adb: error: remote object '{args[1]}' does not exist\n"
            Path(args[2]).write_bytes(self.files[args[1]])
            return 0, "1 file pulled\n"
        return super().__call__(args)

    def shell(self, cmd):
        parts = shlex.split(cmd)
        if parts[:2] == ["am", "start"] and xray.CTRL in parts:
            self.log.append(cmd)
            extras = {parts[i + 1]: parts[i + 2] for i, p in enumerate(parts) if p == "-e"}
            if extras["action"] == "start":
                self.running = True
                self.started.append(extras)
                self.files[f"{xray.DEVICE_DIR}/{extras['pcap_name']}"] = self.pcaps.pop(0)
            elif extras["action"] == "stop":
                self.running = False
            return 0, "Starting: Intent { cmp=com.emanuelef.remote_capture/.activities.CaptureCtrl (has extras) }\n"
        if parts[:2] == ["am", "start"]:
            self.log.append(cmd)
            return 0, "Starting: Intent { act=android.intent.action.VIEW }\n"
        if parts[:3] == ["dumpsys", "activity", "services"]:
            return 0, ("  * ServiceRecord{1 u0 com.emanuelef.remote_capture/.CaptureService}\n" if self.running
                       else "  (nothing)\n")
        if parts[:2] == ["dumpsys", "package"]:
            return 0, f"  Package [{xray.PCAPDROID}]\n    versionCode={self.version} minSdk=21\n    versionName=1.8.4\n"
        if parts[:2] == ["stat", "-c"]:
            path = parts[3]
            if path in self.files:
                return 0, f"{len(self.files[path])}\n"
            return 1, f"stat: '{path}': No such file or directory\n"
        if parts[:2] == ["input", "keyevent"]:
            self.log.append(cmd)
            return 0, ""
        if parts[:2] == ["rm", "-f"]:
            self.files.pop(parts[2], None)
            return 0, ""
        if parts[:4] == ["pm", "list", "packages", "-U"]:
            return 0, UID_LIST
        return super().shell(cmd)


class CaptureCliTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        write_cache(self.dir / "cache" / "xray")
        self.saved = (debloat.BACKUP_DIR, debloat.Adb, xray.SLEEP, os.environ.get("DOAIDE_DEBLOAT_CACHE"),
                      os.environ.get(xray.API_KEY_ENV))
        debloat.BACKUP_DIR = self.dir / "backups"
        os.environ["DOAIDE_DEBLOAT_CACHE"] = str(self.dir / "cache")
        os.environ.pop(xray.API_KEY_ENV, None)
        self.sleeps = []
        xray.SLEEP = self.sleeps.append

    def tearDown(self):
        debloat.BACKUP_DIR, debloat.Adb, xray.SLEEP, cache, key = self.saved
        for name, value in (("DOAIDE_DEBLOAT_CACHE", cache), (xray.API_KEY_ENV, key)):
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value
        self.tmp.cleanup()

    def run_cli(self, fake, argv, main=xray.main):
        real = self.saved[1]
        debloat.Adb = lambda serial=None, adb_path=None, runner=None: real(serial=serial, runner=fake)
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = main(argv)
        return rc, out.getvalue() + err.getvalue()

    def test_before_debloat_after_card(self):
        os.environ[xray.API_KEY_ENV] = "s3cret-key"
        fake = FakePhone([before_traffic().bytes(), after_traffic().bytes()])
        rc, text = self.run_cli(fake, ["capture", "--label", "before", "--yes", "--offline"])
        self.assertEqual(rc, 0, text)
        self.assertNotIn("s3cret-key", text)
        started = fake.started[0]
        for key, value in (("pcap_dump_mode", "pcap_file"), ("dump_extensions", "true"), ("ip_mode", "both"),
                           ("block_quic", "always"), ("auto_block_private_dns", "true"), ("api_key", "s3cret-key")):
            self.assertEqual(started[key], value)
        wakes = [c for c in fake.log if c == "input keyevent KEYCODE_WAKEUP"]
        self.assertEqual(len(wakes), 10)
        self.assertGreaterEqual(sum(self.sleeps), 600)
        self.assertEqual(fake.files, {})                                   # deleted from the phone
        self.assertEqual(list((self.dir / "backups").glob("*.pcap")), [])  # and from the computer
        self.assertIn("6 are on ad/tracking lists", text)
        self.assertIn("com.glance.internet", text)
        before = next((self.dir / "backups").glob("xray-sm-a546e-before-*.json"))

        rc, text = self.run_cli(fake, ["capture", "--label", "after", "--yes", "--offline", "--keep-pcap"])
        self.assertEqual(rc, 0, text)
        self.assertEqual(len(list((self.dir / "backups").glob("*.pcap"))), 1)
        after = next((self.dir / "backups").glob("xray-sm-a546e-after-*.json"))

        record = self.dir / "record.json"
        record.write_text(json.dumps({"actions": [
            {"package": "com.glance.internet", "method": "disable", "ok": True, "output": ""},
            {"package": "com.x", "method": "disable", "ok": False, "output": "refused"},
            {"package": "com.y", "method": "skip", "ok": True, "output": "already disabled"}]}))
        out = self.dir / "card"
        rc, text = self.run_cli(fake, ["card", str(before), str(after), "--record", str(record), "--out", str(out)])
        self.assertEqual(rc, 0, text)
        share = json.loads((out / "share.json").read_text())
        self.assertEqual((share["before"]["tracker_hosts"], share["after"]["tracker_hosts"]), (6, 1))
        self.assertEqual(share["packages_disabled"], 1)
        self.assertTrue((out / "card.svg").exists() and (out / "card.html").exists())
        self.assertIn("/issues/new?template=xray-report.yml", text)

    def test_taps_are_asked_for_without_an_api_key(self):
        fake = FakePhone([after_traffic().bytes()])
        rc, text = self.run_cli(fake, ["capture", "--label", "before", "--yes", "--offline",
                                       "--minutes", "2", "--wakes", "3"])
        self.assertEqual(rc, 0, text)
        self.assertIn("tap Allow", text)
        self.assertNotIn("api_key", fake.started[0])
        self.assertEqual(len([c for c in fake.log if c == "input keyevent KEYCODE_WAKEUP"]), 4)   # 3 + one to stop

    def test_capture_needs_consent(self):
        fake = FakePhone([after_traffic().bytes()])
        rc, text = self.run_cli(fake, ["capture", "--label", "before", "--offline"])
        self.assertEqual(rc, 2, text)
        self.assertEqual(fake.started, [])

    def test_missing_or_old_pcapdroid(self):
        rc, text = self.run_cli(FakePhone([], installed=False), ["capture", "--label", "x", "--yes", "--offline"])
        self.assertEqual(rc, 1)
        self.assertIn("setup --open-store", text)
        rc, text = self.run_cli(FakePhone([], version=60), ["capture", "--label", "x", "--yes", "--offline"])
        self.assertEqual(rc, 1)
        self.assertIn("too old", text)
        fake = FakePhone([], installed=False)
        rc, text = self.run_cli(fake, ["setup", "--open-store"])
        self.assertEqual(rc, 2)
        self.assertTrue(any(xray.PLAY_URL in c for c in fake.log))

    def test_analyze_a_manual_capture_and_show_it(self):
        pcap = self.dir / "manual.pcap"
        pcap.write_bytes(before_traffic().bytes())
        out = self.dir / "manual.json"
        rc, text = self.run_cli(FakePhone([]), ["analyze", str(pcap), "--offline", "--out", str(out)])
        self.assertEqual(rc, 0, text)
        report = json.loads(out.read_text())
        self.assertEqual(report["totals"]["tracker_hosts"], 6)
        self.assertTrue(all(a["system"] is not True or a["uid"] < 10000 for a in report["apps"]))   # no names without --device
        self.assertEqual(xray.share_summary(report)["before"]["top_tracker_domains"],
                         [{"domain": "oemtelemetry.example", "hosts": 1}, {"domain": "trackme.example", "hosts": 1}])
        rc, text = self.run_cli(FakePhone([]), ["show", str(out)])
        self.assertEqual(rc, 0, text)
        self.assertIn("Tracker domains", text)

    def test_card_refuses_mismatched_reports(self):
        before = report_for(before_traffic(), "before", "2026-10-30T10:00:00+0530")
        after = report_for(after_traffic(), "after", "2026-10-30T11:00:00+0530")
        after["protocol"]["minutes"] = 3
        paths = []
        for name, report in (("b.json", before), ("a.json", after)):
            paths.append(self.dir / name)
            paths[-1].write_text(json.dumps(report))
        rc, text = self.run_cli(FakePhone([]), ["card", str(paths[0]), str(paths[1]), "--out", str(self.dir / "c")])
        self.assertEqual(rc, 1)
        self.assertIn("should not be compared", text)


def issue_body(share, market="India"):
    return ("### Brand and model\n\nOnePlus CPH2487\n\n### Where was the phone sold?\n\n" + market +
            "\n\n### X-ray report (share.json)\n\n```json\n" + json.dumps(share) + "\n```\n\n"
            "### Anything else\n\n_No response_\n\n### Privacy check\n\n- [X] I looked at the report\n")


class IndexTests(unittest.TestCase):
    def setUp(self):
        before = report_for(before_traffic(), "before", "2026-10-30T10:00:00+0530")
        after = report_for(after_traffic(), "after", "2026-10-30T11:00:00+0530")
        self.share = xray.share_summary(before, after, disabled=7)

    def issue(self, number, share=None, labels=("xray-report",), market="India"):
        return {"number": number, "url": f"https://github.com/DoAideAi/DoAide-Debloat/issues/{number}",
                "labels": [{"name": l} for l in labels], "body": issue_body(share or self.share, market)}

    def test_build_aggregates_and_leaves_out_bad_reports(self):
        second = json.loads(json.dumps(self.share))
        second["before"]["tracker_hosts"] = 4
        second["before"]["tracker_domains"] = 3
        nonstandard = json.loads(json.dumps(self.share))
        nonstandard["protocol"]["minutes"] = 5
        lying = json.loads(json.dumps(self.share))
        lying["before"]["tracker_hosts"] = 999
        issues = [self.issue(1), self.issue(2, second, market="_No response_"), self.issue(3, labels=("xray-report", "spam")),
                  self.issue(4, nonstandard), self.issue(5, lying),
                  {"number": 6, "labels": [], "body": "no report here"}]
        index = xray_index.build(issues)
        self.assertEqual(index["reports"], 2)
        reasons = {s["number"]: s["reason"] for s in index["skipped"]}
        self.assertEqual(set(reasons), {3, 4, 5, 6})
        self.assertIn("spam", reasons[3])
        self.assertIn("standard", reasons[4])
        self.assertIn("do not add up", reasons[5])
        row = index["rows"][0]
        self.assertEqual((row["maker"], row["model"], row["reports"]), ("OnePlus", "CPH2487", 2))
        self.assertEqual(row["before_tracker_hosts"], 5.0)
        self.assertEqual(row["after_tracker_hosts"], 1.0)
        self.assertEqual(row["markets"], ["India"])
        self.assertEqual(row["top_domains"][0], "glanceapis.example")
        self.assertEqual([i["number"] for i in row["issues"]], [1, 2])
        self.assertEqual(len(xray_index.build([self.issue(4, nonstandard)], any_protocol=True)["rows"]), 1)

    def test_render_escapes_and_handles_no_reports(self):
        evil = json.loads(json.dumps(self.share))
        evil["device"]["model"] = "<script>alert(1)</script>"
        page = xray_index.render(xray_index.build([self.issue(9, evil)]))
        self.assertNotIn("<script>alert", page)
        self.assertIn("&lt;script&gt;", page)
        self.assertIn('href="https://github.com/DoAideAi/DoAide-Debloat/issues/9"', page)
        empty = xray_index.render(xray_index.build([]))
        self.assertIn("No reports yet", empty)

    def test_cli_writes_the_site_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            issues = Path(tmp) / "issues.json"
            issues.write_text(json.dumps([self.issue(1)]))
            with contextlib.redirect_stdout(io.StringIO()):
                rc = xray_index.main(["--issues", str(issues), "--out", tmp])
            self.assertEqual(rc, 0)
            data = json.loads((Path(tmp) / "phone-home.json").read_text())
            self.assertEqual(data["rows"][0]["model"], "CPH2487")
            self.assertIn("CPH2487", (Path(tmp) / "phone-home.html").read_text())


if __name__ == "__main__":
    unittest.main()
