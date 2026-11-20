#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""اختبار دمج SNMP: استعلام جهاز وهمي وحساب المعدلات والتنبيهات."""
import os
import socket
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import nabd  # noqa: E402
import snmp  # noqa: E402

BASE = {
    "1.3.6.1.2.1.1.1.0": "RouterOS 7.16 (MockSwitch)",
    "1.3.6.1.2.1.1.2.0": "1.3.6.1.4.1.14988.1",
    "1.3.6.1.2.1.1.3.0": 8640000,   # 24h in ticks
    "1.3.6.1.2.1.1.5.0": "MockSW",
    "1.3.6.1.2.1.2.2.1.2.1": "ether1",
    "1.3.6.1.2.1.2.2.1.2.2": "sfp1",
    "1.3.6.1.2.1.2.2.1.3.1": 6,
    "1.3.6.1.2.1.2.2.1.3.2": 6,
    "1.3.6.1.2.1.2.2.1.7.1": 1,
    "1.3.6.1.2.1.2.2.1.7.2": 1,
    "1.3.6.1.2.1.2.2.1.8.1": 1,
    "1.3.6.1.2.1.2.2.1.8.2": 1,
    "1.3.6.1.2.1.2.2.1.10.1": 1000,
    "1.3.6.1.2.1.2.2.1.10.2": 2000,
    "1.3.6.1.2.1.2.2.1.14.1": 0,
    "1.3.6.1.2.1.2.2.1.20.1": 0,
    "1.3.6.1.2.1.31.1.1.1.1.1": "ether1",
    "1.3.6.1.2.1.31.1.1.1.1.2": "sfp1",
    "1.3.6.1.2.1.31.1.1.1.6.1": 1000000,
    "1.3.6.1.2.1.31.1.1.1.6.2": 2000000,
    "1.3.6.1.2.1.31.1.1.1.10.1": 500000,
    "1.3.6.1.2.1.31.1.1.1.10.2": 600000,
    "1.3.6.1.2.1.31.1.1.1.15.1": 1000,
    "1.3.6.1.2.1.31.1.1.1.15.2": 10000,
    "1.3.6.1.2.1.31.1.1.1.18.1": "Uplink",
    "1.3.6.1.2.1.25.3.3.1.2.1": 20,
    "1.3.6.1.2.1.25.3.3.1.2.2": 30,
    "1.3.6.1.2.1.25.2.3.1.3.1": "Physical memory",
    "1.3.6.1.2.1.25.2.3.1.4.1": 1024,
    "1.3.6.1.2.1.25.2.3.1.5.1": 1000000,
    "1.3.6.1.2.1.25.2.3.1.6.1": 400000,
    "1.3.6.1.4.1.14988.1.1.3.10.0": 41,
    "1.3.6.1.4.1.14988.1.1.19.1.1.1.1": 1,
    "1.3.6.1.4.1.14988.1.1.19.1.1.2.1": "sfp1",
    "1.3.6.1.4.1.14988.1.1.19.1.1.3.1": 2,
    "1.3.6.1.4.1.14988.1.1.19.1.1.4.1": 2,
    "1.3.6.1.4.1.14988.1.1.19.1.1.5.1": 131000,
    "1.3.6.1.4.1.14988.1.1.19.1.1.6.1": 44,
    "1.3.6.1.4.1.14988.1.1.19.1.1.7.1": 3300,
    "1.3.6.1.4.1.14988.1.1.19.1.1.8.1": 5000,
    "1.3.6.1.4.1.14988.1.1.19.1.1.9.1": 3000,
    "1.3.6.1.4.1.14988.1.1.19.1.1.10.1": -18000,
    "1.3.6.1.4.1.14988.1.1.19.1.1.11.1": "MockOptics",
    "1.3.6.1.4.1.14988.1.1.19.1.1.12.1": "SN123",
    "1.3.6.1.4.1.14988.1.1.1.2.1.1.1": "AA:BB:CC:DD:EE:01",
    "1.3.6.1.4.1.14988.1.1.1.2.1.2.1": "wlan1",
    "1.3.6.1.4.1.14988.1.1.1.2.1.3.1": -61,
    "1.3.6.1.4.1.14988.1.1.1.2.1.4.1": 500000,
    "1.3.6.1.4.1.14988.1.1.1.2.1.5.1": 700000,
    "1.3.6.1.4.1.14988.1.1.1.2.1.8.1": 300,
    "1.3.6.1.4.1.14988.1.1.1.2.1.9.1": 270,
}


def _enc(value):
    if value is None:
        return snmp._tlv(snmp.TAG_NULL)
    if isinstance(value, str):
        return snmp._tlv(snmp.TAG_OCTETS, value.encode())
    return snmp._enc_int(value)


def _key(oid):
    return [int(x) for x in oid.split(".")]


class Agent(threading.Thread):
    def __init__(self, tree):
        super().__init__(daemon=True)
        self.tree = tree
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.stop_flag = threading.Event()

    def run(self):
        while not self.stop_flag.is_set():
            try:
                data, addr = self.sock.recvfrom(65535)
            except OSError:
                return
            self.sock.sendto(self.reply(data), addr)

    def reply(self, data):
        _t, msg, _ = snmp._parse_tlv(data, 0)
        pos = 0
        _t, _ver, pos = snmp._parse_tlv(msg, pos)
        _t, community, pos = snmp._parse_tlv(msg, pos)
        ptag, pdu, _ = snmp._parse_tlv(msg, pos)
        p = 0
        _t, rid, p = snmp._parse_tlv(pdu, p)
        _t, _second, p = snmp._parse_tlv(pdu, p)
        _t, third, p = snmp._parse_tlv(pdu, p)
        maxrep = snmp._decode_int(third) if ptag == snmp.PDU_GETBULK else 1
        _t, vbl, _ = snmp._parse_tlv(pdu, p)
        vpos, req = 0, []
        while vpos < len(vbl):
            _t, vb, vpos = snmp._parse_tlv(vbl, vpos)
            _t, oid_raw, _ = snmp._parse_tlv(vb, 0)
            req.append(snmp._decode_oid(oid_raw))
        ordered = sorted(self.tree, key=_key)
        out = []
        for oid in req:
            if ptag == snmp.PDU_GET:
                out.append((oid, self.tree.get(oid)))
                continue
            after = [x for x in ordered if _key(x) > _key(oid)]
            take = after[:maxrep] if ptag == snmp.PDU_GETBULK else after[:1]
            if take:
                out.extend((x, self.tree[x]) for x in take)
            else:
                out.append((oid, None))
        varbinds = b"".join(snmp._tlv(0x30, snmp._enc_oid(o) + _enc(v))
                            for o, v in out)
        resp = snmp._tlv(0x30,
                         snmp._enc_int(1) + snmp._enc_octets(community) +
                         snmp._tlv(snmp.PDU_RESPONSE,
                                   snmp._enc_int(snmp._decode_int(rid)) +
                                   snmp._enc_int(0) + snmp._enc_int(0) +
                                   snmp._tlv(0x30, varbinds)))
        return resp

    def close(self):
        self.stop_flag.set()
        self.sock.close()


def main():
    tree = dict(BASE)
    agent = Agent(tree)
    agent.start()
    try:
        with nabd.LOCK:
            nabd.DEVS["MockSW"] = nabd.make_dev({
                "name": "MockSW", "ip": "127.0.0.1", "kind": "switch",
                "group": "test", "snmp": "on", "profile": "auto",
            })
            nabd.DEVS["MockSW"]["ip"] = "127.0.0.1"
        nabd.SNMP.update({"community": "public", "port": agent.port,
                          "timeout": 1, "retries": 0, "history_points": 20,
                          "cpu_warn": 85, "sfp_rx_min": -20})
        first = nabd.poll_device("MockSW")
        assert first["ok"], first
        assert first["vendor"] == "mikrotik", first["vendor"]
        assert first["cpu"] == 25.0, first["cpu"]
        assert first["mem"]["pct"] == 40.0, first["mem"]
        assert len(first["interfaces"]) == 2, first["interfaces"]
        assert len(first["sfp"]) == 1 and first["sfp"][0]["rx"] == -18.0, first["sfp"]
        assert first["sfp"][0]["tx"] == 3.0 and first["sfp"][0]["wavelength"] == 1310
        assert len(first["wifi"]) == 1 and first["wifi"][0]["signal"] == -61
        assert first["total"]["in_bps"] == 0

        time.sleep(1.2)
        for oid in ("1.3.6.1.2.1.31.1.1.1.6.1", "1.3.6.1.2.1.31.1.1.1.10.1",
                    "1.3.6.1.2.1.31.1.1.1.6.2", "1.3.6.1.2.1.31.1.1.1.10.2"):
            tree[oid] += 100000
        second = nabd.poll_device("MockSW")
        assert second["ok"], second
        assert second["total"]["in_bps"] > 0 and second["total"]["out_bps"] > 0, second["total"]
        hist = nabd.snmp_history("MockSW")
        assert len(hist) >= 2, hist

        # سقوط منفذ: من up إلى down
        time.sleep(0.1)
        tree["1.3.6.1.2.1.2.2.1.8.1"] = 2
        nabd.poll_device("MockSW")
        assert ("port_down", "MockSW", "ether1") in nabd.SNMP_ALERTS, nabd.SNMP_ALERTS

        # حمل معالج مرتفع مرتين متتاليتين
        for oid in ("1.3.6.1.2.1.25.3.3.1.2.1", "1.3.6.1.2.1.25.3.3.1.2.2"):
            tree[oid] = 95
        nabd.poll_device("MockSW")
        nabd.poll_device("MockSW")
        assert ("high_cpu", "MockSW", "") in nabd.SNMP_ALERTS, nabd.SNMP_ALERTS

        summary = nabd.snmp_summary("MockSW")
        assert summary["cpu"] == 95.0 and summary["ports"] == 2, summary
        print("OK: poll / rates / SFP / WiFi / memory / alerts")
    finally:
        agent.close()


if __name__ == "__main__":
    main()
