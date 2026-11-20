#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""اختبار عميل SNMP مقابل وكيل وهمي على localhost."""
import os
import socket
import sys
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import snmp  # noqa: E402

TREE = {
    "1.3.6.1.2.1.1.1.0": "RouterOS 7.16 (test)",
    "1.3.6.1.2.1.1.3.0": 123456,
    "1.3.6.1.2.1.2.2.1.2.1": "ether1",
    "1.3.6.1.2.1.2.2.1.2.2": "sfp1",
    "1.3.6.1.2.1.2.2.1.8.1": 1,
    "1.3.6.1.2.1.2.2.1.8.2": 2,
    "1.3.6.1.2.1.2.2.1.10.1": 123456789,
    "1.3.6.1.2.1.31.1.1.1.15.1": 1000,
}


def _enc_value(value):
    if isinstance(value, str):
        return snmp._tlv(snmp.TAG_OCTETS, value.encode())
    if isinstance(value, int):
        return snmp._enc_int(value)
    raise TypeError(value)


def _oid_sort_key(oid):
    return [int(x) for x in oid.split(".")]


def serve(sock, stop):
    while not stop.is_set():
        try:
            data, addr = sock.recvfrom(65535)
        except OSError:
            return
        _tag, msg, _ = snmp._parse_tlv(data, 0)
        pos = 0
        _t, ver, pos = snmp._parse_tlv(msg, pos)
        _t, community, pos = snmp._parse_tlv(msg, pos)
        ptag, pdu, _ = snmp._parse_tlv(msg, pos)
        p = 0
        _t, rid, p = snmp._parse_tlv(pdu, p)
        _t, _second, p = snmp._parse_tlv(pdu, p)
        _t, third, p = snmp._parse_tlv(pdu, p)
        maxrep = snmp._decode_int(third) if ptag == snmp.PDU_GETBULK else 1
        _t, vbl, _ = snmp._parse_tlv(pdu, p)
        vpos = 0
        req_oids = []
        while vpos < len(vbl):
            _t, vb, vpos = snmp._parse_tlv(vbl, vpos)
            _t, oid_raw, _ = snmp._parse_tlv(vb, 0)
            req_oids.append(snmp._decode_oid(oid_raw))
        ordered = sorted(TREE, key=_oid_sort_key)
        out = []
        for oid in req_oids:
            if ptag == snmp.PDU_GET:
                out.append((oid, TREE.get(oid)))
            else:
                after = [x for x in ordered if _oid_sort_key(x) > _oid_sort_key(oid)]
                if ptag == snmp.PDU_GETNEXT:
                    out.append((after[0], TREE[after[0]]) if after else (oid, None))
                else:
                    for item in after[:maxrep]:
                        out.append((item, TREE[item]))
                    if not after:
                        out.append((oid, None))
        varbinds = b""
        for oid, value in out:
            varbinds += snmp._tlv(0x30, snmp._enc_oid(oid) + _enc_value(value))
        resp_pdu = snmp._tlv(snmp.PDU_RESPONSE,
                             snmp._enc_int(snmp._decode_int(rid)) +
                             snmp._enc_int(0) + snmp._enc_int(0) +
                             snmp._tlv(0x30, varbinds))
        resp = snmp._tlv(0x30, snmp._enc_int(1) + snmp._enc_octets(community) + resp_pdu)
        sock.sendto(resp, addr)


def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    stop = threading.Event()
    th = threading.Thread(target=serve, args=(sock, stop), daemon=True)
    th.start()
    try:
        client = snmp.SNMPClient("127.0.0.1", "public", port, timeout=2, retries=1)
        descr = client.get(["1.3.6.1.2.1.1.1.0"])
        assert descr["1.3.6.1.2.1.1.1.0"] == "RouterOS 7.16 (test)", descr
        walked = client.walk("1.3.6.1.2.1.2.2.1.2")
        assert walked == {
            "1.3.6.1.2.1.2.2.1.2.1": "ether1",
            "1.3.6.1.2.1.2.2.1.2.2": "sfp1",
        }, walked
        table = client.table("1.3.6.1.2.1.2.2.1", {2: "name", 8: "oper"})
        assert table["1"]["name"] == "ether1" and table["1"]["oper"] == 1, table
        assert table["2"]["name"] == "sfp1" and table["2"]["oper"] == 2, table
        bulk = client.get_bulk(["1.3.6.1.2.1.2.2.1.2"], max_reps=10)
        assert len(bulk) >= 2 and bulk[0][1] == "ether1", bulk
        client.close()
        print("OK: SNMP GET / WALK / GETBULK / TABLE")
    finally:
        stop.set()
        sock.close()


if __name__ == "__main__":
    main()
