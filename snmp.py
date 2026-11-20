#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""عميل SNMP v2c خفيف (بدون مكتبات خارجية).

يدعم GET وGETNEXT وGETBULK وWALK، مع ترميز/فك ترميز BER داخلي.
الاستخدام:
    c = SNMPClient("172.16.0.2", "public", timeout=2)
    c.get(["1.3.6.1.2.1.1.1.0"])
    c.walk("1.3.6.1.2.1.2.2.1.2")
"""
import socket
import threading

__all__ = ["SNMPClient", "SNMPError", "SNMPTimeout", "oid_under", "to_int"]

# أنواع قيم BER في SNMP
TAG_INTEGER = 0x02
TAG_OCTETS = 0x04
TAG_NULL = 0x05
TAG_OID = 0x06
TAG_IPADDR = 0x40
TAG_COUNTER32 = 0x41
TAG_GAUGE32 = 0x42
TAG_TIMETICKS = 0x43
TAG_OPAQUE = 0x44
TAG_COUNTER64 = 0x46
TAG_UINTEGER32 = 0x47
TAG_NO_SUCH_OBJECT = 0x80
TAG_NO_SUCH_INSTANCE = 0x81
TAG_END_OF_MIB = 0x82

PDU_GET = 0xA0
PDU_GETNEXT = 0xA1
PDU_RESPONSE = 0xA2
PDU_GETBULK = 0xA5

ERRORS = {
    0: "noError", 1: "tooBig", 2: "noSuchName", 3: "badValue",
    4: "readOnly", 5: "genErr", 6: "noAccess", 7: "wrongType",
    8: "wrongLength", 9: "wrongEncoding", 10: "wrongValue",
    11: "noCreation", 12: "inconsistentValue", 13: "resourceUnavailable",
    14: "commitFailed", 15: "undoFailed", 16: "authorizationError",
    17: "notWritable", 18: "inconsistentName",
}


class SNMPError(Exception):
    pass


class SNMPTimeout(SNMPError):
    pass


class SNMPAuthError(SNMPError):
    pass


def _enc_len(n):
    if n < 0x80:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def _tlv(tag, payload=b""):
    return bytes([tag]) + _enc_len(len(payload)) + payload


def _enc_int(value, tag=TAG_INTEGER):
    value = int(value)
    if value == 0:
        body = b"\x00"
    else:
        if value > 0:
            body = value.to_bytes((value.bit_length() + 7) // 8, "big")
            if body[0] & 0x80:
                body = b"\x00" + body
        else:
            n = value
            size = 1
            while n < -(1 << (8 * size - 1)):
                size += 1
            body = n.to_bytes(size, "big", signed=True)
            # إزالة البايتات الزائدة (0xff)
            while len(body) > 1 and body[0] == 0xFF and body[1] & 0x80:
                body = body[1:]
    return _tlv(tag, body)


def _enc_octets(value):
    if isinstance(value, str):
        value = value.encode("utf-8")
    return _tlv(TAG_OCTETS, bytes(value))


def _enc_oid(oid):
    arcs = [int(x) for x in str(oid).strip().strip(".").split(".") if x != ""]
    if len(arcs) < 2:
        raise SNMPError("OID غير صالح: " + str(oid))
    first = 40 * arcs[0] + arcs[1]
    body = bytearray()
    for value in [first] + arcs[2:]:
        if value < 0:
            raise SNMPError("OID غير صالح: " + str(oid))
        chunk = [value & 0x7F]
        value >>= 7
        while value:
            chunk.append(0x80 | (value & 0x7F))
            value >>= 7
        body.extend(reversed(chunk))
    return _tlv(TAG_OID, bytes(body))


def _parse_len(data, pos):
    if pos >= len(data):
        raise SNMPError("بيانات BER مبتورة")
    first = data[pos]
    pos += 1
    if first < 0x80:
        return first, pos
    count = first & 0x7F
    if count == 0 or count > 4 or pos + count > len(data):
        raise SNMPError("طول BER غير صالح")
    length = int.from_bytes(data[pos:pos + count], "big")
    return length, pos + count


def _parse_tlv(data, pos):
    """يعيد (tag, value, next_pos)."""
    if pos >= len(data):
        raise SNMPError("TLV مبتور")
    tag = data[pos]
    length, pos = _parse_len(data, pos + 1)
    end = pos + length
    if end > len(data):
        raise SNMPError("TLV أطول من الرسالة")
    return tag, data[pos:end], end


def _decode_int(value, signed=True):
    if not value:
        return 0
    return int.from_bytes(value, "big", signed=signed)


def _decode_oid(value):
    if not value:
        return ""
    first = value[0]
    if first < 40:
        arcs = [0, first]
    elif first < 80:
        arcs = [1, first - 40]
    else:
        arcs = [2, first - 80]
    current = 0
    for byte in value[1:]:
        current = (current << 7) | (byte & 0x7F)
        if not byte & 0x80:
            arcs.append(current)
            current = 0
    return ".".join(str(x) for x in arcs)


def _looks_text(raw):
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if not text:
        return ""
    printable = sum(1 for ch in text if ch.isprintable() or ch in "\r\n\t")
    if printable / len(text) >= 0.9:
        return text.strip("\x00")
    return None


def _decode_octets(raw):
    text = _looks_text(raw)
    if text is not None:
        return text
    if len(raw) in (4, 6, 8, 16):
        return ":".join(f"{b:02x}" for b in raw)
    return "0x" + raw.hex()


def _decode_value(tag, raw):
    if tag in (TAG_NO_SUCH_OBJECT, TAG_NO_SUCH_INSTANCE, TAG_END_OF_MIB, TAG_NULL):
        return None
    if tag == TAG_INTEGER:
        return _decode_int(raw, signed=True)
    if tag in (TAG_COUNTER32, TAG_GAUGE32, TAG_TIMETICKS, TAG_UINTEGER32,
               TAG_COUNTER64):
        return _decode_int(raw, signed=False)
    if tag == TAG_OCTETS:
        return _decode_octets(raw)
    if tag == TAG_OID:
        return _decode_oid(raw)
    if tag == TAG_IPADDR:
        return ".".join(str(b) for b in raw)
    if tag == TAG_OPAQUE:
        return "0x" + raw.hex()
    return "0x" + raw.hex()


def oid_under(oid, root):
    oid, root = oid.strip("."), root.strip(".")
    return oid == root or oid.startswith(root + ".")


def to_int(value, default=0):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


class SNMPClient:
    def __init__(self, host, community="public", port=161, timeout=2.0,
                 retries=1, version=1):
        self.host = str(host)
        self.community = str(community or "public")
        self.port = int(port or 161)
        self.timeout = max(0.2, float(timeout or 2.0))
        self.retries = max(0, min(5, int(retries if retries is not None else 1)))
        self.version = int(version or 1)  # 1 = SNMPv2c
        self._req_id = 0
        self._lock = threading.Lock()
        self._sock = None

    # ------------------------------------------------------------- الإرسال
    def _inc_id(self):
        with self._lock:
            self._req_id = (self._req_id + 1) & 0x7FFFFFFF
            if self._req_id == 0:
                self._req_id = 1
            return self._req_id

    def _packet(self, pdu_tag, oids, non_repeaters=0, max_reps=0):
        req_id = self._inc_id()
        varbinds = b"".join(_tlv(0x30, _enc_oid(oid) + _tlv(TAG_NULL))
                            for oid in oids)
        if pdu_tag == PDU_GETBULK:
            fields = (_enc_int(req_id) + _enc_int(non_repeaters) +
                      _enc_int(max_reps) + _tlv(0x30, varbinds))
        else:
            fields = (_enc_int(req_id) + _enc_int(0) + _enc_int(0) +
                      _tlv(0x30, varbinds))
        pdu = _tlv(pdu_tag, fields)
        msg = _tlv(0x30, _enc_int(self.version) + _enc_octets(self.community) + pdu)
        return req_id, msg

    def _socket(self):
        if self._sock is None:
            family = socket.AF_INET6 if ":" in self.host else socket.AF_INET
            sock = socket.socket(family, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            self._sock = sock
        return self._sock

    def close(self):
        if self._sock is not None:
            try:
                self._sock.close()
            finally:
                self._sock = None

    def _recv_response(self, req_id):
        sock = self._socket()
        while True:
            data, _addr = sock.recvfrom(65535)
            tag, msg, _ = _parse_tlv(data, 0)
            if tag != 0x30:
                continue
            pos = 0
            _t, _v, pos = _parse_tlv(msg, pos)        # version
            _t, _v, pos = _parse_tlv(msg, pos)        # community
            ptag, pdu, _ = _parse_tlv(msg, pos)
            if ptag != PDU_RESPONSE:
                continue
            p = 0
            _t, rid_raw, p = _parse_tlv(pdu, p)
            if _decode_int(rid_raw) != req_id:
                continue
            _t, err_raw, p = _parse_tlv(pdu, p)
            _t, _idx_raw, p = _parse_tlv(pdu, p)
            _t, vbl, _p = _parse_tlv(pdu, p)
            err = _decode_int(err_raw)
            vbs = []
            vpos = 0
            while vpos < len(vbl):
                _t, vb, vpos = _parse_tlv(vbl, vpos)
                vp = 0
                _t, oid_raw, vp = _parse_tlv(vb, vp)
                vtag, val_raw, vp = _parse_tlv(vb, vp)
                vbs.append((_decode_oid(oid_raw), _decode_value(vtag, val_raw)))
            return err, vbs

    def request(self, pdu_tag, oids, max_reps=0):
        if not oids:
            return []
        req_id, packet = self._packet(pdu_tag, oids, max_reps=max_reps)
        last_error = None
        for _attempt in range(self.retries + 1):
            try:
                self._socket().sendto(packet, (self.host, self.port))
                err, vbs = self._recv_response(req_id)
            except socket.timeout:
                last_error = SNMPTimeout(
                    f"لا استجابة SNMP من {self.host}:{self.port}")
                continue
            except OSError as e:
                last_error = SNMPError(f"تعذر الاتصال بـ {self.host}: {e}")
                self.close()
                continue
            if err == 0:
                return vbs
            if err in (2, 16):  # noSuchName / authorizationError
                raise SNMPAuthError(ERRORS.get(err, str(err)))
            if err == 1 and pdu_tag == PDU_GETBULK:
                raise SNMPError("tooBig")
            raise SNMPError(f"SNMP {ERRORS.get(err, err)}")
        raise last_error or SNMPTimeout("انتهت مهلة SNMP")

    # ------------------------------------------------------------- العمليات
    def get(self, oids):
        vbs = self.request(PDU_GET, list(oids))
        return {oid: value for oid, value in vbs}

    def get_one(self, oid, default=None):
        return self.get([oid]).get(str(oid), default)

    def get_next(self, oids):
        return self.request(PDU_GETNEXT, list(oids))

    def get_bulk(self, oids, max_reps=20):
        return self.request(PDU_GETBULK, list(oids), max_reps=max_reps)

    def walk(self, base, max_rows=5000, bulk=True):
        """يمشي تحت OID ويعيد {oid: value}. يستخدم GETBULK مع تراجع تلقائي."""
        base = str(base).strip(".")
        result = {}
        if bulk:
            try:
                return self._walk_bulk(base, max_rows)
            except (SNMPAuthError, SNMPError):
                if result:
                    return result
        return self._walk_next(base, max_rows)

    def _walk_bulk(self, base, max_rows):
        result = {}
        current = base
        while len(result) < max_rows:
            vbs = self.get_bulk([current], max_reps=min(25, max_rows - len(result)))
            if not vbs:
                break
            progressed = False
            for oid, value in vbs:
                if value is None or not oid_under(oid, base):
                    return result
                if oid == current or oid in result:
                    continue
                if oid == base:
                    current = oid
                    continue
                result[oid] = value
                current = oid
                progressed = True
                if len(result) >= max_rows:
                    return result
            if not progressed:
                break
        return result

    def _walk_next(self, base, max_rows):
        result = {}
        current = base
        while len(result) < max_rows:
            vbs = self.get_next([current])
            if not vbs:
                break
            oid, value = vbs[0]
            if value is None or not oid_under(oid, base) or oid == current:
                break
            if oid != base:
                result[oid] = value
            current = oid
        return result

    def table(self, base, columns, max_rows=5000, bulk=True):
        """يقرأ جدولاً.

        columns: dict رقم العمود -> اسم الحقل (يُستثنى عمود الفهرس).
        يعيد dict: {index: {field: value}} حيث index هو ما بعد base.col.
        """
        base = str(base).strip(".")
        out = {}
        for col, name in columns.items():
            walked = self.walk(f"{base}.{col}", max_rows=max_rows, bulk=bulk)
            prefix = f"{base}.{col}."
            for oid, value in walked.items():
                if not oid.startswith(prefix):
                    continue
                idx = oid[len(prefix):]
                out.setdefault(idx, {})[name] = value
        return out

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False
