#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""اختبار المراقبة المتعمّقة: عتبات الأجهزة والمستشعرات المخصصة والتنبيهات.

يعمل في مجلد مؤقت مستقل بمحرك SQLite، لذا لا يحتاج خادم PostgreSQL ولا يلمس
إعداداتك أو بياناتك الحقيقية. يغطّي:
  - توافق devices.csv القديم (أعمدة جديدة غائبة).
  - رفض العتبات وOID غير الصالحة برسالة عربية واضحة.
  - حفظ المستشعرات المخصصة وقراءتها عبر API.
  - التنبيهات الجديدة high_mem / high_rtt / custom_sensor.
  - حفظ سجل المستشعرات في sensor_samples وإرجاعه مع الرسم التاريخي.
"""
import importlib.util
import os
import pathlib
import shutil
import sys
import tempfile
import time

import yaml

ROOT = pathlib.Path(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
TMP = pathlib.Path(tempfile.mkdtemp(prefix="nabd-monitor-"))
os.environ["NABD_HOME"] = str(TMP)
sys.path.insert(0, str(ROOT))

# إعداد معزول: SQLite بلا نسخ احتياطية ولا SNMP ولا قياسات دورية.
cfg = yaml.safe_load((ROOT / "config.example.yaml").read_text(encoding="utf-8")) or {}
cfg["database"] = {"driver": "sqlite", "sqlite_path": "nabd-check.db",
                   "backup": {"dir": "backups", "enabled": False}}
cfg["dashboard"]["host"] = "127.0.0.1"
cfg["snmp"]["enabled"] = False
cfg["metrics"]["enabled"] = False
(TMP / "config.yaml").write_text(yaml.safe_dump(cfg, allow_unicode=True), encoding="utf-8")
(TMP / "devices.csv").write_text(
    "name,ip,kind,parent,group,snmp,snmp_community,profile\n"
    "OLD-Router,192.0.2.10,router,,الراوتر,off,,auto\n"
    "OLD-SW,192.0.2.11,switch,OLD-Router,السويتشات,off,,auto\n",
    encoding="utf-8")

# نحمّل وحدة مستقلة باسم مختلف حتى لا تتأثر ببقية الاختبارات التي تستورد nabd.
spec = importlib.util.spec_from_file_location("nabd_monitor_check", ROOT / "nabd.py")
nabd = importlib.util.module_from_spec(spec)
sys.modules["nabd_monitor_check"] = nabd
spec.loader.exec_module(nabd)

try:
    nabd.init_db()
    nabd.DEVS.update(nabd.load_devices())
    assert len(nabd.DEVS) == 2, nabd.DEVS
    old = nabd.DEVS["OLD-Router"]
    assert all(old["limits"][k] is None
               for k in ("cpu_warn", "mem_warn", "rtt_warn", "sfp_rx_min"))
    assert old["limits"]["sensors"] == []
    print("OK: old devices.csv without new columns loads with global fallbacks")

    client = nabd.app.test_client()
    headers = {"Origin": "http://localhost"}
    status = client.get("/api/status").get_json()
    assert status["devices"][0]["limits"]["cpu_warn"] is None
    print("OK: /api/status exposes device limits")

    base = {"name": "NEW-SW", "ip": "192.0.2.20", "kind": "switch", "group": "اختبار",
            "snmp": "off", "profile": "auto", "cpu_warn": "77", "mem_warn": "88",
            "rtt_warn": "123.5", "sfp_rx_min": "-22.5",
            "sensors": [{"oid": "1.3.6.1.4.1.14988.1.1.3.10.0", "name": "temperature",
                         "unit": "C", "warn": "60", "crit": "70", "scale": "1", "low": False}]}

    bad_cpu = dict(base, name="BAD-CPU", ip="192.0.2.21", cpu_warn="abc")
    r = client.post("/api/devices", json=bad_cpu, headers=headers)
    assert r.status_code == 400 and "CPU" in r.get_json()["error"], (r.status_code, r.data)
    print("OK: invalid threshold rejected:", r.get_json()["error"])

    bad_oid = dict(base, name="BAD-OID", ip="192.0.2.22",
                   sensors=[{"oid": "not-an-oid", "name": "x", "warn": "1", "crit": "2"}])
    r = client.post("/api/devices", json=bad_oid, headers=headers)
    assert r.status_code == 400 and "OID" in r.get_json()["error"], (r.status_code, r.data)
    print("OK: invalid sensor OID rejected:", r.get_json()["error"])

    r = client.post("/api/devices", json=base, headers=headers)
    assert r.status_code == 200, (r.status_code, r.data)
    r = client.get("/api/snmp/sensors/NEW-SW")
    assert r.status_code == 200, (r.status_code, r.data[:400])
    j = r.get_json()
    assert len(j["sensors"]) == 1 and j["sensors"][0]["name"] == "temperature"
    assert j["sensors"][0]["warn"] == 60.0 and j["sensors"][0]["crit"] == 70.0
    print("OK: custom sensor persisted and /api/snmp/sensors works")

    rows, fields = nabd._read_csv_rows()
    assert all(k in fields for k in nabd.CSV_FIELDS)
    added = next(x for x in rows if x["name"] == "NEW-SW")
    assert added["cpu_warn"] == "77" and "temperature" in added["sensors"]
    assert next(x for x in rows if x["name"] == "OLD-Router")["cpu_warn"] == ""
    print("OK: new CSV columns added, old rows kept blank (compatible)")

    with nabd.LOCK:
        d = nabd.DEVS["NEW-SW"]
        d["eff"] = "up"
        d["rtt"] = 250.0
    with nabd.SNMP_LOCK:
        nabd.SNMP_STATE["NEW-SW"] = {
            "ok": True, "at": time.time(), "cpu": 20, "mem_pct": 95.0,
            "sensors": [{"name": "temperature", "oid": "1.3.6.1.4.1.14988.1.1.3.10.0",
                         "unit": "C", "value": 75.0, "state": "critical"}],
        }
    alerts = nabd.active_alerts()
    types = {a["type"] for a in alerts["alerts"] if a["name"] == "NEW-SW"}
    assert {"high_mem", "high_rtt", "custom_sensor"} <= types, types
    print("OK: active alerts include high_mem, high_rtt and custom_sensor:", sorted(types))

    r = client.get("/api/alerts")
    assert r.status_code == 200 and any(
        a["name"] == "NEW-SW" and a["type"] == "custom_sensor" for a in r.get_json()["alerts"])
    print("OK: /api/alerts exposes custom sensor alert")

    nabd._store_sensor_samples(time.time(), "NEW-SW", [
        {"name": "temperature", "value": 75.0, "state": "critical"}])
    r = client.get("/api/snmp/sensors/NEW-SW?range=1h")
    assert r.status_code == 200 and r.get_json()["sensors"][0]["history"]
    print("OK: sensor history persisted in sensor_samples")
finally:
    shutil.rmtree(TMP, ignore_errors=True)

print("OK: database + deeper monitoring")
