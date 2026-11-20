#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""اختبار حفظ إعدادات SNMP والبريد من واجهة الإعدادات (مع استرجاع config.yaml)."""
import glob
import os
import shutil
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import yaml  # noqa: E402

import nabd  # noqa: E402


def main():
    before = set(glob.glob(nabd.CONFIG_PATH + ".bak-*"))
    bak = nabd.CONFIG_PATH + ".verify-bak"
    shutil.copy2(nabd.CONFIG_PATH, bak)
    try:
        c = nabd.app.test_client()
        body = {
            "snmp": {"enabled": True, "community": "verifycomm", "port": 161,
                     "timeout": 2.0, "retries": 2, "poll_seconds": 90,
                     "cpu_warn": 80, "sfp_rx_min": -19.5,
                     "history_points": 60, "alert_cooldown_minutes": 15},
            "email": {"enabled": False, "host": "smtp.example.com", "port": 465,
                      "user": "u@example.com", "password": "secret",
                      "from": "nabd@example.com",
                      "to": ["a@example.com", "b@example.com"],
                      "tls": False, "ssl": True},
            "notifications": {"port_down": False, "high_cpu": True, "sfp_low": False},
            "webhook": {"enabled": True, "url": "https://hooks.example.com/nabd",
                        "secret": "verify-secret", "kinds": ["device_down", "port_down"]},
        }
        r = c.put("/api/settings", json=body)
        assert r.status_code == 200, (r.status_code, r.get_data(as_text=True))
        print("PUT /api/settings ->", r.status_code, r.get_json()["message"])

        g = c.get("/api/settings").get_json()
        assert g["snmp"]["community"] == "verifycomm", g["snmp"]
        assert g["snmp"]["poll_seconds"] == 90, g["snmp"]
        assert g["snmp"]["cpu_warn"] == 80, g["snmp"]
        assert g["snmp"]["sfp_rx_min"] == -19.5, g["snmp"]
        assert g["snmp"]["history_points"] == 60, g["snmp"]
        assert g["email"]["host"] == "smtp.example.com", g["email"]
        assert g["email"]["has_password"] is True, g["email"]
        assert g["email"]["to"] == ["a@example.com", "b@example.com"], g["email"]
        assert g["email"]["ssl"] is True and g["email"]["tls"] is False, g["email"]
        assert g["notifications"]["port_down"] is False, g["notifications"]
        assert g["notifications"]["high_cpu"] is True, g["notifications"]
        assert g["notifications"]["sfp_low"] is False, g["notifications"]
        assert g["webhook"]["enabled"] is True, g["webhook"]
        assert g["webhook"]["url"] == "https://hooks.example.com/nabd", g["webhook"]
        assert g["webhook"]["has_secret"] is True, g["webhook"]
        assert g["webhook"]["kinds"] == ["device_down", "port_down"], g["webhook"]
        print("GET /api/settings -> SNMP/email/notifications/webhook applied in memory")

        with open(nabd.CONFIG_PATH, encoding="utf-8") as f:
            raw = yaml.safe_load(f) or {}
        assert raw["snmp"]["community"] == "verifycomm", raw.get("snmp")
        assert raw["email"]["password"] == "secret", raw.get("email")
        assert raw["email"]["ssl"] is True, raw.get("email")
        assert raw["notifications"]["port_down"] is False, raw.get("notifications")
        assert raw["notifications"]["high_cpu"] is True, raw.get("notifications")
        assert raw["webhook"]["url"] == "https://hooks.example.com/nabd", raw.get("webhook")
        assert raw["webhook"]["secret"] == "verify-secret", raw.get("webhook")
        assert raw["webhook"]["kinds"] == ["device_down", "port_down"], raw.get("webhook")
        for key in ("telegram", "discover", "scan", "dashboard", "snmp", "email", "webhook"):
            assert key in raw, f"فُقد قسم {key} من config.yaml"
        assert raw["telegram"]["token"] == "", raw.get("telegram")
        print("config.yaml -> الأقسام محفوظة ولم تُفقد:", ", ".join(sorted(raw)))

        bad = c.put("/api/settings", json={"email": {"enabled": True, "host": "",
                                                     "to": []}})
        assert bad.status_code == 400, (bad.status_code, bad.get_data(as_text=True))
        print("رفض بريد مفعّل بلا خادم/مستلم ->", bad.status_code,
              bad.get_json()["error"])

        bad2 = c.put("/api/settings", json={"snmp": {"community": "  "}})
        assert bad2.status_code == 400, (bad2.status_code, bad2.get_data(as_text=True))
        print("رفض community فارغ ->", bad2.status_code, bad2.get_json()["error"])

        bad3 = c.put("/api/settings", json={"webhook": {"url": "ftp://example.com"}})
        assert bad3.status_code == 400, (bad3.status_code, bad3.get_data(as_text=True))
        print("رفض رابط Webhook غير صالح ->", bad3.status_code, bad3.get_json()["error"])
        print("OK: settings snmp/email/notifications persist")
    finally:
        shutil.copy2(bak, nabd.CONFIG_PATH)
        os.remove(bak)
        for path in set(glob.glob(nabd.CONFIG_PATH + ".bak-*")) - before:
            try:
                os.remove(path)
            except OSError:
                pass
        print("restored config.yaml")


if __name__ == "__main__":
    main()
