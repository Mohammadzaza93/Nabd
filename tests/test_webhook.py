#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""اختبار إشعارات Webhook: الإرسال والتوقيع والفلاتر وواجهة الاختبار."""
import hashlib
import hmac
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import yaml  # noqa: E402

import nabd  # noqa: E402


class FakeResponse:
    def __init__(self, status_code=200, text="ok"):
        self.status_code = status_code
        self.text = text
        self.ok = 200 <= status_code < 300


def main():
    original_post = nabd._hook_session.post
    captured = {}

    def fake_post(url, data=None, headers=None, timeout=None):
        captured.update(url=url, data=data, headers=headers, timeout=timeout)
        return FakeResponse()

    nabd._hook_session.post = fake_post
    try:
        cfg = nabd.config_for_save()
        cfg["webhook"] = {"enabled": True, "url": "https://example.com/hook",
                          "secret": "s3cr3t", "kinds": ["device_down"]}
        nabd.apply_runtime_config(cfg)
        assert nabd.webhook_ready() is True
        assert nabd.webhook_on("device_down") is True
        assert nabd.webhook_on("high_cpu") is False

        assert nabd.webhook_send("hello", "device_down") == "ok"
        assert captured["url"] == "https://example.com/hook", captured
        payload = json.loads(captured["data"].decode("utf-8"))
        assert payload["source"] == "nabd" and payload["kind"] == "device_down", payload
        assert payload["text"] == "hello", payload
        sig = captured["headers"]["X-Nabd-Signature"].split("=", 1)[1]
        expected = hmac.new(b"s3cr3t", captured["data"], hashlib.sha256).hexdigest()
        assert sig == expected, (sig, expected)
        print("webhook_send -> JSON + HMAC-SHA256 OK")

        while not nabd.HOOKQ.empty():
            nabd.HOOKQ.get_nowait()
        nabd.notify("ممنوع", "high_cpu")
        assert nabd.HOOKQ.empty(), "kind filter لم يُطبّق"
        nabd.notify("مسموح", "device_down")
        assert nabd.HOOKQ.qsize() == 1, "الرسالة المسموحة لم تُضف للطابور"
        assert nabd.HOOKQ.get_nowait() == ("مسموح", "device_down")
        print("notify -> احترام أنواع Webhook OK")

        client = nabd.app.test_client()
        r = client.post("/api/webhook/test", json={
            "url": "https://example.com/hook", "secret": "s3cr3t"})
        assert r.status_code == 200 and r.get_json()["ok"], r.get_data(as_text=True)
        print("POST /api/webhook/test ->", r.status_code, r.get_json())

        r = client.post("/api/webhook/test", json={"url": "ftp://example.com"})
        assert r.status_code == 502, (r.status_code, r.get_data(as_text=True))
        print("رفض رابط غير صالح ->", r.status_code, r.get_json()["error"])
        print("OK: webhook send / signature / filters / test endpoint")
    finally:
        nabd._hook_session.post = original_post
        with open(nabd.CONFIG_PATH, encoding="utf-8") as f:
            nabd.apply_runtime_config(yaml.safe_load(f) or {})
        print("restored runtime config from", nabd.CONFIG_PATH)


if __name__ == "__main__":
    main()
