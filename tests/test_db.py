#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""اختبار طبقة قاعدة البيانات والنسخ الاحتياطي (SQLite أو PostgreSQL)."""
import os
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import yaml  # noqa: E402
from db import Database  # noqa: E402

CFG_PATH = os.path.join(ROOT, "config.yaml")
# config.yaml مستبعد من Git لأسباب أمنية؛ في CI نستخدم النموذج الآمن.
if not os.path.exists(CFG_PATH):
    CFG_PATH = os.path.join(ROOT, "config.example.yaml")
with open(CFG_PATH, encoding="utf-8") as f:
    cfg = yaml.safe_load(f) or {}

db = Database(ROOT, cfg.get("database") or {})
db.init_schema()
st = db.status()
if not st["connected"] and st["driver"] == "postgres":
    # CI/آلة بلا خادم PostgreSQL: نُجري نفس الاختبارات على SQLite
    tmp = os.path.join(tempfile.gettempdir(), "nabd-test-%d.db" % int(time.time()))
    print("postgres غير متاح — fallback إلى SQLite:", tmp)
    db = Database(ROOT, {"driver": "sqlite", "sqlite_path": tmp})
    db.init_schema()
    st = db.status()
print("driver:", st["driver"], "connected:", st["connected"], st["version"])
assert st["connected"], st.get("error")
assert "pool" in st and "idle" in st["pool"], st.get("pool")

h = db.health_report()
print("health:", h["state"], h["latency_ms"], "ms", len(h["recommendations"]), "tips")
assert h["connected"] and isinstance(h["recommendations"], list)
assert h["pool"]["max"] >= 1

now = time.time()
name = "TEST-DB-%d" % int(now)
db.query("INSERT INTO events VALUES (?,?,?,?)", (now, name, "127.0.0.1", "test"))
rows = db.query("SELECT etype FROM events WHERE name=?", (name,))
print("insert/select:", rows)
assert rows and rows[0][0] == "test"
db.query("DELETE FROM events WHERE name=?", (name,))

db.query("INSERT OR REPLACE INTO maintenance VALUES (?,?)", (name, now + 60))
print("upsert:", db.query("SELECT until FROM maintenance WHERE name=?", (name,)))
db.query("DELETE FROM maintenance WHERE name=?", (name,))

backup = db.create_backup("test")
print("backup:", backup["name"], backup["bytes"])
assert backup["ok"]
found = [b for b in db.list_backups() if b["name"] == backup["name"]]
print("verify:", found[0]["verified"] if found else None)
assert found and found[0]["verified"] is True
print("delete:", db.delete_backup(backup["name"]))
assert not db.delete_backup(backup["name"])
print("OK: database + backups")
