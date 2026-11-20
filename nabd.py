#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""نبض (Nabd) - نظام مراقبة الشبكة
ping دوري + تبعيات الأجهزة + إشعارات تيليجرام + لوحة تحكم عربية.

الإعداد التفاعلي: python nabd.py --setup
التشغيل:        python nabd.py
فحص الإعدادات:  python nabd.py --check
معرفة chat id:  python nabd.py --chat-id
اكتشاف من الراوتر: python nabd.py --discover
فحص ذاتي:       python nabd.py --scan
رسالة تجريبية:  python nabd.py --test
"""
import copy
import csv
import hashlib
import hmac
import io
import ipaddress
import json
import os
import platform
import queue
import re
import secrets
import shutil
import smtplib
import socket
import sqlite3
import ssl
import subprocess
import sys
import threading
import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import date, datetime
from email.message import EmailMessage
from urllib.parse import urlparse

import requests
import yaml
from flask import Flask, Response, jsonify, request

try:
    from snmp import SNMPClient, SNMPError, SNMPTimeout, oid_under, to_int
except ImportError:  # تشغيل nabd.py من مجلد آخر
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from snmp import SNMPClient, SNMPError, SNMPTimeout, oid_under, to_int

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stdin.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

VERSION = "2.5"
BASE = os.environ.get("NABD_HOME") or os.path.dirname(os.path.abspath(__file__))
IS_WIN = platform.system() == "Windows"
DB = os.path.join(BASE, "nabd.db")
CONFIG_PATH = os.path.join(BASE, "config.yaml")
DEVICES_PATH = os.path.join(BASE, "devices.csv")


def _fail(msg):
    print(f"خطأ: {msg}", flush=True)
    sys.exit(1)


# ---------------------------------------------------------------- الإعدادات
def _load_cfg():
    try:
        with open(CONFIG_PATH, encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
    except FileNotFoundError:
        _fail(f"لم أجد ملف الإعدادات: {CONFIG_PATH}")
    except yaml.YAMLError as e:
        _fail(f"config.yaml غير صالح: {e}")
    if not isinstance(data, dict):
        _fail("config.yaml يجب أن يحتوي على قاموس إعدادات")
    return data


CFG = _load_cfg()


def _as_int(value, default, minimum=0):
    try:
        value = int(value)
    except (TypeError, ValueError):
        return default
    return value if value >= minimum else default


def _as_float(value, default, minimum=0.0):
    try:
        value = float(value)
    except (TypeError, ValueError):
        return default
    return value if value >= minimum else default


def _as_range(value, default, low, high):
    try:
        value = float(value)
    except (TypeError, ValueError):
        return default
    return min(high, max(low, value))


TG = CFG.get("telegram") or {}
TOKEN = os.environ.get("NABD_TELEGRAM_TOKEN", "").strip() or str(TG.get("token") or "").strip()
CHATS = [str(c).strip() for c in (TG.get("chat_ids") or []) if str(c).strip()]
TOKEN_OK = bool(TOKEN) and not TOKEN.startswith("PUT_")
TG_ON = TOKEN_OK and bool(CHATS) and not any(c.startswith("PUT_") for c in CHATS)

INTERVAL = _as_int(CFG.get("check_interval", 10), 10, 2)
THRESH = _as_int(CFG.get("fail_threshold", 3), 3, 1)
WORKERS = _as_int(CFG.get("workers", 100), 100, 1)
EVENTS_KEEP_DAYS = _as_int(CFG.get("events_retention_days", 30), 30, 1)
HB_HOUR = CFG.get("heartbeat_hour", 8)
if HB_HOUR is not None:
    try:
        HB_HOUR = int(HB_HOUR)
        if not 0 <= HB_HOUR <= 23:
            HB_HOUR = None
    except (TypeError, ValueError):
        HB_HOUR = None

DASH = CFG.get("dashboard") or {}
DASH_PW = os.environ.get("NABD_DASH_PASSWORD", "") or str(DASH.get("password") or "")
DASH_HOST = str(DASH.get("host") or "0.0.0.0")
DASH_PORT = _as_int(DASH.get("port", 8080), 8080, 1)
LIVE_SECONDS = _as_int(DASH.get("live_seconds", 5), 5, 2)

DISC = CFG.get("discover") or {}
SCAN = CFG.get("scan") or {}
_DR = DISC.get("router") or {}
DISC_ON = bool(_DR.get("host")) and bool(_DR.get("password")) and not str(_DR.get("password")).startswith("PUT_")

NOTIF_KEYS = ("device_down", "device_up", "internet", "new_device", "daily_report",
              "port_down", "high_cpu", "sfp_low")
NOTIF = dict(CFG.get("notifications") or {})
CFG_LOCK = threading.RLock()
DISCOVER_LOCK = threading.Lock()
SCAN_LOCK = threading.Lock()
SCAN_STATE = {"running": False, "started": 0.0, "finished": 0.0, "total": 0,
              "done": 0, "alive": 0, "results": [], "error": "", "subnets": []}

# ---------------------------------------------------------------- حالة SNMP
SNMP = dict(CFG.get("snmp") or {})
SNMP_ON = bool(SNMP.get("enabled", True))
EMAIL = dict(CFG.get("email") or {})
SNMP_LOCK = threading.RLock()
SNMP_POLL_LOCK = threading.Lock()
SNMP_STATE = {}          # اسم الجهاز -> آخر نتيجة استعلام كاملة
SNMP_HISTORY = {}        # اسم الجهاز -> deque([(ts, in_bps, out_bps)])
SNMP_PREV = {}           # اسم الجهاز -> {ifindex: (ts, in_octets, out_octets, oper)}
SNMP_ALERTS = {}         # (نوع, جهاز, مفتاح) -> آخر وقت إرسال
SNMP_POLL_STATE = {"running": False, "started": 0.0, "finished": 0.0,
                   "done": 0, "total": 0, "ok": 0, "error": ""}
SNMP_KINDS = {"router", "switch", "mikrotik", "routeros", "wifi", "ap", "ubiquiti",
              "ubnt", "wireless", "sfp"}
EMAILQ = queue.Queue()
EMAIL_MAX_QUEUE = 200
WEBHOOK = dict(CFG.get("webhook") or {})
HOOKQ = queue.Queue()
HOOK_MAX_QUEUE = 200

# ---------------------------------------------------------------- سجل القياسات
METRICS = dict(CFG.get("metrics") or {})
METRICS_ON = bool(METRICS.get("enabled", True))
METRICS_STEP = _as_int(METRICS.get("sample_seconds", 60), 60, 10)
METRICS_KEEP_DAYS = _as_int(METRICS.get("keep_days", 30), 30, 1)
LAST_SAMPLE = 0.0
MAINT_LOCK = threading.RLock()



def _norm_hour(value):
    if value is None or value == "":
        return None
    try:
        value = int(value)
    except (TypeError, ValueError):
        return None
    return value if 0 <= value <= 23 else None


def notif_on(kind):
    return bool(NOTIF.get(kind, True))


def _normalize_config(cfg):
    """يكمل المفاتيح الناقصة حتى تعمل الإعدادات القادمة من الواجهة بأمان."""
    cfg = copy.deepcopy(cfg) if isinstance(cfg, dict) else {}
    tg = cfg.get("telegram") or {}
    cfg["telegram"] = tg
    tg["token"] = str(tg.get("token") or "")
    chats = tg.get("chat_ids") or []
    if isinstance(chats, str):
        chats = [chats]
    tg["chat_ids"] = [str(x).strip() for x in chats if str(x).strip()]

    nots = cfg.get("notifications") or {}
    cfg["notifications"] = nots
    for key in NOTIF_KEYS:
        nots[key] = bool(nots.get(key, True))

    dash = cfg.get("dashboard") or {}
    cfg["dashboard"] = dash
    dash["host"] = str(dash.get("host") or "0.0.0.0")
    dash["port"] = _as_int(dash.get("port", 8080), 8080, 1)
    dash["password"] = str(dash.get("password") or "")
    dash["live_seconds"] = _as_int(dash.get("live_seconds", 5), 5, 2)

    disc = cfg.get("discover") or {}
    cfg["discover"] = disc
    dr = disc.get("router") or {}
    disc["router"] = dr
    dr["host"] = str(dr.get("host") or "")
    dr["user"] = str(dr.get("user") or "nabd")
    dr["password"] = str(dr.get("password") or "")
    dr["port"] = _as_int(dr.get("port", 8728), 8728, 1)
    disc["auto_minutes"] = _as_float(disc.get("auto_minutes", 30), 30, 0)
    disc["exclude_interfaces"] = list(disc.get("exclude_interfaces") or [])
    disc["only_interfaces"] = list(disc.get("only_interfaces") or [])
    disc["port_map"] = dict(disc.get("port_map") or {})
    disc["new_group"] = str(disc.get("new_group") or "مكتشف")
    disc["max_new_per_run"] = _as_int(disc.get("max_new_per_run", 400), 400, 1)

    scan = cfg.get("scan") or {}
    cfg["scan"] = scan
    scan["subnets"] = [str(x).strip() for x in (scan.get("subnets") or []) if str(x).strip()]
    scan["auto_minutes"] = _as_float(scan.get("auto_minutes", 0), 0, 0)

    snmp = cfg.get("snmp") or {}
    cfg["snmp"] = snmp
    snmp["enabled"] = bool(snmp.get("enabled", True))
    snmp["community"] = str(snmp.get("community") or "public").strip() or "public"
    snmp["port"] = _as_int(snmp.get("port", 161), 161, 1)
    snmp["timeout"] = _as_range(snmp.get("timeout", 1.5), 1.5, 0.2, 15)
    snmp["retries"] = _as_int(snmp.get("retries", 1), 1, 0)
    snmp["poll_seconds"] = _as_int(snmp.get("poll_seconds", 60), 60, 10)
    snmp["cpu_warn"] = _as_int(snmp.get("cpu_warn", 85), 85, 1)
    snmp["sfp_rx_min"] = _as_range(snmp.get("sfp_rx_min", -20.0), -20.0, -60, 10)
    snmp["history_points"] = _as_int(snmp.get("history_points", 120), 120, 10)
    snmp["alert_cooldown_minutes"] = _as_int(
        snmp.get("alert_cooldown_minutes", 30), 30, 0)

    met = cfg.get("metrics") or {}
    cfg["metrics"] = met
    met["enabled"] = bool(met.get("enabled", True))
    met["sample_seconds"] = _as_int(met.get("sample_seconds", 60), 60, 10)
    met["keep_days"] = _as_int(met.get("keep_days", 30), 30, 1)

    hook = cfg.get("webhook") or {}
    cfg["webhook"] = hook
    hook["enabled"] = bool(hook.get("enabled", False))
    hook["url"] = str(hook.get("url") or "").strip()
    hook["secret"] = str(hook.get("secret") or "")
    kinds = hook.get("kinds") or []
    if isinstance(kinds, str):
        kinds = re.split(r"[,،\s]+", kinds)
    hook["kinds"] = [k for k in NOTIF_KEYS if k in {str(x).strip() for x in kinds}]

    em = cfg.get("email") or {}
    cfg["email"] = em
    em["enabled"] = bool(em.get("enabled", False))
    em["host"] = str(em.get("host") or "").strip()
    em["port"] = _as_int(em.get("port", 587), 587, 1)
    em["user"] = str(em.get("user") or "").strip()
    em["password"] = str(em.get("password") or "")
    em["from"] = str(em.get("from") or em.get("sender") or "").strip()
    em.pop("sender", None)
    to = em.get("to") or []
    if isinstance(to, str):
        to = re.split(r"[,;\s]+", to)
    em["to"] = [str(x).strip() for x in to if str(x).strip()]
    em["tls"] = bool(em.get("tls", True))
    em["ssl"] = bool(em.get("ssl", False))

    cfg["check_interval"] = _as_int(cfg.get("check_interval", 10), 10, 2)
    cfg["fail_threshold"] = _as_int(cfg.get("fail_threshold", 3), 3, 1)
    cfg["workers"] = _as_int(cfg.get("workers", 100), 100, 1)
    cfg["events_retention_days"] = _as_int(cfg.get("events_retention_days", 30), 30, 1)
    cfg["heartbeat_hour"] = _norm_hour(cfg.get("heartbeat_hour", 8))
    return cfg


def apply_runtime_config(cfg):
    """يطبّق الإعدادات فوراً على العاملين في الخلفية دون إعادة تشغيل."""
    global TOKEN, CHATS, TOKEN_OK, TG_ON, INTERVAL, THRESH, WORKERS, EVENTS_KEEP_DAYS, HB_HOUR
    global DASH_PW, DASH_HOST, DASH_PORT, LIVE_SECONDS, DISC, SCAN, _DR, DISC_ON, NOTIF
    global SNMP, SNMP_ON, EMAIL, METRICS, METRICS_ON, METRICS_STEP, METRICS_KEEP_DAYS, WEBHOOK
    cfg = _normalize_config(cfg)
    tg = cfg["telegram"]
    TOKEN = os.environ.get("NABD_TELEGRAM_TOKEN", "").strip() or str(tg.get("token") or "").strip()
    CHATS = list(tg.get("chat_ids") or [])
    TOKEN_OK = bool(TOKEN) and not TOKEN.startswith("PUT_")
    TG_ON = TOKEN_OK and bool(CHATS) and not any(c.startswith("PUT_") for c in CHATS)
    INTERVAL = cfg["check_interval"]
    THRESH = cfg["fail_threshold"]
    WORKERS = cfg["workers"]
    EVENTS_KEEP_DAYS = cfg["events_retention_days"]
    HB_HOUR = cfg["heartbeat_hour"]
    dash = cfg["dashboard"]
    DASH_PW = os.environ.get("NABD_DASH_PASSWORD", "") or str(dash.get("password") or "")
    DASH_HOST = str(dash.get("host") or "0.0.0.0")
    DASH_PORT = _as_int(dash.get("port", 8080), 8080, 1)
    LIVE_SECONDS = _as_int(dash.get("live_seconds", 5), 5, 2)
    DISC = cfg["discover"]
    SCAN = cfg["scan"]
    _DR = DISC["router"]
    DISC_ON = (bool(_DR.get("host")) and bool(_DR.get("password"))
               and not str(_DR.get("password")).startswith("PUT_"))
    old_snmp = SNMP if isinstance(SNMP, dict) else {}
    new_snmp = cfg["snmp"]
    if (old_snmp.get("community") != new_snmp.get("community") or
            old_snmp.get("port") != new_snmp.get("port")):
        with SNMP_LOCK:
            SNMP_PREV.clear()
    SNMP = new_snmp
    SNMP_ON = bool(SNMP.get("enabled", True))
    EMAIL = cfg["email"]
    WEBHOOK = cfg["webhook"]
    METRICS = cfg["metrics"]
    METRICS_ON = bool(METRICS.get("enabled", True))
    METRICS_STEP = _as_int(METRICS.get("sample_seconds", 60), 60, 10)
    METRICS_KEEP_DAYS = _as_int(METRICS.get("keep_days", 30), 30, 1)
    NOTIF = dict(cfg["notifications"])
    with CFG_LOCK:
        CFG.clear()
        CFG.update(cfg)


def config_for_save():
    with CFG_LOCK:
        return _normalize_config(CFG)


def save_config_file(cfg):
    _backup(CONFIG_PATH)
    tmp = CONFIG_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline="\n") as f:
        f.write(render_config(_normalize_config(cfg)))
    os.replace(tmp, CONFIG_PATH)

LOCK = threading.Lock()
DEVS = {}
NET = {"state": "unknown", "since": time.time(), "down_at": None, "probes": 0, "probes_up": 0, "ready": False}
OUTQ = queue.Queue()
STARTED_AT = time.time()
RTT_RE = re.compile(r"[=<]\s*(\d+(?:[.,]\d+)?)\s*ms", re.I)
TG_MAX_QUEUE = 500
TG_MAX_PENDING = 500


def now_str():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def log(msg):
    print(f"[{now_str()}] {msg}", flush=True)


def fmt_dur(sec):
    try:
        sec = max(0, int(sec))
    except (TypeError, ValueError):
        sec = 0
    d, r = divmod(sec, 86400)
    h, r = divmod(r, 3600)
    m, s = divmod(r, 60)
    if d:
        return f"{d} يوم و {h} ساعة"
    if h:
        return f"{h} ساعة و {m} دقيقة"
    if m:
        return f"{m} دقيقة"
    return f"{s} ثانية"


def valid_ip(value):
    try:
        ipaddress.IPv4Address(str(value))
        return True
    except (ipaddress.AddressValueError, ValueError):
        return False


def lan_ips():
    ips = set()
    try:
        for ip in socket.gethostbyname_ex(socket.gethostname())[2]:
            if not ip.startswith("127.") and not ip.startswith("169.254."):
                ips.add(ip)
    except OSError:
        pass
    return sorted(ips)


# ---------------------------------------------------------------- قاعدة البيانات
def db_exec(sql, args=()):
    c = sqlite3.connect(DB, timeout=15)
    try:
        c.execute("PRAGMA busy_timeout=8000")
        cur = c.execute(sql, args)
        rows = cur.fetchall()
        c.commit()
        return rows
    finally:
        c.close()


def db_execmany(sql, rows):
    c = sqlite3.connect(DB, timeout=15)
    try:
        c.execute("PRAGMA busy_timeout=8000")
        c.executemany(sql, rows)
        c.commit()
    finally:
        c.close()


def prune_events():
    cutoff = time.time() - EVENTS_KEEP_DAYS * 86400
    try:
        db_exec("DELETE FROM events WHERE ts < ?", (cutoff,))
    except Exception as e:
        log(f"تعذر تنظيف الأحداث القديمة: {e}")


def prune_samples():
    cutoff = time.time() - METRICS_KEEP_DAYS * 86400
    try:
        db_exec("DELETE FROM samples WHERE ts < ?", (cutoff,))
        db_exec("DELETE FROM alert_acks WHERE at < ?", (cutoff,))
        db_exec("DELETE FROM maintenance WHERE until < ?", (time.time() - 86400,))
        db_exec("DELETE FROM maintenance_log WHERE ended < ?", (cutoff,))
    except Exception as e:
        log(f"تعذر تنظيف سجل القياسات: {e}")


def init_db():
    try:
        db_exec("PRAGMA journal_mode=WAL")
        db_exec("CREATE TABLE IF NOT EXISTS events(ts REAL, name TEXT, ip TEXT, etype TEXT)")
        db_exec("CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts)")
        db_exec("""CREATE TABLE IF NOT EXISTS samples(
            ts REAL NOT NULL, name TEXT NOT NULL, rtt REAL, cpu REAL, mem REAL,
            in_bps REAL, out_bps REAL, ports_up INTEGER, ports_total INTEGER)""")
        db_exec("CREATE INDEX IF NOT EXISTS idx_samples_name_ts ON samples(name, ts)")
        db_exec("CREATE TABLE IF NOT EXISTS alert_acks(key TEXT PRIMARY KEY, name TEXT, at REAL)")
        db_exec("CREATE TABLE IF NOT EXISTS maintenance(name TEXT PRIMARY KEY, until REAL)")
        db_exec("""CREATE TABLE IF NOT EXISTS maintenance_log(
            name TEXT, started REAL, ended REAL)""")
        db_exec("CREATE INDEX IF NOT EXISTS idx_maint_log ON maintenance_log(name, started)")
        prune_events()
        prune_samples()
    except Exception as e:
        log(f"تعذر تهيئة قاعدة البيانات: {e}")


def log_event(ts, name, ip, etype):
    try:
        db_exec("INSERT INTO events VALUES (?,?,?,?)", (ts, name, ip, etype))
    except Exception as e:
        log(f"خطأ في قاعدة البيانات: {e}")


# ---------------------------------------------------------------- القياسات وSLA
def record_samples(force=False):
    """يحفظ نقطة قياس لكل جهاز في SQLite (ping + SNMP) كل METRICS_STEP ثانية."""
    global LAST_SAMPLE
    if not METRICS_ON:
        return 0
    now = time.time()
    if not force and now - LAST_SAMPLE < METRICS_STEP:
        return 0
    LAST_SAMPLE = now
    with LOCK:
        devs = [dict(d) for d in DEVS.values()]
    with SNMP_LOCK:
        states = {n: dict(s) for n, s in SNMP_STATE.items() if s.get("ok")}
    rows = []
    for d in devs:
        st = states.get(d["name"]) or {}
        sm = st.get("summary") or {}
        up = d.get("raw") == "up"
        rows.append((
            now, d["name"], d.get("rtt") if up else None,
            sm.get("cpu"), sm.get("mem_pct"), sm.get("in_bps"), sm.get("out_bps"),
            sm.get("ports_up"), sm.get("ports"),
        ))
    if not rows:
        return 0
    try:
        db_execmany("INSERT INTO samples VALUES (?,?,?,?,?,?,?,?,?)", rows)
        return len(rows)
    except Exception as e:
        log(f"تعذر حفظ القياسات: {e}")
        return 0


SAMPLE_RANGES = {"1h": 3600, "6h": 21600, "24h": 86400,
                 "7d": 604800, "30d": 2592000, "90d": 7776000}


def metrics_series(name, range_key="24h", max_points=240):
    seconds = SAMPLE_RANGES.get(range_key)
    if not seconds:
        return None
    now = time.time()
    since = now - seconds
    step = max(METRICS_STEP, int(seconds / max_points))
    rows = db_exec(
        """SELECT CAST(ts/? AS INTEGER)*?, AVG(rtt), AVG(cpu), AVG(mem),
                  AVG(in_bps), AVG(out_bps),
                  SUM(CASE WHEN rtt IS NOT NULL THEN 1 ELSE 0 END), COUNT(*)
           FROM samples WHERE name=? AND ts>=? GROUP BY 1 ORDER BY 1""",
        (step, step, name, since))
    series = []
    for r in rows:
        series.append([int(r[0]),
                       None if r[1] is None else round(r[1], 2),
                       None if r[2] is None else round(r[2], 1),
                       None if r[3] is None else round(r[3], 1),
                       None if r[4] is None else round(r[4], 1),
                       None if r[5] is None else round(r[5], 1),
                       int(r[6] or 0), int(r[7] or 0)])
    total = sum(p[7] for p in series)
    up = sum(p[6] for p in series)
    pcts = [p[2] for p in series if p[2] is not None]
    mems = [p[3] for p in series if p[3] is not None]
    summary = {
        "samples": total,
        "up": up,
        "pct": round(up * 100.0 / total, 2) if total else None,
        "avg_cpu": round(sum(pcts) / len(pcts), 1) if pcts else None,
        "avg_mem": round(sum(mems) / len(mems), 1) if mems else None,
        "peak_in": max([p[4] for p in series if p[4] is not None] or [0]),
        "peak_out": max([p[5] for p in series if p[5] is not None] or [0]),
    }
    return {"name": name, "range": range_key, "since": since, "until": now,
            "step": step, "series": series, "summary": summary}


def sla_report(range_key="24h"):
    seconds = SAMPLE_RANGES.get(range_key)
    if not seconds:
        return None
    now = time.time()
    since = now - seconds
    stats = {}
    for r in db_exec(
            """SELECT s.name, COUNT(*),
                      SUM(CASE WHEN s.rtt IS NOT NULL THEN 1 ELSE 0 END),
                      AVG(CASE WHEN s.rtt IS NOT NULL THEN s.rtt END),
                      AVG(s.cpu), AVG(s.mem), MAX(s.in_bps), MAX(s.out_bps),
                      MIN(s.ts), MAX(s.ts)
               FROM samples s
               WHERE s.ts>=? AND NOT EXISTS (
                   SELECT 1 FROM maintenance_log m
                   WHERE m.name=s.name AND s.ts BETWEEN m.started AND m.ended)
               GROUP BY s.name""", (since,)):
        stats[r[0]] = {
            "samples": r[1] or 0, "up_samples": r[2] or 0,
            "avg_rtt": None if r[3] is None else round(r[3], 1),
            "avg_cpu": None if r[4] is None else round(r[4], 1),
            "avg_mem": None if r[5] is None else round(r[5], 1),
            "peak_in": r[6] or 0, "peak_out": r[7] or 0,
            "first": r[8], "last": r[9],
        }
    outages = {}
    for r in db_exec(
            """SELECT name, SUM(CASE WHEN up=0 AND prev=1 THEN 1 ELSE 0 END)
               FROM (SELECT s.name, s.ts,
                            CASE WHEN s.rtt IS NOT NULL THEN 1 ELSE 0 END up,
                            LAG(CASE WHEN s.rtt IS NOT NULL THEN 1 ELSE 0 END)
                              OVER (PARTITION BY s.name ORDER BY s.ts) prev
                     FROM samples s
                     WHERE s.ts>=? AND NOT EXISTS (
                         SELECT 1 FROM maintenance_log m
                         WHERE m.name=s.name AND s.ts BETWEEN m.started AND m.ended))
               WHERE prev=1 AND up=0 GROUP BY name""", (since,)):
        outages[r[0]] = int(r[1] or 0)
    days = {}
    for r in db_exec(
            """SELECT s.name, CAST((? - s.ts)/86400 AS INTEGER) d, COUNT(*),
                      SUM(CASE WHEN s.rtt IS NOT NULL THEN 1 ELSE 0 END)
               FROM samples s
               WHERE s.ts>=? AND NOT EXISTS (
                   SELECT 1 FROM maintenance_log m
                   WHERE m.name=s.name AND s.ts BETWEEN m.started AND m.ended)
               GROUP BY s.name, d""", (now, since)):
        days.setdefault(r[0], {})[int(r[1])] = (r[3] or 0) * 100.0 / (r[2] or 1)
    with LOCK:
        devs = [dict(d) for d in DEVS.values()]
    out = []
    total_samples = total_up = 0
    for d in devs:
        st = stats.get(d["name"])
        maint = round(maintenance_seconds(d["name"], since, now), 1)
        if not st or not st["samples"]:
            out.append({"name": d["name"], "ip": d["ip"], "kind": d["kind"],
                        "group": d["group"], "eff": d["eff"], "samples": 0,
                        "pct": None, "avg_rtt": None, "outages": 0,
                        "downtime": 0, "mttr": None, "avg_cpu": None,
                        "avg_mem": None, "peak_in": 0, "peak_out": 0,
                        "maintenance": maint, "days": []})
            continue
        pct = st["up_samples"] * 100.0 / st["samples"]
        span = max(0.0, (st["last"] or now) - (st["first"] or now))
        span = min(seconds, span + METRICS_STEP) if st["samples"] > 1 else 0
        covered = maintenance_seconds(d["name"], st["first"] or since, st["last"] or now)
        span = max(0.0, span - covered)
        down = span * (1 - pct / 100.0)
        oc = outages.get(d["name"], 0)
        total_samples += st["samples"]
        total_up += st["up_samples"]
        out.append({
            "name": d["name"], "ip": d["ip"], "kind": d["kind"], "group": d["group"],
            "eff": d["eff"], "samples": st["samples"], "pct": round(pct, 2),
            "avg_rtt": st["avg_rtt"], "outages": oc,
            "downtime": round(down, 0),
            "mttr": round(down / oc, 0) if oc else None,
            "avg_cpu": st["avg_cpu"], "avg_mem": st["avg_mem"],
            "peak_in": st["peak_in"], "peak_out": st["peak_out"],
            "maintenance": maint,
            "days": [{"d": k, "pct": round(v, 1)}
                     for k, v in sorted(days.get(d["name"], {}).items()) if k < 90],
        })
    out.sort(key=lambda x: (x["pct"] if x["pct"] is not None else 101, x["name"]))
    return {
        "range": range_key, "since": since, "until": now,
        "summary": {
            "devices": len(out),
            "monitored": sum(1 for x in out if x["samples"]),
            "pct": round(total_up * 100.0 / total_samples, 2) if total_samples else None,
            "outages": sum(x["outages"] for x in out),
            "downtime": round(sum(x["downtime"] for x in out), 0),
            "maintenance": round(sum(x["maintenance"] for x in out), 1),
        },
        "devices": out,
    }


# ---------------------------------------------------------------- الصيانة والتنبيهات
def maintenance_map():
    now = time.time()
    try:
        rows = db_exec("SELECT name, until FROM maintenance WHERE until > ?", (now,))
        return {r[0]: r[1] for r in rows}
    except Exception:
        return {}


def maintenance_until(name):
    try:
        rows = db_exec("SELECT until FROM maintenance WHERE name=?", (name,))
        return rows[0][0] if rows and rows[0][0] > time.time() else 0
    except Exception:
        return 0


def latest_maint_row(name):
    try:
        rows = db_exec("SELECT rowid, started, ended FROM maintenance_log "
                       "WHERE name=? ORDER BY started DESC LIMIT 1", (name,))
        return rows[0] if rows else None
    except Exception:
        return None


def set_maintenance(name, minutes):
    """يفعّل/يوقف الصيانة، ويسجّل نافذتها الزمنية لاستبعادها من تقارير SLA."""
    minutes = _as_int(minutes, 0, 0)
    now = time.time()
    try:
        rows = db_exec("SELECT until FROM maintenance WHERE name=?", (name,))
        old_until = rows[0][0] if rows else 0
    except Exception:
        old_until = 0
    if minutes <= 0:
        db_exec("DELETE FROM maintenance WHERE name=?", (name,))
        row = latest_maint_row(name)
        if row and (row[2] or 0) > now:
            db_exec("UPDATE maintenance_log SET ended=? WHERE rowid=?",
                    (max(now, row[1]), row[0]))
        return 0
    until = now + min(minutes, 60 * 24 * 60) * 60
    db_exec("INSERT OR REPLACE INTO maintenance VALUES (?,?)", (name, until))
    row = latest_maint_row(name) if old_until > now else None
    if row and (row[2] or 0) > now:
        db_exec("UPDATE maintenance_log SET ended=? WHERE rowid=?", (until, row[0]))
    else:
        db_exec("INSERT INTO maintenance_log(name, started, ended) VALUES (?,?,?)",
                (name, now, until))
    return until


def maintenance_windows(name, since, until=None):
    """نوافذ الصيانة التي تقاطع الفترة المطلوبة، داخل حدودها."""
    until = time.time() if until is None else until
    if until <= since:
        return []
    try:
        rows = db_exec("SELECT started, ended FROM maintenance_log "
                       "WHERE name=? AND ended>? AND started<?", (name, since, until))
    except Exception:
        return []
    out = []
    for start, end in rows:
        a, b = max(start, since), min(end, until)
        if b > a:
            out.append((a, b))
    return out


def maintenance_seconds(name, since, until=None):
    return sum(b - a for a, b in maintenance_windows(name, since, until))


def suppressed(name):
    """يتخطى الإشعارات أثناء وضع الصيانة."""
    return maintenance_until(name) > time.time()


def ack_alert(key, ack=True):
    key = str(key or "").strip()
    if not key:
        return False
    if ack:
        db_exec("INSERT OR REPLACE INTO alert_acks VALUES (?,?,?)", (key, "", time.time()))
    else:
        db_exec("DELETE FROM alert_acks WHERE key=?", (key,))
    return True


# ---------------------------------------------------------------- الأجهزة
def make_dev(row):
    return {
        "name": row["name"],
        "ip": row["ip"],
        "kind": (row.get("kind") or "device").strip() or "device",
        "parent": (row.get("parent") or "").strip(),
        "group": (row.get("group") or "عام").strip() or "عام",
        "fails": 0,
        "raw": "unknown",
        "eff": "unknown",
        "since": time.time(),
        "down_at": None,
        "alerted": False,
        "rtt": None,
        "last_ok": None,
        "ports": [],
        "ports_at": None,
        "snmp": (row.get("snmp") or "").strip().lower(),
        "snmp_community": (row.get("snmp_community") or "").strip(),
        "profile": (row.get("profile") or "auto").strip().lower() or "auto",
    }


def load_devices():
    devs = {}
    if not os.path.exists(DEVICES_PATH):
        log(f"تحذير: لم أجد {DEVICES_PATH}")
        return devs
    try:
        f = open(DEVICES_PATH, encoding="utf-8-sig", newline="")
    except OSError as e:
        log(f"تعذر فتح devices.csv: {e}")
        return devs

    with f:
        reader = csv.DictReader(f)
        fields = [str(x).strip().lower() for x in (reader.fieldnames or [])]
        if "name" not in fields or "ip" not in fields:
            log("تحذير: devices.csv يجب أن يحتوي على العمودين name و ip")
            return devs
        for line_no, row in enumerate(reader, start=2):
            row = {str(k).strip().lower(): v for k, v in row.items() if k is not None}
            name = (row.get("name") or "").strip()
            ip = (row.get("ip") or "").strip()
            if not name or name.startswith("#") or not ip:
                continue
            if not valid_ip(ip):
                log(f"تحذير: عنوان غير صالح في devices.csv السطر {line_no}: {ip} ({name})")
                continue
            if name in devs:
                log(f"تحذير: الاسم مكرر في devices.csv وتم تجاهل السطر {line_no}: {name}")
                continue
            d = make_dev(row)
            if d["parent"] == name:
                d["parent"] = ""
            devs[name] = d
    return devs


# ---------------------------------------------------------------- إدارة ملف الأجهزة
CSV_FIELDS = ("name", "ip", "kind", "parent", "group", "snmp",
              "snmp_community", "profile")
CSV_LOCK = threading.RLock()


def _read_csv_rows():
    """يقرأ devices.csv مع الحفاظ على أي أعمدة إضافية أضافها المستخدم."""
    if not os.path.exists(DEVICES_PATH):
        return [], list(CSV_FIELDS)
    try:
        with open(DEVICES_PATH, encoding="utf-8-sig", newline="") as f:
            reader = csv.DictReader(f)
            fields = []
            for fld in (reader.fieldnames or []):
                key = str(fld).strip().lower()
                if key and key not in fields:
                    fields.append(key)
            for need in CSV_FIELDS:
                if need not in fields:
                    fields.append(need)
            rows = []
            for row in reader:
                clean = {}
                for k, v in row.items():
                    if k is None:
                        continue
                    clean[str(k).strip().lower()] = "" if v is None else str(v).strip()
                if any(clean.values()):
                    rows.append(clean)
            return rows, fields
    except (OSError, csv.Error) as e:
        log(f"تعذر قراءة devices.csv: {e}")
        return [], list(CSV_FIELDS)


def _write_csv_rows(rows, fields=None):
    """كتابة آمنة: ملف مؤقت ثم استبدال، حتى لا يتلف devices.csv عند الانقطاع."""
    fields = [str(x).strip().lower() for x in (fields or CSV_FIELDS)]
    for need in CSV_FIELDS:
        if need not in fields:
            fields.append(need)
    tmp = DEVICES_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore", lineterminator="\n")
        w.writeheader()
        for row in rows:
            w.writerow({k: row.get(k, "") for k in fields})
    os.replace(tmp, DEVICES_PATH)


def _backup(path):
    if not os.path.exists(path):
        return None
    dest = path + ".bak-" + datetime.now().strftime("%Y%m%d-%H%M%S")
    try:
        shutil.copy2(path, dest)
        return dest
    except OSError as e:
        log(f"تعذر إنشاء نسخة احتياطية لـ {os.path.basename(path)}: {e}")
        return None


def normalize_device(data):
    """يتحقق من بيانات جهاز قادمة من اللوحة أو الإعداد التفاعلي."""
    name = str(data.get("name") or "").strip()
    ip = str(data.get("ip") or "").strip()
    kind = str(data.get("kind") or "device").strip() or "device"
    parent = str(data.get("parent") or "").strip()
    group = str(data.get("group") or "").strip() or "عام"
    snmp_mode = str(data.get("snmp") or "").strip().lower()
    if snmp_mode not in ("", "auto", "on", "off", "1", "0", "yes", "no", "true", "false"):
        snmp_mode = "auto"
    if snmp_mode in ("1", "yes", "true", "on"):
        snmp_mode = "on"
    elif snmp_mode in ("0", "no", "false", "off"):
        snmp_mode = "off"
    community = str(data.get("snmp_community") or "").strip()
    profile = str(data.get("profile") or "auto").strip().lower() or "auto"
    if profile not in ("auto", "mikrotik", "routeros", "ubiquiti", "ubnt", "generic"):
        profile = "auto"
    if not name:
        raise ValueError("اكتب اسم الجهاز")
    if len(name) > 64:
        raise ValueError("اسم الجهاز طويل جداً (64 حرفاً كحد أقصى)")
    if not valid_ip(ip):
        raise ValueError("عنوان IP غير صالح")
    if len(kind) > 32 or len(group) > 64 or len(parent) > 64:
        raise ValueError("قيمة طويلة جداً")
    if len(community) > 64:
        raise ValueError("اسم مجتمع SNMP طويل جداً")
    if parent == name:
        raise ValueError("لا يمكن أن يتبع الجهاز نفسه")
    return {"name": name, "ip": ip, "kind": kind, "parent": parent, "group": group,
            "snmp": snmp_mode, "snmp_community": community, "profile": profile}


def add_device(data):
    row = normalize_device(data)
    with LOCK:
        for d in DEVS.values():
            if d["name"].lower() == row["name"].lower():
                raise ValueError("يوجد جهاز بهذا الاسم")
            if d["ip"] == row["ip"]:
                raise ValueError(f"العنوان مستخدم بالفعل للجهاز {d['name']}")
    with CSV_LOCK:
        rows, fields = _read_csv_rows()
        for r in rows:
            if (r.get("name") or "").strip().lower() == row["name"].lower():
                raise ValueError("يوجد جهاز بهذا الاسم")
            if (r.get("ip") or "").strip() == row["ip"]:
                raise ValueError(f"العنوان مستخدم بالفعل للجهاز {(r.get('name') or '').strip()}")
        rows.append(row)
        _write_csv_rows(rows, fields)
    with LOCK:
        DEVS[row["name"]] = make_dev(row)
    return row


def update_device(old_name, data):
    row = normalize_device(data)
    with CSV_LOCK:
        rows, fields = _read_csv_rows()
        idx = next((i for i, r in enumerate(rows)
                    if (r.get("name") or "").strip() == old_name), None)
        if idx is None:
            raise ValueError("لم أجد الجهاز")
        for i, r in enumerate(rows):
            if i == idx:
                continue
            if (r.get("name") or "").strip().lower() == row["name"].lower():
                raise ValueError("يوجد جهاز آخر بهذا الاسم")
            if (r.get("ip") or "").strip() == row["ip"]:
                raise ValueError(f"العنوان مستخدم بالفعل للجهاز {(r.get('name') or '').strip()}")
        merged = dict(rows[idx])
        merged.update(row)
        rows[idx] = merged
        if old_name != row["name"]:
            for r in rows:
                if (r.get("parent") or "").strip() == old_name:
                    r["parent"] = row["name"]
        _write_csv_rows(rows, fields)
    with LOCK:
        old = DEVS.pop(old_name, None)
        if old and old_name == row["name"] and old["ip"] == row["ip"]:
            old.update({k: row[k] for k in ("kind", "parent", "group")})
            DEVS[row["name"]] = old
        else:
            DEVS[row["name"]] = make_dev(row)
        for d in DEVS.values():
            if d["parent"] == old_name and old_name != row["name"]:
                d["parent"] = row["name"]
    return row


def delete_device(name):
    with CSV_LOCK:
        rows, fields = _read_csv_rows()
        kept = [r for r in rows if (r.get("name") or "").strip() != name]
        if len(kept) == len(rows):
            raise ValueError("لم أجد الجهاز")
        for r in kept:
            if (r.get("parent") or "").strip() == name:
                r["parent"] = ""
        _write_csv_rows(kept, fields)
    with LOCK:
        DEVS.pop(name, None)
        for d in DEVS.values():
            if d["parent"] == name:
                d["parent"] = ""



def ping(ip):
    if IS_WIN:
        cmd = ["ping", "-n", "1", "-w", "1200", ip]
        kw = {"creationflags": 0x08000000}
    else:
        cmd = ["ping", "-c", "1", "-W", "2", ip]
        kw = {}
    try:
        p = subprocess.run(
            cmd, capture_output=True, text=True, errors="replace",
            timeout=5, stdin=subprocess.DEVNULL, **kw
        )
    except Exception:
        return False, None
    out = p.stdout or ""
    ok = p.returncode == 0
    if IS_WIN and ok and "TTL=" not in out.upper():
        ok = False  # ويندوز يرجع 0 أحياناً مع "Destination host unreachable"
    if not ok:
        return False, None
    m = RTT_RE.search(out)
    if m:
        try:
            return True, float(m.group(1).replace(",", "."))
        except ValueError:
            pass
    return True, 1.0


def chain_has_down(device):
    seen = set()
    parent = device["parent"]
    while parent and parent in DEVS and parent not in seen:
        seen.add(parent)
        if DEVS[parent]["raw"] == "down":
            return True
        parent = DEVS[parent]["parent"]
    return False


def affected_by(name):
    count = 0
    for d in DEVS.values():
        if d["name"] == name or d["raw"] != "down":
            continue
        seen = set()
        parent = d["parent"]
        while parent and parent in DEVS and parent not in seen:
            if parent == name:
                count += 1
                break
            seen.add(parent)
            parent = DEVS[parent]["parent"]
    return count


# ---------------------------------------------------------------- تيليجرام
def email_ready():
    em = EMAIL or {}
    return bool(em.get("enabled") and em.get("host") and em.get("to"))


def webhook_ready():
    wh = WEBHOOK or {}
    url = str(wh.get("url") or "").strip()
    return bool(wh.get("enabled") and url.startswith(("http://", "https://")))


def webhook_on(kind):
    if not webhook_ready():
        return False
    kinds = (WEBHOOK or {}).get("kinds") or []
    return not kinds or not kind or kind in kinds


def notify(text, kind=None):
    text = str(text)
    log("إشعار: " + text.replace("\n", " | "))
    if kind and not notif_on(kind):
        return
    if email_ready():
        try:
            while EMAILQ.qsize() >= EMAIL_MAX_QUEUE:
                EMAILQ.get_nowait()
        except Exception:
            pass
        EMAILQ.put(str(text))
    if webhook_on(kind):
        try:
            while HOOKQ.qsize() >= HOOK_MAX_QUEUE:
                HOOKQ.get_nowait()
        except Exception:
            pass
        HOOKQ.put((text, kind or "info"))
    if not TG_ON:
        return
    try:
        while OUTQ.qsize() >= TG_MAX_QUEUE:
            OUTQ.get_nowait()
    except Exception:
        pass
    OUTQ.put(text)


_tg_session = requests.Session()


def tg_send(chat, text):
    """ترجع "ok" عند النجاح، "drop" عند خطأ دائم، و"retry" عند خطأ مؤقت."""
    try:
        r = _tg_session.post(
            f"https://api.telegram.org/bot{TOKEN}/sendMessage",
            data={
                "chat_id": chat,
                "text": text[:3900],
                "disable_web_page_preview": "true",
            },
            timeout=15,
        )
    except Exception:
        return "retry"  # غالباً الإنترنت مقطوع: تبقى الرسالة بالانتظار وتُرسل عند العودة
    if r.ok:
        return "ok"
    if r.status_code in (400, 403):
        log(f"تيليجرام رفض المحادثة {chat}: {r.status_code} {r.text[:120]}")
        return "drop"  # خطأ دائم: لا فائدة من إعادة المحاولة
    log(f"تيليجرام: {r.status_code} {r.text[:120]}")
    return "retry"


def tg_worker():
    pending = deque()  # عناصرها [نص, مجموعة المحادثات المتبقية]
    backoff = 5
    while True:
        try:
            while True:
                pending.append([OUTQ.get_nowait(), set(CHATS)])
        except queue.Empty:
            pass
        while len(pending) > TG_MAX_PENDING:
            pending.popleft()
        if not pending:
            time.sleep(1)
            continue
        item = pending[0]
        for chat in list(item[1]):
            if tg_send(chat, item[0]) != "retry":
                item[1].discard(chat)
        if not item[1]:
            pending.popleft()
            backoff = 5
        else:
            time.sleep(backoff)
            backoff = min(300, backoff * 2)


# ---------------------------------------------------------------- البريد
def email_send(subject, text):
    """يرسل رسالة بريد واحدة. يعيد None عند النجاح أو نص الخطأ."""
    em = dict(EMAIL or {})
    host = str(em.get("host") or "").strip()
    to = list(em.get("to") or [])
    if not host or not to:
        return "لم يُضبط خادم البريد أو المستلمون"
    sender = str(em.get("from") or em.get("user") or "").strip()
    if not sender:
        return "لم يُحدد مرسل البريد (from)"
    password = os.environ.get("NABD_SMTP_PASSWORD", "") or str(em.get("password") or "")
    msg = EmailMessage()
    msg["Subject"] = str(subject)[:180]
    msg["From"] = sender
    msg["To"] = ", ".join(to)
    msg.set_content(str(text))
    port = to_int(em.get("port"), 587) or 587
    context = ssl.create_default_context()
    try:
        if em.get("ssl"):
            server = smtplib.SMTP_SSL(host, port, timeout=25, context=context)
        else:
            server = smtplib.SMTP(host, port, timeout=25)
        with server:
            server.ehlo()
            if em.get("tls") and not em.get("ssl"):
                server.starttls(context=context)
                server.ehlo()
            if em.get("user"):
                server.login(em["user"], password)
            server.send_message(msg)
        return None
    except Exception as e:
        return str(e)


def email_worker():
    pending = deque()  # [نص, محاولات]
    while True:
        try:
            while True:
                pending.append([EMAILQ.get_nowait(), 0])
        except queue.Empty:
            pass
        while len(pending) > EMAIL_MAX_QUEUE:
            pending.popleft()
        if not pending:
            time.sleep(1)
            continue
        text, tries = pending[0]
        first = next((ln for ln in str(text).splitlines() if ln.strip()), "تنبيه نبض")
        err = email_send("نبض — " + first[:120], text)
        if err is None:
            pending.popleft()
            continue
        tries += 1
        pending[0][1] = tries
        if tries >= 3:
            log(f"تعذر إرسال البريد بعد 3 محاولات: {err}")
            pending.popleft()
        else:
            time.sleep(min(120, 15 * tries))


# ---------------------------------------------------------------- Webhook
_hook_session = requests.Session()


def webhook_send(text, kind="info", url=None, secret=None):
    """يرسل حدثاً JSON إلى Webhook. يعيد ok/drop/retry أو نص الخطأ للاختبار."""
    wh = WEBHOOK or {}
    url = str(url if url is not None else wh.get("url") or "").strip()
    if not url.startswith(("http://", "https://")) or len(url) > 2000:
        return "رابط Webhook غير صالح (يجب أن يبدأ بـ http:// أو https://)"
    secret = str(secret if secret is not None else wh.get("secret") or "")
    payload = {
        "source": "nabd",
        "version": VERSION,
        "kind": str(kind or "info")[:64],
        "title": str(text).splitlines()[0][:180] if str(text).splitlines() else "نبض",
        "text": str(text)[:8000],
        "timestamp": time.time(),
        "time": now_str(),
    }
    body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    headers = {
        "Content-Type": "application/json; charset=utf-8",
        "User-Agent": "Nabd/" + str(VERSION),
        "X-Nabd-Source": "nabd",
        "X-Nabd-Event": payload["kind"],
    }
    if secret:
        headers["X-Nabd-Signature"] = "sha256=" + hmac.new(
            secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    try:
        r = _hook_session.post(url, data=body, headers=headers, timeout=12)
    except Exception as e:
        return "retry"  # انقطاع شبكة مؤقت: تبقى الرسالة في الانتظار
    if 200 <= r.status_code < 300:
        return "ok"
    if r.status_code in (408, 429) or r.status_code >= 500:
        return f"retry ({r.status_code})"
    return f"drop ({r.status_code})"


def webhook_worker():
    pending = deque()  # [نص, نوع, محاولات]
    while True:
        try:
            while True:
                text, kind = HOOKQ.get_nowait()
                pending.append([text, kind, 0])
        except queue.Empty:
            pass
        while len(pending) > HOOK_MAX_QUEUE:
            pending.popleft()
        if not pending:
            time.sleep(1)
            continue
        text, kind, tries = pending[0]
        result = webhook_send(text, kind)
        if result == "ok" or result.startswith("drop"):
            pending.popleft()
            if result.startswith("drop"):
                log(f"Webhook رفض الإرسال: {result}")
            continue
        tries += 1
        pending[0][2] = tries
        if tries >= 3:
            log(f"تعذر إرسال Webhook بعد 3 محاولات: {result}")
            pending.popleft()
        else:
            time.sleep(min(60, 10 * tries))


# ---------------------------------------------------------------- دورة الفحص
def send_group(items, icon, title, tail_fn, kind=None):
    if not items:
        return
    stamp = now_str()
    if len(items) <= 5:
        for d in items:
            notify(
                f"{icon} {title}: {d['name']} ({d['ip']})\n"
                f"النوع: {d['kind']} | المجموعة: {d['group']}\n"
                f"{tail_fn(d)}الوقت: {stamp}",
                kind,
            )
        return
    groups = {}
    for d in items:
        groups[d["group"]] = groups.get(d["group"], 0) + 1
    lines = "\n".join(f"• {g}: {n}" for g, n in sorted(groups.items(), key=lambda x: -x[1]))
    names = "، ".join(d["name"] for d in items[:12]) + (" ..." if len(items) > 12 else "")
    notify(f"{icon} {title} ({len(items)} جهاز دفعة واحدة)\n{lines}\n{names}\nالوقت: {stamp}", kind)


def cycle():
    with LOCK:
        names = list(DEVS)

    def one(name):
        return name, *ping(DEVS[name]["ip"])

    with ThreadPoolExecutor(max_workers=max(1, min(WORKERS, 256))) as ex:
        results = list(ex.map(one, names))

    now = time.time()
    downs, ups = [], []
    deps, down_dur = {}, {}
    net_msg = None
    maint = maintenance_map()

    with LOCK:
        for name, ok, rtt in results:
            d = DEVS[name]
            if ok:
                d["fails"] = 0
                d["rtt"] = rtt
                d["raw"] = "up"
                d["last_ok"] = now
            else:
                d["fails"] += 1
                if d["fails"] >= THRESH and d["raw"] != "down":
                    d["raw"] = "down"
                    d["down_at"] = now
                    d["rtt"] = None

        for d in DEVS.values():
            old = d["eff"]
            if d["raw"] == "up":
                new = "up"
            elif d["raw"] == "down":
                new = "unreachable" if chain_has_down(d) else "down"
            else:
                new = "unknown"
            if new == d["eff"]:
                continue
            silent_maint = d["name"] in maint
            d["eff"] = new
            d["since"] = now
            if new == "down":
                if d["kind"] != "internet":
                    d["alerted"] = True
                    if not silent_maint:
                        downs.append(d)
                log_event(now, d["name"], d["ip"], "down")
            elif new == "unreachable":
                log_event(now, d["name"], d["ip"], "unreachable")
            elif new == "up":
                if d["alerted"]:
                    d["alerted"] = False
                    if not silent_maint:
                        ups.append(d)
                if old != "unknown":
                    log_event(now, d["name"], d["ip"], "up")

        deps = {d["name"]: affected_by(d["name"]) for d in downs}
        down_dur = {d["name"]: now - (d["down_at"] or d["since"]) for d in ups}

        # حالة الإنترنت: نعتمد على الفحص المباشر لخوادم الإنترنت.
        # هذا يتعامل أيضاً مع انقطاع الإنترنت الذي يكون سببه الراوتر نفسه.
        nets = [d for d in DEVS.values() if d["kind"] == "internet"]
        NET["probes"] = len(nets)
        NET["probes_up"] = sum(1 for d in nets if d["raw"] == "up")
        if nets:
            if NET["probes_up"] > 0:
                ns = "up"
            elif all(d["raw"] == "down" for d in nets):
                ns = "down"
            else:
                ns = NET["state"]
            if ns != NET["state"]:
                isp = next((d for d in DEVS.values() if d["kind"] == "isp"), None)
                isp_txt = ""
                if isp:
                    isp_txt = "\nبوابة المزود: " + ("متاحة" if isp["raw"] == "up" else "لا تستجيب") + "\n"
                if ns == "down":
                    NET["down_at"] = now
                    net_msg = f"🌐❌ انقطع الإنترنت{isp_txt}\nالوقت: {now_str()}"
                    log_event(now, "الإنترنت", "-", "down")
                elif NET["state"] == "down":
                    dur = fmt_dur(now - (NET["down_at"] or now))
                    net_msg = f"🌐✅ عاد الإنترنت\nمدة الانقطاع: {dur}\nالوقت: {now_str()}"
                    log_event(now, "الإنترنت", "-", "up")
                NET["state"] = ns
                NET["since"] = now
        NET["ready"] = True

    def down_tail(d):
        n = deps.get(d["name"], 0)
        return f"⛓ بسببه تعذّر الوصول إلى {n} جهاز\n" if n else ""

    send_group(downs, "🔴", "سقط", down_tail, "device_down")
    send_group(ups, "🟢", "رجع", lambda d: f"مدة الانقطاع: {fmt_dur(down_dur.get(d['name'], 0))}\n", "device_up")
    if net_msg:
        notify(net_msg, "internet")


def monitor_loop():
    last_hb = None
    last_prune = None
    while True:
        started = time.time()
        try:
            cycle()
        except Exception as e:
            log(f"خطأ في دورة الفحص: {e}")
        try:
            record_samples()
        except Exception as e:
            log(f"خطأ في حفظ القياسات: {e}")
        try:
            today = date.today()
            if last_prune != today:
                prune_events()
                prune_samples()
                last_prune = today
            now = datetime.now()
            if HB_HOUR is not None and now.hour == HB_HOUR and last_hb != today:
                last_hb = today
                with LOCK:
                    vals = list(DEVS.values())
                up = sum(1 for d in vals if d["eff"] == "up")
                bad = [d["name"] for d in vals if d["eff"] == "down"]
                unreachable = sum(1 for d in vals if d["eff"] == "unreachable")
                txt = f"💓 نبض يعمل بشكل طبيعي\nمتصل: {up} من {len(vals)}"
                if bad:
                    txt += f"\nمتوقف: {len(bad)} ← " + "، ".join(bad[:15])
                if unreachable:
                    txt += f"\nتعذر الوصول (بسبب جهاز أعلى): {unreachable}"
                notify(txt, "daily_report")
        except Exception as e:
            log(f"خطأ في التقرير اليومي: {e}")
        time.sleep(max(1, INTERVAL - (time.time() - started)))


# ---------------------------------------------------------------- SNMP والمراقبة الاحترافية
SYS_OIDS = {
    "descr": "1.3.6.1.2.1.1.1.0",
    "objectid": "1.3.6.1.2.1.1.2.0",
    "uptime": "1.3.6.1.2.1.1.3.0",
    "name": "1.3.6.1.2.1.1.5.0",
    "contact": "1.3.6.1.2.1.1.4.0",
    "location": "1.3.6.1.2.1.1.6.0",
}
IF_BASE = "1.3.6.1.2.1.2.2.1"
IF_COLUMNS = {2: "descr", 3: "type", 5: "speed_bps", 6: "mac", 7: "admin",
              8: "oper", 10: "in_octets", 13: "in_discards", 14: "in_errors",
              16: "out_octets", 19: "out_discards", 20: "out_errors"}
IFX_BASE = "1.3.6.1.2.1.31.1.1.1"
IFX_COLUMNS = {1: "name", 6: "in_hc", 10: "out_hc", 15: "high_speed", 18: "alias"}
CPU_WALK = "1.3.6.1.2.1.25.3.3.1.2"
CPU_UCD_IDLE = "1.3.6.1.4.1.2021.11.11.0"
MEM_BASE = "1.3.6.1.2.1.25.2.3.1"
MEM_COLUMNS = {3: "descr", 4: "unit", 5: "size", 6: "used"}
UCD_MEM_TOTAL = "1.3.6.1.4.1.2021.4.5.0"
UCD_MEM_AVAIL = "1.3.6.1.4.1.2021.4.6.0"
MT_OPT_BASE = "1.3.6.1.4.1.14988.1.1.19.1.1"
MT_OPT_COLUMNS = {1: "index", 2: "name", 3: "rx_loss", 4: "tx_fault",
                  5: "wavelength", 6: "temp", 7: "voltage", 8: "bias",
                  9: "tx_power", 10: "rx_power", 11: "vendor", 12: "serial"}
MT_WL_RTAB = "1.3.6.1.4.1.14988.1.1.1.2.1"
MT_WL_RTAB_COLUMNS = {1: "mac", 2: "iface", 3: "signal", 4: "tx_bytes",
                      5: "rx_bytes", 6: "tx_packets", 7: "rx_packets",
                      8: "tx_rate", 9: "rx_rate", 11: "uptime", 12: "snr"}
MT_WL_AP = "1.3.6.1.4.1.14988.1.1.1.3.1"
MT_WL_AP_COLUMNS = {4: "ssid", 5: "bssid", 6: "stations"}
MT_WL_STAT = "1.3.6.1.4.1.14988.1.1.1.1.1"
MT_WL_STAT_COLUMNS = {2: "tx_rate", 3: "rx_rate", 4: "signal", 5: "ssid",
                      6: "bssid", 7: "freq", 8: "band", 9: "tx_ccq", 10: "rx_ccq"}
UB_WL_STAT = "1.3.6.1.4.1.41112.1.4.5.1"
UB_WL_STAT_COLUMNS = {2: "ssid", 4: "ap_mac", 5: "signal", 6: "rssi",
                      7: "ccq", 8: "noise", 9: "tx_rate", 10: "rx_rate",
                      15: "stations"}
UB_WL_STA = "1.3.6.1.4.1.41112.1.4.7.1"
UB_WL_STA_COLUMNS = {1: "mac", 2: "name", 3: "signal", 4: "noise", 5: "distance",
                     6: "ccq", 10: "ip", 11: "tx_rate", 12: "rx_rate",
                     13: "tx_bytes", 14: "rx_bytes"}
MT_HEALTH_TEMP = "1.3.6.1.4.1.14988.1.1.3.10.0"
MT_HEALTH_CPU_TEMP = "1.3.6.1.4.1.14988.1.1.3.11.0"


def _num(value, default=None):
    if isinstance(value, bool) or value is None:
        return default
    if isinstance(value, (int, float)):
        return value
    try:
        text = str(value).strip()
        return float(text) if "." in text else int(text)
    except (TypeError, ValueError):
        return default


def _safe_walk(client, base, max_rows=4000):
    try:
        return client.walk(base, max_rows=max_rows)
    except (SNMPError, OSError):
        return {}


def _walk_table(client, base, columns, max_rows=4000):
    """جدول متسامح: يتوقف عند أول عمود لا يستجيب بدل تعليق الاستعلام."""
    out = {}
    for col, name in columns.items():
        try:
            walked = client.walk(f"{base}.{col}", max_rows=max_rows)
        except (SNMPError, OSError):
            break
        prefix = f"{base}.{col}."
        for oid, value in walked.items():
            if not oid.startswith(prefix):
                continue
            idx = oid[len(prefix):]
            out.setdefault(idx, {})[name] = value
    return out


def _detect_vendor(descr, objectid, profile=""):
    profile = str(profile or "auto").lower()
    if profile in ("mikrotik", "routeros"):
        return "mikrotik"
    if profile in ("ubiquiti", "ubnt"):
        return "ubiquiti"
    if profile == "generic":
        return "generic"
    text = str(descr or "").lower()
    oid = str(objectid or "")
    if oid.startswith("1.3.6.1.4.1.14988") or "routeros" in text or "mikrotik" in text:
        return "mikrotik"
    if oid.startswith("1.3.6.1.4.1.41112") or "ubiquiti" in text or "airmax" in text or "air os" in text:
        return "ubiquiti"
    return "generic"


def _alert_ready(kind, name, key=""):
    cooldown = _as_int(SNMP.get("alert_cooldown_minutes", 30), 30, 0) * 60
    now = time.time()
    skey = (kind, name, key)
    with SNMP_LOCK:
        last = SNMP_ALERTS.get(skey, 0)
        if cooldown and now - last < cooldown:
            return False
        SNMP_ALERTS[skey] = now
        if len(SNMP_ALERTS) > 4000:
            cut = now - 86400
            for k, when in list(SNMP_ALERTS.items()):
                if when < cut:
                    SNMP_ALERTS.pop(k, None)
    return True


def _snmp_credentials(dev):
    community = (dev.get("snmp_community") or "").strip() or str(SNMP.get("community") or "public")
    return community, _as_int(SNMP.get("port", 161), 161, 1), _as_range(
        SNMP.get("timeout", 1.5), 1.5, 0.2, 15), _as_int(SNMP.get("retries", 1), 1, 0)


def _if_name(row, index):
    return str(row.get("name") or row.get("descr") or f"if{index}").strip()


def _read_cpu(client, vendor):
    total, count = 0, 0
    walked = _safe_walk(client, CPU_WALK, max_rows=64)
    for value in walked.values():
        n = _num(value)
        if n is not None and 0 <= n <= 100:
            total += n
            count += 1
    if count:
        return round(total / count, 1)
    idle = _num(client.get_one(CPU_UCD_IDLE))
    if idle is not None and 0 <= idle <= 100:
        return round(100 - idle, 1)
    return None


def _read_memory(client):
    rows = _walk_table(client, MEM_BASE, MEM_COLUMNS, max_rows=128)
    best = None
    for row in rows.values():
        descr = str(row.get("descr") or "").lower()
        unit = _num(row.get("unit"))
        size = _num(row.get("size"))
        used = _num(row.get("used"))
        if unit is None or size is None:
            continue
        if size <= 0:
            continue
        score = size * unit
        if any(k in descr for k in ("physical", "main memory", "system memory", "ram")):
            score *= 4
        if best is None or score > best[0]:
            best = (score, unit, size, used or 0, descr)
    if best:
        _score, unit, size, used, descr = best
        total = int(size * unit)
        used_b = int(min(size, used) * unit)
        pct = round(used_b * 100 / total, 1) if total else None
        return {"total": total, "used": used_b,
                "free": max(0, total - used_b), "pct": pct, "label": descr}
    total_kb = _num(client.get_one(UCD_MEM_TOTAL))
    avail_kb = _num(client.get_one(UCD_MEM_AVAIL))
    if total_kb and avail_kb is not None:
        total = int(total_kb * 1024)
        free = int(max(0, min(total_kb, avail_kb)) * 1024)
        return {"total": total, "used": total - free, "free": free,
                "pct": round((total - free) * 100 / total, 1) if total else None,
                "label": "RAM"}
    return None


def _read_interfaces(client, rates_prev, now):
    base_rows = _walk_table(client, IF_BASE, IF_COLUMNS)
    xrows = _walk_table(client, IFX_BASE, IFX_COLUMNS)
    interfaces = []
    total_in = total_out = 0.0
    prev_oper = {}
    for idx, row in base_rows.items():
        xrow = xrows.get(idx, {})
        name = _if_name({**row, **xrow}, idx)
        admin = _num(row.get("admin"))
        oper = _num(row.get("oper"))
        high = _num(xrow.get("high_speed"))
        if high is not None and high > 0:
            speed = round(high, 1)
        else:
            speed = round((_num(row.get("speed_bps"), 0) or 0) / 1_000_000, 1)
        in_oct = _num(xrow.get("in_hc"))
        if in_oct is None:
            in_oct = _num(row.get("in_octets"), 0)
        out_oct = _num(xrow.get("out_hc"))
        if out_oct is None:
            out_oct = _num(row.get("out_octets"), 0)
        in_oct, out_oct = int(in_oct or 0), int(out_oct or 0)
        in_bps = out_bps = 0
        was = rates_prev.get(idx)
        if was:
            p_ts, p_in, p_out, p_oper = was
            dt = now - p_ts
            if dt > 0.5:
                if in_oct >= p_in:
                    in_bps = round((in_oct - p_in) * 8 / dt)
                if out_oct >= p_out:
                    out_bps = round((out_oct - p_out) * 8 / dt)
            prev_oper[name] = p_oper
        total_in += in_bps
        total_out += out_bps
        interfaces.append({
            "index": idx, "name": name,
            "descr": str(row.get("descr") or ""),
            "alias": str(xrow.get("alias") or ""),
            "type": _num(row.get("type"), 0),
            "mac": str(row.get("mac") or ""),
            "admin": int(admin) if admin is not None else None,
            "oper": int(oper) if oper is not None else None,
            "speed": speed,
            "in_octets": in_oct, "out_octets": out_oct,
            "in_bps": in_bps, "out_bps": out_bps,
            "in_errors": int(_num(row.get("in_errors"), 0) or 0),
            "out_errors": int(_num(row.get("out_errors"), 0) or 0),
            "in_discards": int(_num(row.get("in_discards"), 0) or 0),
            "out_discards": int(_num(row.get("out_discards"), 0) or 0),
        })
    interfaces.sort(key=lambda r: (
        0 if (r["oper"] == 1) else 1,
        0 if "/" not in r["name"] else 1,
        r["name"],
    ))
    new_prev = {r["index"]: (now, r["in_octets"], r["out_octets"], r["oper"])
                for r in interfaces}
    return interfaces, new_prev, round(total_in), round(total_out)


def _read_optical(client, vendor):
    if vendor not in ("mikrotik", "auto"):
        return []
    rows = _walk_table(client, MT_OPT_BASE, MT_OPT_COLUMNS, max_rows=64)
    sfp = []
    for idx, row in rows.items():
        name = str(row.get("name") or "").strip() or f"SFP {idx}"
        def scaled(key, div):
            value = _num(row.get(key))
            return round(value / div, 2) if value is not None else None
        rx = scaled("rx_power", 1000)
        tx = scaled("tx_power", 1000)
        wavelength = _num(row.get("wavelength"))
        sfp.append({
            "index": idx, "name": name,
            "rx": rx, "tx": tx,
            "temp": _num(row.get("temp")),
            "voltage": scaled("voltage", 1000),
            "bias": scaled("bias", 1000),
            "wavelength": round(wavelength / 100) if wavelength else None,
            "rx_loss": bool(_num(row.get("rx_loss"), 0)),
            "tx_fault": bool(_num(row.get("tx_fault"), 0)),
            "vendor": str(row.get("vendor") or ""),
            "serial": str(row.get("serial") or ""),
        })
    sfp.sort(key=lambda r: r["name"])
    return sfp


def _read_wifi(client, vendor):
    wifi = []
    errors = 0
    def add(row, kind, extra=None):
        item = {"kind": kind, "mac": str(row.get("mac") or ""),
                "name": str(row.get("name") or ""),
                "ssid": str(row.get("ssid") or ""),
                "signal": _num(row.get("signal")),
                "noise": _num(row.get("noise")),
                "snr": _num(row.get("snr")),
                "tx_rate": _num(row.get("tx_rate")),
                "rx_rate": _num(row.get("rx_rate")),
                "ccq": _num(row.get("ccq")),
                "freq": _num(row.get("freq")),
                "band": str(row.get("band") or ""),
                "ip": str(row.get("ip") or ""),
                "uptime": _num(row.get("uptime")),
                "tx_bytes": _num(row.get("tx_bytes")),
                "rx_bytes": _num(row.get("rx_bytes"))}
        if extra:
            item.update(extra)
        wifi.append(item)
    if vendor in ("mikrotik", "auto"):
        rows = _walk_table(client, MT_WL_RTAB, MT_WL_RTAB_COLUMNS, max_rows=2000)
        for _idx, row in rows.items():
            add(row, "client")
        aps = _walk_table(client, MT_WL_AP, MT_WL_AP_COLUMNS, max_rows=256)
        for idx, row in aps.items():
            add(row, "ap", {"name": f"AP {idx}", "ccq": None})
        radios = _walk_table(client, MT_WL_STAT, MT_WL_STAT_COLUMNS, max_rows=256)
        for idx, row in radios.items():
            add(row, "radio", {"name": str(row.get("ssid") or f"radio{idx}"),
                               "ccq": _num(row.get("tx_ccq"))})
    if vendor in ("ubiquiti", "auto"):
        rows = _walk_table(client, UB_WL_STA, UB_WL_STA_COLUMNS, max_rows=2000)
        for _idx, row in rows.items():
            add(row, "client")
        aps = _walk_table(client, UB_WL_STAT, UB_WL_STAT_COLUMNS, max_rows=256)
        for idx, row in aps.items():
            add(row, "ap", {"name": f"AP {idx}",
                            "ccq": _num(row.get("ccq")),
                            "stations": _num(row.get("stations"))})
    if not wifi:
        return []
    # إزالة التكرار: نفس MAC قد يظهر في جدول العميل وجدول الراديو
    seen, unique = set(), []
    for item in wifi:
        key = (item["kind"], item["mac"] or item["name"] or item["ssid"])
        if key in seen:
            continue
        seen.add(key)
        unique.append(item)
    unique.sort(key=lambda r: (0 if r["kind"] == "client" else 1,
                               -(r["signal"] if isinstance(r["signal"], (int, float)) else -999)))
    return unique


def _read_temperature(client, vendor):
    if vendor == "mikrotik":
        for oid in (MT_HEALTH_TEMP, MT_HEALTH_CPU_TEMP):
            value = _num(client.get_one(oid))
            if value is not None and 0 < value < 150:
                return value
    return None


def poll_device(name, force=False):
    """يستعلم جهازاً واحداً عبر SNMP ويحدّث الحالة والرسوم والتنبيهات."""
    with LOCK:
        dev = DEVS.get(name)
        dev = dict(dev) if dev else None
    if not dev:
        return {"ok": False, "error": "لم أجد الجهاز"}
    silent = suppressed(name)
    now = time.time()
    community, port, timeout, retries = _snmp_credentials(dev)
    state_prev = SNMP_STATE.get(name) or {}
    try:
        client = SNMPClient(dev["ip"], community, port=port,
                            timeout=timeout, retries=retries)
        sysvals = client.get(list(SYS_OIDS.values()))
        sysmap = {key: sysvals.get(oid) for key, oid in SYS_OIDS.items()}
        descr = sysmap.get("descr")
        if descr is None and not sysmap.get("objectid"):
            raise SNMPTimeout("لا استجابة SNMP")
        vendor = _detect_vendor(descr, sysmap.get("objectid"), dev.get("profile"))
        cpu = _read_cpu(client, vendor)
        memory = _read_memory(client)
        interfaces, new_prev, total_in, total_out = _read_interfaces(
            client, SNMP_PREV.get(name, {}), now)
        sfp = _read_optical(client, vendor)
        wifi = _read_wifi(client, vendor)
        temp = _read_temperature(client, vendor)
        sysmap["uptime_ticks"] = _num(sysmap.get("uptime"))
        sysmap["uptime_seconds"] = round((sysmap["uptime_ticks"] or 0) / 100) if sysmap.get("uptime_ticks") else None
        sysmap["descr"] = str(descr or "")
        sysmap["name"] = str(sysmap.get("name") or "")
        sysmap["location"] = str(sysmap.get("location") or "")
        sysmap["contact"] = str(sysmap.get("contact") or "")
        sysmap["objectid"] = str(sysmap.get("objectid") or "")
        client.close()
    except (SNMPError, OSError, ValueError) as e:
        err = str(e) or "تعذر الاستعلام"
        with SNMP_LOCK:
            prev = SNMP_STATE.get(name)
            if prev:
                prev = dict(prev)
                prev.update({"at": now, "ok": False, "error": err})
            else:
                prev = {"at": now, "ok": False, "error": err, "summary": {}}
            SNMP_STATE[name] = prev
        return {"ok": False, "error": err, "at": now}

    port_alerts = []
    prev_state = state_prev if state_prev.get("ok") else {}
    prev_interfaces = {r["name"]: r for r in (prev_state.get("interfaces") or [])}
    for row in interfaces:
        before = prev_interfaces.get(row["name"])
        if before and before.get("oper") == 1 and row.get("oper") != 1 and row.get("admin") == 1:
            key = row["name"]
            if not silent and _alert_ready("port_down", name, key):
                port_alerts.append(row)

    cpu_hits = int(state_prev.get("cpu_hits") or 0)
    cpu_warn = _as_int(SNMP.get("cpu_warn", 85), 85, 1)
    if cpu is not None and cpu >= cpu_warn:
        cpu_hits += 1
    else:
        cpu_hits = 0
    if cpu_hits >= 2 and not silent and _alert_ready("high_cpu", name):
        log_event(now, name, dev["ip"], "high_cpu")
        notify(f"🔥 حمل معالج مرتفع: {name} ({dev['ip']})\n"
               f"CPU: {cpu}% (الحد {cpu_warn}%)\nالوقت: {now_str()}", "high_cpu")

    sfp_min = _as_range(SNMP.get("sfp_rx_min", -20.0), -20.0, -60, 10)
    prev_sfp = {r["name"]: r for r in (state_prev.get("sfp") or [])}
    for row in sfp:
        rx = row.get("rx")
        before = prev_sfp.get(row["name"]) or {}
        low_now = (row.get("rx_loss") or
                   (isinstance(rx, (int, float)) and -60 <= rx <= sfp_min))
        was_low = (before.get("rx_loss") or
                   (isinstance(before.get("rx"), (int, float)) and -60 <= before.get("rx") <= sfp_min))
        if low_now and not was_low and not silent and _alert_ready("sfp_low", name, row["name"]):
            log_event(now, name, dev["ip"], "sfp_low")
            notify(f"🔻 ضعف إشارة SFP: {name} ({dev['ip']})\n"
                   f"المنفذ: {row['name']} | الاستقبال: {rx} dBm (الحد {sfp_min} dBm)\n"
                   f"الوقت: {now_str()}", "sfp_low")

    if port_alerts:
        log_event(now, name, dev["ip"], "port_down")
        lines = "\n".join(
            f"• {r['name']} — السرعة {r['speed']} Mbps" for r in port_alerts[:12])
        more = f"\n... و{len(port_alerts) - 12} منفذاً آخر" if len(port_alerts) > 12 else ""
        notify(f"🔌 سقط منفذ/منافذ في {name} ({dev['ip']})\n{lines}{more}\n"
               f"الوقت: {now_str()}", "port_down")

    history = SNMP_HISTORY.get(name)
    if history is None:
        history = deque(maxlen=_as_int(SNMP.get("history_points", 120), 120, 10))
        SNMP_HISTORY[name] = history
    history.append((now, total_in, total_out))

    up_ports = sum(1 for r in interfaces if r.get("oper") == 1)
    result = {
        "at": now, "ok": True, "error": "",
        "sys": sysmap, "vendor": vendor,
        "cpu": cpu, "cpu_hits": cpu_hits, "mem": memory, "temp": temp,
        "interfaces": interfaces, "sfp": sfp, "wifi": wifi,
        "total": {"in_bps": total_in, "out_bps": total_out},
        "summary": {
            "at": now, "ok": True, "cpu": cpu, "mem_pct": (memory or {}).get("pct"),
            "temp": temp, "uptime": sysmap.get("uptime_seconds"),
            "sysname": sysmap.get("name") or "",
            "descr": sysmap.get("descr") or "",
            "vendor": vendor,
            "ports": len(interfaces), "ports_up": up_ports,
            "wifi": len(wifi), "sfp": len(sfp),
            "in_bps": total_in, "out_bps": total_out,
            "max_temp": max([r.get("temp") for r in sfp if isinstance(r.get("temp"), (int, float))] or [temp or 0]) or None,
        },
    }
    with SNMP_LOCK:
        SNMP_STATE[name] = result
        SNMP_PREV[name] = new_prev
    return result


def snmp_candidates():
    with LOCK:
        devs = [dict(d) for d in DEVS.values()]
    out = []
    for d in devs:
        mode = (d.get("snmp") or "auto").lower()
        if mode in ("off", "0", "no", "false"):
            continue
        kind = (d.get("kind") or "").lower()
        if mode in ("on", "1", "yes", "true"):
            out.append(d)
        elif kind not in ("internet", "isp", "dvr", "camera", "printer"):
            out.append(d)
    return out


def poll_all(force=False):
    if not SNMP_ON:
        return {"ok": False, "error": "SNMP متوقف من الإعدادات"}
    if not SNMP_POLL_LOCK.acquire(False):
        return {"ok": False, "error": "استعلام SNMP قيد التنفيذ"}
    try:
        devs = snmp_candidates()
        with SNMP_LOCK:
            queued = [(d["name"], d["ip"]) for d in devs]
            SNMP_POLL_STATE.update({"running": True, "started": time.time(),
                                    "finished": 0.0, "done": 0, "total": len(queued),
                                    "ok": 0, "error": ""})
        ok = 0
        if queued:
            def one(item):
                return poll_device(item[0], force=force)
            with ThreadPoolExecutor(max_workers=min(8, len(queued))) as ex:
                for result in ex.map(one, queued):
                    if result.get("ok"):
                        ok += 1
                    with SNMP_LOCK:
                        SNMP_POLL_STATE["done"] += 1
                        SNMP_POLL_STATE["ok"] = ok
        with SNMP_LOCK:
            SNMP_POLL_STATE.update({"running": False, "finished": time.time(),
                                    "ok": ok})
        return {"ok": True, "total": len(queued), "responded": ok}
    finally:
        SNMP_POLL_LOCK.release()


def snmp_loop():
    time.sleep(15)
    last = 0.0
    while True:
        try:
            if SNMP_ON:
                interval = _as_int(SNMP.get("poll_seconds", 60), 60, 10)
                if last == 0 or time.time() - last >= interval:
                    last = time.time()
                    poll_all()
        except Exception as e:
            log(f"خطأ في استعلام SNMP: {e}")
        time.sleep(5)


def snmp_summary(name):
    with SNMP_LOCK:
        state = SNMP_STATE.get(name)
        if not state:
            return None
        summary = dict(state.get("summary") or {})
        summary["ok"] = bool(state.get("ok"))
        summary["error"] = state.get("error") or ""
        summary["at"] = state.get("at")
        return summary


def snmp_history(name):
    points = SNMP_HISTORY.get(name)
    if not points:
        return []
    return [[round(ts, 1), in_bps, out_bps] for ts, in_bps, out_bps in points]


def snmp_snapshot(name):
    with SNMP_LOCK:
        state = SNMP_STATE.get(name)
        if not state:
            return None
        return copy.deepcopy(state)


def active_alerts():
    """يجمع المشاكل الحالية من ping وSNMP في قائمة مركز التنبيهات."""
    now = time.time()
    maint = maintenance_map()
    try:
        acked = {r[0] for r in db_exec("SELECT key FROM alert_acks")}
    except Exception:
        acked = set()
    with LOCK:
        devs = [dict(d) for d in DEVS.values()]
    with SNMP_LOCK:
        states = {n: dict(s) for n, s in SNMP_STATE.items()}
    cpu_warn = _as_int(SNMP.get("cpu_warn", 85), 85, 1)
    sfp_min = _as_range(SNMP.get("sfp_rx_min", -20.0), -20.0, -60, 10)
    alerts = []

    def add(key, d, severity, etype, message, since, detail=""):
        alerts.append({
            "key": key, "name": d["name"], "ip": d["ip"],
            "group": d.get("group") or "—", "severity": severity,
            "type": etype, "message": message, "since": since,
            "duration": max(0, now - since) if since else 0,
            "detail": detail, "acked": key in acked,
        })

    for d in devs:
        name = d["name"]
        if name in maint:
            continue
        if d["eff"] == "down":
            add("device:" + name, d, "critical", "device_down",
                "الجهاز لا يستجيب للـ ping", d.get("down_at") or d.get("since"),
                "توقف كامل — تحقق من الطاقة والشبكة")
        elif d["eff"] == "unreachable":
            add("unreachable:" + name, d, "warning", "unreachable",
                "لا يمكن الوصول إليه بسبب توقف جهاز أعلى", d.get("since"),
                "تابع الجهاز الأب: " + (d.get("parent") or "—"))
        if d["eff"] in ("down", "unreachable", "unknown"):
            continue
        st = states.get(name)
        if not st or not st.get("ok"):
            continue
        cpu = st.get("cpu")
        if isinstance(cpu, (int, float)) and cpu >= cpu_warn:
            add("cpu:" + name, d, "warning", "high_cpu",
                "ارتفاع حمل المعالج", st.get("at") or now,
                f"CPU: {round(cpu)}% (الحد {cpu_warn}%)")
        down_ports = []
        for r in (st.get("interfaces") or []):
            if (r.get("admin") == 1 and r.get("oper") != 1 and
                    ((r.get("in_octets") or 0) > 0 or (r.get("out_octets") or 0) > 0)):
                down_ports.append(r)
        for r in down_ports[:8]:
            add("port:" + name + ":" + str(r.get("name")), d, "warning", "port_down",
                "منفذ مستخدم متوقف: " + str(r.get("name")), st.get("at") or now,
                "السرعة: " + str(r.get("speed") or "—") + " Mbps")
        if len(down_ports) > 8:
            add("ports:" + name, d, "warning", "port_down",
                f"منافذ متوقفة إضافية: {len(down_ports) - 8}", st.get("at") or now)
        for r in (st.get("sfp") or []):
            rx = r.get("rx")
            low = r.get("rx_loss") or (isinstance(rx, (int, float)) and -60 <= rx <= sfp_min)
            if low:
                add("sfp:" + name + ":" + str(r.get("name")), d, "critical",
                    "sfp_low", "ضعف إشارة SFP: " + str(r.get("name")),
                    st.get("at") or now,
                    "الاستقبال: " + str(rx) + " dBm (الحد " + str(sfp_min) + " dBm)")

    order = {"critical": 0, "warning": 1, "info": 2}
    alerts.sort(key=lambda a: (order.get(a["severity"], 9), -a["duration"], a["name"]))
    return {
        "at": now, "alerts": alerts,
        "counts": {
            "total": len(alerts),
            "critical": sum(1 for a in alerts if a["severity"] == "critical"),
            "warning": sum(1 for a in alerts if a["severity"] == "warning"),
            "unacked": sum(1 for a in alerts if not a["acked"]),
        },
        "maintenance": [{"name": n, "until": u} for n, u in sorted(maint.items())],
    }


# ---------------------------------------------------------------- لوحة التحكم
app = Flask(__name__)
try:
    app.json.ensure_ascii = False
except Exception:
    pass


@app.before_request
def _auth():
    if request.endpoint in ("healthz", "favicon"):
        return None
    if not DASH_PW:
        return None
    a = request.authorization
    if not a or not hmac.compare_digest(str(a.password or ""), DASH_PW):
        return Response("مطلوب كلمة المرور", 401, {"WWW-Authenticate": 'Basic realm="Nabd"'})
    return None


@app.after_request
def _headers(resp):
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
    resp.headers.setdefault("Referrer-Policy", "same-origin")
    if request.path == "/" or request.path.startswith("/api/"):
        resp.headers["Cache-Control"] = "no-store, max-age=0"
    return resp


@app.route("/api/status")
def api_status():
    limit = request.args.get("limit", 40, type=int)
    if limit is None:
        limit = 40
    limit = max(1, min(200, limit))
    with LOCK:
        devs = [
            {k: d[k] for k in ("name", "ip", "kind", "group", "parent", "eff", "rtt",
                               "since", "last_ok", "down_at", "ports", "ports_at",
                               "snmp", "snmp_community", "profile")}
            for d in DEVS.values()
        ]
        net = {k: NET[k] for k in ("state", "since", "down_at", "probes", "probes_up", "ready")}
    maint = maintenance_map()
    for d in devs:
        d["maint_until"] = maint.get(d["name"], 0)
        d["snmp_info"] = snmp_summary(d["name"])
    snmp_list = [d["snmp_info"] for d in devs if d.get("snmp_info")]
    with SNMP_LOCK:
        snmp_poll = dict(SNMP_POLL_STATE)
    snmp_block = {
        "enabled": bool(SNMP_ON),
        "monitored": len(snmp_candidates()),
        "responded": sum(1 for s in snmp_list if s.get("ok")),
        "poll": snmp_poll,
    }
    counts = {"total": len(devs), "up": 0, "down": 0, "unreachable": 0, "unknown": 0}
    for d in devs:
        counts[d["eff"]] = counts.get(d["eff"], 0) + 1
    try:
        rows = db_exec(
            "SELECT ts,name,ip,etype FROM events ORDER BY ts DESC LIMIT ?", (limit,)
        )
    except Exception:
        rows = []
    events = [{"ts": r[0], "name": r[1], "ip": r[2], "type": r[3]} for r in rows]
    return jsonify({
        "now": time.time(),
        "started": STARTED_AT,
        "interval": INTERVAL,
        "live": LIVE_SECONDS,
        "version": VERSION,
        "counts": counts,
        "net": net,
        "snmp": snmp_block,
        "alerts": alert_counts(),
        "auth": bool(DASH_PW),
        "devices": devs,
        "events": events,
    })


@app.route("/api/metrics/<name>")
def api_metrics(name):
    rng = request.args.get("range", "24h")
    if rng not in SAMPLE_RANGES:
        return jsonify({"ok": False, "error": "مدة غير صالحة"}), 400
    return jsonify(metrics_series(name, rng))


@app.route("/api/reports")
def api_reports():
    rng = request.args.get("range", "24h")
    if rng not in SAMPLE_RANGES:
        return jsonify({"ok": False, "error": "مدة غير صالحة"}), 400
    return jsonify(sla_report(rng))


@app.route("/api/reports/export")
def api_reports_export():
    rng = request.args.get("range", "24h")
    if rng not in SAMPLE_RANGES:
        return jsonify({"ok": False, "error": "مدة غير صالحة"}), 400
    rep = sla_report(rng) or {"devices": []}
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["الجهاز", "IP", "المجموعة", "التوفر %", "متوسط التأخير ms",
                "انقطاعات", "زمن التوقف (ثانية)", "MTTR (ثانية)", "CPU %",
                "الذاكرة %", "ذروة الدخول bps", "ذروة الخروج bps", "صيانة (ثانية)",
                "العينات"])
    for d in rep["devices"]:
        w.writerow([d["name"], d["ip"], d["group"], d["pct"], d["avg_rtt"],
                    d["outages"], d["downtime"], d["mttr"], d["avg_cpu"],
                    d["avg_mem"], d["peak_in"], d["peak_out"],
                    d.get("maintenance", 0), d["samples"]])
    return Response("\ufeff" + buf.getvalue(),
                    mimetype="text/csv; charset=utf-8",
                    headers={"Content-Disposition":
                             'attachment; filename="nabd-sla-' + rng + '.csv"'})


def event_filters():
    q = str(request.args.get("q") or "").strip()[:120]
    etype = str(request.args.get("type") or "").strip()[:40]
    name = str(request.args.get("name") or "").strip()[:120]
    rng = str(request.args.get("range") or "24h").strip()
    if rng not in SAMPLE_RANGES and rng != "all":
        rng = "24h"
    limit = request.args.get("limit", 200, type=int)
    if limit is None:
        limit = 200
    limit = max(1, min(2000, limit))
    clauses, args = [], []
    if rng != "all":
        clauses.append("ts>=?")
        args.append(time.time() - SAMPLE_RANGES[rng])
    if q:
        clauses.append("(name LIKE ? OR ip LIKE ? OR etype LIKE ?)")
        args.extend(["%" + q + "%"] * 3)
    if etype:
        clauses.append("etype=?")
        args.append(etype)
    if name:
        clauses.append("name=?")
        args.append(name)
    where = " WHERE " + " AND ".join(clauses) if clauses else ""
    return where, args, limit, {"q": q, "type": etype, "name": name,
                                "range": rng, "limit": limit}


@app.route("/api/events")
def api_events():
    where, args, limit, meta = event_filters()
    try:
        rows = db_exec("SELECT ts,name,ip,etype FROM events" + where +
                       " ORDER BY ts DESC LIMIT ?", tuple(args) + (limit,))
        counts = db_exec("SELECT etype, COUNT(*) FROM events" + where +
                         " GROUP BY etype ORDER BY COUNT(*) DESC", tuple(args))
    except Exception as e:
        log(f"تعذر جلب السجل: {e}")
        return jsonify({"ok": False, "error": "تعذر جلب السجل"}), 500
    return jsonify({
        "ok": True, "now": time.time(), "filters": meta,
        "events": [{"ts": r[0], "name": r[1], "ip": r[2], "type": r[3]} for r in rows],
        "total": sum(c[1] for c in counts),
        "types": [{"type": c[0], "count": c[1]} for c in counts],
    })


@app.route("/api/events/export")
def api_events_export():
    where, args, _, meta = event_filters()
    try:
        rows = db_exec("SELECT ts,name,ip,etype FROM events" + where +
                       " ORDER BY ts DESC LIMIT 20000", tuple(args))
    except Exception as e:
        log(f"تعذر تصدير السجل: {e}")
        return jsonify({"ok": False, "error": "تعذر تصدير السجل"}), 500
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["الوقت", "الجهاز", "IP", "الحدث"])
    for ts, name, ip, etype in rows:
        w.writerow([datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S"),
                    name, ip, etype])
    return Response("\ufeff" + buf.getvalue(),
                    mimetype="text/csv; charset=utf-8",
                    headers={"Content-Disposition": 'attachment; filename="nabd-events.csv"'})


@app.route("/api/alerts")
def api_alerts():
    return jsonify(active_alerts())


@app.route("/api/alerts/ack", methods=["POST"])
def api_alerts_ack():
    guard = _write_guard()
    if guard:
        return guard
    data = request.get_json(silent=True) or {}
    key = str(data.get("key") or "").strip()
    if not key or len(key) > 200:
        return jsonify({"ok": False, "error": "مفتاح التنبيه غير صالح"}), 400
    ack_alert(key, bool(data.get("ack", True)))
    return jsonify({"ok": True, "key": key, "acked": bool(data.get("ack", True))})


@app.route("/api/devices/<name>/maintenance", methods=["POST"])
def api_device_maintenance(name):
    guard = _write_guard()
    if guard:
        return guard
    with LOCK:
        if name not in DEVS:
            return jsonify({"ok": False, "error": "لم أجد الجهاز"}), 404
    data = request.get_json(silent=True) or {}
    minutes = _as_int(data.get("minutes", 0), 0, 0)
    until = set_maintenance(name, minutes)
    log_event(time.time(), name,
              (DEVS.get(name) or {}).get("ip", "-"),
              "maintenance_on" if minutes else "maintenance_off")
    log(f"وضع الصيانة لجهاز {name}: " +
        ("مفعّل " + str(minutes) + " دقيقة" if minutes else "متوقف"))
    return jsonify({"ok": True, "name": name, "until": until,
                    "active": until > time.time()})


def alert_counts():
    try:
        data = active_alerts()
        counts = dict(data.get("counts") or {})
        counts["maint"] = len(data.get("maintenance") or [])
        return counts
    except Exception:
        return {"total": 0, "critical": 0, "warning": 0, "unacked": 0, "maint": 0}


def _write_guard():
    if request.method in ("POST", "PUT") and not request.is_json:
        return jsonify({"ok": False, "error": "أرسل البيانات بصيغة JSON"}), 415
    origin = request.headers.get("Origin")
    if origin and urlparse(origin).netloc != request.host:
        return jsonify({"ok": False, "error": "طلب غير مسموح"}), 403
    return None


@app.route("/api/devices", methods=["POST"])
def api_add_device():
    guard = _write_guard()
    if guard:
        return guard
    try:
        row = add_device(request.get_json(silent=True) or {})
    except ValueError as e:
        return jsonify({"ok": False, "error": str(e)}), 400
    except Exception as e:
        log(f"خطأ في إضافة جهاز: {e}")
        return jsonify({"ok": False, "error": "تعذر حفظ الجهاز"}), 500
    log(f"أُضيف جهاز من اللوحة: {row['name']} ({row['ip']})")
    return jsonify({"ok": True, "device": row})


@app.route("/api/devices/<name>", methods=["PUT", "DELETE"])
def api_change_device(name):
    guard = _write_guard()
    if guard:
        return guard
    try:
        if request.method == "DELETE":
            delete_device(name)
            log(f"حُذف جهاز من اللوحة: {name}")
            return jsonify({"ok": True})
        row = update_device(name, request.get_json(silent=True) or {})
    except ValueError as e:
        return jsonify({"ok": False, "error": str(e)}), 400
    except Exception as e:
        log(f"خطأ في تعديل جهاز: {e}")
        return jsonify({"ok": False, "error": "تعذر حفظ التعديل"}), 500
    log(f"عُدّل جهاز من اللوحة: {name} → {row['name']} ({row['ip']})")
    return jsonify({"ok": True, "device": row})


@app.route("/api/settings", methods=["GET", "PUT"])
def api_settings():
    if request.method == "GET":
        with CFG_LOCK:
            cfg = _normalize_config(CFG)
        dr = cfg["discover"]["router"]
        return jsonify({
            "monitor": {
                "check_interval": INTERVAL,
                "fail_threshold": THRESH,
                "workers": WORKERS,
                "events_retention_days": EVENTS_KEEP_DAYS,
                "heartbeat_hour": HB_HOUR,
            },
            "notifications": {k: notif_on(k) for k in NOTIF_KEYS},
            "telegram": {
                "has_token": TOKEN_OK,
                "token_from_env": bool(os.environ.get("NABD_TELEGRAM_TOKEN", "").strip()),
                "chat_ids": list(CHATS),
                "enabled": TG_ON,
            },
            "scan": {
                "subnets": cfg["scan"]["subnets"],
                "auto_minutes": cfg["scan"]["auto_minutes"],
                "effective_subnets": _effective_subnets(),
            },
            "discover": {
                "host": dr["host"],
                "user": dr["user"],
                "has_password": bool(dr["password"]) and not str(dr["password"]).startswith("PUT_"),
                "port": dr["port"],
                "auto_minutes": cfg["discover"]["auto_minutes"],
                "enabled": DISC_ON,
            },
            "dashboard": {
                "host": DASH_HOST,
                "port": DASH_PORT,
                "has_password": bool(DASH_PW),
                "password_from_env": bool(os.environ.get("NABD_DASH_PASSWORD", "")),
                "live_seconds": LIVE_SECONDS,
            },
            "snmp": {
                "enabled": bool(cfg["snmp"]["enabled"]),
                "community": cfg["snmp"]["community"],
                "port": cfg["snmp"]["port"],
                "timeout": cfg["snmp"]["timeout"],
                "retries": cfg["snmp"]["retries"],
                "poll_seconds": cfg["snmp"]["poll_seconds"],
                "cpu_warn": cfg["snmp"]["cpu_warn"],
                "sfp_rx_min": cfg["snmp"]["sfp_rx_min"],
                "history_points": cfg["snmp"]["history_points"],
                "alert_cooldown_minutes": cfg["snmp"]["alert_cooldown_minutes"],
                "poll": dict(SNMP_POLL_STATE),
            },
            "metrics": {
                "enabled": bool(cfg["metrics"]["enabled"]),
                "sample_seconds": cfg["metrics"]["sample_seconds"],
                "keep_days": cfg["metrics"]["keep_days"],
            },
            "webhook": {
                "enabled": bool(cfg["webhook"]["enabled"]),
                "url": cfg["webhook"]["url"],
                "has_secret": bool(cfg["webhook"]["secret"]),
                "kinds": list(cfg["webhook"]["kinds"]),
                "ready": webhook_ready(),
            },
            "email": {
                "enabled": bool(cfg["email"]["enabled"]),
                "host": cfg["email"]["host"],
                "port": cfg["email"]["port"],
                "user": cfg["email"]["user"],
                "has_password": bool(cfg["email"]["password"]),
                "password_from_env": bool(os.environ.get("NABD_SMTP_PASSWORD", "")),
                "from": cfg["email"]["from"],
                "to": list(cfg["email"]["to"]),
                "tls": bool(cfg["email"]["tls"]),
                "ssl": bool(cfg["email"]["ssl"]),
            },
            "version": VERSION,
        })

    guard = _write_guard()
    if guard:
        return guard
    data = request.get_json(silent=True) or {}
    with CFG_LOCK:
        cfg = _normalize_config(CFG)
    old_host, old_port = DASH_HOST, DASH_PORT
    old_pw = DASH_PW

    mon = data.get("monitor") or {}
    cfg["check_interval"] = _as_int(mon.get("check_interval", INTERVAL), INTERVAL, 2)
    cfg["fail_threshold"] = _as_int(mon.get("fail_threshold", THRESH), THRESH, 1)
    cfg["workers"] = min(512, _as_int(mon.get("workers", WORKERS), WORKERS, 1))
    cfg["events_retention_days"] = _as_int(
        mon.get("events_retention_days", EVENTS_KEEP_DAYS), EVENTS_KEEP_DAYS, 1)
    cfg["heartbeat_hour"] = _norm_hour(mon.get("heartbeat_hour", HB_HOUR))

    nots = data.get("notifications") or {}
    for key in NOTIF_KEYS:
        if key in nots:
            cfg["notifications"][key] = bool(nots[key])

    tg = data.get("telegram") or {}
    token = str(tg.get("token") or "").strip()
    if token and not token.startswith("PUT_"):
        cfg["telegram"]["token"] = token
    if tg.get("clear_token"):
        cfg["telegram"]["token"] = ""
    if "chat_ids" in tg:
        raw_chats = tg.get("chat_ids") or []
        if isinstance(raw_chats, str):
            raw_chats = re.split(r"[,،\s]+", raw_chats)
        cfg["telegram"]["chat_ids"] = [
            str(c).strip() for c in raw_chats
            if str(c).strip() and not str(c).strip().startswith("PUT_")
        ]

    scan_in = data.get("scan") or {}
    if "subnets" in scan_in:
        raw = scan_in.get("subnets") or []
        if isinstance(raw, str):
            raw = re.split(r"[,،\s]+", raw)
        subnets, bad = [], []
        for item in raw:
            prefix = subnet_prefix(item)
            if not prefix:
                continue
            if _valid_subnet(prefix):
                if prefix not in subnets:
                    subnets.append(prefix)
            else:
                bad.append(str(item))
        if bad:
            return jsonify({"ok": False, "error": "شبكة غير صالحة: " + "، ".join(bad)}), 400
        cfg["scan"]["subnets"] = subnets
    if "auto_minutes" in scan_in:
        cfg["scan"]["auto_minutes"] = _as_float(scan_in.get("auto_minutes", 0), 0, 0)

    disc_in = data.get("discover") or {}
    dr = cfg["discover"]["router"]
    if "host" in disc_in:
        host = str(disc_in.get("host") or "").strip()
        if host and not valid_ip(host):
            return jsonify({"ok": False, "error": "عنوان الراوتر غير صالح"}), 400
        dr["host"] = host
    if "user" in disc_in:
        dr["user"] = str(disc_in.get("user") or "nabd").strip() or "nabd"
    if "password" in disc_in:
        password = str(disc_in.get("password") or "")
        if password:
            dr["password"] = password
    if disc_in.get("clear_password"):
        dr["password"] = ""
    if "port" in disc_in:
        dr["port"] = _as_int(disc_in.get("port", dr["port"]), dr["port"], 1)
    if "auto_minutes" in disc_in:
        cfg["discover"]["auto_minutes"] = _as_float(
            disc_in.get("auto_minutes", 0), 0, 0)

    dash_in = data.get("dashboard") or {}
    if "host" in dash_in:
        host = str(dash_in.get("host") or "0.0.0.0").strip() or "0.0.0.0"
        if len(host) > 64:
            return jsonify({"ok": False, "error": "عنوان الاستماع طويل جداً"}), 400
        cfg["dashboard"]["host"] = host
    if "port" in dash_in:
        cfg["dashboard"]["port"] = _as_int(dash_in.get("port", DASH_PORT), DASH_PORT, 1)
    if "live_seconds" in dash_in:
        cfg["dashboard"]["live_seconds"] = _as_int(
            dash_in.get("live_seconds", LIVE_SECONDS), LIVE_SECONDS, 2)
    password = str(dash_in.get("password") or "")
    if password:
        cfg["dashboard"]["password"] = password
    if dash_in.get("clear_password"):
        cfg["dashboard"]["password"] = ""

    snmp_in = data.get("snmp") or {}
    sn = cfg["snmp"]
    if "enabled" in snmp_in:
        sn["enabled"] = bool(snmp_in["enabled"])
    if "community" in snmp_in:
        community = str(snmp_in.get("community") or "").strip()
        if not community:
            return jsonify({"ok": False, "error": "اكتب اسم مجتمع SNMP (community)"}), 400
        if len(community) > 64:
            return jsonify({"ok": False, "error": "اسم مجتمع SNMP طويل جداً"}), 400
        sn["community"] = community
    if "port" in snmp_in:
        sn["port"] = _as_int(snmp_in.get("port", sn["port"]), sn["port"], 1)
    if "timeout" in snmp_in:
        sn["timeout"] = _as_range(snmp_in.get("timeout", sn["timeout"]), sn["timeout"], 0.2, 15)
    if "retries" in snmp_in:
        sn["retries"] = _as_int(snmp_in.get("retries", sn["retries"]), sn["retries"], 0)
    if "poll_seconds" in snmp_in:
        sn["poll_seconds"] = _as_int(snmp_in.get("poll_seconds", sn["poll_seconds"]), sn["poll_seconds"], 10)
    if "cpu_warn" in snmp_in:
        sn["cpu_warn"] = min(100, _as_int(snmp_in.get("cpu_warn", sn["cpu_warn"]), sn["cpu_warn"], 1))
    if "sfp_rx_min" in snmp_in:
        sn["sfp_rx_min"] = _as_range(snmp_in.get("sfp_rx_min", sn["sfp_rx_min"]), sn["sfp_rx_min"], -60, 10)
    if "history_points" in snmp_in:
        sn["history_points"] = min(1440, _as_int(
            snmp_in.get("history_points", sn["history_points"]), sn["history_points"], 10))
    if "alert_cooldown_minutes" in snmp_in:
        sn["alert_cooldown_minutes"] = min(1440, _as_int(
            snmp_in.get("alert_cooldown_minutes", sn["alert_cooldown_minutes"]),
            sn["alert_cooldown_minutes"], 0))

    metrics_in = data.get("metrics") or {}
    mt = cfg["metrics"]
    if "enabled" in metrics_in:
        mt["enabled"] = bool(metrics_in["enabled"])
    if "sample_seconds" in metrics_in:
        mt["sample_seconds"] = _as_int(
            metrics_in.get("sample_seconds", mt["sample_seconds"]),
            mt["sample_seconds"], 10)
    if "keep_days" in metrics_in:
        mt["keep_days"] = min(3650, _as_int(
            metrics_in.get("keep_days", mt["keep_days"]), mt["keep_days"], 1))

    email_in = data.get("email") or {}
    em = cfg["email"]
    if "enabled" in email_in:
        em["enabled"] = bool(email_in["enabled"])
    if "host" in email_in:
        em["host"] = str(email_in.get("host") or "").strip()
    if "port" in email_in:
        em["port"] = _as_int(email_in.get("port", em["port"]), em["port"], 1)
    if "user" in email_in:
        em["user"] = str(email_in.get("user") or "").strip()
    if "password" in email_in:
        password = str(email_in.get("password") or "")
        if password:
            em["password"] = password
    if email_in.get("clear_password"):
        em["password"] = ""
    if "from" in email_in:
        em["from"] = str(email_in.get("from") or "").strip()
    if "to" in email_in:
        raw_to = email_in.get("to") or []
        if isinstance(raw_to, str):
            raw_to = re.split(r"[,;\s]+", raw_to)
        em["to"] = [str(x).strip() for x in raw_to if str(x).strip()]
    if "tls" in email_in:
        em["tls"] = bool(email_in["tls"])
    if "ssl" in email_in:
        em["ssl"] = bool(email_in["ssl"])
    if em["enabled"] and (not em["host"] or not em["to"]):
        return jsonify({"ok": False,
                        "error": "لتشغيل البريد: اكتب خادم SMTP وعنوان المستلم"}), 400
    if em["enabled"] and not (em["from"] or em["user"]):
        return jsonify({"ok": False, "error": "اكتب بريد المرسل (from)"}), 400

    hook_in = data.get("webhook") or {}
    wh = cfg["webhook"]
    if "enabled" in hook_in:
        wh["enabled"] = bool(hook_in["enabled"])
    if "url" in hook_in:
        url = str(hook_in.get("url") or "").strip()
        if url and not url.startswith(("http://", "https://")):
            return jsonify({"ok": False, "error": "رابط Webhook يجب أن يبدأ بـ http:// أو https://"}), 400
        if len(url) > 2000:
            return jsonify({"ok": False, "error": "رابط Webhook طويل جداً"}), 400
        wh["url"] = url
    if "secret" in hook_in:
        secret = str(hook_in.get("secret") or "")
        if secret:
            wh["secret"] = secret
    if hook_in.get("clear_secret"):
        wh["secret"] = ""
    if "kinds" in hook_in:
        raw_kinds = hook_in.get("kinds") or []
        if isinstance(raw_kinds, str):
            raw_kinds = re.split(r"[,،\s]+", raw_kinds)
        wh["kinds"] = [k for k in NOTIF_KEYS if k in {str(x).strip() for x in raw_kinds}]
    if wh["enabled"] and not wh["url"]:
        return jsonify({"ok": False, "error": "لتشغيل Webhook: اكتب رابط الاستقبال"}), 400

    try:
        save_config_file(cfg)
    except Exception as e:
        log(f"تعذر حفظ الإعدادات: {e}")
        return jsonify({"ok": False, "error": "تعذر حفظ الإعدادات"}), 500
    apply_runtime_config(cfg)
    restart = (DASH_HOST != old_host or DASH_PORT != old_port)
    password_changed = bool(DASH_PW) and DASH_PW != old_pw
    log("حُدّثت الإعدادات من اللوحة" + (" (يتطلب إعادة تشغيل لتغيير المنفذ)" if restart else ""))
    message = "حُفظت الإعدادات وطُبّقت فوراً."
    if restart:
        message = "حُفظت الإعدادات. أعد تشغيل نبض لتطبيق تغيير المنفذ/الاستماع."
    if password_changed:
        message += " أعد تحميل الصفحة وأدخل كلمة المرور الجديدة."
    return jsonify({
        "ok": True,
        "restart_required": restart,
        "password_changed": password_changed,
        "telegram_enabled": TG_ON,
        "message": message,
    })


@app.route("/api/telegram/test", methods=["POST"])
def api_tg_test():
    guard = _write_guard()
    if guard:
        return guard
    if not TG_ON:
        return jsonify({"ok": False, "error": "أضف توكن البوت وchat_id أولاً"}), 400
    results = []
    for chat in CHATS:
        results.append({"chat": chat,
                        "result": tg_send(chat, f"💓 نبض: رسالة تجريبية ناجحة\nالوقت: {now_str()}")})
    return jsonify({"ok": all(r["result"] == "ok" for r in results), "results": results})


@app.route("/api/webhook/test", methods=["POST"])
def api_webhook_test():
    guard = _write_guard()
    if guard:
        return guard
    data = request.get_json(silent=True) or {}
    url = str(data.get("url") or "").strip() or None
    secret = data.get("secret") if "secret" in data else None
    if url is None and not webhook_ready():
        return jsonify({"ok": False, "error": "اكتب رابط Webhook واحفظ الإعدادات أولاً"}), 400
    result = webhook_send("💓 نبض: إشعار Webhook تجريبي ناجح\nالوقت: " + now_str(),
                          "daily_report", url=url, secret=secret)
    if result != "ok":
        return jsonify({"ok": False, "error": result}), 502
    return jsonify({"ok": True, "message": "وصل الإشعار التجريبي بنجاح"})


@app.route("/api/telegram/chats", methods=["POST"])
def api_tg_chats():
    guard = _write_guard()
    if guard:
        return guard
    data = request.get_json(silent=True) or {}
    token = str(data.get("token") or "").strip() or TOKEN
    if not token or token.startswith("PUT_"):
        return jsonify({"ok": False, "error": "ضع توكن البوت أولاً"}), 400
    try:
        r = requests.get(f"https://api.telegram.org/bot{token}/getUpdates", timeout=20).json()
    except Exception as e:
        return jsonify({"ok": False, "error": f"تعذر الاتصال بتيليجرام: {e}"}), 502
    if not r.get("ok"):
        return jsonify({"ok": False,
                        "error": str(r.get("description") or "رفض تيليجرام التوكن")}), 400
    seen = {}
    for update in r.get("result", []):
        m = (update.get("message") or update.get("channel_post")
             or update.get("my_chat_member") or {})
        chat = m.get("chat")
        if chat:
            seen[str(chat["id"])] = (chat.get("title") or chat.get("username")
                                     or chat.get("first_name") or "")
    chats = [{"id": cid, "title": title} for cid, title in seen.items()]
    return jsonify({"ok": True, "chats": chats})


@app.route("/api/scan/start", methods=["POST"])
def api_scan_start():
    guard = _write_guard()
    if guard:
        return guard
    try:
        start_scan_async()
    except RuntimeError as e:
        return jsonify({"ok": False, "error": str(e)}), 409
    return jsonify({"ok": True, "message": "بدأ فحص الشبكة"})


@app.route("/api/scan/status")
def api_scan_status():
    with SCAN_LOCK:
        state = {k: v for k, v in SCAN_STATE.items() if k != "results"}
        state["results"] = list(SCAN_STATE["results"])
    return jsonify(state)


@app.route("/api/scan/add", methods=["POST"])
def api_scan_add():
    guard = _write_guard()
    if guard:
        return guard
    data = request.get_json(silent=True) or {}
    with SCAN_LOCK:
        results = list(SCAN_STATE["results"])
    if data.get("all"):
        chosen = [r for r in results if not r.get("known")]
    else:
        wanted = {str(x) for x in (data.get("ips") or [])}
        chosen = [r for r in results if r.get("ip") in wanted]
    added, skipped = add_scan_candidates(chosen)
    if added:
        for x in added:
            log_event(time.time(), x["name"], x["ip"], "new_device")
        notify(f"🆕 أُضيف {len(added)} جهاز من فحص الشبكة إلى المراقبة\n"
               + "، ".join(f"{x['name']} ({x['ip']})" for x in added[:10]),
               "new_device")
    return jsonify({"ok": True, "added": added, "skipped": skipped})


@app.route("/api/discover", methods=["POST"])
def api_discover_now():
    guard = _write_guard()
    if guard:
        return guard
    if not DISC_ON:
        return jsonify({"ok": False,
                        "error": "أكمل عنوان الراوتر ومستخدمه وكلمة مروره في الإعدادات أولاً"}), 400
    if not DISCOVER_LOCK.acquire(False):
        return jsonify({"ok": False, "error": "الاكتشاف قيد التنفيذ بالفعل"}), 409
    try:
        new = run_discovery(live=True)
    except Exception as e:
        log(f"فشل الاكتشاف من اللوحة: {e}")
        return jsonify({"ok": False, "error": f"فشل الاكتشاف: {e}"}), 502
    finally:
        DISCOVER_LOCK.release()
    if new:
        for x in new:
            log_event(time.time(), x["name"], x["ip"], "new_device")
        notify(f"🆕 اكتُشف {len(new)} جهاز من الراوتر وأُضيف للمراقبة\n"
               + "، ".join(f"{x['name']} ({x['ip']})" for x in new[:10]), "new_device")
    return jsonify({"ok": True, "new": new})


@app.route("/api/device/<name>/ports", methods=["POST"])
def api_device_ports(name):
    guard = _write_guard()
    if guard:
        return guard
    with LOCK:
        dev = DEVS.get(name)
        ip = dev["ip"] if dev else None
    if not ip:
        return jsonify({"ok": False, "error": "لم أجد الجهاز"}), 404
    opened = check_ports(ip)
    with LOCK:
        if name in DEVS:
            DEVS[name]["ports"] = opened
            DEVS[name]["ports_at"] = time.time()
    return jsonify({"ok": True, "ports": opened, "checked": time.time()})


@app.route("/api/snmp/device/<name>")
def api_snmp_device(name):
    state = snmp_snapshot(name)
    if not state:
        return jsonify({"ok": False, "pending": True, "error_code": "no_data",
                        "error": "لم يُستعلم هذا الجهاز عبر SNMP بعد"})
    state["history"] = snmp_history(name)
    state["ok"] = bool(state.get("ok"))
    state["error"] = state.get("error") or ""
    return jsonify(state)


@app.route("/api/snmp/poll", methods=["POST"])
def api_snmp_poll():
    guard = _write_guard()
    if guard:
        return guard
    data = request.get_json(silent=True) or {}
    name = str(data.get("name") or "").strip()
    if name:
        result = poll_device(name)
        if not result.get("ok") and result.get("error") == "لم أجد الجهاز":
            return jsonify({"ok": False, "error": result["error"]}), 404
        return jsonify({"ok": bool(result.get("ok")), "result": result,
                        "error": result.get("error") or ""})
    result = poll_all(force=True)
    if not result.get("ok"):
        return jsonify(result), 409
    return jsonify(result)


@app.route("/api/snmp/test", methods=["POST"])
def api_snmp_test():
    guard = _write_guard()
    if guard:
        return guard
    data = request.get_json(silent=True) or {}
    with LOCK:
        dev = DEVS.get(str(data.get("name") or "").strip())
        dev = dict(dev) if dev else None
    if dev:
        ip = dev["ip"]
        community, port, timeout, retries = _snmp_credentials(dev)
        profile = dev.get("profile", "auto")
    else:
        ip = str(data.get("ip") or "").strip()
        community = str(data.get("community") or SNMP.get("community") or "public").strip()
        port = _as_int(data.get("port", SNMP.get("port", 161)), 161, 1)
        timeout = _as_range(SNMP.get("timeout", 1.5), 1.5, 0.2, 15)
        retries = _as_int(SNMP.get("retries", 1), 1, 0)
        profile = str(data.get("profile") or "auto")
    if not valid_ip(ip):
        return jsonify({"ok": False, "error": "عنوان IP غير صالح"}), 400
    started = time.time()
    try:
        client = SNMPClient(ip, community, port=port, timeout=timeout, retries=retries)
        vals = client.get(list(SYS_OIDS.values()))
        descr = vals.get(SYS_OIDS["descr"])
        obj = vals.get(SYS_OIDS["objectid"])
        vendor = _detect_vendor(descr, obj, profile)
        cpu = _read_cpu(client, vendor)
        mem = _read_memory(client)
        ifaces, _prev, _in, _out = _read_interfaces(client, {}, time.time())
        sfp = _read_optical(client, vendor)
        wifi = _read_wifi(client, vendor)
        client.close()
        return jsonify({
            "ok": True, "ip": ip, "vendor": vendor,
            "sys": {"descr": str(descr or ""), "name": str(vals.get(SYS_OIDS["name"]) or ""),
                    "objectid": str(obj or ""),
                    "uptime": round((_num(vals.get(SYS_OIDS["uptime"])) or 0) / 100)},
            "cpu": cpu, "mem": mem,
            "counts": {"interfaces": len(ifaces), "sfp": len(sfp), "wifi": len(wifi)},
            "elapsed": round(time.time() - started, 2),
        })
    except (SNMPError, OSError) as e:
        return jsonify({"ok": False, "error": str(e) or "لا استجابة SNMP"}), 502


@app.route("/api/email/test", methods=["POST"])
def api_email_test():
    guard = _write_guard()
    if guard:
        return guard
    if not EMAIL.get("enabled"):
        return jsonify({"ok": False, "error": "شغّل البريد واحفظ إعدادات SMTP أولاً"}), 400
    err = email_send("نبض — رسالة تجريبية",
                     f"💓 رسالة تجريبية من نبض\nالوقت: {now_str()}\n"
                     f"إن وصلتك هذه الرسالة فإعداد البريد يعمل.")
    if err:
        return jsonify({"ok": False, "error": err}), 502
    return jsonify({"ok": True, "message": "أُرسلت الرسالة التجريبية"})


@app.route("/healthz")
def healthz():
    db_ok = True
    try:
        db_exec("SELECT 1")
    except Exception:
        db_ok = False
    with LOCK:
        devices = len(DEVS)
        net = NET["state"]
    return jsonify({"ok": db_ok, "time": time.time(), "devices": devices, "net": net})


FAVICON = (
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">'
    '<rect width="64" height="64" rx="14" fill="#0e1822"/>'
    '<path d="M6 34h12l5-12 8 24 6-18 4 6h17" fill="none" stroke="#3fb950" '
    'stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/></svg>'
)


@app.route("/favicon.svg")
@app.route("/favicon.ico")
def favicon():
    return Response(FAVICON, mimetype="image/svg+xml",
                    headers={"Cache-Control": "public, max-age=86400"})


PAGE = """<!doctype html><html lang="ar" dir="rtl"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="dark">
<meta name="theme-color" content="#0a1118">
<title>نبض — مراقبة الشبكة</title>
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
<style>
:root{--bg:#0a1118;--card:#121d29;--card2:#162333;--line:#223243;--tx:#e8eef5;--mut:#8ea0b3;
--ok:#3fb950;--bad:#f85149;--warn:#d29922;--info:#58a6ff;--rad:14px;--shadow:0 10px 28px rgba(0,0,0,.28)}
*{box-sizing:border-box}
body{margin:0;min-height:100vh;color:var(--tx);font-family:"Segoe UI",Tahoma,Arial,sans-serif;
font-size:15px;line-height:1.5;background:radial-gradient(1100px 520px at 88% -8%,#13263a 0,transparent 55%),var(--bg)}
header{position:sticky;top:0;z-index:20;display:flex;align-items:center;gap:14px;flex-wrap:wrap;
padding:12px 18px;background:rgba(10,17,24,.86);backdrop-filter:blur(12px);border-bottom:1px solid var(--line)}
.brand{display:flex;align-items:center;gap:11px}
.logo{width:40px;height:40px;display:grid;place-items:center;border-radius:12px;font-size:21px;
background:linear-gradient(145deg,#19324c,#0f1c2a);border:1px solid #274764;box-shadow:inset 0 0 18px rgba(88,166,255,.14)}
h1{margin:0;font-size:19px;letter-spacing:.2px}
.brand p{margin:0;color:var(--mut);font-size:12px}
.head-right{margin-inline-start:auto;display:flex;align-items:center;gap:9px;flex-wrap:wrap}
.conn{display:inline-flex;align-items:center;gap:7px;padding:4px 11px;border-radius:999px;font-size:12.5px;
border:1px solid var(--line);background:var(--card);color:var(--mut)}
.conn::before{content:"";width:8px;height:8px;border-radius:50%;background:var(--mut)}
.conn.live{color:#9fe6ad;border-color:#1e4d2b;background:#102218}
.conn.live::before{background:var(--ok);box-shadow:0 0 9px var(--ok)}
.conn.bad{color:#ffb4ae;border-color:#5a2320;background:#2a1514}
.conn.bad::before{background:var(--bad);box-shadow:0 0 9px var(--bad)}
.conn.paused{color:#f0d48a;border-color:#5a4a1e;background:#241f10}
.conn.paused::before{background:var(--warn)}
.muted{color:var(--mut);font-size:13px}
.btn{cursor:pointer;border:1px solid var(--line);background:var(--card2);color:var(--tx);
padding:7px 13px;border-radius:9px;font-family:inherit;font-size:13.5px;transition:background .15s,border-color .15s}
.btn:hover{background:#1d2c3d;border-color:#31506c}
.btn.ghost{background:transparent}
.wrap{max-width:1240px;margin:0 auto;padding:16px 18px 34px}
.err{margin:0 0 12px;padding:11px 14px;border-radius:11px;background:#2a1514;border:1px solid #5a2320;color:#ffb4ae}
.warnbox{margin:0 0 12px;padding:11px 14px;border-radius:11px;background:#241f10;border:1px solid #5a4a1e;color:#f0d48a;font-size:13.5px}
.net{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;
padding:14px 16px;border-radius:var(--rad);background:linear-gradient(120deg,var(--card),#101b27);
border:1px solid var(--line);border-inline-start:4px solid var(--mut);margin-bottom:14px;box-shadow:var(--shadow)}
.net-main{display:flex;align-items:center;gap:10px;font-size:16px}
.net-main .ico{font-size:20px}
.net.up{border-inline-start-color:var(--ok)}
.net.down{border-inline-start-color:var(--bad);background:linear-gradient(120deg,#2a1517,#1a1216)}
.net.unknown{border-inline-start-color:var(--warn)}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(132px,1fr));gap:11px;margin-bottom:14px}
.card{position:relative;overflow:hidden;background:var(--card);border:1px solid var(--line);border-radius:var(--rad);padding:13px 15px}
.card::after{content:"";position:absolute;inset:auto -30% -60% auto;width:120px;height:120px;border-radius:50%;
background:radial-gradient(circle,rgba(88,166,255,.10),transparent 70%)}
.card .k{color:var(--mut);font-size:12.5px}
.card b{display:block;margin-top:2px;font-size:29px;font-variant-numeric:tabular-nums;letter-spacing:.5px}
.card.ok b{color:var(--ok)}.card.bad b{color:var(--bad)}.card.warn b{color:var(--warn)}.card.neutral b{color:var(--info)}
.bar{display:flex;gap:9px;align-items:center;flex-wrap:wrap;margin-bottom:11px}
.bar input[type=search],.bar select{background:var(--card);border:1px solid var(--line);color:var(--tx);
padding:9px 11px;border-radius:10px;font-family:inherit;font-size:14px;outline:none}
.bar input[type=search]{flex:1 1 220px;min-width:170px}
.bar input[type=search]:focus,.bar select:focus{border-color:#3b6d99;box-shadow:0 0 0 3px rgba(88,166,255,.13)}
.scroll{overflow:auto;max-height:64vh;background:var(--card);border:1px solid var(--line);border-radius:var(--rad);box-shadow:var(--shadow)}
table{width:100%;border-collapse:separate;border-spacing:0;font-size:14px}
th,td{padding:9px 11px;text-align:start;border-bottom:1px solid var(--line);white-space:nowrap}
th{position:sticky;top:0;z-index:2;background:#0f1a25;color:var(--mut);font-weight:600;font-size:12.5px}
tbody tr:hover{background:#162331}
tbody tr:last-child td{border-bottom:none}
tr.down{background:rgba(248,81,73,.055)}
tr.unreachable{background:rgba(210,153,34,.035)}
.pill{display:inline-flex;align-items:center;gap:6px;padding:3px 10px;border-radius:999px;
font-size:12.5px;font-weight:600;border:1px solid transparent;line-height:1.35}
.pill::before{content:"";width:7px;height:7px;border-radius:50%;background:currentColor}
.st-up{color:#9fe6ad;background:#102218;border-color:#1e4d2b}
.st-down{color:#ffb4ae;background:#2a1514;border-color:#5a2320}
.st-unreachable{color:#f0d48a;background:#241f10;border-color:#5a4a1e}
.st-unknown{color:#b9c6d4;background:#18232f;border-color:#2a3a4b}
.rtt-ok{color:var(--ok)}.rtt-mid{color:var(--warn)}.rtt-bad{color:var(--bad)}
.name{font-weight:600}
.sub{color:var(--mut);font-size:11.5px}
h2{font-size:16px;margin:24px 0 9px;display:flex;align-items:center;gap:8px}
h2 .muted{font-weight:400}
.ev-up{color:#9fe6ad;background:#102218;border-color:#1e4d2b}
.ev-down{color:#ffb4ae;background:#2a1514;border-color:#5a2320}
.ev-unreachable{color:#f0d48a;background:#241f10;border-color:#5a4a1e}
.ev-sfp_low,.ev-high_cpu,.ev-port_down{color:#f0d48a;background:#241f10;border-color:#5a4a1e}
.ev-new_device,.ev-maintenance_on,.ev-maintenance_off{color:#9ecbff;background:#10243a;border-color:#1f4468}
.foot{margin-top:20px;color:#65788b;font-size:12px;text-align:center}
.btn.primary{background:#1f6feb;border-color:#2f81f7}
.btn.primary:hover{background:#2f81f7}
.btn.mini{padding:3px 8px;font-size:12px;border-radius:7px}
.btn.danger{color:#ffb4ae;border-color:#5a2320;background:#2a1514}
.btn.danger:hover{background:#3a1a18;border-color:#7a2f2a}
.acts{display:flex;gap:5px}
.modal{border:1px solid var(--line);border-radius:16px;background:var(--card);color:var(--tx);
padding:0;width:min(440px,92vw);box-shadow:0 30px 80px rgba(0,0,0,.6)}
.modal::backdrop{background:rgba(3,8,13,.72);backdrop-filter:blur(3px)}
.modal form{display:grid;gap:10px;padding:18px}
.modal h3{margin:0 0 4px;font-size:17px}
.modal label{display:grid;gap:5px;font-size:12.5px;color:var(--mut)}
.modal input{background:var(--card2);border:1px solid var(--line);color:var(--tx);
padding:9px 11px;border-radius:9px;font-family:inherit;font-size:14px;outline:none}
.modal input:focus{border-color:#3b6d99;box-shadow:0 0 0 3px rgba(88,166,255,.13)}
.modal .err{margin:0;font-size:13px}
.modal-actions{display:flex;gap:8px;margin-top:6px;align-items:center;flex-wrap:wrap}
.modal.wide{width:min(820px,96vw)}
.modal form{max-height:88vh;overflow:auto}
.modal .sect{border:1px solid var(--line);border-radius:11px;padding:11px 12px;display:grid;gap:9px;background:rgba(255,255,255,.015)}
.modal .sect h4{margin:0;font-size:13.5px;color:#9fb4c8;font-weight:600}
.modal .grid2{display:grid;grid-template-columns:1fr 1fr;gap:9px}
.modal .checks{display:flex;flex-wrap:wrap;gap:9px 16px}
.modal .checks label{display:flex;align-items:center;gap:6px;color:var(--tx);font-size:13.5px}
.modal .checks input{width:auto}
.modal textarea{background:var(--card2);border:1px solid var(--line);color:var(--tx);
padding:9px 11px;border-radius:9px;font-family:inherit;font-size:13.5px;outline:none;resize:vertical;min-height:44px}
.modal .hint{font-size:12px;color:var(--mut);line-height:1.5}
.msg{font-size:13px;border-radius:9px;padding:8px 11px;border:1px solid var(--line);background:var(--card2)}
.msg.ok{color:#9fe6ad;border-color:#1e4d2b;background:#102218}
.msg.bad{color:#ffb4ae;border-color:#5a2320;background:#2a1514}
.scan-head{display:flex;gap:8px;flex-wrap:wrap;align-items:center}
.scan-progress{height:8px;border-radius:6px;background:var(--card2);overflow:hidden;border:1px solid var(--line)}
.scan-progress i{display:block;height:100%;background:#2f81f7;width:0;transition:width .25s}
.scan-wrap{max-height:46vh;overflow:auto;border:1px solid var(--line);border-radius:11px}
.scan-wrap table{min-width:560px}
.scan-wrap th,.scan-wrap td{padding:6px 8px;font-size:13px}
.scan-wrap td.ports{color:#9fb4c8;font-size:12px}
.known{color:#9fe6ad}
.newdev{color:#f0d48a}
.detail-grid{display:grid;grid-template-columns:auto 1fr;gap:6px 12px;font-size:14px}
.detail-grid dt{color:var(--mut)}
.detail-grid dd{margin:0}
.ports{display:flex;flex-wrap:wrap;gap:6px}
.port{background:var(--card2);border:1px solid var(--line);border-radius:7px;padding:2px 8px;font-size:12.5px}
.modal select{background:var(--card2);border:1px solid var(--line);color:var(--tx);border-radius:8px;padding:8px 10px;font:inherit}
.modal select:focus{border-color:#3b6d99;box-shadow:0 0 0 3px rgba(88,166,255,.13)}
.tabs{display:flex;gap:6px;flex-wrap:wrap;border-bottom:1px solid var(--line);padding-bottom:8px}
.tabs button{background:transparent;border:1px solid transparent;color:var(--mut);border-radius:8px;padding:5px 11px;font:inherit;font-size:12.5px;cursor:pointer}
.tabs button:hover{background:var(--card2);color:var(--tx)}
.tabs button.active{background:#12283d;border-color:#2d5a80;color:#cfe6ff}
.snmp-pane{min-height:110px;max-height:40vh;overflow:auto;border:1px solid var(--line);border-radius:10px;padding:8px;background:rgba(0,0,0,.08)}
.snmp-table{width:100%;border-collapse:collapse;font-size:12px;white-space:nowrap}
.snmp-table th{position:sticky;top:0;background:#141e29;color:#9fb4c8;font-weight:600;text-align:right;padding:6px 8px;border-bottom:1px solid var(--line)}
.snmp-table td{padding:5px 8px;border-bottom:1px solid rgba(255,255,255,.05);font-variant-numeric:tabular-nums}
.snmp-table tr:hover td{background:rgba(88,166,255,.05)}
.snmp-table .num{text-align:left;direction:ltr}
.metrics{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:8px;margin-bottom:9px}
.metric{background:var(--card2);border:1px solid var(--line);border-radius:9px;padding:8px 10px}
.metric .k{display:block;color:var(--mut);font-size:11.5px;margin-bottom:2px}
.metric b{font-size:17px;font-variant-numeric:tabular-nums}
.metric small{color:var(--mut);font-size:11px}
.bar{height:7px;border-radius:5px;background:#22303d;overflow:hidden;margin-top:5px}
.bar i{display:block;height:100%;background:#3fb950;transition:width .3s}
.bar i.mid{background:#d29922}.bar i.bad{background:#f85149}
.chart{width:100%;height:auto;background:var(--card2);border:1px solid var(--line);border-radius:10px}
.legend{display:flex;gap:14px;font-size:12px;color:var(--mut);margin:6px 2px}
.legend i{display:inline-block;width:10px;height:10px;border-radius:2px;margin-inline-end:4px;vertical-align:middle}
.sig-good{color:#3fb950}.sig-mid{color:#d29922}.sig-bad{color:#f85149}
.up-dot,.down-dot{display:inline-block;width:7px;height:7px;border-radius:50%;margin-inline-end:4px;vertical-align:middle}
.up-dot{background:#3fb950}.down-dot{background:#6e7681}
.snmp-badge{display:inline-block;margin-inline-start:6px;font-size:10.5px;color:#9fb4c8;border:1px solid var(--line);border-radius:5px;padding:0 4px;vertical-align:middle}
.snmp-badge.bad{color:#ffb4ae;border-color:#5a2320}
.snmp-badge.warn{color:#f0d48a;border-color:#5a4a1e}
.snmp-chip{font-size:12px;padding:6px 9px;font-variant-numeric:tabular-nums}
.snmp-chip.ok{color:#7ee2a8;border-color:#1f5133;background:#0f1f16}
.snmp-chip.warn{color:#f0d48a;border-color:#5a4a1e;background:#1f1a0d}
.snmp-chip.bad{color:#ffb4ae;border-color:#5a2320;background:#1f1010}
/* التنقل بين العروض */
.views{display:flex;gap:6px;flex-wrap:wrap;margin-bottom:14px;padding:5px;border:1px solid var(--line);
background:var(--card);border-radius:12px;box-shadow:var(--shadow)}
.views button{cursor:pointer;border:1px solid transparent;background:transparent;color:var(--mut);
padding:8px 16px;border-radius:9px;font-family:inherit;font-size:13.5px;display:inline-flex;align-items:center;gap:7px}
.views button:hover{color:var(--tx);background:var(--card2)}
.views button.active{color:#dbeafe;background:#173049;border-color:#2b5273}
.views .badge{min-width:20px;height:20px;padding:0 6px;border-radius:999px;background:#5a2320;color:#ffb4ae;
font-size:11px;display:inline-flex;align-items:center;justify-content:center;font-variant-numeric:tabular-nums}
.views .badge.zero{background:#1e4d2b;color:#9fe6ad}
.viewhead{display:flex;align-items:center;gap:12px;flex-wrap:wrap;margin:0 0 12px}
.viewhead h2{margin:0;font-size:17px}
.viewhead .spacer{margin-inline-start:auto}
.rangebar{display:inline-flex;gap:4px;background:var(--card);border:1px solid var(--line);padding:4px;border-radius:9px}
.rangebar button{cursor:pointer;border:0;background:transparent;color:var(--mut);padding:5px 10px;border-radius:6px;
font-family:inherit;font-size:12.5px}
.rangebar button:hover{color:var(--tx)}
.rangebar button.active{background:#173049;color:#dbeafe}
/* أعلى استهلاكاً */
.talkers{display:grid;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:9px}
.talker{background:var(--card);border:1px solid var(--line);border-radius:11px;padding:9px 12px}
.talker .t{display:flex;justify-content:space-between;gap:8px;font-size:13px}
.talker .t b{font-weight:600}
.talker .t span{color:var(--mut);font-size:11.5px;font-variant-numeric:tabular-nums}
.talker .bar{height:6px;margin-top:6px}
/* مركز التنبيهات */
.alerts{display:grid;gap:9px}
.alert{display:grid;grid-template-columns:auto 1fr auto;gap:11px;align-items:center;
background:var(--card);border:1px solid var(--line);border-inline-start:4px solid var(--warn);
border-radius:11px;padding:10px 13px}
.alert.critical{border-inline-start-color:var(--bad)}
.alert.info{border-inline-start-color:var(--info)}
.alert.acked{opacity:.55}
.alert .sev{font-size:11px;font-weight:700;padding:3px 8px;border-radius:999px;white-space:nowrap}
.alert.critical .sev{background:#2a1514;color:#ffb4ae;border:1px solid #5a2320}
.alert.warning .sev{background:#241f10;color:#f0d48a;border:1px solid #5a4a1e}
.alert .msg{background:transparent;border:0;padding:0}
.alert .msg b{font-size:13.5px}
.alert .meta{color:var(--mut);font-size:11.5px;margin-top:2px}
.alert .ops{display:flex;gap:5px;flex-wrap:wrap;justify-content:flex-end}
.alert .sev.info{background:#10243a;color:#9ecbff;border:1px solid #1f4468}
.alerts-empty{padding:24px;text-align:center;color:var(--mut);border:1px dashed var(--line);border-radius:12px}
/* خريطة الشبكة */
.mapwrap{position:relative;height:min(66vh,620px);background:
radial-gradient(circle at 20% 0,rgba(88,166,255,.06),transparent 55%),var(--card);
border:1px solid var(--line);border-radius:var(--rad);overflow:hidden;box-shadow:var(--shadow);touch-action:none}
.mapwrap svg{width:100%;height:100%;display:block;cursor:grab}
.mapwrap svg.panning{cursor:grabbing}
.mapnode{cursor:pointer}
.mapnode rect{stroke-width:1.5}
.mapnode text{pointer-events:none;user-select:none}
.mapnode:hover rect{filter:brightness(1.25)}
.map-legend{display:flex;gap:15px;flex-wrap:wrap;font-size:12px;color:var(--mut);margin:9px 2px}
.map-legend i{display:inline-block;width:9px;height:9px;border-radius:50%;margin-inline-end:5px;vertical-align:middle}
.map-hint{color:var(--mut);font-size:12px;margin-top:6px}
/* التقارير */
.heat{display:inline-flex;gap:2px;direction:ltr}
.heat i{width:7px;height:15px;border-radius:2px;background:#26333f}
.heat i.h99{background:#2ea043}.heat i.h95{background:#d29922}.heat i.h0{background:#f85149}
.heat i.hna{background:#1a242e}
.sla-bar{display:inline-block;width:74px;height:7px;border-radius:5px;background:#22303d;overflow:hidden;vertical-align:middle;margin-inline-end:7px}
.sla-bar i{display:block;height:100%;background:var(--ok)}
.sla-bar i.mid{background:var(--warn)}.sla-bar i.bad{background:var(--bad)}
.pct{font-variant-numeric:tabular-nums;font-weight:600}
.maint-badge{display:inline-block;margin-inline-start:6px;font-size:10.5px;color:#f0d48a;border:1px solid #5a4a1e;
background:#1f1a0d;border-radius:5px;padding:0 4px;vertical-align:middle}
/* رسوم تاريخية */
.chart-controls{display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-bottom:8px}
.chart-split{display:grid;gap:10px;margin-top:8px}
.alert-list-head{display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin:16px 0 8px}
@media(max-width:980px){.col-group,.col-parent{display:none}}
@media(max-width:720px){.col-kind,.col-seen{display:none}header{padding:10px 12px}.wrap{padding:13px 12px 30px}
.card b{font-size:25px}.brand p{display:none}}
@media(prefers-reduced-motion:reduce){*{transition:none!important;animation:none!important}}
</style></head><body>
<header>
  <div class="brand"><span class="logo">💓</span><div><h1>نبض</h1><p>مراقبة الشبكة</p></div></div>
  <div class="head-right">
    <span id="conn" class="conn live">مباشر</span>
    <span id="upd" class="muted"></span>
    <button id="snmpchip" class="btn ghost snmp-chip" type="button" title="اضغط للاستعلام عن SNMP الآن">📡 SNMP</button>
    <button id="alertchip" class="btn ghost snmp-chip" type="button" title="مركز التنبيهات">🔔 <span id="alertchip-n">0</span></button>
    <button id="netbtn" class="btn ghost" type="button" title="فحص الشبكة والاكتشاف">🌐 الشبكة</button>
    <button id="settingsbtn" class="btn ghost" type="button" title="الإعدادات والإشعارات">⚙ الإعدادات</button>
    <button id="pause" class="btn ghost" type="button">⏸ إيقاف</button>
    <button id="refresh" class="btn" type="button">↻ تحديث</button>
  </div>
</header>
<div class="wrap">
  <div id="err" class="err" hidden></div>
  <div id="authwarn" class="warnbox" hidden>
    ⚠️ اللوحة غير محمية بكلمة مرور — أي جهاز على الشبكة يستطيع عرض الأجهزة وإضافة/تعديل/حذف العناوين.
    عيّن <b>dashboard.password</b> أو نفّذ <b>python nabd.py --setup</b>.
  </div>

  <nav class="views" id="views" aria-label="عروض اللوحة">
    <button type="button" data-view="devices" class="active">🖥 الأجهزة</button>
    <button type="button" data-view="map">🗺 الخريطة</button>
    <button type="button" data-view="reports">📊 التقارير</button>
    <button type="button" data-view="alerts">🔔 التنبيهات <span id="alerts-badge" class="badge zero">0</span></button>
    <button type="button" data-view="events">📜 السجل</button>
  </nav>

  <section id="view-devices" class="view">
  <section id="net" class="net unknown" aria-live="polite">
    <div class="net-main"><span class="ico" id="net-ico">🌐</span><strong id="net-title">حالة الإنترنت قيد الفحص</strong></div>
    <div id="net-sub" class="muted"></div>
  </section>

  <section class="cards">
    <div class="card neutral"><span class="k">إجمالي الأجهزة</span><b id="c-total">0</b></div>
    <div class="card ok"><span class="k">تعمل</span><b id="c-up">0</b></div>
    <div class="card bad"><span class="k">متوقفة</span><b id="c-down">0</b></div>
    <div class="card warn"><span class="k">لا يمكن الوصول إليها</span><b id="c-unreachable">0</b></div>
    <div class="card"><span class="k">قيد الفحص</span><b id="c-unknown">0</b></div>
  </section>

  <div class="bar">
    <button id="add" class="btn" type="button">＋ إضافة جهاز</button>
    <input type="search" id="q" placeholder="بحث بالاسم أو العنوان أو المجموعة…" aria-label="بحث">
    <select id="group" aria-label="المجموعة"><option value="">كل المجموعات</option></select>
    <select id="filter" aria-label="الحالة">
      <option value="all">كل الحالات</option>
      <option value="problems">المشاكل فقط</option>
      <option value="down">متوقف</option>
      <option value="unreachable">لا يمكن الوصول</option>
      <option value="up">يعمل</option>
      <option value="unknown">قيد الفحص</option>
    </select>
    <select id="sort" aria-label="الترتيب">
      <option value="status">الحالة أولاً</option>
      <option value="name">الاسم</option>
      <option value="latency">الأبطأ أولاً</option>
    </select>
    <span id="count" class="muted" style="margin-inline-start:auto"></span>
  </div>

  <div class="scroll"><table>
    <thead><tr><th>الحالة</th><th>الاسم</th><th>العنوان</th><th class="col-kind">النوع</th>
    <th class="col-group">المجموعة</th><th class="col-parent">يتبع</th><th>التأخير</th><th>المدة</th>
    <th class="col-seen">آخر ظهور</th><th class="col-act">إجراءات</th></tr></thead>
    <tbody id="tb"></tbody>
  </table></div>

  <h2>أعلى استهلاك للحركة الآن <span class="muted">(SNMP)</span></h2>
  <div id="talkers" class="talkers"></div>

  <h2>آخر الأحداث <span id="evcount" class="muted"></span></h2>
  <div class="scroll"><table>
    <thead><tr><th>منذ</th><th>الجهاز</th><th>الحدث</th></tr></thead>
    <tbody id="ev"></tbody>
  </table></div>
  </section>

  <section id="view-map" class="view" hidden>
    <div class="viewhead">
      <h2>🗺 خريطة الشبكة</h2>
      <span class="hint" id="map-hint">اسحب العقد لإعادة ترتيبها، واضغط عقدة لعرض تفاصيلها.</span>
      <span class="spacer"></span>
      <input type="search" id="map-q" placeholder="بحث بالاسم أو IP" aria-label="بحث في الخريطة" style="max-width:170px">
      <select id="map-status" aria-label="حالة الأجهزة في الخريطة">
        <option value="all">كل الحالات</option>
        <option value="problems">المشاكل فقط</option>
        <option value="down">متوقف</option>
        <option value="unreachable">لا يمكن الوصول</option>
        <option value="up">يعمل</option>
        <option value="unknown">قيد الفحص</option>
        <option value="maint">وضع صيانة</option>
      </select>
      <select id="map-group" aria-label="مجموعة الأجهزة في الخريطة"><option value="">كل المجموعات</option></select>
      <button type="button" class="btn ghost mini" id="map-zoom-in" title="تكبير">＋</button>
      <button type="button" class="btn ghost mini" id="map-zoom-out" title="تصغير">－</button>
      <button type="button" class="btn ghost mini" id="map-fit">ملاءمة</button>
      <button type="button" class="btn ghost mini" id="map-reset">إعادة ترتيب</button>
    </div>
    <div class="mapwrap" id="mapwrap"></div>
    <div class="map-legend">
      <span><i style="background:#3fb950"></i>يعمل</span>
      <span><i style="background:#f85149"></i>متوقف</span>
      <span><i style="background:#d29922"></i>لا يمكن الوصول</span>
      <span><i style="background:#6e7681"></i>قيد الفحص</span>
      <span><i style="background:#58a6ff"></i>وضع صيانة</span>
      <span>الخطوط: تبعية الأجهزة (يتبع)</span>
    </div>
  </section>

  <section id="view-reports" class="view" hidden>
    <div class="viewhead">
      <h2>📊 تقارير التوفر (SLA)</h2>
      <span class="spacer"></span>
      <div class="rangebar" id="rep-ranges">
        <button type="button" data-range="24h" class="active">24 ساعة</button>
        <button type="button" data-range="7d">7 أيام</button>
        <button type="button" data-range="30d">30 يوماً</button>
      </div>
      <a class="btn ghost mini" id="rep-export" href="/api/reports/export?range=24h">⬇ تصدير CSV</a>
    </div>
    <div class="cards" id="rep-cards"></div>
    <div class="hint" id="rep-hint" style="margin-bottom:9px">جارٍ حساب التقارير…</div>
    <div class="scroll"><table>
      <thead><tr><th>الجهاز</th><th>التوفر</th><th>آخر 30 يوماً</th><th>متوسط التأخير</th>
      <th>انقطاعات</th><th>زمن التوقف</th><th>MTTR</th><th>CPU</th><th>الذاكرة</th>
      <th>ذروة الحركة</th><th>العينات</th></tr></thead>
      <tbody id="rep-tbody"></tbody>
    </table></div>
  </section>

  <section id="view-alerts" class="view" hidden>
    <div class="viewhead">
      <h2>🔔 مركز التنبيهات</h2>
      <span class="hint" id="alert-summary"></span>
      <span class="spacer"></span>
      <button type="button" class="btn ghost mini" id="alert-refresh">↻ تحديث</button>
      <button type="button" class="btn ghost mini" id="alert-ackall">تأكيد الكل</button>
    </div>
    <div id="alert-list" class="alerts"></div>
    <div class="alert-list-head"><h2 style="margin:0">🛠 وضع الصيانة النشط</h2>
      <span class="hint" id="maint-count"></span></div>
    <div id="maint-list" class="alerts"></div>
  </section>

  <section id="view-events" class="view" hidden>
    <div class="viewhead">
      <h2>📜 سجل الأحداث</h2>
      <span class="hint" id="ev-hint">آخر الأحداث المسجّلة في قاعدة البيانات</span>
      <span class="spacer"></span>
      <div class="rangebar" id="ev-ranges">
        <button type="button" data-range="24h" class="active">24 ساعة</button>
        <button type="button" data-range="7d">7 أيام</button>
        <button type="button" data-range="30d">30 يوماً</button>
        <button type="button" data-range="all">الكل</button>
      </div>
      <button type="button" class="btn ghost mini" id="ev-refresh">↻ تحديث</button>
      <a class="btn ghost mini" id="ev-export" href="/api/events/export?range=24h">⬇ تصدير CSV</a>
    </div>
    <div class="bar">
      <input type="search" id="ev-q" placeholder="بحث بالاسم أو العنوان أو الحدث…" aria-label="بحث في السجل">
      <select id="ev-type" aria-label="نوع الحدث">
        <option value="">كل الأحداث</option>
        <option value="down">سقوط جهاز</option>
        <option value="up">عودة جهاز</option>
        <option value="unreachable">تعذر الوصول</option>
        <option value="new_device">جهاز جديد</option>
        <option value="port_down">سقوط منفذ</option>
        <option value="high_cpu">ارتفاع CPU</option>
        <option value="sfp_low">ضعف SFP</option>
        <option value="maintenance_on">بدء صيانة</option>
        <option value="maintenance_off">انتهاء صيانة</option>
      </select>
      <select id="ev-name" aria-label="الجهاز"><option value="">كل الأجهزة</option></select>
      <select id="ev-limit" aria-label="عدد النتائج">
        <option value="100">آخر 100</option>
        <option value="200" selected>آخر 200</option>
        <option value="500">آخر 500</option>
        <option value="1000">آخر 1000</option>
      </select>
      <span id="ev-count" class="muted" style="margin-inline-start:auto"></span>
    </div>
    <div class="cards" id="ev-cards"></div>
    <div class="scroll"><table>
      <thead><tr><th>الوقت</th><th>منذ</th><th>الجهاز</th><th>العنوان</th><th>الحدث</th></tr></thead>
      <tbody id="ev-tbody"></tbody>
    </table></div>
  </section>

  <div class="foot">نبض نسخة <span id="ver">2.5</span> · تحديث تلقائي كل <span id="intv">5</span> ثوانٍ</div>
</div>

<dialog id="dlg" class="modal" aria-labelledby="dtitle">
  <form id="df">
    <h3 id="dtitle">إضافة جهاز</h3>
    <div id="derr" class="err" hidden></div>
    <label>اسم الجهاز<input id="f-name" required maxlength="64" autocomplete="off"></label>
    <label>عنوان IP<input id="f-ip" required inputmode="numeric" maxlength="15" placeholder="192.168.1.10" autocomplete="off"></label>
    <label>النوع<input id="f-kind" list="dl-kinds" maxlength="32" placeholder="device"></label>
    <label>المجموعة<input id="f-group" list="dl-groups" maxlength="64" placeholder="عام"></label>
    <label>يتبع جهازاً (اختياري)<input id="f-parent" list="dl-parents" maxlength="64"></label>
    <div class="grid2">
      <label>مراقبة SNMP
        <select id="f-snmp">
          <option value="auto">تلقائي (حسب النوع)</option>
          <option value="on">مفعّلة دائماً</option>
          <option value="off">متوقفة</option>
        </select>
      </label>
      <label>نوع SNMP
        <select id="f-profile">
          <option value="auto">اكتشاف تلقائي</option>
          <option value="mikrotik">MikroTik / RouterOS</option>
          <option value="ubiquiti">Ubiquiti / AirMAX</option>
          <option value="generic">عام (IF-MIB)</option>
        </select>
      </label>
    </div>
    <label>مجتمع SNMP خاص بهذا الجهاز (اختياري)<input id="f-community" maxlength="64" autocomplete="off" placeholder="اتركه فارغاً لاستخدام المجتمع العام"></label>
    <datalist id="dl-kinds">
      <option value="router"></option><option value="internet"></option><option value="isp"></option>
      <option value="switch"></option><option value="dvr"></option><option value="camera"></option>
      <option value="server"></option><option value="wifi"></option><option value="printer"></option>
      <option value="device"></option>
    </datalist>
    <datalist id="dl-groups"></datalist>
    <datalist id="dl-parents"></datalist>
    <div class="modal-actions">
      <button type="submit" class="btn primary">حفظ</button>
      <button type="button" class="btn ghost" id="dcancel">إلغاء</button>
    </div>
  </form>
</dialog>

<dialog id="settings" class="modal wide" aria-labelledby="stitle">
  <form id="settings-form">
    <h3 id="stitle">⚙ الإعدادات والإشعارات</h3>
    <div id="s-msg" class="msg" hidden></div>

    <div class="sect">
      <h4>المراقبة</h4>
      <div class="grid2">
        <label>فحص كل كم ثانية<input id="s-interval" type="number" min="2" max="3600"></label>
        <label>حد الفشل قبل اعتبار الجهاز متوقفاً<input id="s-thresh" type="number" min="1" max="50"></label>
        <label>عدد الفحوصات المتوازية<input id="s-workers" type="number" min="1" max="512"></label>
        <label>الاحتفاظ بالأحداث (أيام)<input id="s-retention" type="number" min="1" max="3650"></label>
        <label>ساعة التقرير اليومي (0-23، فارغ = إلغاء)<input id="s-heartbeat" type="number" min="0" max="23" placeholder="8"></label>
        <label>تحديث اللوحة كل كم ثانية<input id="s-live" type="number" min="2" max="120"></label>
      </div>
    </div>

    <div class="sect">
      <h4>إشعارات البوت</h4>
      <div class="checks">
        <label><input type="checkbox" id="n-device_down"> سقوط جهاز</label>
        <label><input type="checkbox" id="n-device_up"> رجوع جهاز</label>
        <label><input type="checkbox" id="n-internet"> انقطاع/عودة الإنترنت</label>
        <label><input type="checkbox" id="n-new_device"> جهاز جديد مكتشف</label>
        <label><input type="checkbox" id="n-daily_report"> التقرير اليومي</label>
        <label><input type="checkbox" id="n-port_down"> سقوط منفذ</label>
        <label><input type="checkbox" id="n-high_cpu"> ارتفاع CPU</label>
        <label><input type="checkbox" id="n-sfp_low"> ضعف إشارة SFP</label>
      </div>
      <div class="hint">تُطبَّق الاختيارات فوراً على كل الإشعارات القادمة.</div>
    </div>

    <div class="sect">
      <h4>تيليجرام</h4>
      <label>توكن البوت<input id="s-token" type="password" autocomplete="off" placeholder="اتركه فارغاً للإبقاء على التوكن الحالي"></label>
      <div id="s-token-hint" class="hint"></div>
      <label>chat_id (واحد أو أكثر، مفصولة بفاصلة)<input id="s-chats" autocomplete="off" placeholder="مثال: 123456789"></label>
      <div class="modal-actions">
        <button type="button" class="btn" id="tg-test">💓 إرسال رسالة تجريبية</button>
        <button type="button" class="btn ghost" id="tg-chats">🔎 جلب chat_id من رسائل البوت</button>
      </div>
      <div id="tg-msg" class="msg" hidden></div>
    </div>

    <div class="sect">
      <h4>فحص الشبكة</h4>
      <label>الشبكات المفحوصة (مثل 192.168.1, 10.0.0 — فارغ = شبكات هذا الجهاز تلقائياً)
        <input id="s-scan-subnets" placeholder="192.168.1, 172.16.0"></label>
      <div id="s-scan-hint" class="hint"></div>
      <label>إعادة الفحص تلقائياً كل كم دقيقة (0 = يدوي فقط)
        <input id="s-scan-auto" type="number" min="0" max="10080"></label>
    </div>

    <div class="sect">
      <h4>الاكتشاف من راوتر مايكروتك (اختياري)</h4>
      <div class="grid2">
        <label>عنوان الراوتر<input id="s-disc-host" placeholder="192.168.1.1" autocomplete="off"></label>
        <label>مستخدم القراءة فقط<input id="s-disc-user" autocomplete="off"></label>
        <label>كلمة مرور المستخدم<input id="s-disc-pass" type="password" autocomplete="off" placeholder="اتركها فارغة للإبقاء"></label>
        <label>منفذ API<input id="s-disc-port" type="number" min="1" max="65535"></label>
        <label>إعادة الاكتشاف كل كم دقيقة (0 = إيقاف)<input id="s-disc-auto" type="number" min="0" max="10080"></label>
      </div>
      <div class="hint">ينشئ الأجهزة المكتشفة تلقائياً في المراقبة. يمكنك أيضاً الاكتشاف يدوياً من زر «🌐 الشبكة».</div>
    </div>

    <div class="sect">
      <h4>SNMP — السويتشات والمنافذ واللاسلكي</h4>
      <label class="checks" style="color:var(--tx);font-size:13.5px">
        <span style="display:flex;align-items:center;gap:6px">
          <input type="checkbox" id="s-snmp-on"> تشغيل مراقبة SNMP الدورية
        </span>
      </label>
      <div class="grid2">
        <label>مجتمع SNMP (community)<input id="s-snmp-community" autocomplete="off" placeholder="public"></label>
        <label>منفذ SNMP<input id="s-snmp-port" type="number" min="1" max="65535"></label>
        <label>فترة الاستعلام (ثانية)<input id="s-snmp-poll" type="number" min="10" max="3600"></label>
        <label>المهلة (ثانية)<input id="s-snmp-timeout" type="number" min="0.2" max="15" step="0.1"></label>
        <label>عدد المحاولات<input id="s-snmp-retries" type="number" min="0" max="5"></label>
        <label>حد تنبيه CPU (%)<input id="s-snmp-cpu" type="number" min="1" max="100"></label>
        <label>حد ضعف SFP (dBm)<input id="s-snmp-sfp" type="number" min="-60" max="10" step="0.5"></label>
        <label>نقاط رسم الحركة<input id="s-snmp-history" type="number" min="10" max="1440"></label>
        <label>تبريد التنبيه (دقيقة)<input id="s-snmp-cooldown" type="number" min="0" max="1440"></label>
      </div>
      <div class="hint" id="s-snmp-hint"></div>
      <div class="modal-actions">
        <input id="s-snmp-test-ip" placeholder="عنوان IP لاختبار سريع (اختياري)" style="max-width:260px" autocomplete="off">
        <button type="button" class="btn" id="snmp-test">🔍 اختبار SNMP</button>
        <button type="button" class="btn ghost" id="snmp-poll">⟳ استعلام كل الأجهزة الآن</button>
      </div>
      <div id="snmp-msg" class="msg" hidden></div>
      <div class="hint">يفتح SNMP على الأجهزة: MikroTik → IP → SNMP، ثم فعّل وحدّد community. للقراءة فقط أنشئ مجتمعاً منفصلاً.</div>
    </div>

    <div class="sect">
      <h4>السجل التاريخي والتقارير (SLA)</h4>
      <label class="checks" style="color:var(--tx);font-size:13.5px">
        <span style="display:flex;align-items:center;gap:6px">
          <input type="checkbox" id="m-enabled"> حفظ القياسات في قاعدة البيانات
        </span>
      </label>
      <div class="grid2">
        <label>فترة العينة (ثانية)<input id="m-seconds" type="number" min="10" max="86400"></label>
        <label>مدة الاحتفاظ (يوم)<input id="m-days" type="number" min="1" max="3650"></label>
      </div>
      <div class="hint">تُحفظ نقطة لكل جهاز (ping + SNMP) وتُستخدم في تقارير التوفر ورسوم التفاصيل والتصدير إلى CSV.</div>
    </div>

    <div class="sect">
      <h4>البريد الإلكتروني (SMTP)</h4>
      <label class="checks" style="color:var(--tx);font-size:13.5px">
        <span style="display:flex;align-items:center;gap:6px">
          <input type="checkbox" id="e-enabled"> إرسال الإشعارات بالبريد
        </span>
      </label>
      <div class="grid2">
        <label>خادم SMTP<input id="e-host" placeholder="smtp.example.com" autocomplete="off"></label>
        <label>المنفذ<input id="e-port" type="number" min="1" max="65535"></label>
        <label>المستخدم<input id="e-user" autocomplete="off"></label>
        <label>كلمة المرور<input id="e-pass" type="password" autocomplete="new-password" placeholder="اتركها فارغة للإبقاء"></label>
        <label>بريد المرسل (from)<input id="e-from" placeholder="nabd@example.com" autocomplete="off"></label>
        <label>بريد المستلمين (مفصول بفاصلة)<input id="e-to" placeholder="admin@example.com" autocomplete="off"></label>
      </div>
      <div class="checks">
        <label><input type="checkbox" id="e-tls"> STARTTLS (منفذ 587 عادة)</label>
        <label><input type="checkbox" id="e-ssl"> SSL مباشر (منفذ 465 عادة)</label>
      </div>
      <div class="modal-actions">
        <button type="button" class="btn" id="email-test">✉ إرسال بريد تجريبي</button>
      </div>
      <div id="email-msg" class="msg" hidden></div>
    </div>

    <div class="sect">
      <h4>Webhook — إشعارات JSON</h4>
      <label class="checks" style="color:var(--tx);font-size:13.5px">
        <span style="display:flex;align-items:center;gap:6px">
          <input type="checkbox" id="w-enabled"> إرسال الإشعارات إلى Webhook
        </span>
      </label>
      <label>رابط الاستقبال<input id="w-url" type="url" placeholder="https://hooks.example.com/nabd" autocomplete="off"></label>
      <label>مفتاح التوقيع السري (اختياري)<input id="w-secret" type="password" autocomplete="new-password" placeholder="اتركه فارغاً للإبقاء"></label>
      <label class="checks" style="color:var(--mut);font-size:12.5px">
        <input type="checkbox" id="w-clear-secret"> إزالة المفتاح الحالي
      </label>
      <label>الأنواع المرسلة — اختر واحدة أو أكثر (بدون اختيار = كل الأنواع)
        <select id="w-kinds" multiple size="5">
          <option value="device_down">سقوط جهاز</option>
          <option value="device_up">عودة جهاز</option>
          <option value="internet">انقطاع/عودة الإنترنت</option>
          <option value="new_device">جهاز جديد</option>
          <option value="daily_report">التقرير اليومي</option>
          <option value="port_down">سقوط منفذ</option>
          <option value="high_cpu">ارتفاع CPU</option>
          <option value="sfp_low">ضعف إشارة SFP</option>
        </select>
      </label>
      <div class="hint">يُرسل الطلب JSON مع ترويسات X-Nabd-Event وX-Nabd-Signature (HMAC-SHA256 عند وجود مفتاح سري). يعمل مع تيليجرام والبريد معاً.</div>
      <div class="modal-actions">
        <button type="button" class="btn" id="w-test">🔗 إرسال إشعار تجريبي</button>
      </div>
      <div id="w-msg" class="msg" hidden></div>
    </div>

    <div class="sect">
      <h4>اللوحة</h4>
      <div class="grid2">
        <label>كلمة مرور جديدة (فارغة = بدون تغيير)<input id="s-dash-pass" type="password" autocomplete="new-password" placeholder="اتركها فارغة للإبقاء"></label>
        <label>منفذ اللوحة (يتطلب إعادة تشغيل)<input id="s-dash-port" type="number" min="1" max="65535"></label>
      </div>
      <label class="checks" style="color:var(--mut);font-size:12.5px">
        <input type="checkbox" id="s-dash-clear"> إزالة كلمة المرور الحالية (غير مستحسن)
      </label>
    </div>

    <div class="modal-actions">
      <button type="submit" class="btn primary">حفظ الإعدادات</button>
      <button type="button" class="btn ghost" id="s-cancel">إغلاق</button>
      <span class="hint" style="margin-inline-start:auto">تُحفظ في config.yaml وتُطبَّق دون إعادة تشغيل (عدا المنفذ).</span>
    </div>
  </form>
</dialog>

<dialog id="network" class="modal wide" aria-labelledby="ntitle">
  <form id="network-form" onsubmit="return false">
    <h3 id="ntitle">🌐 فحص الشبكة والاكتشاف</h3>
    <div id="scan-msg" class="msg" hidden></div>
    <div class="scan-head">
      <button type="button" class="btn primary" id="scan-start">▶ بدء فحص الشبكة</button>
      <button type="button" class="btn" id="scan-discover">🔎 اكتشاف من الراوتر</button>
      <span id="scan-status" class="hint" style="margin-inline-start:auto"></span>
    </div>
    <div class="scan-progress"><i id="scan-fill"></i></div>
    <div class="scan-wrap"><table>
      <thead><tr><th><input type="checkbox" id="scan-all" aria-label="تحديد الكل"></th>
      <th>العنوان</th><th>الاسم</th><th>النوع</th><th>المجموعة</th><th>التأخير</th><th>المنافذ</th><th>الحالة</th></tr></thead>
      <tbody id="scan-tbody"></tbody>
    </table></div>
    <div class="hint" id="scan-summary">لم يبدأ الفحص بعد.</div>
    <div class="modal-actions">
      <button type="button" class="btn primary" id="scan-addsel">＋ إضافة المحدد للمراقبة</button>
      <button type="button" class="btn ghost" id="scan-addall">＋ إضافة كل الجديد</button>
      <button type="button" class="btn ghost" id="scan-close" style="margin-inline-start:auto">إغلاق</button>
    </div>
  </form>
</dialog>

<dialog id="detail" class="modal wide" aria-labelledby="dettitle">
  <form id="detail-form" onsubmit="return false">
    <h3 id="dettitle">تفاصيل الجهاز</h3>
    <dl id="det-body" class="detail-grid"></dl>

    <div class="sect">
      <h4>مراقبة SNMP <span id="det-snmp-at" class="hint"></span></h4>
      <div class="tabs" id="det-tabs">
        <button type="button" data-tab="system" class="active">النظام</button>
        <button type="button" data-tab="ports">المنافذ</button>
        <button type="button" data-tab="sfp">SFP الضوئي</button>
        <button type="button" data-tab="wifi">اللاسلكي</button>
        <button type="button" data-tab="traffic">الحركة</button>
      </div>
      <div id="det-pane" class="snmp-pane"><span class="hint">جارٍ جلب بيانات SNMP…</span></div>
      <div class="modal-actions">
        <button type="button" class="btn" id="det-snmp-poll">⟳ استعلام SNMP الآن</button>
        <button type="button" class="btn ghost" id="det-snmp-test">🔍 اختبار SNMP</button>
        <span class="hint" id="det-snmp-hint" style="margin-inline-start:auto"></span>
      </div>
    </div>

    <div class="sect">
      <h4>وضع الصيانة</h4>
      <div class="hint" id="det-maint-hint">غير مفعّل — تُرسل التنبيهات عند أي مشكلة.</div>
      <div class="modal-actions">
        <button type="button" class="btn mini" data-maint="30">30 دقيقة</button>
        <button type="button" class="btn mini" data-maint="120">ساعتان</button>
        <button type="button" class="btn mini" data-maint="480">8 ساعات</button>
        <button type="button" class="btn mini" data-maint="1440">24 ساعة</button>
        <button type="button" class="btn mini ghost" data-maint="0">إيقاف</button>
      </div>
    </div>

    <div class="sect">
      <h4>المنافذ والخدمات المفتوحة (TCP)</h4>
      <div id="det-ports" class="ports"><span class="hint">لم يُفحص بعد.</span></div>
      <div id="det-msg" class="msg" hidden></div>
    </div>
    <div class="modal-actions">
      <button type="button" class="btn primary" id="det-check">🔌 فحص منافذ TCP الآن</button>
      <button type="button" class="btn ghost" id="det-close" style="margin-inline-start:auto">إغلاق</button>
    </div>
  </form>
</dialog>

<dialog id="maint" class="modal" aria-labelledby="mtitle">
  <form onsubmit="return false">
    <h3 id="mtitle">🛠 وضع الصيانة</h3>
    <div id="maint-text" class="hint"></div>
    <div class="modal-actions" id="maint-opts">
      <button type="button" class="btn" data-min="30">30 دقيقة</button>
      <button type="button" class="btn" data-min="120">ساعتان</button>
      <button type="button" class="btn" data-min="480">8 ساعات</button>
      <button type="button" class="btn" data-min="1440">24 ساعة</button>
      <button type="button" class="btn ghost" data-min="0">إيقاف الصيانة</button>
    </div>
    <div class="modal-actions">
      <button type="button" class="btn ghost" id="maint-close" style="margin-inline-start:auto">إغلاق</button>
    </div>
  </form>
</dialog>

<script>
"use strict";
const $ = (id) => document.getElementById(id);
const LBL = {up:"يعمل", down:"متوقف", unreachable:"لا يمكن الوصول", unknown:"قيد الفحص"};
const ORD = {down:0, unreachable:1, unknown:2, up:3};
const EVC = {down:"سقط", up:"رجع", unreachable:"تعذر الوصول (جهاز أعلى متوقف)",
  new_device:"جهاز جديد", port_down:"سقط منفذ", high_cpu:"ارتفاع CPU",
  sfp_low:"ضعف إشارة SFP", maintenance_on:"بدأت الصيانة", maintenance_off:"انتهت الصيانة"};
const EVI = {down:"🔴", up:"🟢", unreachable:"🟠", new_device:"🆕", port_down:"🔌",
  high_cpu:"🔥", sfp_low:"🔻", maintenance_on:"🛠", maintenance_off:"✅"};
const SKEY = "nabd.ui.v2";

const state = {q:"", group:"", filter:"all", sort:"status", paused:false,
               data:null, timer:null, loading:false, groups:[], failed:false, editing:null,
               detailName:null, scanTimer:null, scanResults:[], settings:null,
               detailSnmp:null, detailTab:"system", detailSnmpAt:0, detailSnmpBusy:false,
               view:"devices", reportRange:"24h", report:null, reportBusy:false,
               detailRange:"24h", detailMetrics:null, detailMetricsRange:"",
               mapPos:{}, mapView:null, mapDragging:false, maintName:null,
               mapLayout:null, alerts:null, alertsAt:0, alertCounts:null,
               alertMaint:[], reportAt:0, mapQ:"", mapStatus:"all", mapGroup:"",
              history:null, historyAt:0, historyRange:"24h", historyBusy:false};
const VIEWS = ["devices", "map", "reports", "alerts", "events"];

function fmtDur(s){
  s = Math.max(0, Math.floor(Number(s) || 0));
  const d = Math.floor(s / 86400), h = Math.floor(s % 86400 / 3600), m = Math.floor(s % 3600 / 60);
  if (d) return d + " يوم و " + h + " ساعة";
  if (h) return h + " ساعة و " + m + " دقيقة";
  if (m) return m + " دقيقة";
  return s + " ثانية";
}
function fmtRtt(v){
  if (v == null || isNaN(v)) return {t:"—", c:""};
  const n = Math.round(v);
  return {t:n + " ms", c:n < 30 ? "rtt-ok" : (n < 120 ? "rtt-mid" : "rtt-bad")};
}
function fmtBps(v){
  const n = Number(v);
  if (!isFinite(n) || n <= 0) return "0 bps";
  if (n >= 1e9) return (n / 1e9).toFixed(2) + " Gbps";
  if (n >= 1e6) return (n / 1e6).toFixed(2) + " Mbps";
  if (n >= 1e3) return (n / 1e3).toFixed(1) + " Kbps";
  return Math.round(n) + " bps";
}
function fmtBytes(v){
  const n = Number(v);
  if (!isFinite(n) || n <= 0) return "—";
  if (n >= 1099511627776) return (n / 1099511627776).toFixed(2) + " TB";
  if (n >= 1073741824) return (n / 1073741824).toFixed(2) + " GB";
  if (n >= 1048576) return (n / 1048576).toFixed(1) + " MB";
  if (n >= 1024) return (n / 1024).toFixed(0) + " KB";
  return Math.round(n) + " B";
}
function sigClass(v){
  if (v == null || isNaN(v)) return "";
  const n = Number(v);
  return n >= -67 ? "sig-good" : (n >= -75 ? "sig-mid" : "sig-bad");
}
function safeText(v){ return v == null ? "—" : String(v); }
function td(txt, cls){
  const x = document.createElement("td");
  if (cls) x.className = cls;
  x.textContent = txt;
  return x;
}
function setConn(kind, text){
  const c = $("conn");
  c.className = "conn " + kind;
  c.textContent = text;
}
function setError(msg){
  const e = $("err");
  if (msg) { e.hidden = false; e.textContent = msg; }
  else { e.hidden = true; e.textContent = ""; }
}
function saveUi(){
  try { localStorage.setItem(SKEY, JSON.stringify({q:state.q, group:state.group,
    filter:state.filter, sort:state.sort, view:state.view})); } catch (e) {}
}
function restoreUi(){
  try {
    const v = JSON.parse(localStorage.getItem(SKEY) || "{}");
    if (typeof v.q === "string") state.q = v.q;
    if (typeof v.group === "string") state.group = v.group;
    if (typeof v.filter === "string") state.filter = v.filter;
    if (typeof v.sort === "string") state.sort = v.sort;
    if (VIEWS.includes(v.view)) state.view = v.view;
  } catch (e) {}
  $("q").value = state.q;
  $("filter").value = state.filter;
  $("sort").value = state.sort;
}
function applyView(){
  for (const name of VIEWS) $("view-" + name).hidden = name !== state.view;
  document.querySelectorAll("#views button[data-view]").forEach(b =>
    b.classList.toggle("active", b.dataset.view === state.view));
}
function setView(v){
  if (!VIEWS.includes(v)) v = "devices";
  state.view = v;
  applyView();
  saveUi();
  if (v === "reports"){ if (!state.report) loadReports(); }
  else if (v === "alerts"){ if (!state.alerts) loadAlerts(); else renderAlerts(); }
  else if (v === "events"){ if (!state.history) loadHistory(); else renderHistory(); }
  else if (v === "map") renderMap();
}

function renderNet(j){
  const net = $("net"), n = j.net || {};
  net.className = "net " + (n.state || "unknown");
  if (n.state === "up"){
    $("net-ico").textContent = "🌐";
    $("net-title").textContent = "الإنترنت يعمل";
    $("net-sub").textContent = "استجابة " + (n.probes_up || 0) + " من " + (n.probes || 0) +
      " · مستقر منذ " + fmtDur(j.now - n.since);
  } else if (n.state === "down"){
    $("net-ico").textContent = "🌐";
    $("net-title").textContent = "الإنترنت مقطوع";
    $("net-sub").textContent = "منذ " + fmtDur(j.now - (n.down_at || n.since));
  } else {
    $("net-ico").textContent = "🌐";
    if (n.ready && !n.probes){
      $("net-title").textContent = "لا توجد أجهزة إنترنت مضبوطة";
      $("net-sub").textContent = "أضف جهازاً بنوع internet في devices.csv لمراقبة الإنترنت";
    } else {
      $("net-title").textContent = "حالة الإنترنت قيد الفحص";
      $("net-sub").textContent = "بانتظار أول دورة فحص…";
    }
  }
}

function renderGroups(j){
  const gs = Array.from(new Set(j.devices.map(d => d.group).filter(Boolean)))
    .sort((a, b) => a.localeCompare(b, "ar"));
  if (state.group && !gs.includes(state.group)) { state.group = ""; saveUi(); }
  if (gs.join("\\u0000") === state.groups.join("\\u0000")) return;
  state.groups = gs;
  const sel = $("group");
  sel.replaceChildren(new Option("كل المجموعات", ""));
  for (const g of gs) sel.appendChild(new Option(g, g));
  sel.value = state.group;
  const ms = $("map-group");
  if (ms){
    ms.replaceChildren(new Option("كل المجموعات", ""));
    for (const g of gs) ms.appendChild(new Option(g, g));
    ms.value = state.mapGroup;
  }
  const ns = $("ev-name");
  if (ns && j.devices.length){
    const chosen = ns.value;
    ns.replaceChildren(new Option("كل الأجهزة", ""));
    for (const d of j.devices.slice().sort((a, b) => a.name.localeCompare(b.name, "ar")))
      ns.appendChild(new Option(d.name, d.name));
    ns.value = chosen;
  }
}

function renderTable(j){
  const q = state.q.trim().toLowerCase();
  let rows = j.devices.filter(d => {
    if (state.group && d.group !== state.group) return false;
    if (state.filter === "problems"){ if (d.eff === "up") return false; }
    else if (state.filter !== "all" && d.eff !== state.filter) return false;
    if (q){
      const hay = (d.name + " " + d.ip + " " + (d.group || "") + " " +
        (d.kind || "") + " " + (d.parent || "")).toLowerCase();
      if (!hay.includes(q)) return false;
    }
    return true;
  });
  rows.sort((a, b) => {
    if (state.sort === "name") return a.name.localeCompare(b.name, "ar", {numeric:true});
    if (state.sort === "latency"){
      const av = a.rtt == null ? -1 : a.rtt, bv = b.rtt == null ? -1 : b.rtt;
      return bv - av || a.name.localeCompare(b.name, "ar", {numeric:true});
    }
    return (ORD[a.eff] ?? 9) - (ORD[b.eff] ?? 9) ||
      a.name.localeCompare(b.name, "ar", {numeric:true});
  });

  const tb = $("tb");
  const frag = document.createDocumentFragment();
  for (const d of rows){
    const tr = document.createElement("tr");
    tr.className = d.eff;
    const c1 = document.createElement("td");
    const pill = document.createElement("span");
    pill.className = "pill st-" + d.eff;
    pill.textContent = LBL[d.eff] || d.eff;
    c1.appendChild(pill);
    tr.appendChild(c1);
    const nameTd = td(d.name, "name");
    if (d.kind) nameTd.title = "النوع: " + d.kind;
    const si = d.snmp_info;
    if (si){
      const badge = document.createElement("span");
      const cpuHigh = si.cpu != null && si.cpu >= 85;
      badge.className = "snmp-badge" + (!si.ok ? " bad" : (cpuHigh ? " warn" : ""));
      badge.textContent = !si.ok ? "SNMP ✕" : (si.cpu != null ? "CPU " + Math.round(si.cpu) + "%" : "SNMP");
      badge.title = !si.ok ? ("SNMP: " + (si.error || "لا استجابة"))
        : "SNMP متصل · منافذ " + (si.ports_up ?? 0) + "/" + (si.ports ?? 0) +
          (si.wifi ? " · لاسلكي " + si.wifi : "") +
          " · حركة " + fmtBps(si.in_bps || 0) + " دخول / " + fmtBps(si.out_bps || 0) + " خروج";
      nameTd.appendChild(badge);
    }
    tr.appendChild(nameTd);
    tr.appendChild(td(d.ip));
    tr.appendChild(td(d.kind, "col-kind"));
    tr.appendChild(td(d.group, "col-group"));
    tr.appendChild(td(d.parent || "—", "col-parent sub"));
    const r = fmtRtt(d.rtt);
    tr.appendChild(td(r.t, r.c));
    tr.appendChild(td(d.eff === "unknown" ? "—" : fmtDur(j.now - d.since)));
    const seen = d.last_ok == null ? "—" :
      (j.now - d.last_ok < 15 ? "الآن" : fmtDur(j.now - d.last_ok) + " مضت");
    tr.appendChild(td(seen, "col-seen sub"));
    const act = document.createElement("td");
    act.className = "col-act";
    const box = document.createElement("div");
    box.className = "acts";
    const ib = document.createElement("button");
    ib.type = "button";
    ib.className = "btn mini";
    ib.textContent = "تفاصيل";
    ib.dataset.action = "info";
    ib.dataset.name = d.name;
    const eb = document.createElement("button");
    eb.type = "button";
    eb.className = "btn mini";
    eb.textContent = "تعديل";
    eb.dataset.action = "edit";
    eb.dataset.name = d.name;
    const db = document.createElement("button");
    db.type = "button";
    db.className = "btn mini danger";
    db.textContent = "حذف";
    db.dataset.action = "del";
    db.dataset.name = d.name;
    box.append(ib, eb, db);
    act.appendChild(box);
    tr.appendChild(act);
    frag.appendChild(tr);
  }
  tb.replaceChildren(frag);
  $("count").textContent = "عرض " + rows.length + " من " + j.devices.length;
}

function renderSnmpChip(j){
  const chip = $("snmpchip");
  if (chip.dataset.busy) return;
  const s = j.snmp || {};
  if (!s.enabled){
    chip.className = "btn ghost snmp-chip bad";
    chip.textContent = "📡 SNMP متوقف";
    chip.title = "مراقبة SNMP متوقفة من الإعدادات";
    return;
  }
  const p = s.poll || {};
  if (p.running){
    chip.className = "btn ghost snmp-chip warn";
    chip.textContent = "📡 SNMP " + (p.done || 0) + "/" + (p.total || 0);
    chip.title = "جارٍ الاستعلام عن الأجهزة عبر SNMP…";
    return;
  }
  const total = s.monitored || 0, ok = s.responded || 0;
  chip.className = "btn ghost snmp-chip " +
    (!total ? "warn" : (ok === 0 ? "bad" : (ok < total ? "warn" : "ok")));
  chip.textContent = "📡 SNMP " + ok + "/" + total;
  chip.title = "أجهزة تستجيب لـ SNMP: " + ok + " من " + total +
    (p.finished ? " · آخر استعلام " + new Date(p.finished * 1000).toLocaleTimeString("ar-SY")
                : " · لم يُستعلم بعد") +
    " — اضغط للاستعلام الآن";
}

function renderEvents(j){
  const ev = $("ev");
  const frag = document.createDocumentFragment();
  for (const e of j.events){
    const tr = document.createElement("tr");
    tr.appendChild(td(fmtDur(j.now - e.ts) + " مضت", "sub"));
    tr.appendChild(td(e.name + (e.ip && e.ip !== "-" ? " · " + e.ip : "")));
    const cell = document.createElement("td");
    const pill = document.createElement("span");
    pill.className = "pill ev-" + e.type;
    pill.textContent = (EVI[e.type] || "•") + " " + (EVC[e.type] || e.type);
    pill.title = new Date(e.ts * 1000).toLocaleString("ar-SY");
    cell.appendChild(pill);
    tr.appendChild(cell);
    frag.appendChild(tr);
  }
  ev.replaceChildren(frag);
  $("evcount").textContent = j.events.length ? "(" + j.events.length + ")" : "";
}

function render(){
  const j = state.data;
  if (!j) return;
  for (const k of ["total", "up", "down", "unreachable", "unknown"]){
    $("c-" + k).textContent = j.counts[k] ?? 0;
  }
  renderNet(j);
  renderGroups(j);
  renderSnmpChip(j);
  renderTable(j);
  renderEvents(j);
  renderTalkers(j);
  updateAlertBadges(j.alerts);
  if (state.view === "map") renderMap();
  else if (state.view === "alerts" && Date.now() - (state.alertsAt || 0) > 15000) loadAlerts();
  else if (state.view === "events" && Date.now() - (state.historyAt || 0) > 30000) loadHistory();
  else if (state.view === "reports" && state.report &&
           Date.now() - (state.reportAt || 0) > 60000) loadReports();
  $("intv").textContent = j.live || j.interval || 5;
  $("ver").textContent = j.version || "2.5";
  $("authwarn").hidden = !!j.auth;
  document.title = (j.counts.down ? "(" + j.counts.down + ") " : "") + "نبض — مراقبة الشبكة";
}

function schedule(){
  clearTimeout(state.timer);
  if (state.paused) return;
  const seconds = (state.data && (state.data.live || state.data.interval)) || 5;
  state.timer = setTimeout(load, seconds * 1000);
}

async function load(){
  if (state.loading) return;
  state.loading = true;
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), 9000);
  try {
    const r = await fetch("/api/status", {signal: ctrl.signal, cache: "no-store"});
    if (!r.ok) throw new Error("HTTP " + r.status);
    state.data = await r.json();
    state.failed = false;
    setError("");
    setConn(state.paused ? "paused" : "live", state.paused ? "متوقف مؤقتاً" : "مباشر");
    $("upd").textContent = "آخر تحديث: " + new Date().toLocaleTimeString("ar-SY");
    render();
    if ($("detail").open && state.detailName &&
        Date.now() - state.detailSnmpAt > 15000){
      loadSnmpDetail(state.detailName, false);
    }
  } catch (e) {
    state.failed = true;
    setConn("bad", "غير متصل");
    setError("تعذر الاتصال بنبض — ستتم إعادة المحاولة تلقائياً.");
  } finally {
    clearTimeout(t);
    state.loading = false;
    schedule();
  }
}

function setPaused(p){
  state.paused = p;
  $("pause").textContent = p ? "▶ تشغيل" : "⏸ إيقاف";
  if (p){ setConn("paused", "متوقف مؤقتاً"); clearTimeout(state.timer); }
  else { setConn("live", "مباشر"); load(); }
}

$("q").addEventListener("input", () => { state.q = $("q").value; saveUi(); render(); });
$("group").addEventListener("change", () => { state.group = $("group").value; saveUi(); render(); });
$("filter").addEventListener("change", () => { state.filter = $("filter").value; saveUi(); render(); });
$("sort").addEventListener("change", () => { state.sort = $("sort").value; saveUi(); render(); });
$("refresh").addEventListener("click", load);
$("snmpchip").addEventListener("click", async () => {
  const chip = $("snmpchip");
  if (chip.dataset.busy) return;
  chip.dataset.busy = "1";
  chip.className = "btn ghost snmp-chip warn";
  chip.textContent = "📡 جارٍ الاستعلام…";
  try {
    await postJSON("/api/snmp/poll", {force: true});
    setError("");
  } catch (e) {
    const m = String((e && e.message) || e);
    if (!m.includes("قيد التنفيذ")) setError("تعذر بدء استعلام SNMP: " + m);
  } finally {
    delete chip.dataset.busy;
    load();
  }
});
$("pause").addEventListener("click", () => setPaused(!state.paused));
$("add").addEventListener("click", () => openForm(null));
$("dcancel").addEventListener("click", () => $("dlg").close());
$("df").addEventListener("submit", saveDevice);
$("tb").addEventListener("click", (e) => {
  const b = e.target.closest("button[data-action]");
  if (!b) return;
  if (b.dataset.action === "edit"){
    const d = ((state.data && state.data.devices) || []).find(x => x.name === b.dataset.name);
    if (d) openForm(d);
  } else if (b.dataset.action === "info"){
    openDetail(b.dataset.name);
  } else {
    delDevice(b.dataset.name);
  }
});

function fillList(id, values){
  const el = $(id);
  el.replaceChildren();
  for (const v of values){
    if (!v) continue;
    const o = document.createElement("option");
    o.value = v;
    el.appendChild(o);
  }
}
function setFormError(msg){
  const e = $("derr");
  if (msg){ e.hidden = false; e.textContent = msg; }
  else { e.hidden = true; e.textContent = ""; }
}
function openForm(dev){
  state.editing = dev ? dev.name : null;
  $("dtitle").textContent = dev ? "تعديل جهاز" : "إضافة جهاز";
  $("f-name").value = dev ? dev.name : "";
  $("f-ip").value = dev ? dev.ip : "";
  $("f-kind").value = dev ? (dev.kind || "device") : "device";
  $("f-group").value = dev ? (dev.group || "") : "عام";
  $("f-parent").value = dev ? (dev.parent || "") : "";
  $("f-snmp").value = dev ? (dev.snmp || "auto") : "auto";
  $("f-profile").value = dev ? (dev.profile || "auto") : "auto";
  $("f-community").value = dev ? (dev.snmp_community || "") : "";
  setFormError("");
  const ds = (state.data && state.data.devices) || [];
  fillList("dl-groups", Array.from(new Set(ds.map(x => x.group).filter(Boolean))).sort());
  fillList("dl-parents", ds.map(x => x.name).filter(n => !dev || n !== dev.name).sort());
  $("dlg").showModal();
  setTimeout(() => $("f-name").focus(), 30);
}
async function saveDevice(ev){
  ev.preventDefault();
  const body = {
    name: $("f-name").value.trim(),
    ip: $("f-ip").value.trim(),
    kind: $("f-kind").value.trim() || "device",
    group: $("f-group").value.trim() || "عام",
    parent: $("f-parent").value.trim(),
    snmp: $("f-snmp").value,
    profile: $("f-profile").value,
    snmp_community: $("f-community").value.trim()
  };
  if (!body.name || !body.ip){ setFormError("الاسم والعنوان مطلوبان"); return; }
  const btn = ev.submitter || $("df").querySelector("button[type=submit]");
  btn.disabled = true;
  setFormError("");
  try {
    const url = state.editing ? "/api/devices/" + encodeURIComponent(state.editing) : "/api/devices";
    const r = await fetch(url, {
      method: state.editing ? "PUT" : "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify(body)
    });
    const j = await r.json().catch(() => ({}));
    if (!r.ok || !j.ok) throw new Error(j.error || ("HTTP " + r.status));
    $("dlg").close();
    await load();
  } catch (err) {
    setFormError(err.message || "تعذر الحفظ");
  } finally {
    btn.disabled = false;
  }
}
async function delDevice(name){
  if (!confirm("حذف «" + name + "» من المراقبة؟")) return;
  try {
    const r = await fetch("/api/devices/" + encodeURIComponent(name), {method: "DELETE"});
    const j = await r.json().catch(() => ({}));
    if (!r.ok || !j.ok) throw new Error(j.error || ("HTTP " + r.status));
    await load();
  } catch (err) {
    setError(err.message || "تعذر حذف الجهاز");
    setTimeout(() => setError(""), 5000);
  }
}

function msg(el, text, kind){
  const e = typeof el === "string" ? $(el) : el;
  if (!text){ e.hidden = true; e.textContent = ""; e.className = "msg"; return; }
  e.hidden = false;
  e.textContent = text;
  e.className = "msg" + (kind ? " " + kind : "");
}
function postJSON(url, body){
  return fetch(url, {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify(body || {})
  }).then(async (r) => {
    const j = await r.json().catch(() => ({}));
    if (!r.ok || j.ok === false) throw new Error(j.error || ("HTTP " + r.status));
    return j;
  });
}

/* ---------------- الإعدادات ---------------- */
const NOTIF_IDS = {device_down:"n-device_down", device_up:"n-device_up",
  internet:"n-internet", new_device:"n-new_device", daily_report:"n-daily_report",
  port_down:"n-port_down", high_cpu:"n-high_cpu", sfp_low:"n-sfp_low"};

async function openSettings(){
  msg("s-msg", "");
  msg("tg-msg", "");
  try {
    const r = await fetch("/api/settings", {cache: "no-store"});
    if (!r.ok) throw new Error("HTTP " + r.status);
    const j = await r.json();
    state.settings = j;
    const m = j.monitor || {};
    $("s-interval").value = m.check_interval ?? "";
    $("s-thresh").value = m.fail_threshold ?? "";
    $("s-workers").value = m.workers ?? "";
    $("s-retention").value = m.events_retention_days ?? "";
    $("s-heartbeat").value = m.heartbeat_hour == null ? "" : m.heartbeat_hour;
    $("s-live").value = (j.dashboard && j.dashboard.live_seconds) || "";
    const n = j.notifications || {};
    for (const [k, id] of Object.entries(NOTIF_IDS)) $(id).checked = n[k] !== false;
    const tg = j.telegram || {};
    $("s-token").value = "";
    $("s-token").placeholder = tg.has_token ? "•••••• (محفوظ — اتركه فارغاً للإبقاء)" : "الصق توكن البوت من BotFather";
    $("s-chats").value = (tg.chat_ids || []).join(", ");
    $("s-token-hint").textContent = tg.token_from_env
      ? "التوكن يُقرأ من المتغير NABD_TELEGRAM_TOKEN — غيّره من نظام التشغيل."
      : (tg.enabled ? "الإشعارات مفعّلة." : "أضف التوكن وchat_id لتفعيل إشعارات البوت.");
    const s = j.scan || {};
    $("s-scan-subnets").value = (s.subnets || []).join(", ");
    $("s-scan-hint").textContent = "الشبكات الفعلية: " + ((s.effective_subnets || []).map(x => x + ".0/24").join("، ") || "غير معروفة");
    $("s-scan-auto").value = s.auto_minutes ?? 0;
    const d = j.discover || {};
    $("s-disc-host").value = d.host || "";
    $("s-disc-user").value = d.user || "";
    $("s-disc-pass").value = "";
    $("s-disc-pass").placeholder = d.has_password ? "•••••• (محفوظة — اتركها فارغة للإبقاء)" : "كلمة مرور مستخدم القراءة فقط";
    $("s-disc-port").value = d.port ?? 8728;
    $("s-disc-auto").value = d.auto_minutes ?? 0;
    const dd = j.dashboard || {};
    $("s-dash-pass").value = "";
    $("s-dash-pass").placeholder = dd.has_password ? "•••••• (محفوظة — اتركها فارغة للإبقاء)" : "بدون كلمة مرور";
    $("s-dash-port").value = dd.port ?? 8080;
    $("s-dash-clear").checked = false;

    const sn = j.snmp || {};
    $("s-snmp-on").checked = sn.enabled !== false;
    $("s-snmp-community").value = sn.community || "";
    $("s-snmp-port").value = sn.port ?? 161;
    $("s-snmp-poll").value = sn.poll_seconds ?? 60;
    $("s-snmp-timeout").value = sn.timeout ?? 1.5;
    $("s-snmp-retries").value = sn.retries ?? 1;
    $("s-snmp-cpu").value = sn.cpu_warn ?? 85;
    $("s-snmp-sfp").value = sn.sfp_rx_min ?? -20;
    $("s-snmp-history").value = sn.history_points ?? 120;
    $("s-snmp-cooldown").value = sn.alert_cooldown_minutes ?? 30;
    const poll = sn.poll || {};
    $("s-snmp-hint").textContent = poll.running
      ? ("جارٍ الاستعلام الآن… " + (poll.done || 0) + "/" + (poll.total || 0))
      : (poll.finished ? ("آخر استعلام: استجاب " + (poll.ok || 0) + " من " + (poll.total || 0) + " جهاز")
                       : "لم يُجرَ استعلام بعد — سيبدأ تلقائياً بعد التشغيل.");
    msg("snmp-msg", "");
    const mt = j.metrics || {};
    $("m-enabled").checked = mt.enabled !== false;
    $("m-seconds").value = mt.sample_seconds ?? 60;
    $("m-days").value = mt.keep_days ?? 30;
    const em = j.email || {};
    $("e-enabled").checked = !!em.enabled;
    $("e-host").value = em.host || "";
    $("e-port").value = em.port ?? 587;
    $("e-user").value = em.user || "";
    $("e-pass").value = "";
    $("e-pass").placeholder = em.has_password ? "•••••• (محفوظة — اتركها فارغة للإبقاء)" : "كلمة مرور SMTP";
    $("e-from").value = em.from || "";
    $("e-to").value = (em.to || []).join(", ");
    $("e-tls").checked = em.tls !== false;
    $("e-ssl").checked = !!em.ssl;
    msg("email-msg", "");
    const wh = j.webhook || {};
    $("w-enabled").checked = !!wh.enabled;
    $("w-url").value = wh.url || "";
    $("w-secret").value = "";
    $("w-secret").placeholder = wh.has_secret ? "•••••• (محفوظ — اتركه فارغاً للإبقاء)" : "مفتاح توقيع اختياري";
    $("w-clear-secret").checked = false;
    const kinds = wh.kinds || [];
    for (const opt of $("w-kinds").options) opt.selected = kinds.includes(opt.value);
    $("w-url").placeholder = wh.ready ? "جاهز للإرسال" : "https://hooks.example.com/nabd";
    msg("w-msg", "");
    $("settings").showModal();
  } catch (e) {
    setError("تعذر جلب الإعدادات: " + e.message);
  }
}

async function saveSettings(ev){
  ev.preventDefault();
  const btn = $("settings-form").querySelector("button[type=submit]");
  btn.disabled = true;
  msg("s-msg", "جارٍ الحفظ…");
  const hb = $("s-heartbeat").value.trim();
  const body = {
    monitor: {
      check_interval: Number($("s-interval").value) || 10,
      fail_threshold: Number($("s-thresh").value) || 3,
      workers: Number($("s-workers").value) || 100,
      events_retention_days: Number($("s-retention").value) || 30,
      heartbeat_hour: hb === "" ? null : Number(hb)
    },
    notifications: {},
    telegram: {
      token: $("s-token").value.trim(),
      chat_ids: $("s-chats").value.split(/[,،\\s]+/).map(x => x.trim()).filter(Boolean)
    },
    scan: {
      subnets: $("s-scan-subnets").value,
      auto_minutes: Number($("s-scan-auto").value) || 0
    },
    discover: {
      host: $("s-disc-host").value.trim(),
      user: $("s-disc-user").value.trim(),
      password: $("s-disc-pass").value,
      port: Number($("s-disc-port").value) || 8728,
      auto_minutes: Number($("s-disc-auto").value) || 0
    },
    dashboard: {
      password: $("s-dash-pass").value,
      port: Number($("s-dash-port").value) || 8080,
      live_seconds: Number($("s-live").value) || 5,
      clear_password: $("s-dash-clear").checked
    },
    snmp: {
      enabled: $("s-snmp-on").checked,
      community: $("s-snmp-community").value.trim() || "public",
      port: Number($("s-snmp-port").value) || 161,
      poll_seconds: Number($("s-snmp-poll").value) || 60,
      timeout: Number($("s-snmp-timeout").value) || 1.5,
      retries: Number($("s-snmp-retries").value) || 0,
      cpu_warn: Number($("s-snmp-cpu").value) || 85,
      sfp_rx_min: Number($("s-snmp-sfp").value || -20),
      history_points: Number($("s-snmp-history").value) || 120,
      alert_cooldown_minutes: Number($("s-snmp-cooldown").value) || 0
    },
    metrics: {
      enabled: $("m-enabled").checked,
      sample_seconds: Number($("m-seconds").value) || 60,
      keep_days: Number($("m-days").value) || 30
    },
    email: {
      enabled: $("e-enabled").checked,
      host: $("e-host").value.trim(),
      port: Number($("e-port").value) || 587,
      user: $("e-user").value.trim(),
      password: $("e-pass").value,
      from: $("e-from").value.trim(),
      to: $("e-to").value.split(/[,;\\s]+/).map(x => x.trim()).filter(Boolean),
      tls: $("e-tls").checked,
      ssl: $("e-ssl").checked
    },
    webhook: {
      enabled: $("w-enabled").checked,
      url: $("w-url").value.trim(),
      secret: $("w-secret").value,
      clear_secret: $("w-clear-secret").checked,
      kinds: Array.from($("w-kinds").selectedOptions).map(o => o.value)
    }
  };
  for (const [k, id] of Object.entries(NOTIF_IDS)) body.notifications[k] = $(id).checked;
  try {
    const r = await fetch("/api/settings", {
      method: "PUT",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify(body)
    });
    const j = await r.json().catch(() => ({}));
    if (!r.ok || !j.ok) throw new Error(j.error || ("HTTP " + r.status));
    msg("s-msg", j.message || "حُفظت الإعدادات.", j.restart_required ? "" : "ok");
    await load();
  } catch (e) {
    msg("s-msg", e.message || "تعذر حفظ الإعدادات", "bad");
  } finally {
    btn.disabled = false;
  }
}

async function tgTest(){
  msg("tg-msg", "جارٍ الإرسال…");
  try {
    const j = await postJSON("/api/telegram/test", {});
    const lines = (j.results || []).map(r => r.chat + ": " + (r.result === "ok" ? "وصلت ✓" : r.result));
    msg("tg-msg", "تم الإرسال — " + (lines.join(" · ") || "لا نتائج"), j.ok ? "ok" : "bad");
  } catch (e) {
    msg("tg-msg", e.message || "تعذر الإرسال — احفظ الإعدادات أولاً", "bad");
  }
}

async function tgChats(){
  msg("tg-msg", "جارٍ جلب المحادثات…");
  try {
    const token = $("s-token").value.trim();
    const j = await postJSON("/api/telegram/chats", token ? {token} : {});
    if (!j.chats || !j.chats.length){
      msg("tg-msg", "لا محادثات. أرسل رسالة للبوت من تيليجرام أولاً ثم أعد المحاولة.", "bad");
      return;
    }
    $("s-chats").value = j.chats.map(c => c.id).join(", ");
    msg("tg-msg", "وُجدت: " + j.chats.map(c => (c.title ? c.title + " (" + c.id + ")" : c.id)).join(" · "), "ok");
  } catch (e) {
    msg("tg-msg", e.message || "تعذر جلب المحادثات", "bad");
  }
}

/* ---------------- فحص الشبكة ---------------- */
function openNetwork(){
  msg("scan-msg", "");
  $("network").showModal();
  refreshScan();
}
function renderPortsInline(ports){
  if (!ports || !ports.length) return "—";
  return ports.map(p => typeof p === "object" ? (p.port + (p.service ? " " + p.service : "")) : p).join("، ");
}
function renderScan(){
  const tb = $("scan-tbody");
  const frag = document.createDocumentFragment();
  for (const r of state.scanResults){
    const tr = document.createElement("tr");
    const c0 = document.createElement("td");
    if (!r.known){
      const cb = document.createElement("input");
      cb.type = "checkbox";
      cb.className = "scan-check";
      cb.value = r.ip;
      c0.appendChild(cb);
    }
    tr.appendChild(c0);
    tr.appendChild(td(r.ip));
    tr.appendChild(td(r.name || "—", "name"));
    tr.appendChild(td(r.kind || "—"));
    tr.appendChild(td(r.group || "—"));
    const rt = fmtRtt(r.rtt);
    tr.appendChild(td(rt.t, rt.c));
    tr.appendChild(td(renderPortsInline(r.ports), "ports"));
    const st = document.createElement("td");
    const pill = document.createElement("span");
    pill.className = "pill " + (r.known ? "st-up" : "st-unknown");
    pill.textContent = r.known ? "مراقَب" : "جديد";
    st.appendChild(pill);
    tr.appendChild(st);
    frag.appendChild(tr);
  }
  tb.replaceChildren(frag);
  $("scan-all").checked = false;
}
function renderScanState(j){
  const total = j.total || 0, done = j.done || 0;
  const pct = total ? Math.min(100, Math.round(done * 100 / total)) : 0;
  $("scan-fill").style.width = pct + "%";
  const parts = [];
  if (j.running) parts.push("جارٍ الفحص… " + done + "/" + total + " (" + pct + "%)");
  else if (j.finished) parts.push("انتهى الفحص");
  if (j.subnets && j.subnets.length) parts.push("الشبكات: " + j.subnets.map(x => x + ".0/24").join("، "));
  if (j.alive) parts.push("استجاب: " + j.alive);
  $("scan-status").textContent = parts.join(" · ");
  const news = state.scanResults.filter(r => !r.known).length;
  $("scan-summary").textContent = state.scanResults.length
    ? ("النتائج: " + state.scanResults.length + " جهاز ظاهر · جديد غير مراقَب: " + news)
    : (j.running ? "جارٍ الفحص…" : "لم يبدأ الفحص بعد.");
  if (j.error) msg("scan-msg", j.error, "bad");
}
async function refreshScan(){
  try {
    const r = await fetch("/api/scan/status", {cache: "no-store"});
    const j = await r.json();
    if (Array.isArray(j.results)) state.scanResults = j.results;
    renderScan();
    renderScanState(j);
    clearTimeout(state.scanTimer);
    if (j.running) state.scanTimer = setTimeout(refreshScan, 1500);
  } catch (e) {
    msg("scan-msg", "تعذر جلب حالة الفحص", "bad");
  }
}
async function startScan(){
  msg("scan-msg", "");
  try {
    const j = await postJSON("/api/scan/start", {});
    msg("scan-msg", j.message || "بدأ الفحص", "ok");
    state.scanResults = [];
    refreshScan();
  } catch (e) {
    msg("scan-msg", e.message || "تعذر بدء الفحص", "bad");
  }
}
async function scanAdd(all){
  const ips = Array.from(document.querySelectorAll(".scan-check:checked")).map(x => x.value);
  if (!all && !ips.length){ msg("scan-msg", "حدّد أجهزة أولاً، أو استخدم «إضافة كل الجديد».", "bad"); return; }
  msg("scan-msg", "جارٍ الإضافة…");
  try {
    const j = await postJSON("/api/scan/add", all ? {all: true} : {ips});
    msg("scan-msg", "أُضيف " + (j.added || []).length + " جهاز" +
      ((j.skipped || 0) ? " · تُخطّي " + j.skipped : ""), "ok");
    await load();
    refreshScan();
  } catch (e) {
    msg("scan-msg", e.message || "تعذر إضافة الأجهزة", "bad");
  }
}
async function discoverNow(){
  msg("scan-msg", "جارٍ الاكتشاف من الراوتر… قد يستغرق بعض الوقت.");
  const btn = $("scan-discover");
  btn.disabled = true;
  try {
    const j = await postJSON("/api/discover", {});
    const newOnes = j.new || [];
    msg("scan-msg", newOnes.length ? ("اكتُشف وأُضيف: " + newOnes.map(x => x.name + " (" + x.ip + ")").join("، ")) : "لا أجهزة جديدة من الراوتر.", "ok");
    await load();
  } catch (e) {
    msg("scan-msg", e.message || "تعذر الاكتشاف", "bad");
  } finally {
    btn.disabled = false;
  }
}

/* ---------------- عرض SNMP داخل تفاصيل الجهاز ---------------- */
const WIFI_KIND = {client:"عميل", ap:"نقطة وصول", radio:"راديو"};
function mk(tag, cls, text){
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text != null) e.textContent = text;
  return e;
}
function snmpTable(headers, rows){
  const wrap = mk("div");
  const table = mk("table", "snmp-table");
  const thead = document.createElement("thead");
  const hr = document.createElement("tr");
  for (const h of headers) hr.appendChild(mk("th", "", h));
  thead.appendChild(hr);
  const tbody = document.createElement("tbody");
  for (const row of rows){
    const tr = document.createElement("tr");
    for (const cell of row){
      const val = (cell && typeof cell === "object") ? cell : {t: cell};
      const tdEl = mk("td", val.c || "", val.t == null ? "—" : String(val.t));
      if (val.title) tdEl.title = val.title;
      tr.appendChild(tdEl);
    }
    tbody.appendChild(tr);
  }
  table.append(thead, tbody);
  wrap.appendChild(table);
  return wrap;
}
function metricCard(label, value, sub, barPct, barClass){
  const box = mk("div", "metric");
  box.appendChild(mk("span", "k", label));
  box.appendChild(mk("b", "", value == null ? "—" : String(value)));
  if (sub) box.appendChild(mk("small", "", " " + sub));
  if (barPct != null && isFinite(barPct)){
    const bar = mk("div", "bar");
    const fill = document.createElement("i");
    fill.style.width = Math.max(0, Math.min(100, barPct)) + "%";
    if (barClass) fill.className = barClass;
    bar.appendChild(fill);
    box.appendChild(bar);
  }
  return box;
}
function svgNode(name, attrs){
  const e = document.createElementNS("http://www.w3.org/2000/svg", name);
  for (const [k, v] of Object.entries(attrs || {})) e.setAttribute(k, v);
  return e;
}
function drawTrafficChart(history){
  const box = mk("div");
  const points = (history || []).filter(p => Array.isArray(p) && p.length >= 3);
  if (points.length < 2){
    box.appendChild(mk("div", "hint", "لا توجد نقاط كافية بعد — ستظهر الحركة بعد استعلامين متتاليين."));
    return box;
  }
  const W = 680, H = 230, L = 62, R = 12, T = 14, B = 28;
  const max = Math.max(1, ...points.map(p => Math.max(Number(p[1]) || 0, Number(p[2]) || 0)));
  const x = i => L + i * (W - L - R) / Math.max(1, points.length - 1);
  const y = v => T + (1 - (Number(v) || 0) / max) * (H - T - B);
  const svg = svgNode("svg", {viewBox: `0 0 ${W} ${H}`, class: "chart", role: "img",
    "aria-label": "رسم حركة البيانات الداخلة والخارجة"});
  for (let i = 0; i <= 4; i++){
    const gy = T + i * (H - T - B) / 4;
    svg.appendChild(svgNode("line", {x1: L, y1: gy, x2: W - R, y2: gy,
      stroke: "rgba(255,255,255,.08)", "stroke-width": 1}));
    const label = svgNode("text", {x: L - 8, y: gy + 4, fill: "#8b98a5",
      "font-size": 11, "text-anchor": "end"});
    label.textContent = fmtBps(Math.round(max * (1 - i / 4)));
    svg.appendChild(label);
  }
  const mkPath = (key, color, fill) => {
    const pts = points.map((p, i) => `${x(i).toFixed(1)},${y(p[key]).toFixed(1)}`);
    if (fill){
      const area = `M ${L},${H - B} L ${pts.join(" L ")} L ${x(points.length - 1)},${H - B} Z`;
      svg.appendChild(svgNode("path", {d: area, fill: color, "fill-opacity": ".12", stroke: "none"}));
    }
    svg.appendChild(svgNode("polyline", {points: pts.join(" "), fill: "none",
      stroke: color, "stroke-width": 2, "stroke-linejoin": "round", "stroke-linecap": "round"}));
    const last = points[points.length - 1];
    svg.appendChild(svgNode("circle", {cx: x(points.length - 1), cy: y(last[key]),
      r: 3, fill: color}));
  };
  mkPath(1, "#3fb950", true);
  mkPath(2, "#2f81f7", true);
  const t0 = new Date(points[0][0] * 1000).toLocaleTimeString("ar-SY",
    {hour: "2-digit", minute: "2-digit"});
  const t1 = new Date(points[points.length - 1][0] * 1000).toLocaleTimeString("ar-SY",
    {hour: "2-digit", minute: "2-digit"});
  const l0 = svgNode("text", {x: L, y: H - 8, fill: "#8b98a5", "font-size": 11});
  l0.textContent = t0;
  const l1 = svgNode("text", {x: W - R, y: H - 8, fill: "#8b98a5",
    "font-size": 11, "text-anchor": "end"});
  l1.textContent = t1;
  svg.append(l0, l1);
  box.appendChild(svg);
  const legend = mk("div", "legend");
  const inL = mk("span"); inL.innerHTML = '<i style="background:#3fb950"></i>دخول';
  const outL = mk("span"); outL.innerHTML = '<i style="background:#2f81f7"></i>خروج';
  legend.append(inL, outL);
  box.appendChild(legend);
  return box;
}
function renderSnmpPane(){
  const pane = $("det-pane");
  pane.replaceChildren();
  document.querySelectorAll("#det-tabs button").forEach(b => {
    b.classList.toggle("active", b.dataset.tab === state.detailTab);
  });
  const s = state.detailSnmp;
  const tab = state.detailTab;
  if (tab === "traffic"){
    renderTrafficPane(pane, s || {});
    return;
  }
  if (!s){
    pane.appendChild(mk("span", "hint", "لا توجد بيانات SNMP بعد. اضغط «استعلام SNMP الآن»."));
    return;
  }
  if (!s.ok){
    const err = mk("div", "msg bad", "SNMP: " + (s.error || "لا استجابة"));
    pane.appendChild(err);
    if (!(s.interfaces && s.interfaces.length) && !(s.sfp && s.sfp.length)) return;
  }
  if (tab === "system"){
    const sys = s.sys || {}, mem = s.mem || {};
    const grid = mk("div", "metrics");
    grid.append(
      metricCard("المعالج (CPU)", s.cpu == null ? "—" : Math.round(s.cpu) + "%",
        s.cpu == null ? "غير متاح" : (s.cpu >= 85 ? "مرتفع" : "طبيعي")),
      metricCard("الذاكرة", mem.pct == null ? "—" : mem.pct + "%",
        mem.total ? fmtBytes(mem.used) + " من " + fmtBytes(mem.total) : "غير متاحة",
        mem.pct, mem.pct >= 90 ? "bad" : (mem.pct >= 75 ? "mid" : "")),
      metricCard("الحرارة", s.temp == null ? "—" : Math.round(s.temp) + "°",
        s.temp >= 70 ? "مرتفعة" : "طبيعية"),
      metricCard("مدة التشغيل", sys.uptime_seconds ? fmtDur(sys.uptime_seconds) : "—", "منذ آخر إقلاع"),
      metricCard("المنافذ", (s.summary && s.summary.ports_up != null ? s.summary.ports_up + "/" + s.summary.ports : "—"),
        "منفذ يعمل"),
      metricCard("الحركة الآن", fmtBps((s.total || {}).in_bps || 0),
        "دخول · " + fmtBps((s.total || {}).out_bps || 0) + " خروج"),
      metricCard("اللاسلكي", (s.wifi || []).length, "جهاز/راديو"),
      metricCard("SFP", (s.sfp || []).length, "منفذ ضوئي")
    );
    pane.appendChild(grid);
    const rows = [
      ["النظام", sys.descr || "—"],
      ["اسم النظام", sys.name || "—"],
      ["الشركة/النوع", s.vendor || "—"],
      ["Object ID", sys.objectid || "—"],
      ["الموقع", sys.location || "—"],
      ["جهة الاتصال", sys.contact || "—"],
      ["آخر استعلام", s.at ? new Date(s.at * 1000).toLocaleString("ar-SY") : "—"],
    ];
    pane.appendChild(snmpTable(["الحقل", "القيمة"], rows));
  } else if (tab === "ports"){
    const items = s.interfaces || [];
    if (!items.length) pane.appendChild(mk("div", "hint", "لا توجد واجهات IF-MIB — قد يكون SNMP مغلقاً أو الجهاز لا يدعم الجدول."));
    else {
      const rows = items.map(r => {
        const up = r.oper === 1;
        const st = {t: up ? "يعمل" : (r.admin === 2 ? "معطّل" : "متوقف"), c: up ? "sig-good" : "sig-bad"};
        return [
          {t: r.name, title: r.alias || r.descr || ""},
          st,
          (r.speed || 0) ? String(r.speed) + " Mbps" : "—",
          fmtBps(r.in_bps),
          fmtBps(r.out_bps),
          fmtBytes(r.in_octets),
          fmtBytes(r.out_octets),
          (r.in_errors || 0) + " / " + (r.out_errors || 0),
          (r.in_discards || 0) + " / " + (r.out_discards || 0),
          r.alias || r.descr || "—"
        ];
      });
      pane.appendChild(snmpTable(["المنفذ", "الحالة", "السرعة", "دخول", "خروج",
        "بايتات داخلة", "بايتات خارجة", "أخطاء دخ/خر", "مهمَل دخ/خر", "الوصف"], rows));
    }
  } else if (tab === "sfp"){
    const items = s.sfp || [];
    if (!items.length) pane.appendChild(mk("div", "hint", "لا توجد بيانات SFP. هذه الميزة تُقرأ تلقائياً من MikroTik (mtxrOpticalTable)."));
    else {
      const rows = items.map(r => {
        const rxCls = r.rx == null ? "" : (r.rx <= -20 ? "sig-bad" : (r.rx <= -15 ? "sig-mid" : "sig-good"));
        return [
          {t: r.name, title: r.vendor || ""},
          {t: r.rx == null ? "—" : r.rx + " dBm", c: rxCls},
          r.tx == null ? "—" : r.tx + " dBm",
          r.temp == null ? "—" : r.temp + "°",
          r.voltage == null ? "—" : r.voltage + " V",
          r.bias == null ? "—" : r.bias + " mA",
          r.wavelength ? r.wavelength + " nm" : "—",
          r.rx_loss ? "فقد استقبال" : (r.tx_fault ? "خطأ إرسال" : "سليم"),
          r.serial || r.vendor || "—"
        ];
      });
      pane.appendChild(snmpTable(["المنفذ", "استقبال Rx", "إرسال Tx", "الحرارة",
        "الجهد", "التيار", "الطول الموجي", "الحالة", "الماركة/التسلسل"], rows));
    }
  } else if (tab === "wifi"){
    const items = s.wifi || [];
    if (!items.length) pane.appendChild(mk("div", "hint", "لا يوجد عملاء أو راديوهات لاسلكية في SNMP لهذا الجهاز."));
    else {
      const rows = items.map(r => [
        WIFI_KIND[r.kind] || r.kind || "—",
        {t: r.ssid || r.name || "—", title: r.mac || ""},
        {t: r.signal == null ? "—" : r.signal + " dBm", c: sigClass(r.signal)},
        r.noise == null ? "—" : r.noise + " dBm",
        r.snr == null ? "—" : r.snr + " dB",
        r.tx_rate == null ? "—" : r.tx_rate + " Mbps",
        r.rx_rate == null ? "—" : r.rx_rate + " Mbps",
        r.ccq == null ? "—" : r.ccq + "%",
        r.freq ? (r.freq + " MHz") : (r.band || "—"),
        r.ip || "—",
        r.uptime ? fmtDur(r.uptime) : "—"
      ]);
      pane.appendChild(snmpTable(["النوع", "الاسم/SSID", "الإشارة", "الضجيج", "SNR",
        "إرسال", "استقبال", "CCQ", "التردد", "IP", "المدة"], rows));
    }
  }
}
function renderTrafficPane(pane, s){
  const total = s.total || {};
    const grid = mk("div", "metrics");
    grid.append(
      metricCard("الحركة الداخلة", fmtBps(total.in_bps || 0), "الآن"),
      metricCard("الحركة الخارجة", fmtBps(total.out_bps || 0), "الآن"),
      metricCard("نقاط الرسم", (s.history || []).length, "نقطة في الذاكرة")
    );
    pane.appendChild(grid);
    pane.appendChild(drawTrafficChart(s.history));
    const hist = mk("div", "sect");
    hist.appendChild(mk("h4", "", "📈 السجل التاريخي (قاعدة البيانات)"));
    const bar = mk("div", "rangebar");
    for (const [key, label] of [["1h", "ساعة"], ["6h", "6 ساعات"],
                                 ["24h", "24 ساعة"], ["7d", "7 أيام"], ["30d", "30 يوماً"]]){
      const b = mk("button", state.detailRange === key ? "active" : "", label);
      b.type = "button";
      b.dataset.hrange = key;
      b.addEventListener("click", () => { state.detailRange = key; loadDetailMetrics(); });
      bar.appendChild(b);
    }
    hist.appendChild(bar);
    const hbox = mk("div", "chart-split");
    hbox.id = "det-hchart";
    hbox.appendChild(mk("div", "hint", "جارٍ تحميل السجل…"));
    hist.appendChild(hbox);
    pane.appendChild(hist);
    loadDetailMetrics();
}
function drawHistoryChart(points, defs, title){
  const wrap = mk("div");
  if (title) wrap.appendChild(mk("div", "hint", title));
  const rows = (points || []).filter(p => defs.some(d => p[d.idx] != null));
  if (rows.length < 2){
    wrap.appendChild(mk("div", "hint", "لا توجد نقاط كافية لهذا الرسم بعد."));
    return wrap;
  }
  const W = 680, H = 210, L = 66, R = 12, T = 12, B = 26;
  let max = 1;
  for (const p of rows) for (const d of defs){
    const v = Number(p[d.idx]);
    if (!isNaN(v) && v > max) max = v;
  }
  const x = i => L + i * (W - L - R) / Math.max(1, rows.length - 1);
  const y = v => T + (1 - (Number(v) || 0) / max) * (H - T - B);
  const svg = svgNode("svg", {viewBox: `0 0 ${W} ${H}`, class: "chart", role: "img",
    "aria-label": title || "رسم بياني"});
  for (let i = 0; i <= 4; i++){
    const gy = T + i * (H - T - B) / 4;
    svg.appendChild(svgNode("line", {x1: L, y1: gy, x2: W - R, y2: gy,
      stroke: "rgba(255,255,255,.08)", "stroke-width": 1}));
    const lb = svgNode("text", {x: L - 8, y: gy + 4, fill: "#8b98a5",
      "font-size": 11, "text-anchor": "end"});
    lb.textContent = defs[0].fmt(Math.round(max * (1 - i / 4)));
    svg.appendChild(lb);
  }
  for (const d of defs){
    let run = [];
    const flush = () => {
      if (run.length > 1){
        svg.appendChild(svgNode("polyline", {points: run.join(" "), fill: "none",
          stroke: d.color, "stroke-width": 2, "stroke-linejoin": "round",
          "stroke-linecap": "round"}));
      } else if (run.length === 1){
        const [cx, cy] = run[0].split(",");
        svg.appendChild(svgNode("circle", {cx, cy, r: 2, fill: d.color}));
      }
      run = [];
    };
    rows.forEach((p, i) => {
      const v = p[d.idx];
      if (v == null){ flush(); return; }
      run.push(`${x(i).toFixed(1)},${y(v).toFixed(1)}`);
    });
    flush();
  }
  const span = rows[rows.length - 1][0] - rows[0][0];
  const tf = ts => new Date(ts * 1000).toLocaleString("ar-SY",
    span > 172800 ? {month: "2-digit", day: "2-digit"} : {hour: "2-digit", minute: "2-digit"});
  const l0 = svgNode("text", {x: L, y: H - 7, fill: "#8b98a5", "font-size": 11});
  l0.textContent = tf(rows[0][0]);
  const lm = svgNode("text", {x: W / 2, y: H - 7, fill: "#8b98a5",
    "font-size": 11, "text-anchor": "middle"});
  lm.textContent = tf(rows[Math.floor(rows.length / 2)][0]);
  const l1 = svgNode("text", {x: W - R, y: H - 7, fill: "#8b98a5",
    "font-size": 11, "text-anchor": "end"});
  l1.textContent = tf(rows[rows.length - 1][0]);
  svg.append(l0, lm, l1);
  wrap.appendChild(svg);
  const legend = mk("div", "legend");
  for (const d of defs){
    const s = mk("span");
    s.innerHTML = '<i style="background:' + d.color + '"></i>' + d.label;
    legend.appendChild(s);
  }
  wrap.appendChild(legend);
  return wrap;
}
async function loadDetailMetrics(){
  const name = state.detailName;
  const box = $("det-hchart");
  if (!name || !box) return;
  box.replaceChildren(mk("div", "hint", "جارٍ تحميل السجل…"));
  try {
    const r = await fetch("/api/metrics/" + encodeURIComponent(name) +
      "?range=" + encodeURIComponent(state.detailRange), {cache: "no-store"});
    const j = await r.json();
    if (state.detailName !== name || !$("det-hchart")) return;
    state.detailMetrics = j;
    const box2 = $("det-hchart");
    box2.replaceChildren();
    const pts = j.series || [];
    if (!pts.length){
      box2.appendChild(mk("div", "hint",
        "لا توجد قياسات محفوظة لهذه المدة بعد. يُحفظ سجل جديد كل " +
        (j.step || 60) + " ثانية تقريباً."));
      return;
    }
    const sum = j.summary || {};
    const g = mk("div", "metrics");
    g.append(
      metricCard("التوفر", sum.pct == null ? "—" : sum.pct + "%",
        (sum.up || 0) + " من " + (sum.samples || 0) + " عينة"),
      metricCard("متوسط التأخير", sum.avg_rtt == null ? "—" : Math.round(sum.avg_rtt) + " ms", "خلال المدة"),
      metricCard("متوسط CPU", sum.avg_cpu == null ? "—" : sum.avg_cpu + "%", "حسب SNMP"),
      metricCard("متوسط الذاكرة", sum.avg_mem == null ? "—" : sum.avg_mem + "%", "حسب SNMP"),
      metricCard("ذروة الدخول", fmtBps(sum.peak_in || 0), "أعلى قيمة"),
      metricCard("ذروة الخروج", fmtBps(sum.peak_out || 0), "أعلى قيمة")
    );
    box2.appendChild(g);
    const split = mk("div", "chart-split");
    split.appendChild(drawHistoryChart(pts, [
      {idx: 1, label: "التأخير (ms)", color: "#d29922", fmt: v => Math.round(v) + " ms"},
      {idx: 2, label: "CPU %", color: "#f85149", fmt: v => Math.round(v) + "%"},
      {idx: 3, label: "الذاكرة %", color: "#a371f7", fmt: v => Math.round(v) + "%"}
    ], "الأداء"));
    split.appendChild(drawHistoryChart(pts, [
      {idx: 4, label: "دخول", color: "#3fb950", fmt: fmtBps},
      {idx: 5, label: "خروج", color: "#2f81f7", fmt: fmtBps}
    ], "الحركة"));
    box2.appendChild(split);
    box2.appendChild(mk("div", "hint",
      "المصدر: قياسات محفوظة في nabd.db · " + (j.series || []).length + " نقطة"));
  } catch (e) {
    const b = $("det-hchart");
    if (b) b.replaceChildren(mk("div", "msg bad", "تعذر جلب السجل التاريخي"));
  }
}
function setDetailTab(tab){
  state.detailTab = tab;
  renderSnmpPane();
}
function setSnmpHint(text, kind){
  const el = $("det-snmp-hint");
  el.textContent = text || "";
  el.className = "hint" + (kind ? " " + kind : "");
}
async function loadSnmpDetail(name, force){
  if (!name || state.detailSnmpBusy) return;
  state.detailSnmpBusy = true;
  setSnmpHint(force ? "جارٍ الاستعلام عبر SNMP…" : "جارٍ التحديث…");
  try {
    if (force){
      const r = await postJSON("/api/snmp/poll", {name});
      if (!r.ok) throw new Error(r.error || "لا استجابة SNMP");
    }
    const res = await fetch("/api/snmp/device/" + encodeURIComponent(name), {cache: "no-store"});
    if (res.status === 404){
      state.detailSnmp = null;
      state.detailSnmpAt = Date.now();
      renderSnmpPane();
      setSnmpHint("لم يُستعلم هذا الجهاز بعد.");
      return;
    }
    if (!res.ok) throw new Error("HTTP " + res.status);
    state.detailSnmp = await res.json();
    if (state.detailSnmp.pending || state.detailSnmp.error_code === "no_data"){
      state.detailSnmp = null;
      state.detailSnmpAt = Date.now();
      renderSnmpPane();
      setSnmpHint("لم يُستعلم هذا الجهاز بعد.");
      return;
    }
    state.detailSnmpAt = Date.now();
    renderSnmpPane();
    $("det-snmp-at").textContent = state.detailSnmp.at
      ? "· آخر استعلام " + new Date(state.detailSnmp.at * 1000).toLocaleTimeString("ar-SY") : "";
    setSnmpHint(state.detailSnmp.ok ? "" : ("تعذر: " + (state.detailSnmp.error || "لا استجابة")));
  } catch (e){
    setSnmpHint(e.message || "تعذر جلب بيانات SNMP", "bad");
  } finally {
    state.detailSnmpBusy = false;
  }
}
function renderPorts(el, ports, at){
  el.replaceChildren();
  if (!ports || !ports.length){
    const s = document.createElement("span");
    s.className = "hint";
    s.textContent = "لا منافذ مفتوحة من القائمة المفحوصة.";
    el.appendChild(s);
    return;
  }
  for (const p of ports){
    const row = document.createElement("span");
    row.className = "port";
    row.textContent = typeof p === "object" ? (p.port + (p.service ? " · " + p.service : "")) : String(p);
    el.appendChild(row);
  }
  if (at){
    const s = document.createElement("span");
    s.className = "hint";
    s.textContent = "فُحص " + new Date(at * 1000).toLocaleString("ar-SY");
    el.appendChild(s);
  }
}
function openDetail(name){
  const d = ((state.data && state.data.devices) || []).find(x => x.name === name);
  if (!d) return;
  state.detailName = name;
  msg("det-msg", "");
  $("dettitle").textContent = "تفاصيل: " + d.name;
  const dl = $("det-body");
  dl.replaceChildren();
  const rows = [
    ["العنوان", d.ip], ["الحالة", LBL[d.eff] || d.eff],
    ["النوع", d.kind || "—"], ["المجموعة", d.group || "—"],
    ["يتبع", d.parent || "—"],
    ["التأخير", d.rtt == null ? "—" : Math.round(d.rtt) + " ms"],
    ["آخر ظهور", d.last_ok == null ? "—" : new Date(d.last_ok * 1000).toLocaleString("ar-SY")]
  ];
  for (const [k, v] of rows){
    const dt = document.createElement("dt"); dt.textContent = k;
    const dd = document.createElement("dd"); dd.textContent = v;
    dl.append(dt, dd);
  }
  renderPorts($("det-ports"), d.ports, d.ports_at);
  state.detailSnmp = null;
  state.detailTab = "system";
  $("det-snmp-at").textContent = "";
  setDetailTab("system");
  $("detail").showModal();
  updateMaintHint();
  loadSnmpDetail(name, false);
}
async function checkPorts(){
  if (!state.detailName) return;
  const btn = $("det-check");
  btn.disabled = true;
  msg("det-msg", "جارٍ فحص المنافذ…");
  try {
    const j = await postJSON("/api/device/" + encodeURIComponent(state.detailName) + "/ports", {});
    renderPorts($("det-ports"), j.ports, j.checked);
    msg("det-msg", j.ports.length ? ("فُتح " + j.ports.length + " منفذ") : "لا منافذ مفتوحة من القائمة المفحوصة.", "ok");
    await load();
  } catch (e) {
    msg("det-msg", e.message || "تعذر فحص المنافذ", "bad");
  } finally {
    btn.disabled = false;
  }
}

async function snmpTest(){
  msg("snmp-msg", "جارٍ اختبار SNMP…");
  let body = {};
  const ip = $("s-snmp-test-ip").value.trim();
  if (ip) body.ip = ip;
  else {
    const d = ((state.data && state.data.devices) || []).find(x =>
      (x.snmp || "auto") !== "off" && ["router","switch","mikrotik","wifi","ap","server","device"].includes(x.kind));
    if (!d){ msg("snmp-msg", "اكتب عنوان IP لاختباره، أو أضف جهازاً أولاً.", "bad"); return; }
    body.name = d.name;
  }
  const btn = $("snmp-test");
  btn.disabled = true;
  try {
    const j = await postJSON("/api/snmp/test", body);
    const c = j.counts || {};
    msg("snmp-msg", "نجح الاتصال بـ " + j.ip + " (" + j.vendor + ") — " +
      safeText((j.sys || {}).descr) + " · واجهات: " + (c.interfaces || 0) +
      " · SFP: " + (c.sfp || 0) + " · لاسلكي: " + (c.wifi || 0) +
      " · CPU: " + (j.cpu == null ? "—" : j.cpu + "%"), "ok");
    await load();
  } catch(e){
    msg("snmp-msg", e.message || "فشل اختبار SNMP", "bad");
  } finally { btn.disabled = false; }
}
async function snmpPollNow(){
  msg("snmp-msg", "جارٍ استعلام كل الأجهزة عبر SNMP… قد يستغرق بعض الوقت.");
  const btn = $("snmp-poll");
  btn.disabled = true;
  try {
    const j = await postJSON("/api/snmp/poll", {});
    msg("snmp-msg", "انتهى الاستعلام: استجاب " + (j.responded || 0) + " من " + (j.total || 0) + " جهاز.", "ok");
    await load();
  } catch(e){
    msg("snmp-msg", e.message || "تعذر الاستعلام", "bad");
  } finally { btn.disabled = false; }
}
async function emailTest(){
  msg("email-msg", "جارٍ إرسال البريد…");
  const btn = $("email-test");
  btn.disabled = true;
  try {
    const j = await postJSON("/api/email/test", {});
    msg("email-msg", j.message || "أُرسل البريد.", "ok");
  } catch(e){
    msg("email-msg", e.message || "تعذر إرسال البريد — احفظ الإعدادات أولاً", "bad");
  } finally { btn.disabled = false; }
}
async function webhookTest(){
  msg("w-msg", "جارٍ الإرسال…");
  const btn = $("w-test");
  btn.disabled = true;
  const body = {};
  if ($("w-url").value.trim()) body.url = $("w-url").value.trim();
  if ($("w-secret").value) body.secret = $("w-secret").value;
  try {
    const j = await postJSON("/api/webhook/test", body);
    msg("w-msg", j.message || "وصل الإشعار التجريبي.", "ok");
  } catch(e){
    msg("w-msg", e.message || "تعذر الإرسال — احفظ الإعدادات أولاً", "bad");
  } finally { btn.disabled = false; }
}
async function detailSnmpTest(){
  if (!state.detailName) return;
  setSnmpHint("جارٍ اختبار الاتصال…");
  try {
    const j = await postJSON("/api/snmp/test", {name: state.detailName});
    setSnmpHint("نجح الاتصال (" + j.vendor + ") · واجهات " + ((j.counts || {}).interfaces || 0) +
      " · CPU " + (j.cpu == null ? "—" : j.cpu + "%"));
  } catch(e){
    setSnmpHint(e.message || "فشل اختبار SNMP", "bad");
  }
}

$("det-tabs").addEventListener("click", (e) => {
  const b = e.target.closest("button[data-tab]");
  if (b) setDetailTab(b.dataset.tab);
});
$("det-snmp-poll").addEventListener("click", () => loadSnmpDetail(state.detailName, true));
$("det-snmp-test").addEventListener("click", detailSnmpTest);
$("snmp-test").addEventListener("click", snmpTest);
$("snmp-poll").addEventListener("click", snmpPollNow);
$("email-test").addEventListener("click", emailTest);
$("w-test").addEventListener("click", webhookTest);
$("netbtn").addEventListener("click", openNetwork);
$("settingsbtn").addEventListener("click", openSettings);
$("s-cancel").addEventListener("click", () => $("settings").close());
$("settings-form").addEventListener("submit", saveSettings);
$("tg-test").addEventListener("click", tgTest);
$("tg-chats").addEventListener("click", tgChats);
$("scan-start").addEventListener("click", startScan);
$("scan-discover").addEventListener("click", discoverNow);
$("scan-addsel").addEventListener("click", () => scanAdd(false));
$("scan-addall").addEventListener("click", () => scanAdd(true));
$("scan-close").addEventListener("click", () => { clearTimeout(state.scanTimer); $("network").close(); });
$("scan-all").addEventListener("change", (e) => {
  for (const cb of document.querySelectorAll(".scan-check")) cb.checked = e.target.checked;
});
$("det-check").addEventListener("click", checkPorts);
$("detail").addEventListener("click", (e) => {
  const b = e.target.closest("button[data-maint]");
  if (!b || !state.detailName) return;
  doMaint(state.detailName, Number(b.dataset.maint) || 0);
});
$("det-close").addEventListener("click", () => $("detail").close());
$("detail").addEventListener("close", () => {
  state.detailName = null;
  state.detailSnmp = null;
  state.detailSnmpAt = 0;
});
$("network").addEventListener("close", () => clearTimeout(state.scanTimer));

/* ---- التنقل بين العروض ---- */
document.querySelectorAll("#views button[data-view]").forEach(b =>
  b.addEventListener("click", () => setView(b.dataset.view)));
$("alertchip").addEventListener("click", () => setView("alerts"));
$("alert-refresh").addEventListener("click", loadAlerts);
$("alert-ackall").addEventListener("click", async () => {
  const alerts = (state.alerts && state.alerts.alerts) || [];
  const todo = alerts.filter(a => !a.acked);
  if (!todo.length) return;
  try {
    await Promise.all(todo.map(a =>
      postJSON("/api/alerts/ack", {key: a.key, ack: true})));
    loadAlerts();
  } catch (e) { setError("تعذر تأكيد بعض التنبيهات"); }
});
$("rep-ranges").addEventListener("click", (e) => {
  const b = e.target.closest("button[data-range]");
  if (!b) return;
  state.reportRange = b.dataset.range;
  loadReports();
});
$("maint-opts").addEventListener("click", (e) => {
  const b = e.target.closest("button[data-min]");
  if (!b || !state.maintName) return;
  doMaint(state.maintName, Number(b.dataset.min) || 0);
});
$("maint-close").addEventListener("click", () => $("maint").close());
$("map-q").addEventListener("input", (e) => {
  state.mapQ = e.target.value;
  renderMap();
});
$("map-status").addEventListener("change", (e) => {
  state.mapStatus = e.target.value;
  renderMap();
});
$("map-group").addEventListener("change", (e) => {
  state.mapGroup = e.target.value;
  renderMap();
});
$("ev-refresh").addEventListener("click", loadHistory);
$("ev-q").addEventListener("change", loadHistory);
$("ev-type").addEventListener("change", loadHistory);
$("ev-name").addEventListener("change", loadHistory);
$("ev-limit").addEventListener("change", loadHistory);
$("ev-ranges").addEventListener("click", (e) => {
  const b = e.target.closest("button[data-range]");
  if (!b) return;
  state.historyRange = b.dataset.range;
  for (const x of $("ev-ranges").querySelectorAll("button[data-range]"))
    x.classList.toggle("active", x === b);
  loadHistory();
});
$("map-zoom-in").addEventListener("click", () => mapZoom(1.25));
$("map-zoom-out").addEventListener("click", () => mapZoom(1 / 1.25));
$("map-fit").addEventListener("click", () => {
  state.mapView = {x: 0, y: 0, k: 1};
  renderMap();
});
$("map-reset").addEventListener("click", () => {
  state.mapPos = {};
  state.mapView = {x: 0, y: 0, k: 1};
  saveMapPos();
  renderMap();
});

document.addEventListener("keydown", (e) => {
  if (e.key === "/" && !/^(INPUT|SELECT|TEXTAREA)$/.test(document.activeElement.tagName)){
    e.preventDefault();
    $("q").focus();
  } else if (e.key === "Escape" && document.activeElement === $("q")){
    $("q").value = ""; state.q = ""; saveUi(); render(); $("q").blur();
  }
});
document.addEventListener("visibilitychange", () => {
  if (!document.hidden && !state.paused) load();
});

/* ================= أعلى استهلاكاً للحركة ================= */
function renderTalkers(j){
  const box = $("talkers");
  if (!box) return;
  const items = [];
  for (const d of (j.devices || [])){
    const s = d.snmp_info;
    if (!s || !s.ok) continue;
    const rate = (s.in_bps || 0) + (s.out_bps || 0);
    if (rate <= 0) continue;
    items.push({d, s, rate});
  }
  items.sort((a, b) => b.rate - a.rate);
  const top = items.slice(0, 6);
  box.replaceChildren();
  if (!top.length){
    box.appendChild(mk("div", "hint",
      "لا توجد حركة SNMP بعد. فعّل SNMP على الأجهزة وحدّد community من الإعدادات."));
    return;
  }
  const max = Math.max(...top.map(x => x.rate), 1);
  for (const it of top){
    const card = mk("div", "talker");
    const head = mk("div", "t");
    head.appendChild(mk("b", "", it.d.name));
    head.appendChild(mk("span", "", fmtBps(it.rate)));
    const bar = mk("div", "bar");
    const fill = mk("i", "");
    fill.style.width = Math.max(2, Math.round(it.rate * 100 / max)) + "%";
    bar.appendChild(fill);
    card.append(head, bar);
    card.title = "دخول " + fmtBps(it.s.in_bps || 0) + " · خروج " +
      fmtBps(it.s.out_bps || 0) + " — اضغط للتفاصيل";
    card.addEventListener("click", () => openDetail(it.d.name));
    box.appendChild(card);
  }
}

/* ================= مركز التنبيهات ================= */
function updateAlertBadges(c){
  c = c || state.alertCounts || {};
  const n = c.unacked || 0, total = c.total || 0, crit = c.critical || 0;
  const badge = $("alerts-badge");
  if (badge){
    badge.textContent = n;
    badge.className = "badge" + (n ? "" : " zero");
  }
  const chip = $("alertchip");
  if (chip){
    chip.className = "btn ghost snmp-chip " + (crit ? "bad" : (total ? "warn" : "ok"));
    chip.title = "مركز التنبيهات — نشطة: " + total + " · حرجة: " + crit +
      " · غير مؤكدة: " + n;
    const cn = $("alertchip-n");
    if (cn) cn.textContent = n;
  }
}
async function loadAlerts(){
  try {
    const r = await fetch("/api/alerts", {cache: "no-store"});
    state.alerts = await r.json();
    state.alertsAt = Date.now();
    state.alertCounts = state.alerts.counts || {};
    state.alertMaint = state.alerts.maintenance || [];
    updateAlertBadges(state.alertCounts);
    renderAlerts();
  } catch (e) {
    const l = $("alert-list");
    if (l) l.replaceChildren(mk("div", "msg bad", "تعذر جلب التنبيهات من الخادم"));
  }
}
function miniBtn(text, cls, fn){
  const b = mk("button", "btn mini " + (cls || ""), text);
  b.type = "button";
  b.addEventListener("click", (e) => { e.stopPropagation(); fn(); });
  return b;
}
function renderAlerts(){
  const list = $("alert-list");
  const mlist = $("maint-list");
  if (!list || !mlist) return;
  const A = state.alerts;
  if (!A){
    list.replaceChildren(mk("div", "hint", "جارٍ تحميل التنبيهات…"));
    return;
  }
  const c = A.counts || {};
  $("alert-summary").textContent = "حرجة: " + (c.critical || 0) +
    " · تحذيرات: " + (c.warning || 0) + " · غير مؤكدة: " + (c.unacked || 0) +
    " · صيانة: " + (A.maintenance || []).length;
  updateAlertBadges(c);
  const alerts = A.alerts || [];
  list.replaceChildren();
  if (!alerts.length){
    list.appendChild(mk("div", "alerts-empty", "✅ لا توجد تنبيهات نشطة — كل شيء يعمل."));
  }
  for (const a of alerts){
    const card = mk("div", "alert " + (a.severity || "warning") + (a.acked ? " acked" : ""));
    const sev = mk("span", "sev " + (a.severity || "warning"),
      a.severity === "critical" ? "حرج" : (a.severity === "warning" ? "تحذير" : "معلومة"));
    const body = mk("div", "msg");
    body.appendChild(mk("b", "", a.message));
    const meta = mk("div", "meta", a.name + " · " + a.ip + " · منذ " + fmtDur(a.duration) +
      (a.detail ? " · " + a.detail : ""));
    body.appendChild(meta);
    const ops = mk("div", "ops");
    ops.appendChild(miniBtn("تفاصيل", "ghost", () => openDetail(a.name)));
    ops.appendChild(miniBtn(a.acked ? "إلغاء التأكيد" : "تأكيد", "ghost", async () => {
      try {
        await postJSON("/api/alerts/ack", {key: a.key, ack: !a.acked});
        loadAlerts();
      } catch (e) { setError("تعذر تحديث التنبيه"); }
    }));
    ops.appendChild(miniBtn("🛠 صيانة", "ghost", () => openMaint(a.name)));
    card.append(sev, body, ops);
    list.appendChild(card);
  }
  mlist.replaceChildren();
  const maint = A.maintenance || [];
  $("maint-count").textContent = maint.length ? "(" + maint.length + ")" : "";
  if (!maint.length){
    mlist.appendChild(mk("div", "hint", "لا يوجد جهاز في وضع الصيانة حالياً."));
  }
  for (const m of maint){
    const until = new Date(m.until * 1000);
    const left = Math.max(0, Math.round((m.until * 1000 - Date.now()) / 1000));
    const card = mk("div", "alert info");
    card.appendChild(mk("span", "sev info", "صيانة"));
    const body = mk("div", "msg");
    body.appendChild(mk("b", "", m.name));
    body.appendChild(mk("div", "meta", "حتى " + until.toLocaleString("ar-SY") +
      " · متبقٍ " + fmtDur(left)));
    card.appendChild(body);
    const ops = mk("div", "ops");
    ops.appendChild(miniBtn("إيقاف الصيانة", "ghost", () => doMaint(m.name, 0)));
    card.appendChild(ops);
    mlist.appendChild(card);
  }
}
function openMaint(name){
  state.maintName = name;
  const d = ((state.data && state.data.devices) || []).find(x => x.name === name);
  const until = d && d.maint_until ? new Date(d.maint_until * 1000).toLocaleString("ar-SY") : "";
  $("maint-text").textContent = until
    ? "الجهاز " + name + " في وضع الصيانة حتى " + until + ". لن تُرسل تنبيهات حتى انتهاء المدة."
    : "اختر مدة الصيانة للجهاز " + name + " — لن تُرسل تنبيهات خلالها ولن يظهر في مركز التنبيهات.";
  $("maint").showModal();
}
function updateMaintHint(){
  const el = $("det-maint-hint");
  if (!el) return;
  const d = ((state.data && state.data.devices) || []).find(x => x.name === state.detailName);
  const until = d && d.maint_until ? new Date(d.maint_until * 1000) : null;
  el.textContent = until && until.getTime() > Date.now()
    ? "مفعّل حتى " + until.toLocaleString("ar-SY") + " — لن تُرسل تنبيهات."
    : "غير مفعّل — تُرسل التنبيهات عند أي مشكلة.";
}
async function doMaint(name, minutes){
  try {
    await postJSON("/api/devices/" + encodeURIComponent(name) + "/maintenance",
      {minutes: minutes});
    if ($("maint").open) $("maint").close();
    await load();
    updateMaintHint();
    loadAlerts();
  } catch (e) {
    setError("تعذر ضبط وضع الصيانة: " + String((e && e.message) || e));
  }
}

/* ================= التقارير (SLA) ================= */
const RANGE_LBL = {"1h": "ساعة", "6h": "6 ساعات", "24h": "24 ساعة",
                   "7d": "7 أيام", "30d": "30 يوماً", "90d": "90 يوماً"};
function bigCard(label, value, cls){
  const c = mk("div", "card " + (cls || ""));
  c.appendChild(mk("div", "k", label));
  c.appendChild(mk("b", "", value));
  return c;
}
async function loadReports(){
  if (state.reportBusy) return;
  state.reportBusy = true;
  const hint = $("rep-hint");
  if (hint) hint.textContent = "جارٍ حساب التقارير…";
  try {
    const r = await fetch("/api/reports?range=" + encodeURIComponent(state.reportRange),
      {cache: "no-store"});
    state.report = await r.json();
    state.reportAt = Date.now();
    renderReports();
  } catch (e) {
    if (hint) hint.textContent = "تعذر جلب التقرير — تحقق من الاتصال بالخادم.";
  } finally {
    state.reportBusy = false;
  }
}
function renderReports(){
  const rep = state.report;
  if (!rep) return;
  const s = rep.summary || {};
  const range = RANGE_LBL[rep.range] || rep.range;
  $("rep-cards").replaceChildren(
    bigCard("إجمالي الأجهزة", String(s.devices ?? "—"), ""),
    bigCard("مراقَبة بسجل", String(s.monitored ?? "—"), "neutral"),
    bigCard("متوسط التوفر", s.pct == null ? "—" : s.pct + "%",
      s.pct == null ? "" : (s.pct >= 99 ? "ok" : (s.pct >= 95 ? "warn" : "bad"))),
    bigCard("الانقطاعات", String(s.outages ?? 0), (s.outages ? "warn" : "ok")),
    bigCard("زمن التوقف الكلي", fmtDur(s.downtime || 0), (s.downtime ? "warn" : "ok"))
  );
  $("rep-hint").textContent = "المدة: " + range + " · " +
    new Date(rep.since * 1000).toLocaleString("ar-SY") + " ← " +
    new Date(rep.until * 1000).toLocaleString("ar-SY");
  const tb = $("rep-tbody");
  const frag = document.createDocumentFragment();
  const devs = rep.devices || [];
  if (!devs.length){
    const tr = document.createElement("tr");
    const td0 = document.createElement("td");
    td0.colSpan = 11;
    td0.className = "hint";
    td0.textContent = "لا توجد أجهزة.";
    tr.appendChild(td0);
    frag.appendChild(tr);
  }
  for (const d of devs){
    const tr = document.createElement("tr");
    tr.style.cursor = "pointer";
    tr.title = "اضغط لعرض تفاصيل " + d.name;
    tr.addEventListener("click", () => openDetail(d.name));
    const nameTd = td(d.name, "name");
    if (d.maint_until && d.maint_until * 1000 > Date.now())
      nameTd.appendChild(mk("span", "maint-badge", "صيانة"));
    tr.appendChild(nameTd);
    const av = document.createElement("td");
    const pct = d.pct;
    const bar = mk("span", "sla-bar");
    const fill = mk("i", pct == null ? "" : (pct >= 99 ? "" : (pct >= 95 ? "mid" : "bad")));
    fill.style.width = (pct == null ? 0 : Math.max(2, Math.min(100, pct))) + "%";
    bar.appendChild(fill);
    av.append(bar, mk("span", "pct", pct == null ? "—" : pct + "%"));
    tr.appendChild(av);
    const heatTd = document.createElement("td");
    const heat = mk("span", "heat");
    const days = new Map((d.days || []).map(x => [x.d, x.pct]));
    for (let i = 29; i >= 0; i--){
      const v = days.has(i) ? days.get(i) : null;
      const cell = mk("i", v == null ? "hna" : (v >= 99 ? "h99" : (v >= 95 ? "h95" : "h0")));
      cell.title = (i === 0 ? "اليوم" : "قبل " + i + " يوم") + ": " +
        (v == null ? "لا بيانات" : v + "%");
      heat.appendChild(cell);
    }
    heatTd.appendChild(heat);
    tr.appendChild(heatTd);
    tr.appendChild(td(d.avg_rtt == null ? "—" : Math.round(d.avg_rtt) + " ms"));
    tr.appendChild(td(String(d.outages || 0), d.outages ? "sig-bad" : ""));
    tr.appendChild(td(fmtDur(d.downtime || 0)));
    tr.appendChild(td(d.mttr == null ? "—" : fmtDur(d.mttr)));
    tr.appendChild(td(d.avg_cpu == null ? "—" : d.avg_cpu + "%"));
    tr.appendChild(td(d.avg_mem == null ? "—" : d.avg_mem + "%"));
    tr.appendChild(td(fmtBps(d.peak_in || 0) + " / " + fmtBps(d.peak_out || 0)));
    tr.appendChild(td(String(d.samples || 0), "sub"));
    frag.appendChild(tr);
  }
  tb.replaceChildren(frag);
  document.querySelectorAll("#rep-ranges button[data-range]").forEach(b =>
    b.classList.toggle("active", b.dataset.range === state.reportRange));
  $("rep-export").href = "/api/reports/export?range=" + encodeURIComponent(state.reportRange);
}

/* ================= خريطة الشبكة ================= */
const MAP_KEY = "nabd.map.v1";
const MAP_COLORS = {up: "#3fb950", down: "#f85149", unreachable: "#d29922", unknown: "#6e7681"};
function loadMapPos(){
  try { return JSON.parse(localStorage.getItem(MAP_KEY) || "{}") || {}; }
  catch (e) { return {}; }
}
function saveMapPos(){
  try { localStorage.setItem(MAP_KEY, JSON.stringify(state.mapPos || {})); }
  catch (e) {}
}
function mapLayout(devs){
  const names = new Set(devs.map(d => d.name));
  const kids = new Map();
  const isChild = new Set();
  for (const d of devs){
    if (d.parent && names.has(d.parent) && d.parent !== d.name){
      if (!kids.has(d.parent)) kids.set(d.parent, []);
      kids.get(d.parent).push(d.name);
      isChild.add(d.name);
    }
  }
  const roots = devs.filter(d => !isChild.has(d.name)).map(d => d.name);
  const W = 1000, nodeW = 140, nodeH = 46, gapX = 12, gapY = 66;
  const pos = {};
  let cursorY = 30;
  const mainRoots = roots.slice(0, 4);
  const extraRoots = roots.slice(4);
  mainRoots.forEach((n, i) => {
    pos[n] = {x: W / 2 + (i - (mainRoots.length - 1) / 2) * (nodeW + gapX * 3), y: cursorY};
  });
  cursorY += nodeH + 56;
  if (extraRoots.length){
    const cols = Math.max(1, Math.min(6, extraRoots.length));
    extraRoots.forEach((n, i) => {
      const row = Math.floor(i / cols), col = i % cols;
      const count = Math.min(cols, extraRoots.length - row * cols);
      pos[n] = {x: W / 2 + (col - (count - 1) / 2) * (nodeW + gapX),
                y: cursorY + row * (nodeH + gapY)};
    });
    cursorY += Math.ceil(extraRoots.length / 6) * (nodeH + gapY) + 24;
  }
  for (const r of mainRoots.concat(extraRoots)){
    const cs = (kids.get(r) || []).filter(n => !pos[n]);
    if (!cs.length) continue;
    const cols = Math.max(2, Math.min(6, Math.ceil(Math.sqrt(cs.length * 1.7))));
    cs.forEach((n, i) => {
      const row = Math.floor(i / cols), col = i % cols;
      const count = Math.min(cols, cs.length - row * cols);
      pos[n] = {x: W / 2 + (col - (count - 1) / 2) * (nodeW + gapX),
                y: cursorY + row * (nodeH + gapY)};
    });
    cursorY += Math.ceil(cs.length / cols) * (nodeH + gapY) + 24;
  }
  const saved = state.mapPos || {};
  for (const n of Object.keys(pos)){
    const sp = saved[n];
    if (sp && typeof sp.x === "number" && typeof sp.y === "number")
      pos[n] = {x: sp.x, y: sp.y};
  }
  return {pos, W, H: Math.max(560, cursorY + 20), nodeW, nodeH, roots, kids};
}
function svgPoint(svg, ev){
  const p = svg.createSVGPoint();
  p.x = ev.clientX; p.y = ev.clientY;
  return p.matrixTransform(svg.getScreenCTM().inverse());
}
function mapLocal(g, svg, ev){
  const p = svg.createSVGPoint();
  p.x = ev.clientX; p.y = ev.clientY;
  const m = g.getScreenCTM();
  return m ? p.matrixTransform(m.inverse()) : p;
}
/* ================= سجل الأحداث ================= */
function historyQuery(){
  const p = new URLSearchParams({range: state.historyRange,
                                 limit: $("ev-limit").value});
  const q = $("ev-q").value.trim();
  const t = $("ev-type").value;
  const n = $("ev-name").value;
  if (q) p.set("q", q);
  if (t) p.set("type", t);
  if (n) p.set("name", n);
  return p.toString();
}
async function loadHistory(){
  if (state.historyBusy) return;
  state.historyBusy = true;
  try {
    const r = await fetch("/api/events?" + historyQuery(), {cache: "no-store"});
    if (!r.ok) throw new Error("HTTP " + r.status);
    state.history = await r.json();
    state.historyAt = Date.now();
    renderHistory();
  } catch (e) {
    setError("تعذر جلب السجل: " + e.message);
  } finally { state.historyBusy = false; }
}
function renderHistory(){
  const j = state.history;
  if (!j) return;
  const types = Object.fromEntries((j.types || []).map(x => [x.type, x.count]));
  $("ev-export").href = "/api/events/export?" + historyQuery();
  $("ev-count").textContent = "(" + j.events.length + " من " + j.total + ")";
  $("ev-hint").textContent = j.total
    ? "أحدث الأحداث أولاً — " + j.total + " حدث مطابق للفلاتر"
    : "لا توجد أحداث في هذه الفترة.";
  const cards = $("ev-cards");
  const stats = [
    ["إجمالي الأحداث", j.total, "neutral"],
    ["سقوط", types.down || 0, "bad"],
    ["عودة", types.up || 0, "ok"],
    ["منافذ/CPU/SFP", (types.port_down || 0) + (types.high_cpu || 0) + (types.sfp_low || 0), "warn"],
  ];
  cards.replaceChildren(...stats.map(([label, value, cls]) => {
    const c = mk("div", "card " + cls);
    c.append(mk("span", "k", label), mk("b", "", String(value)));
    return c;
  }));
  const body = $("ev-tbody");
  const frag = document.createDocumentFragment();
  for (const e of j.events){
    const tr = document.createElement("tr");
    const when = new Date(e.ts * 1000);
    tr.appendChild(td(when.toLocaleString("ar-SY"), "sub"));
    tr.appendChild(td(fmtDur(j.now - e.ts) + " مضت", "sub"));
    tr.appendChild(td(e.name || "—"));
    tr.appendChild(td(e.ip || "—", "sub"));
    const cell = document.createElement("td");
    const pill = mk("span", "pill ev-" + e.type,
      (EVI[e.type] || "•") + " " + (EVC[e.type] || e.type));
    pill.title = e.type;
    cell.appendChild(pill);
    tr.appendChild(cell);
    frag.appendChild(tr);
  }
  if (!j.events.length){
    const tr = document.createElement("tr");
    const cell = td("لا توجد نتائج — جرّب توسيع المدة أو إزالة البحث", "sub");
    cell.colSpan = 5;
    tr.appendChild(cell);
    frag.appendChild(tr);
  }
  body.replaceChildren(frag);
}
function renderMap(){
  const wrap = $("mapwrap");
  if (!wrap || state.mapDragging) return;
  const all = (state.data && state.data.devices) || [];
  const q = state.mapQ.trim().toLowerCase();
  const devs = all.filter(d => {
    if (state.mapGroup && d.group !== state.mapGroup) return false;
    if (q && !((d.name || "") + " " + (d.ip || "") + " " + (d.group || ""))
        .toLowerCase().includes(q)) return false;
    const maint = d.maint_until && d.maint_until * 1000 > Date.now();
    if (state.mapStatus === "problems") return d.eff !== "up" || !!maint;
    if (state.mapStatus === "maint") return !!maint;
    if (state.mapStatus !== "all") return d.eff === state.mapStatus;
    return true;
  });
  wrap.replaceChildren();
  if (!devs.length){
    wrap.appendChild(mk("div", "hint", "لا توجد أجهزة مطابقة للفلاتر على الخريطة."));
    $("map-hint").textContent = "المعروض: 0 من " + all.length + " — غيّر الفلاتر لعرض الأجهزة.";
    return;
  }
  const L = mapLayout(devs);
  state.mapLayout = L;
  const W = L.W, H = L.H;
  const svg = svgNode("svg", {viewBox: "0 0 " + W + " " + H, role: "img",
    "aria-label": "خريطة الشبكة"});
  const g = svgNode("g", {});
  svg.appendChild(g);
  if (!state.mapView) state.mapView = {x: 0, y: 0, k: 1};
  const view = state.mapView;
  const applyView = () => g.setAttribute("transform",
    "translate(" + view.x + " " + view.y + ") scale(" + view.k + ")");
  applyView();
  for (const n of Object.keys(L.pos)){
    const d = devs.find(x => x.name === n);
    if (!d || !d.parent) continue;
    const pp = L.pos[d.parent], p = L.pos[n];
    if (!pp || !p) continue;
    const base = MAP_COLORS[d.eff] || "#6e7681";
    const x1 = pp.x, y1 = pp.y + L.nodeH / 2, x2 = p.x, y2 = p.y - L.nodeH / 2;
    const my = (y1 + y2) / 2;
    g.appendChild(svgNode("path", {
      d: "M " + x1 + " " + y1 + " C " + x1 + " " + my + " " + x2 + " " + my +
         " " + x2 + " " + y2,
      fill: "none", stroke: base, "stroke-opacity": ".4", "stroke-width": 1.5}));
  }
  for (const d of devs){
    const p = L.pos[d.name];
    if (!p) continue;
    const maint = d.maint_until && d.maint_until * 1000 > Date.now();
    const color = maint ? "#58a6ff" : (MAP_COLORS[d.eff] || "#6e7681");
    const half = L.nodeW / 2;
    const node = svgNode("g", {class: "mapnode",
      transform: "translate(" + p.x + " " + p.y + ")"});
    const title = svgNode("title", {});
    title.textContent = d.name + " · " + (LBL[d.eff] || d.eff) +
      (maint ? " · صيانة" : "") + " · " + d.ip;
    node.appendChild(title);
    node.appendChild(svgNode("rect", {x: -half, y: -L.nodeH / 2, width: L.nodeW,
      height: L.nodeH, rx: 10, ry: 10, fill: "#152134", stroke: color,
      "stroke-opacity": ".9"}));
    node.appendChild(svgNode("circle", {cx: -half + 14, cy: -7, r: 4.5, fill: color}));
    const t1 = svgNode("text", {x: -half + 26, y: -2, fill: "#e8eef5", "font-size": 12});
    t1.textContent = d.name.length > 15 ? d.name.slice(0, 14) + "…" : d.name;
    const sub = (d.ip || "") + (d.group ? " · " + d.group : "");
    const t2 = svgNode("text", {x: -half + 26, y: 14, fill: "#8ea0b3", "font-size": 9.5});
    t2.textContent = sub.length > 24 ? sub.slice(0, 23) + "…" : sub;
    node.append(t1, t2);
    let dragging = false, moved = 0, startLocal = null, orig = null;
    node.addEventListener("pointerdown", (ev) => {
      ev.stopPropagation();
      ev.preventDefault();
      dragging = true;
      moved = 0;
      state.mapDragging = true;
      orig = {x: p.x, y: p.y};
      startLocal = mapLocal(g, svg, ev);
      try { node.setPointerCapture(ev.pointerId); } catch (e) {}
      svg.classList.add("panning");
    });
    node.addEventListener("pointermove", (ev) => {
      if (!dragging) return;
      const cur = mapLocal(g, svg, ev);
      p.x = orig.x + (cur.x - startLocal.x);
      p.y = orig.y + (cur.y - startLocal.y);
      moved = Math.max(moved, Math.abs(cur.x - startLocal.x) + Math.abs(cur.y - startLocal.y));
      node.setAttribute("transform", "translate(" + p.x + " " + p.y + ")");
    });
    const endDrag = () => {
      if (!dragging) return;
      dragging = false;
      state.mapDragging = false;
      svg.classList.remove("panning");
      if (moved > 4){
        state.mapPos = state.mapPos || {};
        state.mapPos[d.name] = {x: Math.round(p.x), y: Math.round(p.y)};
        saveMapPos();
        renderMap();
      } else {
        openDetail(d.name);
      }
    };
    node.addEventListener("pointerup", endDrag);
    node.addEventListener("pointercancel", endDrag);
    g.appendChild(node);
  }
  let panning = false, panStart = null, panView = null, panMoved = 0;
  svg.addEventListener("pointerdown", (ev) => {
    if (ev.button !== 0) return;
    panning = true;
    panMoved = 0;
    panStart = svgPoint(svg, ev);
    panView = {x: view.x, y: view.y};
    svg.classList.add("panning");
    try { svg.setPointerCapture(ev.pointerId); } catch (e) {}
  });
  svg.addEventListener("pointermove", (ev) => {
    if (!panning) return;
    const cur = svgPoint(svg, ev);
    const dx = cur.x - panStart.x, dy = cur.y - panStart.y;
    panMoved = Math.max(panMoved, Math.abs(dx) + Math.abs(dy));
    view.x = panView.x + dx;
    view.y = panView.y + dy;
    applyView();
  });
  const endPan = () => {
    panning = false;
    svg.classList.remove("panning");
  };
  svg.addEventListener("pointerup", endPan);
  svg.addEventListener("pointercancel", endPan);
  svg.addEventListener("wheel", (ev) => {
    ev.preventDefault();
    const pt = svgPoint(svg, ev);
    const factor = ev.deltaY < 0 ? 1.15 : 1 / 1.15;
    const k = Math.max(0.4, Math.min(3, view.k * factor));
    view.x = pt.x - (k / view.k) * (pt.x - view.x);
    view.y = pt.y - (k / view.k) * (pt.y - view.y);
    view.k = k;
    applyView();
  }, {passive: false});
  wrap.appendChild(svg);
  const counts = {up: 0, down: 0, unreachable: 0, unknown: 0};
  for (const d of devs) counts[d.eff] = (counts[d.eff] || 0) + 1;
  $("map-hint").textContent = "المعروض: " + devs.length + " من " + all.length +
    " · يعمل: " + (counts.up || 0) + " · متوقف: " + (counts.down || 0) +
    " · لا يمكن الوصول: " + (counts.unreachable || 0) +
    " — اسحب العقدة لتحريكها، واسحب الخلفية للتنقل، وبالعجلة للتكبير.";
}
function mapZoom(factor){
  const L = state.mapLayout;
  const view = state.mapView || {x: 0, y: 0, k: 1};
  const cx = L ? L.W / 2 : 500, cy = L ? L.H / 2 : 300;
  const k = Math.max(0.4, Math.min(3, view.k * factor));
  view.x = cx - (k / view.k) * (cx - view.x);
  view.y = cy - (k / view.k) * (cy - view.y);
  view.k = k;
  state.mapView = view;
  renderMap();
}

restoreUi();
state.mapPos = loadMapPos();
setView(state.view);
load();
</script></body></html>"""


@app.route("/")
def index():
    return Response(PAGE, mimetype="text/html")


# ---------------------------------------------------------------- الاكتشاف التلقائي
def tcp_open(ip, port, timeout=0.8):
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


def classify(ip):
    try:
        community = str(SNMP.get("community") or "public")
        client = SNMPClient(ip, community, port=_as_int(SNMP.get("port", 161), 161, 1),
                            timeout=0.9, retries=0)
        vals = client.get([SYS_OIDS["descr"], SYS_OIDS["objectid"]])
        client.close()
        vendor = _detect_vendor(vals.get(SYS_OIDS["descr"]), vals.get(SYS_OIDS["objectid"]))
        if vendor == "mikrotik":
            return "mikrotik"
        if vendor == "ubiquiti":
            return "wifi"
    except (SNMPError, OSError, ValueError):
        pass
    if tcp_open(ip, 8291) or tcp_open(ip, 8728):
        return "mikrotik"
    if tcp_open(ip, 8000):
        return "hikvision"
    return "device"


def append_csv(rows):
    with CSV_LOCK:
        existed = os.path.exists(DEVICES_PATH)
        size = os.path.getsize(DEVICES_PATH) if existed else 0
        with open(DEVICES_PATH, "a", encoding="utf-8-sig", newline="") as f:
            if size == 0:
                f.write("name,ip,kind,parent,group,snmp,snmp_community,profile\n")
            else:
                with open(DEVICES_PATH, "rb") as fb:
                    fb.seek(-1, os.SEEK_END)
                    if fb.read(1) not in (b"\n", b"\r"):
                        f.write("\n")
            w = csv.writer(f, lineterminator="\n")
            for c in rows:
                w.writerow([c["name"], c["ip"], c["kind"], c["parent"], c["group"],
                            c.get("snmp", ""), c.get("snmp_community", ""),
                            c.get("profile", "auto")])


def run_discovery(live=True):
    try:
        import discover
    except ImportError as e:
        log(f"الاكتشاف غير متاح (ثبّت librouteros): {e}")
        return []
    with LOCK:
        known = [{"name": d["name"], "ip": d["ip"], "kind": d["kind"]} for d in DEVS.values()]
    data = discover.fetch(DISC)
    new = discover.candidates(data, known, DISC)[: _as_int(DISC.get("max_new_per_run", 400), 400, 1)]
    if not new:
        return []
    with ThreadPoolExecutor(max_workers=min(32, len(new))) as ex:
        kinds = list(ex.map(lambda c: classify(c["ip"]) if c["kind"] == "device" else c["kind"], new))
    for c, k in zip(new, kinds):
        c["kind"] = k
    append_csv(new)
    if live:
        with LOCK:
            for c in new:
                DEVS[c["name"]] = make_dev(c)
    return new


def discover_loop():
    time.sleep(20)
    last = 0.0
    while True:
        try:
            mins = _as_float(DISC.get("auto_minutes", 30), 30, 0)
            if DISC_ON and mins > 0 and (last == 0 or time.time() - last >= mins * 60):
                last = time.time()
                new = run_discovery()
                if new:
                    for c in new:
                        log_event(time.time(), c["name"], c["ip"], "new_device")
                    names = "، ".join(f"{c['name']} ({c['ip']})" for c in new[:10]) + (" ..." if len(new) > 10 else "")
                    notify(f"🆕 اكتُشف {len(new)} جهاز جديد وأُضيف للمراقبة\n{names}", "new_device")
        except Exception as e:
            log(f"خطأ في الاكتشاف التلقائي: {e}")
        time.sleep(10)


def cmd_discover():
    if not DISC_ON:
        print("أكمل قسم discover.router (host/user/password) في config.yaml أولاً")
        return
    DEVS.update(load_devices())
    try:
        new = run_discovery(live=False)
    except Exception as e:
        print(f"فشل الاكتشاف: {e}")
        return
    if not new:
        print("لا أجهزة جديدة.")
        return
    print(f"أُضيف {len(new)} جهاز إلى devices.csv:")
    for c in new:
        print(f"  {c['ip']:<16} {c['name']:<28} {c['kind']:<10} خلف: {c['parent'] or '-'}   [{c['group']}]")


SCAN_PORTS = (22, 23, 53, 80, 161, 443, 445, 554, 3389, 8000, 8080, 8291, 8728, 9100)
SERVICE_NAMES = {
    22: "SSH", 23: "Telnet", 53: "DNS", 80: "HTTP", 161: "SNMP", 443: "HTTPS",
    445: "SMB", 554: "RTSP", 3389: "RDP", 8000: "Hikvision", 8080: "HTTP-Alt",
    8291: "Winbox", 8728: "RouterOS API", 9100: "Printer",
}
GROUP_BY_KIND = {
    "router": "الراوتر", "switch": "السويتشات", "mikrotik": "السويتشات",
    "camera": "الكاميرات", "dvr": "DVR", "server": "السيرفرات",
    "printer": "الطابعات", "wifi": "الواي فاي",
}


def local_subnets():
    nets = set()
    try:
        for ip in socket.gethostbyname_ex(socket.gethostname())[2]:
            if not ip.startswith("127.") and not ip.startswith("169.254."):
                nets.add(".".join(ip.split(".")[:3]))
    except OSError:
        pass
    return sorted(nets)


def subnet_prefix(value):
    parts = str(value).strip().split(".")
    if len(parts) >= 3:
        return ".".join(parts[:3])
    return str(value).strip().rstrip(".")


def _effective_subnets():
    raw = SCAN.get("subnets") or local_subnets()
    out = []
    for item in raw:
        prefix = subnet_prefix(item)
        if _valid_subnet(prefix) and prefix not in out:
            out.append(prefix)
    return out


def check_ports(ip, ports=None):
    ports = list(ports or SCAN_PORTS)

    def one(port):
        return port, tcp_open(ip, port, 0.7)

    with ThreadPoolExecutor(max_workers=min(16, max(1, len(ports)))) as ex:
        res = list(ex.map(one, ports))
    return [{"port": p, "service": SERVICE_NAMES.get(p, "")} for p, ok in res if ok]


def _guess_kind(ports):
    if 8291 in ports or 8728 in ports:
        return "mikrotik", "MikroTik"
    if 8000 in ports or 554 in ports:
        return "camera", "CAM"
    if 9100 in ports:
        return "printer", "Printer"
    if 3389 in ports or 445 in ports or 53 in ports:
        return "server", "Server"
    return "device", "Host"


def _group_for_kind(kind):
    return GROUP_BY_KIND.get(kind, "مكتشف")


def find_network_hosts():
    """فحص كل عناوين الشبكات: ping ثم منافذ. يرجع المراقَب والجديد معاً."""
    subnets = _effective_subnets()
    local_ips = set(lan_ips())
    with LOCK:
        known = {d["ip"]: d for d in DEVS.values()}
        taken_names = set(DEVS)
        default_parent = next((d["name"] for d in DEVS.values() if d["kind"] == "router"), "")
    targets = [
        f"{n}.{i}" for n in subnets for i in range(1, 255)
        if f"{n}.{i}" not in local_ips
    ]
    with SCAN_LOCK:
        SCAN_STATE.update(total=len(targets), done=0, alive=0,
                          results=[], subnets=subnets, error="")

    alive = []
    if targets:
        with ThreadPoolExecutor(max_workers=max(1, min(WORKERS, 256))) as ex:
            futures = {ex.submit(ping, ip): ip for ip in targets}
            for future in as_completed(futures):
                ip = futures[future]
                try:
                    ok, rtt = future.result()
                except Exception:
                    ok, rtt = False, None
                if ok:
                    alive.append((ip, rtt))
                with SCAN_LOCK:
                    SCAN_STATE["done"] += 1
                    SCAN_STATE["alive"] = len(alive)

    def probe(pair):
        ip = pair[0]
        return ip, [p for p in SCAN_PORTS if tcp_open(ip, p, 0.6)]

    port_map = {}
    if alive:
        with ThreadPoolExecutor(max_workers=min(64, max(1, len(alive)))) as ex:
            for ip, opened in ex.map(probe, alive):
                port_map[ip] = opened

    results = []
    for ip, rtt in sorted(alive, key=lambda x: [int(p) for p in x[0].split(".")]):
        ports = sorted(port_map.get(ip, []))
        existing = known.get(ip)
        if existing:
            results.append({
                "ip": ip, "name": existing["name"], "kind": existing["kind"],
                "group": existing["group"], "parent": existing["parent"],
                "rtt": rtt, "ports": ports, "known": True,
            })
            continue
        kind, prefix = _guess_kind(ports)
        a = ip.split(".")
        name = f"{prefix}-{a[2]}-{a[3]}"
        while name in taken_names:
            name += "_"
        taken_names.add(name)
        results.append({
            "ip": ip, "name": name, "kind": kind,
            "group": _group_for_kind(kind), "parent": default_parent,
            "rtt": rtt, "ports": ports, "known": False,
        })
    with SCAN_LOCK:
        SCAN_STATE["results"] = results
        SCAN_STATE["finished"] = time.time()
    return results


def start_scan_async(auto_add=False):
    with SCAN_LOCK:
        if SCAN_STATE["running"]:
            raise RuntimeError("جارٍ فحص الشبكة بالفعل")
        SCAN_STATE.update(running=True, started=time.time(), finished=0, total=0,
                          done=0, alive=0, results=[], error="",
                          subnets=_effective_subnets())
    threading.Thread(target=_scan_worker, args=(auto_add,),
                     daemon=True, name="scan").start()


def _scan_worker(auto_add=False):
    try:
        results = find_network_hosts()
        if auto_add:
            new = [r for r in results if not r.get("known") and r.get("ports")]
            added, _ = add_scan_candidates(new)
            if added:
                for x in added:
                    log_event(time.time(), x["name"], x["ip"], "new_device")
                notify(f"🆕 اكتُشف {len(added)} جهاز من فحص الشبكة وأُضيف للمراقبة\n"
                       + "، ".join(f"{x['name']} ({x['ip']})" for x in added[:10]),
                       "new_device")
    except Exception as e:
        log(f"خطأ في فحص الشبكة: {e}")
        with SCAN_LOCK:
            SCAN_STATE["error"] = str(e)
    finally:
        with SCAN_LOCK:
            SCAN_STATE["running"] = False
            SCAN_STATE["finished"] = time.time()


def add_scan_candidates(items):
    added, skipped = [], 0
    with CSV_LOCK:
        rows, fields = _read_csv_rows()
        names = {(r.get("name") or "").strip().lower() for r in rows}
        ips = {(r.get("ip") or "").strip() for r in rows}
        with LOCK:
            names |= {n.lower() for n in DEVS}
            ips |= {d["ip"] for d in DEVS.values()}
        for item in items:
            try:
                row = normalize_device(item)
            except ValueError:
                skipped += 1
                continue
            if row["name"].lower() in names or row["ip"] in ips:
                skipped += 1
                continue
            rows.append(row)
            names.add(row["name"].lower())
            ips.add(row["ip"])
            added.append(row)
        if added:
            _write_csv_rows(rows, fields)
    if added:
        with LOCK:
            for row in added:
                DEVS[row["name"]] = make_dev(row)
    return added, skipped


def run_scan(live=True):
    """فحص ذاتي: يرجع/يضيف الأجهزة الجديدة التي لها منافذ مفتوحة."""
    results = find_network_hosts()
    new = [r for r in results if not r.get("known") and r.get("ports")]
    skipped = sum(1 for r in results if not r.get("known") and not r.get("ports"))
    if not live:
        return new, skipped
    added, _ = add_scan_candidates(new)
    return added, skipped


def scan_loop():
    time.sleep(30)
    last = 0.0
    while True:
        try:
            mins = _as_float(SCAN.get("auto_minutes", 0), 0)
            if mins > 0 and (last == 0 or time.time() - last >= mins * 60):
                last = time.time()
                with SCAN_LOCK:
                    busy = SCAN_STATE["running"]
                if not busy:
                    try:
                        start_scan_async(auto_add=True)
                    except RuntimeError:
                        pass
        except Exception as e:
            log(f"خطأ في الفحص الذاتي: {e}")
        time.sleep(15)


def cmd_scan():
    DEVS.update(load_devices())
    nets = [subnet_prefix(x) for x in (SCAN.get("subnets") or local_subnets())]
    print("الشبكات المفحوصة:", ", ".join(f"{n}.0/24" for n in nets), "(قد يستغرق دقيقة أو أكثر)")
    try:
        new, skipped = run_scan(live=False)
    except Exception as e:
        print(f"فشل الفحص: {e}")
        return
    print(f"وُجد {len(new)} جهاز جديد أُضيف إلى devices.csv (وتم تجاهل {skipped} جهاز يستجيب لـ ping فقط):")
    for c in new:
        print(f"  {c['ip']:<16} {c['name']:<22} {c['kind']:<10} [{c['group']}]")


# ---------------------------------------------------------------- الإعداد التفاعلي
def _ask(label, default=""):
    default = "" if default is None else str(default)
    suffix = f" [{default}]" if default else ""
    try:
        ans = input(f"{label}{suffix}: ").strip()
    except EOFError:
        return default
    return ans if ans else default


def _ask_yes(label, default=True):
    ans = _ask(label + " (نعم/لا)", "نعم" if default else "لا").strip().lower()
    return ans in ("", "نعم", "ن", "y", "yes", "1", "true", "أجل", "صحيح")


def _ask_ip(label, default=""):
    while True:
        value = _ask(label, default)
        if valid_ip(value):
            return value
        print("  عنوان غير صالح. مثال: 192.168.1.10")


def _valid_subnet(prefix):
    parts = str(prefix).split(".")
    return len(parts) == 3 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


def _yaml_str(value):
    return json.dumps(str(value), ensure_ascii=False)


def render_config(cfg):
    """يكتب config.yaml مع الشرح، بدل الاعتماد على عناوين افتراضية جاهزة."""
    cfg = _normalize_config(cfg)
    tg, d, disc, dr, scan = (cfg["telegram"], cfg["dashboard"], cfg["discover"],
                             cfg["discover"]["router"], cfg["scan"])
    nots = cfg["notifications"]
    chats = "[" + ", ".join(_yaml_str(x) for x in tg["chat_ids"]) + "]"
    subnets = "[" + ", ".join(_yaml_str(x) for x in scan["subnets"]) + "]"
    excludes = json.dumps(disc["exclude_interfaces"], ensure_ascii=False)
    only = json.dumps(disc["only_interfaces"], ensure_ascii=False)
    ports = json.dumps(disc["port_map"], ensure_ascii=False)
    hb = "null" if cfg["heartbeat_hour"] is None else str(cfg["heartbeat_hour"])
    token_note = cfg.get("_token_note") or "توكن البوت من BotFather (أو المتغير NABD_TELEGRAM_TOKEN)"
    lines = [
        "# إعدادات نبض — أُنشئت بواسطة: python nabd.py --setup",
        "# يمكنك تعديلها يدوياً أو إدارة الأجهزة من داخل اللوحة.",
        "# ملاحظة أمنية: لا تشارك هذا الملف؛ فقد يحتوي توكن البوت وكلمة مرور الراوتر.",
        "# الأفضل وضع التوكن في NABD_TELEGRAM_TOKEN وكلمة مرور اللوحة في NABD_DASH_PASSWORD.",
        "",
        "telegram:",
        f"  token: {_yaml_str(tg['token'])}        # {token_note}",
        f"  chat_ids: {chats}     # أرسل رسالة للبوت ثم: python nabd.py --chat-id",
        "",
        "# اختيار الإشعارات التي تُرسل إلى تيليجرام",
        "notifications:",
        f"  device_down: {str(nots['device_down']).lower()}",
        f"  device_up: {str(nots['device_up']).lower()}",
        f"  internet: {str(nots['internet']).lower()}",
        f"  new_device: {str(nots['new_device']).lower()}",
        f"  daily_report: {str(nots['daily_report']).lower()}",
        f"  port_down: {str(nots['port_down']).lower()}",
        f"  high_cpu: {str(nots['high_cpu']).lower()}",
        f"  sfp_low: {str(nots['sfp_low']).lower()}",
        "",
        f"check_interval: {cfg['check_interval']}     # فحص كل كم ثانية",
        f"fail_threshold: {cfg['fail_threshold']}      # عدد الفشل المتتالي قبل اعتبار الجهاز متوقفاً",
        f"workers: {cfg['workers']}           # عدد الفحوصات المتوازية",
        f"events_retention_days: {cfg['events_retention_days']}   # حذف الأحداث الأقدم من هذا العدد من الأيام",
        "",
        "dashboard:",
        f"  host: {_yaml_str(d['host'])}",
        f"  port: {d['port']}",
        f"  password: {_yaml_str(d['password'])}   # فارغة = بدون كلمة مرور",
        f"  live_seconds: {d['live_seconds']}      # تحديث الصفحة كل كم ثانية",
        "",
        f"heartbeat_hour: {hb}      # ساعة التقرير اليومي (0-23)، null لإلغائه",
        "",
        "# مراقبة SNMP للسويتشات والراوترات ونقاط الوصول (v2c)",
        "snmp:",
        f"  enabled: {str(cfg['snmp']['enabled']).lower()}",
        f"  community: {_yaml_str(cfg['snmp']['community'])}   # يفضّل مجتمع قراءة فقط",
        f"  port: {cfg['snmp']['port']}",
        f"  timeout: {cfg['snmp']['timeout']}",
        f"  retries: {cfg['snmp']['retries']}",
        f"  poll_seconds: {cfg['snmp']['poll_seconds']}   # كل كم ثانية يُستعلم عن الأجهزة",
        f"  history_points: {cfg['snmp']['history_points']}   # عدد نقاط رسم الحركة في الذاكرة",
        f"  cpu_warn: {cfg['snmp']['cpu_warn']}   # نسبة CPU التي تُطلق تنبيهاً",
        f"  sfp_rx_min: {cfg['snmp']['sfp_rx_min']}   # حد إنذار ضعف استقبال SFP (dBm)",
        f"  alert_cooldown_minutes: {cfg['snmp']['alert_cooldown_minutes']}   # منع تكرار نفس التنبيه",
        "",
        "# السجل التاريخي والتقارير (SLA) — يُحفظ في nabd.db",
        "metrics:",
        f"  enabled: {str(cfg['metrics']['enabled']).lower()}",
        f"  sample_seconds: {cfg['metrics']['sample_seconds']}   # كل كم ثانية تُحفظ نقطة قياس لكل جهاز",
        f"  keep_days: {cfg['metrics']['keep_days']}   # مدة الاحتفاظ بالقياسات",
        "",
        "# إشعارات Webhook (JSON) — تعمل إلى جانب تيليجرام والبريد",
        "webhook:",
        f"  enabled: {str(cfg['webhook']['enabled']).lower()}",
        f"  url: {_yaml_str(cfg['webhook']['url'])}   # مثلاً: https://hooks.example.com/nabd",
        f"  secret: {_yaml_str(cfg['webhook']['secret'])}   # يُوقّع به الطلب HMAC-SHA256 (اختياري)",
        f"  kinds: [{', '.join(cfg['webhook']['kinds'])}]   # فارغ = كل أنواع الإشعارات",
        "",
        "# إشعارات البريد (SMTP) — تعمل إلى جانب تيليجرام",
        "email:",
        f"  enabled: {str(cfg['email']['enabled']).lower()}",
        f"  host: {_yaml_str(cfg['email']['host'])}",
        f"  port: {cfg['email']['port']}",
        f"  user: {_yaml_str(cfg['email']['user'])}",
        f"  password: {_yaml_str(cfg['email']['password'])}   # أو المتغير NABD_SMTP_PASSWORD",
        f"  from: {_yaml_str(cfg['email']['from'])}   # بريد المرسل",
        f"  to: [{', '.join(_yaml_str(x) for x in cfg['email']['to'])}]",
        f"  tls: {str(cfg['email']['tls']).lower()}   # STARTTLS عادة على المنفذ 587",
        f"  ssl: {str(cfg['email']['ssl']).lower()}   # اتصال SSL مباشر عادة على المنفذ 465",
        "",
        "# الاكتشاف التلقائي للأجهزة من الراوتر المايكروتك (اختياري)",
        "discover:",
        "  router:",
        f"    host: {_yaml_str(dr['host'])}        # عنوان راوترك — اكتبه بنفسك",
        f"    user: {_yaml_str(dr['user'])}",
        f"    password: {_yaml_str(dr['password'])}   # كلمة مرور مستخدم قراءة فقط",
        f"    port: {dr['port']}",
        f"  auto_minutes: {disc['auto_minutes']}                    # إعادة الاكتشاف كل كم دقيقة (0 = إيقاف)",
        f"  exclude_interfaces: {excludes}",
        f"  only_interfaces: {only}                 # فارغ = كل الشبكات الداخلية",
        f"  port_map: {ports}",
        f"  new_group: {_yaml_str(disc['new_group'])}                  # مجموعة الأجهزة المكتشفة",
        f"  max_new_per_run: {disc['max_new_per_run']}",
        "",
        "# الفحص الذاتي من السيرفر (بدون إعداد على الراوتر): python nabd.py --scan",
        "scan:",
        f"  subnets: {subnets}   # فارغ = يكتشف شبكات هذا الجهاز تلقائياً",
        f"  auto_minutes: {scan['auto_minutes']}        # 0 = يدوي فقط",
        "",
    ]
    return "\n".join(lines)


def cmd_setup():
    print("=" * 56)
    print(" إعداد نبض — ستدخل عناوين أجهزتك بنفسك")
    print("=" * 56)
    print("اترك أي حقل فارغاً لتخطيه. كل شيء قابل للتعديل لاحقاً من اللوحة.\n")
    local = local_subnets()

    print("— لوحة التحكم —")
    where = _ask("فتح اللوحة على (1) الشبكة  أو  (2) هذا الجهاز فقط", "1")
    host = "127.0.0.1" if where.strip() in ("2", "هذا الجهاز", "محلي") else "0.0.0.0"
    port = _ask("منفذ اللوحة", str(DASH_PORT))
    try:
        port = min(65535, max(1, int(port)))
    except (TypeError, ValueError):
        port = 8080
    pw = _ask("كلمة مرور اللوحة (فارغة = بدون كلمة مرور)", "")
    if not pw and _ask_yes("توليد كلمة مرور عشوائية تلقائياً؟", True):
        pw = secrets.token_urlsafe(12)
        print(f"  كلمة المرور: {pw}")

    print("\n— تيليجرام (اختياري) —")
    env_token = os.environ.get("NABD_TELEGRAM_TOKEN", "").strip()
    token_from_env = bool(env_token)
    if token_from_env:
        token = ""
        print("  سيُستخدم التوكن من المتغير NABD_TELEGRAM_TOKEN.")
    else:
        token = _ask("توكن بوت تيليجرام (فارغ = تعطيل الإشعارات)", "")
    chat = _ask("chat_id (فارغ = تعطيل الإشعارات)", "" if not CHATS else CHATS[0])
    chats = [chat] if chat and not chat.startswith("PUT_") else []

    print("\n— الشبكات —")
    auto_hint = ",".join(local)
    sub = _ask("شبكات الفحص الذاتي مثل 192.168.1,10.0.0 (فارغ = تلقائي)", auto_hint)
    subnets = []
    for item in re.split(r"[,،\s]+", sub):
        prefix = subnet_prefix(item)
        if not prefix:
            continue
        if _valid_subnet(prefix):
            subnets.append(prefix)
        else:
            print(f"  تجاهلت شبكة غير صالحة: {item}")

    print("\n— الراوتر والاكتشاف التلقائي (اختياري) —")
    router_ip = _ask("عنوان الراوتر (فارغ = بدون اكتشاف تلقائي)", "")
    disc_host, disc_user, disc_pw = "", "nabd", ""
    disc_port = _as_int(_DR.get("port", 8728), 8728, 1)
    disc_minutes = _as_float(DISC.get("auto_minutes", 30), 30, 0)
    if router_ip:
        if not valid_ip(router_ip):
            print("  عنوان غير صالح — تم تعطيل الاكتشاف التلقائي.")
            router_ip = ""
        else:
            disc_host = router_ip
            disc_user = _ask("مستخدم الراوتر (قراءة فقط)", str(_DR.get("user") or "nabd"))
            disc_pw = _ask("كلمة مرور مستخدم الراوتر", "")
            if not disc_pw:
                print("  بدون كلمة مرور لن يعمل الاكتشاف التلقائي.")
            disc_port = _as_int(_ask("منفذ API الراوتر", str(disc_port)), 8728, 1)
            disc_minutes = _as_float(_ask("إعادة الاكتشاف كل كم دقيقة (0 = إيقاف)", "30"), 30, 0)

    print("\n— أجهزة المراقبة —")
    rows = []
    existing_rows, existing_fields = _read_csv_rows()
    if existing_rows:
        print(f"لديك {len(existing_rows)} جهاز محفوظ حالياً.")
        if _ask_yes("الاحتفاظ بها وإضافة عناوين جديدة؟", True):
            for r in existing_rows:
                if valid_ip(str(r.get("ip") or "")):
                    rows.append(r)
        else:
            print("  ستبدأ بقائمة جديدة، وستُحفظ نسخة احتياطية من القديمة.")
    print("أدخل الأجهزة واحداً واحداً. اترك الاسم فارغاً للانتهاء.")
    while True:
        while True:
            name = _ask(f"اسم الجهاز {len(rows) + 1}")
            if not name:
                break
            if any((r.get("name") or "").strip().lower() == name.lower() for r in rows):
                print("  الاسم مستخدم، اختر اسماً آخر.")
                continue
            break
        if not name:
            break
        ip = _ask_ip("عنوان IP")
        if any((r.get("ip") or "").strip() == ip for r in rows):
            print("  هذا العنوان مضاف مسبقاً — تم تجاهل الجهاز.")
        else:
            kinds = "router, internet, isp, switch, dvr, camera, server, wifi, device"
            kind = _ask(f"النوع ({kinds})", "device").lower()
            default_parent = next((r["name"] for r in rows
                                   if (r.get("kind") or "").lower() == "router"), "")
            parent = _ask("يتبع أي جهاز؟ (اختياري)", default_parent)
            group = _ask("المجموعة", "عام")
            rows.append({"name": name, "ip": ip, "kind": kind or "device",
                         "parent": parent, "group": group or "عام"})
            print(f"  أُضيف: {name} ({ip})")
        if not _ask_yes("إضافة جهاز آخر؟", True):
            break

    if not rows:
        print("\nلم تُدخل أي جهاز. لم أغيّر أي ملف.")
        return

    with CFG_LOCK:
        cur_snmp = copy.deepcopy(CFG.get("snmp") or {})
        cur_email = copy.deepcopy(CFG.get("email") or {})
        cur_notif = copy.deepcopy(CFG.get("notifications") or {})
        cur_metrics = copy.deepcopy(CFG.get("metrics") or {})
        cur_webhook = copy.deepcopy(CFG.get("webhook") or {})
    new_cfg = {
        "telegram": {"token": token, "chat_ids": chats},
        "_token_note": ("يُقرأ من NABD_TELEGRAM_TOKEN" if token_from_env
                        else "توكن البوت من BotFather (أو المتغير NABD_TELEGRAM_TOKEN)"),
        "notifications": {k: bool(cur_notif.get(k, True)) for k in NOTIF_KEYS},
        "check_interval": INTERVAL,
        "fail_threshold": THRESH,
        "workers": WORKERS,
        "events_retention_days": EVENTS_KEEP_DAYS,
        "dashboard": {"host": host, "port": port, "password": pw, "live_seconds": LIVE_SECONDS},
        "heartbeat_hour": HB_HOUR,
        "snmp": cur_snmp,
        "email": cur_email,
        "metrics": cur_metrics,
        "webhook": cur_webhook,
        "discover": {
            "router": {"host": disc_host, "user": disc_user, "password": disc_pw, "port": disc_port},
            "auto_minutes": disc_minutes,
            "exclude_interfaces": DISC.get("exclude_interfaces") or [],
            "only_interfaces": DISC.get("only_interfaces") or [],
            "port_map": DISC.get("port_map") or {},
            "new_group": DISC.get("new_group") or "مكتشف",
            "max_new_per_run": _as_int(DISC.get("max_new_per_run", 400), 400, 1),
        },
        "scan": {"subnets": subnets, "auto_minutes": _as_float(SCAN.get("auto_minutes", 0), 0)},
    }

    b1, b2 = _backup(CONFIG_PATH), _backup(DEVICES_PATH)
    tmp = CONFIG_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline="\n") as f:
        f.write(render_config(new_cfg))
    os.replace(tmp, CONFIG_PATH)

    fields = []
    for r in rows:
        for k in r:
            if k not in fields:
                fields.append(k)
    for need in existing_fields:
        if need not in fields:
            fields.append(need)
    with CSV_LOCK:
        _write_csv_rows(rows, fields)

    print("\nتم الحفظ بنجاح:")
    print(f"  {CONFIG_PATH}")
    print(f"  {DEVICES_PATH} ({len(rows)} جهاز)")
    for b in (b1, b2):
        if b:
            print(f"  نسخة احتياطية: {b}")
    print("\nشغّل الآن:  python nabd.py")
    print("ثم افتح اللوحة وأضف/عدّل الأجهزة من زر «＋ إضافة جهاز».")


# ---------------------------------------------------------------- الأوامر
def cmd_chat_id():
    if not TOKEN_OK:
        print("ضع توكن البوت في config.yaml أو في المتغير NABD_TELEGRAM_TOKEN أولاً")
        return
    print("أرسل أي رسالة للبوت (أو في المجموعة بعد إضافته) ثم شغّل هذا الأمر.")
    try:
        r = requests.get(f"https://api.telegram.org/bot{TOKEN}/getUpdates", timeout=20).json()
    except Exception as e:
        print(f"تعذر الاتصال بتيليجرام: {e}")
        return
    seen = {}
    for u in r.get("result", []):
        m = u.get("message") or u.get("channel_post") or u.get("my_chat_member") or {}
        c = m.get("chat")
        if c:
            seen[c["id"]] = c.get("title") or c.get("username") or c.get("first_name") or ""
    if not seen:
        print("لم أجد رسائل. أرسل رسالة للبوت وأعد المحاولة.")
    for cid, title in seen.items():
        print(f"chat_id: {cid}   ({title})")


def cmd_test():
    if not TG_ON:
        print("أكمل token و chat_ids في config.yaml (أو استخدم NABD_TELEGRAM_TOKEN)")
        return
    for c in CHATS:
        result = tg_send(c, f"💓 نبض: رسالة تجريبية ناجحة\nالوقت: {now_str()}")
        if result == "ok":
            print(c, "تم")
        elif result == "drop":
            print(c, "فشل: المحادثة غير صالحة أو البوت محظور")
        else:
            print(c, "فشل: تعذر الاتصال بتيليجرام")


def cmd_check():
    print(f"نبض {VERSION} — فحص الإعدادات")
    print(f"  المجلد: {BASE}")
    print(f"  config.yaml: {'موجود' if os.path.exists(CONFIG_PATH) else 'مفقود'}")
    devs = load_devices()
    print(f"  devices.csv: {len(devs)} جهاز")
    print(f"  فترة الفحص: {INTERVAL} ثانية | حد الفشل: {THRESH} | العمال: {WORKERS}")
    print(f"  الاحتفاظ بالأحداث: {EVENTS_KEEP_DAYS} يوم")
    print(f"  تيليجرام: {'مفعّل (' + str(len(CHATS)) + ' محادثة)' if TG_ON else 'غير مفعّل'}")
    print(f"  كلمة مرور اللوحة: {'مفعّلة' if DASH_PW else 'غير مفعّلة (تحذير)'}")
    print(f"  الاكتشاف من الراوتر: {'مفعّل' if DISC_ON else 'غير مفعّل'}")
    print(f"  SNMP: {'مفعّل' if SNMP_ON else 'غير مفعّل'} | المجتمع: {SNMP.get('community', 'public')} | "
          f"كل {SNMP.get('poll_seconds', 60)} ثانية")
    print(f"  البريد: {'مفعّل' if email_ready() else 'غير مفعّل'}")
    snmp_devs = [d for d in devs.values() if (d.get("snmp") or "auto").lower() != "off"]
    if snmp_devs:
        print(f"  أجهزة ستُستعلم عبر SNMP: {len(snmp_devs)}")
    local = local_subnets()
    print(f"  شبكات هذا السيرفر: {', '.join(n + '.0/24' for n in local) or 'غير معروفة'}")
    outside = [d for d in devs.values()
               if local and ".".join(d["ip"].split(".")[:3]) not in local]
    if outside:
        print(f"  تحذير: {len(outside)} جهاز خارج شبكات هذا السيرفر — شغّل نبض داخل الشبكة المراقبة.")
    missing = sorted({d["parent"] for d in devs.values()
                      if d["parent"] and d["parent"] not in devs})
    if missing:
        print("  تحذير: جهاز يتبع جهازاً غير موجود: " + "، ".join(missing))
    by_ip = {}
    for d in devs.values():
        by_ip.setdefault(d["ip"], []).append(d["name"])
    dupes = [names for names in by_ip.values() if len(names) > 1]
    for names in dupes:
        print("  تحذير: عنوان مكرر: " + "، ".join(names))
    try:
        init_db()
        db_exec("SELECT 1")
        print("  قاعدة البيانات: تعمل")
    except Exception as e:
        print(f"  قاعدة البيانات: خطأ — {e}")
    for name, ip in (("الراوتر", next((d["ip"] for d in devs.values() if d["kind"] == "router"), None)),
                     ("الإنترنت", next((d["ip"] for d in devs.values() if d["kind"] == "internet"), None))):
        if not ip:
            continue
        ok, rtt = ping(ip)
        print(f"  فحص {name} ({ip}): " + (f"يعمل ({rtt:.0f} ms)" if ok else "لا يستجيب"))
    print(f"  عناوين هذا السيرفر: {', '.join(lan_ips()) or 'غير معروفة'}")
    print("إذا كانت أجهزة الشبكة لا تستجيب بينما الراوتر يعمل، تأكد أن نبض يعمل على جهاز داخل نفس الشبكة.")


# ---------------------------------------------------------------- التشغيل
def main():
    if "--setup" in sys.argv:
        return cmd_setup()
    if "--chat-id" in sys.argv:
        return cmd_chat_id()
    if "--test" in sys.argv:
        return cmd_test()
    if "--check" in sys.argv:
        return cmd_check()
    if "--discover" in sys.argv:
        return cmd_discover()
    if "--scan" in sys.argv:
        return cmd_scan()

    init_db()
    DEVS.update(load_devices())
    if not DEVS:
        log("لا توجد أجهزة بعد — أضفها من اللوحة بزر «＋ إضافة جهاز».")
        if not os.path.exists(DEVICES_PATH):
            try:
                _write_csv_rows([], list(CSV_FIELDS))
            except OSError as e:
                log(f"تعذر إنشاء devices.csv: {e}")

    if not TG_ON:
        log("تنبيه: تيليجرام غير مفعّل (أكمل config.yaml). الإشعارات ستظهر في هذه النافذة فقط.")
    if not DASH_PW and DASH_HOST in ("0.0.0.0", "::"):
        log("تحذير: لوحة التحكم مفتوحة لكل من يصل للشبكة بدون كلمة مرور. عيّن dashboard.password.")

    threading.Thread(target=tg_worker, daemon=True, name="telegram").start()
    threading.Thread(target=email_worker, daemon=True, name="email").start()
    threading.Thread(target=webhook_worker, daemon=True, name="webhook").start()
    threading.Thread(target=monitor_loop, daemon=True, name="monitor").start()
    threading.Thread(target=discover_loop, daemon=True, name="discover").start()
    threading.Thread(target=scan_loop, daemon=True, name="scan").start()
    threading.Thread(target=snmp_loop, daemon=True, name="snmp").start()
    notify(f"🚀 بدأ نبض العمل — يراقب {len(DEVS)} جهاز\nالوقت: {now_str()}")

    log(f"لوحة التحكم: http://localhost:{DASH_PORT}")
    for ip in lan_ips():
        log(f"              http://{ip}:{DASH_PORT}")
    try:
        from waitress import serve
    except ImportError:
        try:
            app.run(host=DASH_HOST, port=DASH_PORT, threaded=True)
        except OSError as e:
            log(f"تعذر تشغيل اللوحة على المنفذ {DASH_PORT}: {e}")
    else:
        try:
            serve(app, host=DASH_HOST, port=DASH_PORT, threads=12)
        except OSError as e:
            log(f"تعذر تشغيل اللوحة على المنفذ {DASH_PORT}: {e}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nتم إيقاف نبض.")
