#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""نبض — طبقة قاعدة بيانات موحّدة.

تدعم محركين مجانيين بالكامل:
  * sqlite   — وضع الملف الواحد (افتراضي، بلا تثبيت)
  * postgres — خادم PostgreSQL (GPL/مفتوح المصدر) عبر psycopg 3

كل استعلامات المشروع تُكتب بـ `?` وتُترجم تلقائياً إلى `%s` في PostgreSQL،
وتُترجم تعابير SQLite الخاصة (INSERT OR REPLACE / rowid / CAST … AS INTEGER).

النسخ الاحتياطي محلي بالكامل ومجاني:
  * SQLite  — عبر sqlite3.Connection.backup() (نسخة متسقة أثناء الكتابة)
  * Postgres— عبر pg_dump الرسمي
  * ضغط gzip + SHA-256 + تدوير يومي/أسبوعي/شهري، واستعادة مع نسخة أمان.
"""
import glob
import gzip
import hashlib
import os
import re
import shutil
import sqlite3
import subprocess
import threading
import time
from datetime import datetime

try:
    import psycopg
except ImportError:  # يُترك الاستيراد هنا حتى يعمل وضع SQLite بدون psycopg
    psycopg = None

IS_WIN = os.name == "nt"
STAMP_RE = re.compile(r"nabd-(\d{8})-(\d{6})-([a-z]+)\.(db|sql)\.gz$")


def _to_int(value, default, minimum=0):
    try:
        return max(minimum, int(value))
    except (TypeError, ValueError):
        return default

TABLE_COLUMNS = {
    "events": ["ts", "name", "ip", "etype"],
    "samples": ["ts", "name", "rtt", "cpu", "mem", "in_bps",
                "out_bps", "ports_up", "ports_total"],
    "sensor_samples": ["ts", "name", "sensor", "value", "state"],
    "alert_acks": ["key", "name", "at"],
    "maintenance": ["name", "until"],
    "maintenance_log": ["name", "started", "ended"],
}


def _pg_bin(name):
    """يجد أداة PostgreSQL (pg_dump/psql) دون الحاجة إلى PATH أو صلاحيات admin."""
    found = shutil.which(name)
    if found:
        return found
    exe = name + (".exe" if IS_WIN else "")
    patterns = [
        os.environ.get("NABD_PG_BIN", ""),
        "C:/Program Files/PostgreSQL/*/bin/" + exe,
        "C:/Program Files (x86)/PostgreSQL/*/bin/" + exe,
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "pgsql", "bin", exe),
        os.path.join(os.path.expanduser("~"), "AppData", "Local", "nabd-pg", "bin", exe),
        "/usr/lib/postgresql/*/bin/" + name,
        "/usr/local/bin/" + name,
    ]
    for pat in patterns:
        if not pat:
            continue
        if os.path.isfile(pat):
            return pat
        for hit in sorted(glob.glob(pat), reverse=True):
            if os.path.isfile(hit):
                return hit
    return ""


class Database:
    """واجهة موحّدة: query / executemany / init_schema / backups."""

    def __init__(self, base, cfg=None):
        self.base = base
        cfg = cfg or {}
        driver = str(cfg.get("driver") or "sqlite").lower()
        self.driver = "postgres" if driver in ("postgres", "postgresql", "pg") else "sqlite"
        self.sqlite_path = str(cfg.get("sqlite_path") or "nabd.db")
        if not os.path.isabs(self.sqlite_path):
            self.sqlite_path = os.path.join(base, self.sqlite_path)
        pg = cfg.get("postgres") or {}
        self.pg = {
            "host": str(os.environ.get("NABD_PG_HOST") or pg.get("host") or "127.0.0.1"),
            "port": int(os.environ.get("NABD_PG_PORT") or pg.get("port") or 5432),
            "dbname": str(os.environ.get("NABD_PG_DATABASE") or pg.get("dbname") or "nabd"),
            "user": str(os.environ.get("NABD_PG_USER") or pg.get("user") or "nabd"),
            "password": str(os.environ.get("NABD_PG_PASSWORD") or pg.get("password") or ""),
            "sslmode": str(pg.get("sslmode") or "disable"),
            "bin_dir": str(pg.get("bin_dir") or ""),
        }
        bk = cfg.get("backup") or {}
        self.backup_dir = str(bk.get("dir") or os.path.join(base, "backups"))
        if not os.path.isabs(self.backup_dir):
            self.backup_dir = os.path.join(base, self.backup_dir)
        self.backup_cfg = {
            "dir": os.path.basename(self.backup_dir.rstrip("/\\")) or "backups",
            "enabled": bool(bk.get("enabled", True)),
            "interval_hours": max(1, int(bk.get("interval_hours") or 6)),
            "keep_daily": max(1, int(bk.get("keep_daily") or 7)),
            "keep_weekly": max(0, int(bk.get("keep_weekly") or 4)),
            "keep_monthly": max(0, int(bk.get("keep_monthly") or 3)),
        }
        self._last_backup = 0.0
        self._schema_ready = False
        self._schema_error = ""

        # مراقب PostgreSQL: يعيد تشغيل الخادم تلقائياً إذا توقف أثناء العمل
        wd = pg.get("watchdog")
        if isinstance(wd, dict):
            wd_enabled = bool(wd.get("enabled", True))
            wd_interval = wd.get("interval_seconds")
            wd_data = wd.get("data_dir")
            wd_log = wd.get("log_file")
        else:
            wd_enabled = wd is None or bool(wd)
            wd_interval, wd_data, wd_log = None, None, None
        self.watchdog = {
            "enabled": wd_enabled,
            "interval": _to_int(wd_interval or pg.get("watchdog_seconds"), 15, 5),
            "data_dir": str(wd_data or pg.get("data_dir") or
                            os.environ.get("NABD_PG_DATA") or ""),
            "log_file": str(wd_log or pg.get("log_file") or ""),
        }
        self._wd_lock = threading.Lock()
        self._wd_next = 0.0
        self._wd_fails = 0
        self._wd_restarts = 0
        self._wd_last = ""
        self._wd_last_at = 0.0
        self.on_event = None

        # تجمع اتصالات صغير: يقلّل إنشاء backends في PostgreSQL ويخفّف
        # أخطاء حجز الذاكرة المشتركة على Windows عند كثرة الاستعلامات.
        self.pool_size = _to_int(pg.get("pool_size"), 8, 1)
        self._pool = []
        self._pool_lock = threading.Lock()
        self.pool_stats = {"created": 0, "reused": 0, "closed": 0, "retries": 0}

    # ------------------------------------------------------------- الاتصال
    def _connect(self):
        if self.driver == "sqlite":
            c = sqlite3.connect(self.sqlite_path, timeout=15)
            c.execute("PRAGMA busy_timeout=8000")
            return c
        if psycopg is None:
            raise RuntimeError("psycopg غير مثبّت — ثبّت: pip install 'psycopg[binary]'")
        if self._pool:
            with self._pool_lock:
                if self._pool:
                    self.pool_stats["reused"] += 1
                    return self._pool.pop()
        p = self.pg
        kw = dict(host=p["host"], port=p["port"], dbname=p["dbname"],
                  user=p["user"], password=p["password"],
                  sslmode=p["sslmode"], autocommit=True, connect_timeout=5)
        c = psycopg.connect(**kw)
        self.pool_stats["created"] += 1
        return c

    def _release(self, c):
        if c is None:
            return
        if self.driver == "postgres":
            keep = False
            try:
                keep = not getattr(c, "closed", 1)
            except Exception:
                keep = False
            if keep:
                with self._pool_lock:
                    if len(self._pool) < self.pool_size:
                        self._pool.append(c)
                        return
            try:
                c.close()
            except Exception:
                pass
            self.pool_stats["closed"] += 1
            return
        c.close()

    def _discard(self, c):
        try:
            if c is not None:
                c.close()
        except Exception:
            pass
        if self.driver == "postgres":
            self.pool_stats["closed"] += 1

    def _run(self, fn):
        """ينفّذ عملية على اتصال من التجمع، مع إعادة محاولة واحدة عند فشل PostgreSQL."""
        attempts = 2 if self.driver == "postgres" else 1
        for attempt in range(attempts):
            c = None
            try:
                c = self._connect()
                return fn(c)
            except Exception:
                self._discard(c)   # لا نُعيد اتصالاً فاسداً إلى التجمع
                c = None
                if attempt + 1 >= attempts:
                    raise
                self.pool_stats["retries"] += 1
            finally:
                if c is not None:
                    self._release(c)
        return None

    def set_pool_size(self, n):
        """ضبط حجم التجمع أثناء التشغيل مع إغلاق الاتصالات الزائدة."""
        self.pool_size = _to_int(n, self.pool_size, 1)
        with self._pool_lock:
            extra = self._pool[self.pool_size:]
            self._pool = self._pool[:self.pool_size]
        for c in extra:
            try:
                c.close()
            except Exception:
                pass
        self.pool_stats["closed"] += len(extra)

    def pool_status(self):
        with self._pool_lock:
            idle = len(self._pool)
        return {"driver": self.driver, "idle": idle, "max": self.pool_size,
                **dict(self.pool_stats)}

    def _translate(self, sql, args):
        """يُرجع (SQL, args) بالصيغة المناسبة للمحرك الحالي."""
        if self.driver == "sqlite":
            return sql, tuple(args or ())
        s = sql.strip()
        # أوامر خاصة بـ SQLite لا معنى لها في PostgreSQL
        if s.upper().startswith("PRAGMA "):
            return "", tuple()
        s = s.replace("INSERT OR REPLACE INTO maintenance VALUES",
                      "INSERT INTO maintenance(name,until) VALUES")
        s = s.replace("INSERT OR REPLACE INTO alert_acks VALUES",
                      "INSERT INTO alert_acks(key,name,at) VALUES")
        s = re.sub(r"INSERT\s+INTO\s+maintenance\(name,until\)\s+VALUES\s*(\([^)]*\))\s*$",
                   r"INSERT INTO maintenance(name,until) VALUES \1 "
                   "ON CONFLICT (name) DO UPDATE SET until=EXCLUDED.until", s, flags=re.I)
        s = re.sub(r"INSERT\s+INTO\s+alert_acks\(key,name,at\)\s+VALUES\s*(\([^)]*\))\s*$",
                   r"INSERT INTO alert_acks(key,name,at) VALUES \1 "
                   "ON CONFLICT (key) DO UPDATE SET name=EXCLUDED.name, at=EXCLUDED.at",
                   s, flags=re.I)
        s = s.replace("SELECT rowid,", "SELECT id,")
        s = s.replace("WHERE rowid=?", "WHERE id=?")
        # CAST العبارة تُقرّب في PostgreSQL بينما SQLite يقتطع — نستخدم FLOOR
        s = s.replace("CAST(ts/? AS INTEGER)*?", "FLOOR(ts/?)*?")
        s = s.replace("CAST((? - s.ts)/86400 AS INTEGER) d", "FLOOR((? - s.ts)/86400) d")
        # جدول الصيانة يستخدم id بدل rowid (معرّف صريح في كلا المحركين)
        s = s.replace("SELECT rowid, started, ended", "SELECT id, started, ended")
        s = s.replace("UPDATE maintenance_log SET ended=? WHERE rowid=?",
                      "UPDATE maintenance_log SET ended=? WHERE id=?")
        s = s.replace("?", "%s")
        return s, tuple(args or ())

    def query(self, sql, args=()):
        sql, args = self._translate(sql, args)
        if not sql:
            return []

        def _do(c):
            cur = c.execute(sql, args)
            if cur.description is None:  # CREATE / INSERT / UPDATE / DELETE
                if self.driver == "sqlite":
                    c.commit()
                return []
            return [tuple(r) for r in cur.fetchall()]

        return self._run(_do)

    def executemany(self, sql, rows):
        rows = [tuple(r) for r in (rows or [])]
        if not rows:
            return 0
        sql, _ = self._translate(sql, ())
        if not sql:
            return 0

        def _do(c):
            cur = c.cursor()
            try:
                cur.executemany(sql, rows)
            finally:
                cur.close()
            if self.driver == "sqlite":
                c.commit()
            return len(rows)

        return self._run(_do)

    # ------------------------------------------------------------- المخطط
    def init_schema(self):
        if self.driver == "sqlite":
            stmts = [
                "CREATE TABLE IF NOT EXISTS events(ts REAL, name TEXT, ip TEXT, etype TEXT)",
                "CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts)",
                """CREATE TABLE IF NOT EXISTS samples(
                    ts REAL NOT NULL, name TEXT NOT NULL, rtt REAL, cpu REAL, mem REAL,
                    in_bps REAL, out_bps REAL, ports_up INTEGER, ports_total INTEGER)""",
                "CREATE INDEX IF NOT EXISTS idx_samples_name_ts ON samples(name, ts)",
                """CREATE TABLE IF NOT EXISTS sensor_samples(
                    ts REAL NOT NULL, name TEXT NOT NULL, sensor TEXT NOT NULL,
                    value REAL, state TEXT)""",
                "CREATE INDEX IF NOT EXISTS idx_sensor_name_ts ON sensor_samples(name, sensor, ts)",
                "CREATE TABLE IF NOT EXISTS alert_acks(key TEXT PRIMARY KEY, name TEXT, at REAL)",
                "CREATE TABLE IF NOT EXISTS maintenance(name TEXT PRIMARY KEY, until REAL)",
                """CREATE TABLE IF NOT EXISTS maintenance_log(
                    id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT,
                    started REAL, ended REAL)""",
                "CREATE INDEX IF NOT EXISTS idx_maint_log ON maintenance_log(name, started)",
                "CREATE TABLE IF NOT EXISTS nabd_meta(key TEXT PRIMARY KEY, value TEXT)",
            ]
            for sql in stmts:
                self.query(sql)
            # ترقية قاعدة بيانات قديمة بلا عمود id
            cols = {r[1] for r in self.query("PRAGMA table_info(maintenance_log)")}
            if "id" not in cols:
                self.query("ALTER TABLE maintenance_log ADD COLUMN id INTEGER")
                self.query("UPDATE maintenance_log SET id=rowid WHERE id IS NULL")
            return
        stmts = [
            """CREATE TABLE IF NOT EXISTS events(
                ts DOUBLE PRECISION, name TEXT, ip TEXT, etype TEXT)""",
            "CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts)",
            """CREATE TABLE IF NOT EXISTS samples(
                ts DOUBLE PRECISION NOT NULL, name TEXT NOT NULL, rtt DOUBLE PRECISION,
                cpu DOUBLE PRECISION, mem DOUBLE PRECISION, in_bps DOUBLE PRECISION,
                out_bps DOUBLE PRECISION, ports_up INTEGER, ports_total INTEGER)""",
            "CREATE INDEX IF NOT EXISTS idx_samples_name_ts ON samples(name, ts)",
            """CREATE TABLE IF NOT EXISTS sensor_samples(
                ts DOUBLE PRECISION NOT NULL, name TEXT NOT NULL, sensor TEXT NOT NULL,
                value DOUBLE PRECISION, state TEXT)""",
            "CREATE INDEX IF NOT EXISTS idx_sensor_name_ts ON sensor_samples(name, sensor, ts)",
            "CREATE TABLE IF NOT EXISTS alert_acks(key TEXT PRIMARY KEY, name TEXT, at DOUBLE PRECISION)",
            "CREATE TABLE IF NOT EXISTS maintenance(name TEXT PRIMARY KEY, until DOUBLE PRECISION)",
            """CREATE TABLE IF NOT EXISTS maintenance_log(
                id BIGSERIAL PRIMARY KEY, name TEXT, started DOUBLE PRECISION,
                ended DOUBLE PRECISION)""",
            "CREATE INDEX IF NOT EXISTS idx_maint_log ON maintenance_log(name, started)",
            "CREATE TABLE IF NOT EXISTS nabd_meta(key TEXT PRIMARY KEY, value TEXT)",
        ]
        for sql in stmts:
            self.query(sql)

    def ensure_schema(self):
        """ينشئ الجداول مرة واحدة عند جاهزية المحرك، ويعيد المحاولة بعد تعافيه.

        عند بدء التشغيل مع PostgreSQL متوقفاً قد تفشل init_schema؛ وجود هذه
        الدالة يسمح لمراقب قاعدة البيانات بإكمال الترقية فور عودة الاتصال،
        بدل أن تظل الجداول الجديدة (مثل sensor_samples) ناقصة.
        """
        if self._schema_ready:
            return True
        try:
            self.init_schema()
        except Exception as e:
            self._schema_error = str(e)[:300]
            return False
        self._schema_ready = True
        self._schema_error = ""
        return True

    # ------------------------------------------------------------- مراقب PostgreSQL
    def _notify(self, text):
        cb = getattr(self, "on_event", None)
        if callable(cb):
            try:
                cb(text)
            except Exception:
                pass

    @staticmethod
    def _no_window():
        flag = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        return {"creationflags": flag} if IS_WIN and flag else {}

    def _backoff(self):
        """فترة انتظار متصاعدة حتى لا نُغرق الخادم بمحاولات إعادة تشغيل."""
        return min(300, self.watchdog["interval"] * (2 ** min(self._wd_fails, 5)))

    def _pg_ping(self, timeout=2):
        if psycopg is None:
            return False
        try:
            p = self.pg
            c = psycopg.connect(host=p["host"], port=p["port"], dbname=p["dbname"],
                                user=p["user"], password=p["password"],
                                sslmode=p["sslmode"], autocommit=True,
                                connect_timeout=timeout)
            try:
                c.execute("SELECT 1")
            finally:
                c.close()
            return True
        except Exception:
            return False

    def _pg_ctl_paths(self):
        """يُرجع (pg_ctl, مجلد البيانات, ملف السجل) أو None عند تعذّر الكشف."""
        bindir = self.pg.get("bin_dir") or ""
        ctl = ""
        if bindir:
            cand = os.path.join(bindir, "pg_ctl.exe" if IS_WIN else "pg_ctl")
            if os.path.isfile(cand):
                ctl = cand
        if not ctl:
            ctl = _pg_bin("pg_ctl")
        if not ctl:
            return None

        candidates = []
        if self.watchdog["data_dir"]:
            candidates.append(self.watchdog["data_dir"])
        if bindir:
            candidates += [
                os.path.join(os.path.dirname(os.path.dirname(bindir)), "data"),
                os.path.join(os.path.dirname(bindir), "data"),
            ]
        candidates.append(os.path.join(os.path.expanduser("~"), "AppData",
                                       "Local", "nabd-pg", "data"))
        if IS_WIN:
            candidates += glob.glob("C:/Program Files/PostgreSQL/*/data")
        else:
            candidates += glob.glob("/var/lib/postgresql/*/main")
            candidates += glob.glob("/usr/local/pgsql/data")
        data = ""
        for cand in candidates:
            if cand and os.path.isfile(os.path.join(cand, "PG_VERSION")):
                data = cand
                break
        if not data:
            return None
        log = self.watchdog["log_file"] or os.path.join(os.path.dirname(data), "pg.log")
        return ctl, data, log

    def ensure_postgres(self, force=False):
        """يفحص PostgreSQL ويعيد تشغيله عند التوقف. آمن مع SQLite/CI."""
        if self.driver != "postgres" or not self.watchdog["enabled"] or psycopg is None:
            return False
        with self._wd_lock:
            now = time.time()
            if not force and now < self._wd_next:
                return False
            if self._pg_ping():
                self._wd_fails = 0
                self._wd_last = "متصل"
                self._wd_last_at = now
                return True

            paths = self._pg_ctl_paths()
            if not paths:
                self._wd_fails += 1
                self._wd_next = now + self._backoff()
                self._wd_last = "تعذّر العثور على pg_ctl أو مجلد بيانات PostgreSQL"
                self._wd_last_at = now
                self._notify("⚠ مراقب قاعدة البيانات: " + self._wd_last)
                return False
            ctl, data, log = paths
            p = self.pg
            opts = '-p %d -h "%s"' % (p["port"], p["host"])
            running = False
            try:
                st = subprocess.run([ctl, "status", "-D", data], capture_output=True,
                                    text=True, timeout=10, **self._no_window())
                running = st.returncode == 0
            except Exception:
                running = False
            if running:
                cmd = [ctl, "restart", "-m", "fast", "-D", data, "-o", opts,
                       "-l", log, "-w"]
            else:
                cmd = [ctl, "start", "-D", data, "-o", opts, "-l", log, "-w"]
            proc_ok = False
            try:
                r = subprocess.run(cmd, capture_output=True, text=True, timeout=35,
                                   **self._no_window())
                proc_ok = r.returncode == 0
                lines = [x for x in ((r.stderr or "") + "\n" + (r.stdout or "")).splitlines()
                         if x.strip()]
                detail = lines[-1].strip()[:200] if lines else "لا تفاصيل"
            except Exception as e:
                detail = str(e)[:200]
            # pg_ctl -w يضمن الجاهزية عند نجاحه؛ ننتظر أيضاً تأكيد الاتصال
            ping_ok = False
            for _ in range(30):
                if self._pg_ping():
                    ping_ok = True
                    break
                time.sleep(1)
            ok = proc_ok or ping_ok
            now = time.time()
            if ok:
                self._wd_fails = 0
                self._wd_next = now + self.watchdog["interval"]
                self._wd_restarts += 1
                self._wd_last = "أُعيد تشغيل PostgreSQL تلقائياً"
                self._wd_last_at = now
                self._notify("🔄 " + self._wd_last + " — " + detail)
            else:
                self._wd_fails += 1
                self._wd_next = now + self._backoff()
                self._wd_last = "فشل إعادة تشغيل PostgreSQL: " + detail
                self._wd_last_at = now
                self._notify("⚠ مراقب قاعدة البيانات: " + self._wd_last)
            return ok

    def watchdog_status(self):
        return {
            "enabled": self.driver == "postgres" and self.watchdog["enabled"],
            "interval": self.watchdog["interval"],
            "restarts": self._wd_restarts,
            "last": self._wd_last,
            "at": self._wd_last_at,
        }

    # ------------------------------------------------------------- الحالة
    def status(self):
        out = {"driver": self.driver, "connected": False, "version": "",
               "size_bytes": 0, "tables": {}, "error": ""}
        try:
            if self.driver == "sqlite":
                out["version"] = "SQLite " + self.query("SELECT sqlite_version()")[0][0]
                out["size_bytes"] = (os.path.getsize(self.sqlite_path)
                                     if os.path.exists(self.sqlite_path) else 0)
                out["path"] = self.sqlite_path
            else:
                if not self._pg_ping(2):
                    raise RuntimeError("connection timeout expired")
                out["version"] = str(self.query("SELECT version()")[0][0]).split(",")[0]
                out["size_bytes"] = int(self.query(
                    "SELECT pg_database_size(current_database())")[0][0] or 0)
                out["path"] = f'{self.pg["host"]}:{self.pg["port"]}/{self.pg["dbname"]}'
            for t in TABLE_COLUMNS:
                out["tables"][t] = int(self.query(
                    "SELECT COUNT(*) FROM " + t)[0][0] or 0)
            out["connected"] = True
        except Exception as e:
            out["error"] = str(e)
        out["backup_dir"] = self.backup_dir
        out["backup_count"] = len(self.list_backups())
        out["backup_settings"] = dict(self.backup_cfg)
        out["watchdog"] = self.watchdog_status()
        out["pool"] = self.pool_status()
        return out

    def health_report(self):
        """تقرير صحة شامل يستخدمه كل من التقرير في اللوحة وسطر الأوامر."""
        st = self.status()
        rec = []
        t0 = time.time()
        try:
            self.query("SELECT 1")
            latency = round((time.time() - t0) * 1000, 1)
        except Exception as e:
            latency = None
            rec.append("تعذّل الوصول إلى قاعدة البيانات: " + str(e)[:160])

        pg_info = {}
        if st["connected"] and self.driver == "postgres":
            for key in ("max_connections", "shared_buffers"):
                try:
                    pg_info[key] = str(self.query("SHOW " + key)[0][0])
                except Exception:
                    pass

        bks = self.list_backups()
        latest = bks[0]["ts"] if bks else 0
        age_h = round((time.time() - latest) / 3600, 1) if latest else None
        interval = _to_int(self.backup_cfg.get("interval_hours"), 6, 1)
        binfo = {"enabled": bool(self.backup_cfg.get("enabled")), "count": len(bks),
                 "latest": latest, "age_hours": age_h, "interval_hours": interval,
                 "dir": self.backup_dir}
        if not binfo["enabled"]:
            rec.append("النسخ الاحتياطي التلقائي متوقف — فعّله من واجهة قاعدة البيانات.")
        elif not bks:
            rec.append("لا توجد نسخة احتياطية بعد — أنشئ نسخة الآن.")
        elif age_h is not None and age_h > max(interval * 2, 12):
            rec.append(f"أحدث نسخة احتياطية عمرها {age_h} ساعة — أنشئ نسخة الآن.")

        if self.driver == "postgres":
            if not st["connected"]:
                rec.insert(0, "PostgreSQL غير متصل — استخدم زر «فحص/إصلاح الآن».")
            else:
                mc = _to_int(pg_info.get("max_connections"), 0, 0)
                if mc and mc > 100:
                    rec.append(f"max_connections={mc} مرتفع على Windows — "
                               "يُنصح بخفضه إلى 50 لتقليل أخطاء الذاكرة المشتركة.")
                pool = st.get("pool") or {}
                if _to_int(pool.get("retries"), 0, 0) > 5:
                    rec.append("لوحظت إعادة محاولة اتصالات متعددة — راقب سجل PostgreSQL.")
                wd = st.get("watchdog") or {}
                if not wd.get("enabled"):
                    rec.append("المراقبة التلقائية متوقفة — فعّلها لإعادة تشغيل PostgreSQL عند التوقف.")

        critical = not st["connected"]
        state = "critical" if critical else ("warning" if rec else "good")
        return {"ok": st["connected"], "state": state, "checked_at": time.time(),
                "driver": self.driver, "connected": st["connected"],
                "latency_ms": latency, "version": st.get("version", ""),
                "size_bytes": st.get("size_bytes", 0), "path": st.get("path", ""),
                "tables": st.get("tables", {}), "error": st.get("error", ""),
                "pool": st.get("pool", {}), "watchdog": st.get("watchdog", {}),
                "backups": binfo, "postgres": pg_info, "recommendations": rec}

    # ------------------------------------------------------------- النسخ الاحتياطي
    def _gzip_file(self, src, dst):
        tmp = dst + ".tmp"
        with open(src, "rb") as f_in, gzip.open(tmp, "wb", compresslevel=6) as f_out:
            shutil.copyfileobj(f_in, f_out, 1024 * 1024)
        os.replace(tmp, dst)

    def _sha256(self, path):
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        with open(path + ".sha256", "w", encoding="ascii") as f:
            f.write("%s  %s  %d\n" % (h.hexdigest(), os.path.basename(path),
                                      os.path.getsize(path)))

    def create_backup(self, reason="manual"):
        """ينشئ نسخة احتياطية متسقة ومضغوطة مع SHA-256، ثم يدوّر القديم."""
        os.makedirs(self.backup_dir, exist_ok=True)
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        reason = re.sub(r"[^a-z0-9_-]", "", str(reason).lower())[:16] or "manual"
        ext = "db" if self.driver == "sqlite" else "sql"
        name = f"nabd-{stamp}-{reason}.{ext}.gz"
        dst = os.path.join(self.backup_dir, name)
        tmp = os.path.join(self.backup_dir, "." + name + ".raw")
        try:
            if self.driver == "sqlite":
                if not os.path.exists(self.sqlite_path):
                    raise RuntimeError("ملف nabd.db غير موجود")
                conn = sqlite3.connect(self.sqlite_path, timeout=15)
                try:
                    out = sqlite3.connect(tmp)
                    try:
                        conn.backup(out)
                    finally:
                        out.close()
                finally:
                    conn.close()
            else:
                tool = self.pg.get("bin_dir") and os.path.join(
                    self.pg["bin_dir"], "pg_dump" + (".exe" if IS_WIN else ""))
                tool = tool if tool and os.path.isfile(tool) else _pg_bin("pg_dump")
                if not tool:
                    raise RuntimeError("لم أجد pg_dump — اضبط database.postgres.bin_dir")
                p = self.pg
                env = dict(os.environ)
                env["PGPASSWORD"] = p["password"]
                cmd = [tool, "-h", p["host"], "-p", str(p["port"]), "-U", p["user"],
                       "-d", p["dbname"], "--no-owner", "--no-privileges", "-Fp"]
                with open(tmp, "wb") as f:
                    r = subprocess.run(cmd, stdout=f, stderr=subprocess.PIPE,
                                       env=env, timeout=180)
                if r.returncode:
                    raise RuntimeError(r.stderr.decode("utf-8", "replace").strip()[:300])
            self._gzip_file(tmp, dst)
            self._sha256(dst)
            removed = self._rotate()
            self._last_backup = time.time()
            return {"ok": True, "name": name,
                    "bytes": os.path.getsize(dst), "removed": removed}
        finally:
            if os.path.exists(tmp):
                try:
                    os.remove(tmp)
                except OSError:
                    pass

    def maybe_backup(self):
        """نسخة تلقائية دورية — تُستدعى من حلقة المراقبة، بلا أي تكلفة خارجية."""
        if not self.backup_cfg["enabled"]:
            return None
        step = self.backup_cfg["interval_hours"] * 3600
        if time.time() - self._last_backup < step:
            return None
        try:
            return self.create_backup("auto")
        except Exception:
            return None

    def list_backups(self):
        out = []
        try:
            names = os.listdir(self.backup_dir)
        except OSError:
            return out
        for name in names:
            m = STAMP_RE.match(name)
            if not m:
                continue
            path = os.path.join(self.backup_dir, name)
            try:
                ts = datetime.strptime(m.group(1) + m.group(2), "%Y%m%d%H%M%S").timestamp()
            except ValueError:
                ts = 0
            out.append({
                "name": name, "ts": ts,
                "bytes": os.path.getsize(path),
                "reason": m.group(3),
                "checksum": os.path.exists(path + ".sha256"),
                "verified": self._verify(path) if os.path.exists(path + ".sha256") else None,
            })
        out.sort(key=lambda x: x["ts"], reverse=True)
        return out

    def _verify(self, path):
        try:
            expected = open(path + ".sha256", encoding="ascii").read().split()[0]
            h = hashlib.sha256()
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(1024 * 1024), b""):
                    h.update(chunk)
            return h.hexdigest() == expected
        except Exception:
            return False

    def delete_backup(self, name):
        if not re.match(r"^nabd-\d{8}-\d{6}-[a-z0-9_-]+\.(db|sql)\.gz$", name or ""):
            return False
        path = os.path.join(self.backup_dir, name)
        if not os.path.isfile(path):
            return False
        os.remove(path)
        if os.path.exists(path + ".sha256"):
            os.remove(path + ".sha256")
        return True

    def _rotate(self):
        cfg = self.backup_cfg
        items = self.list_backups()
        kept, weeks, months, daily = set(), set(), set(), 0
        removed = []
        for b in items:
            dt = datetime.fromtimestamp(b["ts"])
            wk, mo = dt.strftime("%G-W%V"), dt.strftime("%Y-%m")
            if daily < cfg["keep_daily"]:
                kept.add(b["name"]); daily += 1; weeks.add(wk); months.add(mo)
            elif cfg["keep_weekly"] and wk not in weeks and len(weeks) < cfg["keep_weekly"]:
                kept.add(b["name"]); weeks.add(wk); months.add(mo)
            elif cfg["keep_monthly"] and mo not in months and len(months) < cfg["keep_monthly"]:
                kept.add(b["name"]); months.add(mo)
            else:
                if self.delete_backup(b["name"]):
                    removed.append(b["name"])
        return removed

    def restore(self, name):
        """استعادة نسخة مع إنشاء نسخة أمان قبل الاستعادة."""
        if not re.match(r"^nabd-\d{8}-\d{6}-[a-z0-9_-]+\.(db|sql)\.gz$", name or ""):
            raise RuntimeError("اسم نسخة غير صالح")
        path = os.path.join(self.backup_dir, name)
        if not os.path.isfile(path):
            raise RuntimeError("النسخة غير موجودة")
        if os.path.exists(path + ".sha256") and not self._verify(path):
            raise RuntimeError("فشل التحقق من SHA-256 — النسخة تالفة")
        safe = self.create_backup("before-restore")
        raw = os.path.join(self.backup_dir, "." + name + ".restore")
        try:
            with gzip.open(path, "rb") as f_in, open(raw, "wb") as f_out:
                shutil.copyfileobj(f_in, f_out, 1024 * 1024)
            if self.driver == "sqlite":
                os.replace(raw, self.sqlite_path)
            else:
                tool = self.pg.get("bin_dir") and os.path.join(
                    self.pg["bin_dir"], "psql" + (".exe" if IS_WIN else ""))
                tool = tool if tool and os.path.isfile(tool) else _pg_bin("psql")
                if not tool:
                    raise RuntimeError("لم أجد psql — اضبط database.postgres.bin_dir")
                p = self.pg
                env = dict(os.environ)
                env["PGPASSWORD"] = p["password"]
                base = [tool, "-h", p["host"], "-p", str(p["port"]),
                        "-U", p["user"], "-d", p["dbname"], "-v", "ON_ERROR_STOP=1", "-q"]
                r = subprocess.run(base + ["-c", "DROP SCHEMA public CASCADE; "
                                           "CREATE SCHEMA public;"],
                                   env=env, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, timeout=120)
                if r.returncode:
                    raise RuntimeError(r.stderr.decode("utf-8", "replace")[:300])
                with open(raw, "rb") as f:
                    r = subprocess.run(base, stdin=f, stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE, env=env, timeout=300)
                if r.returncode:
                    raise RuntimeError(r.stderr.decode("utf-8", "replace")[:300])
                os.remove(raw)
            self.init_schema()
            return {"ok": True, "restored": name, "safety_backup": safe["name"]}
        finally:
            if os.path.exists(raw):
                try:
                    os.remove(raw)
                except OSError:
                    pass

    # ------------------------------------------------------------- الترحيل
    def migrate_from_sqlite(self):
        """ينقل بيانات nabd.db القديمة إلى PostgreSQL مرة واحدة."""
        if self.driver != "postgres":
            return {"ok": False, "error": "المحرك الحالي ليس PostgreSQL"}
        if self.query("SELECT value FROM nabd_meta WHERE key='migrated_sqlite'"):
            return {"ok": False, "error": "تم الترحيل مسبقاً"}
        src_path = self.sqlite_path
        if not os.path.exists(src_path):
            return {"ok": False, "error": "لا يوجد nabd.db للترحيل منه"}
        src = Database(self.base, {"driver": "sqlite", "sqlite_path": src_path})
        counts = {}
        try:
            for table, cols in TABLE_COLUMNS.items():
                try:
                    rows = src.query("SELECT " + ",".join(cols) + " FROM " + table)
                except Exception:
                    continue  # جدول جديد في نسخة حديثة وغير موجود في قاعدة قديمة
                if not rows:
                    continue
                marks = ",".join(["%s"] * len(cols))
                conflict = (" ON CONFLICT (key) DO NOTHING" if table == "alert_acks" else
                            " ON CONFLICT (name) DO NOTHING" if table == "maintenance" else "")
                self.executemany(
                    "INSERT INTO %s(%s) VALUES (%s)%s" % (table, ",".join(cols), marks, conflict),
                    rows)
                counts[table] = len(rows)
            self.query("INSERT INTO nabd_meta(key,value) VALUES ('migrated_sqlite',%s) "
                       "ON CONFLICT (key) DO NOTHING", (datetime.now().isoformat(),))
            return {"ok": True, "counts": counts}
        except Exception as e:
            return {"ok": False, "error": str(e)[:300], "counts": counts}
