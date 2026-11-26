#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""تهيئة حاوية نبض ثم تشغيل التطبيق.

كل الإعدادات تُدار من اللوحة العربية بعد أول تشغيل. هذا السكربت يبني ملف
config.yaml مرة واحدة فقط من النموذج الآمن، ويضبط اتصال PostgreSQL من متغيرات
`NABD_SEED_*` التي يمررها docker-compose، ثم يترك الملف تحت سيطرة اللوحة.

وجود الملف يعني أن تغييراتك من الواجهة محفوظة ولا تُعاد كتابتها عند إعادة
إنشاء الحاوية. استخدم مجلد بيانات جديداً (volume جديد) للعودة للإعدادات الافتراضية.
"""
import os
import pathlib
import sys

import yaml

APP = pathlib.Path(__file__).resolve().parent


def prepare(app=APP, data=None):
    """ينشئ بيانات الحاوية عند أول تشغيل، ويتركها كما هي بعد ذلك.

    `:param app`: مجلد المصدر الذي يحوي النماذج الآمنة.
    `:param data`: مجلد البيانات الدائم (NABD_HOME).
    """
    data = pathlib.Path(data or os.environ.get("NABD_HOME", "/data"))
    data.mkdir(parents=True, exist_ok=True)
    cfg_path = data / "config.yaml"

    if not cfg_path.exists():
        cfg = yaml.safe_load((pathlib.Path(app) / "config.example.yaml").read_text(
            encoding="utf-8")) or {}
        database = cfg.setdefault("database", {})
        driver = os.environ.get("NABD_SEED_DB_DRIVER", "postgres").strip().lower()
        database["driver"] = "postgres" if driver in ("postgres", "postgresql", "pg") else "sqlite"

        pg = database.setdefault("postgres", {})
        pg["host"] = os.environ.get("NABD_SEED_PG_HOST", "db")
        pg["port"] = int(os.environ.get("NABD_SEED_PG_PORT", "5432"))
        pg["dbname"] = os.environ.get("NABD_SEED_PG_DATABASE", "nabd")
        pg["user"] = os.environ.get("NABD_SEED_PG_USER", "nabd")
        pg["password"] = os.environ.get("NABD_SEED_PG_PASSWORD", "")

        # داخل Docker يتولى restart policy إعادة تشغيل قاعدة البيانات؛ مراقب
        # pg_ctl الخاص بالتثبيت المحلي غير قابل للتطبيق هنا.
        pg["watchdog"] = False

        cfg_path.write_text(yaml.safe_dump(cfg, allow_unicode=True, sort_keys=False),
                            encoding="utf-8")

    # قائمة أجهزة فارغة بالأعمدة الصحيحة؛ تضاف الأجهزة من زر «＋ إضافة جهاز».
    dev_path = data / "devices.csv"
    if not dev_path.exists():
        dev_path.write_text(
            "name,ip,kind,parent,group,snmp,snmp_community,profile,"
            "cpu_warn,mem_warn,rtt_warn,sfp_rx_min,sensors\n",
            encoding="utf-8")

    (data / "backups").mkdir(exist_ok=True)
    return cfg_path, dev_path


def main():
    prepare(APP, os.environ.get("NABD_HOME", "/data"))
    # exec حتى يصبح نبض هو العملية الرئيسية وتصل إليه إشارات الإيقاف مباشرة
    os.execv(sys.executable, [sys.executable, "-u", str(APP / "nabd.py")])


if __name__ == "__main__":
    main()
