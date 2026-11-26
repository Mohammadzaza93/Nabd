#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""اختبار تهيئة حاوية Docker دون الحاجة إلى تشغيل Docker فعلياً.

يتحقق أن إعدادات PostgreSQL تُكتب من المتغيرات عند أول تشغيل، وأن تغييرات
اللوحة محفوظة لا تُعاد كتابتها، وأن وضع SQLite يعمل أيضاً.
"""
import os
import pathlib
import shutil
import sys
import tempfile

import yaml

ROOT = pathlib.Path(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, str(ROOT))
import docker_entrypoint  # noqa: E402

SEED = {
    "NABD_SEED_DB_DRIVER": "postgres",
    "NABD_SEED_PG_HOST": "db",
    "NABD_SEED_PG_PORT": "5432",
    "NABD_SEED_PG_DATABASE": "nabd",
    "NABD_SEED_PG_USER": "nabd",
    "NABD_SEED_PG_PASSWORD": "local-test-password",
}
for key, value in SEED.items():
    os.environ[key] = value

tmp = pathlib.Path(tempfile.mkdtemp(prefix="nabd-docker-"))
try:
    cfg_path, dev_path = docker_entrypoint.prepare(ROOT, tmp)
    cfg = yaml.safe_load(cfg_path.read_text(encoding="utf-8"))
    assert cfg["database"]["driver"] == "postgres", cfg["database"]
    pg = cfg["database"]["postgres"]
    assert pg["host"] == "db" and pg["port"] == 5432
    assert pg["dbname"] == "nabd" and pg["user"] == "nabd"
    assert pg["password"] == "local-test-password"
    assert pg["watchdog"] is False, "مراقب pg_ctl لا يعمل داخل الحاوية"
    assert cfg["dashboard"]["host"] == "0.0.0.0"
    assert dev_path.read_text(encoding="utf-8").startswith("name,ip,kind")
    assert (tmp / "backups").is_dir()
    print("OK: Docker seeds PostgreSQL config, empty CSV and backups folder")

    # محاكاة حفظ المستخدم من اللوحة ثم إعادة إنشاء الحاوية
    cfg["check_interval"] = 42
    cfg_path.write_text(yaml.safe_dump(cfg, allow_unicode=True), encoding="utf-8")
    dev_path.write_text("name,ip\nMY-DEVICE,192.0.2.55\n", encoding="utf-8")
    docker_entrypoint.prepare(ROOT, tmp)
    again = yaml.safe_load(cfg_path.read_text(encoding="utf-8"))
    assert again["check_interval"] == 42
    assert "MY-DEVICE" in dev_path.read_text(encoding="utf-8")
    print("OK: settings saved from the UI survive container restart")

    # وضع SQLite اختياري
    tmp2 = pathlib.Path(tempfile.mkdtemp(prefix="nabd-docker-sqlite-", dir=str(tmp)))
    os.environ["NABD_SEED_DB_DRIVER"] = "sqlite"
    cfg2, _ = docker_entrypoint.prepare(ROOT, tmp2)
    assert yaml.safe_load(cfg2.read_text(encoding="utf-8"))["database"]["driver"] == "sqlite"
    print("OK: optional SQLite container mode works too")
finally:
    shutil.rmtree(tmp, ignore_errors=True)

print("OK: Docker entrypoint")
