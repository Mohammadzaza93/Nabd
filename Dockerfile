# نبض — صورة التطبيق (بدون أي أسرار داخل الصورة)
FROM python:3.11-slim

# عميل PostgreSQL مطلوب لأخذ النسخ الاحتياطية واستعادتها داخل الحاوية
# (pg_dump / psql). إصدار العميل يطابق إصدار خادم postgres:15 في compose.
RUN apt-get update \
 && apt-get install -y --no-install-recommends postgresql-client \
 && rm -rf /var/lib/apt/lists/*

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    NABD_HOME=/data

WORKDIR /app

# ننسخ ملفات المصدر والنماذج فقط — config.yaml و devices.csv يُنشآن في /data
COPY requirements.txt ./
RUN python -m pip install --no-cache-dir -r requirements.txt

COPY nabd.py db.py snmp.py discover.py docker_entrypoint.py ./
COPY config.example.yaml devices.example.csv ./

RUN mkdir -p /data

# /data مجلد بيانات دائم يحوي config.yaml و devices.csv و nabd.db و backups/
VOLUME ["/data"]

# المنفذ الذي تستخدمه اللوحة؛ يمكن تغييره من compose عبر ports
EXPOSE 8080

CMD ["python", "/app/docker_entrypoint.py"]
