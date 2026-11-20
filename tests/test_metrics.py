import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import nabd

nabd.init_db()
nabd.DEVS.update(nabd.load_devices())
n = nabd.record_samples(force=True)
print("samples written:", n)

c = nabd.app.test_client()

r = c.get("/api/status")
j = r.get_json()
print("status:", r.status_code, "devices", len(j["devices"]), "alerts", j.get("alerts"))

r = c.get("/api/alerts")
j = r.get_json()
print("alerts:", r.status_code, "counts", j.get("counts"), "maint", len(j.get("maintenance") or []))

r = c.get("/api/reports?range=24h")
j = r.get_json()
print("reports:", r.status_code, "summary", j.get("summary"))

name = j["devices"][0]["name"] if j.get("devices") else "Router"
r = c.get("/api/metrics/" + name + "?range=1h")
j = r.get_json()
print("metrics:", r.status_code, "points", len(j.get("series") or []), "summary", j.get("summary"))

r = c.get("/api/reports/export?range=24h")
print("export:", r.status_code, r.headers.get("Content-Type"), "bytes", len(r.data))

r = c.post("/api/devices/%s/maintenance" % name, json={"minutes": 30})
print("maint on:", r.status_code, r.get_json())
r = c.get("/api/alerts")
print("alerts after maint:", r.get_json()["counts"], "maint", r.get_json()["maintenance"])
r = c.post("/api/devices/%s/maintenance" % name, json={"minutes": 0})
print("maint off:", r.status_code, r.get_json().get("active"))

r = c.get("/api/events?range=all&limit=10")
j = r.get_json()
assert r.status_code == 200 and "events" in j, (r.status_code, j)
print("events:", r.status_code, "total", j["total"], "returned", len(j["events"]))
r = c.get("/api/events?range=all&type=maintenance_on&name=" + name)
j2 = r.get_json()
assert r.status_code == 200 and all(e["type"] == "maintenance_on" for e in j2["events"]), j2
print("events filter:", r.status_code, "matched", j2["total"])
r = c.get("/api/events/export?range=all")
assert r.status_code == 200 and "text/csv" in r.headers.get("Content-Type", ""), r.status_code
print("events export:", r.status_code, "bytes", len(r.data))
rep2 = c.get("/api/reports?range=24h").get_json()
assert "maintenance" in rep2.get("summary", {}), rep2.get("summary")
print("SLA maintenance excluded:", rep2["summary"].get("maintenance"), "seconds")
assert nabd.maintenance_seconds(name, time.time() - 60, time.time()) >= 0

nabd.set_maintenance(name, 60)
assert nabd.maintenance_seconds(name, time.time() - 60, time.time() + 1) > 0, \
    "نافذة الصيانة لم تُسجّل في السجل"
rep3 = c.get("/api/reports?range=1h").get_json()
assert rep3["summary"]["maintenance"] > 0, rep3["summary"]
print("SLA 1h maintenance window:", rep3["summary"]["maintenance"], "seconds")
nabd.set_maintenance(name, 0)

r = c.post("/api/alerts/ack", json={"key": "device:test"})
print("ack:", r.status_code, r.get_json())
r = c.post("/api/alerts/ack", json={"key": "device:test", "ack": False})
print("unack:", r.status_code, r.get_json())

r = c.get("/")
print("page:", r.status_code, "bytes", len(r.data))
print("OK: metrics / reports / alerts / maintenance")
