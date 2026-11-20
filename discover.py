# -*- coding: utf-8 -*-
"""اكتشاف تلقائي للأجهزة من راوتر مايكروتك عبر RouterOS API.

الفكرة:
  1) جدول ARP يحوي كل جهاز تكلّم مع الراوتر (عنوان IP + MAC).
  2) نستبعد الأجهزة التي أخذت عنوانها من DHCP ديناميكياً (هواتف وحواسيب الموظفين)،
     فيبقى الأجهزة ذات العنوان الثابت: DVR وكاميرات وسويتشات وسيرفرات.
  3) جدول bridge host يخبرنا على أي منفذ فيزيائي تعلّم الراوتر كل MAC،
     وتعليق المنفذ (مثل "To SW3 172.16.0.3") يخبرنا أي سويتش هو الأب.
  4) جدول ip neighbor (MNDP/LLDP) يكشف السويتشات المجاورة.

ملاحظة: إصدارات librouteros المختلفة ترجع القيم المنطقية إما bool أو نصاً
("true"/"false"/"yes"/"no")، ولذلك نستخدم _bool للتعامل مع الحالتين.
"""
import ipaddress
import re

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def _bool(value, default=False):
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    if isinstance(value, (int, float)):
        return bool(value)
    return str(value).strip().lower() in ("true", "yes", "on", "1", "enabled")


def _mac(value):
    return str(value or "").strip().upper()


def _safe(value):
    return re.sub(r'[,"\r\n]', " ", str(value or "")).strip()


def _valid_ip(value):
    try:
        ipaddress.IPv4Address(str(value))
        return True
    except (ipaddress.AddressValueError, ValueError):
        return False


def fetch(cfg):
    from librouteros import connect

    router = cfg.get("router") or {}
    api = connect(
        username=router["user"],
        password=str(router["password"]),
        host=router["host"],
        port=int(router.get("port", 8728)),
        timeout=15,
    )
    try:
        def query(*path):
            try:
                return [dict(x) for x in api.path(*path)]
            except Exception:
                return []

        return {
            "arp": query("ip", "arp"),
            "hosts": query("interface", "bridge", "host"),
            "leases": query("ip", "dhcp-server", "lease"),
            "eth": query("interface", "ethernet"),
            "vlan": query("interface", "vlan"),
            "neigh": query("ip", "neighbor"),
        }
    finally:
        try:
            api.close()
        except Exception:
            pass


def _resolve(name, vlan_parent):
    """يتتبع واجهة VLAN حتى المنفذ الفيزيائي تحتها."""
    seen = set()
    while name in vlan_parent and name not in seen:
        seen.add(name)
        name = vlan_parent[name]
    return name


def port_parents(eth, known, extra=None):
    """خريطة: اسم المنفذ -> اسم الجهاز المتصل به، من تعليق المنفذ أو من port_map يدوي."""
    mapping = {}
    for entry in eth:
        comment = str(entry.get("comment") or "")
        name = entry.get("name")
        if not name or not comment:
            continue
        for ip in IP_RE.findall(comment):
            if not _valid_ip(ip):
                continue
            for item in known:
                if item["ip"] == ip:
                    mapping[name] = item["name"]
        if name not in mapping:
            low = comment.lower()
            for item in known:
                candidate = re.escape(str(item["name"]).lower())
                if candidate and re.search(r"(?<![\w-])" + candidate + r"(?![\w-])", low):
                    mapping[name] = item["name"]
                    break
    mapping.update(extra or {})
    return mapping


def candidates(data, known, cfg):
    """يرجع قائمة بالأجهزة الجديدة (غير الموجودة في known) مع الأب والمجموعة."""
    exclude = set(cfg.get("exclude_interfaces") or ["WAN-interface"])
    only = set(cfg.get("only_interfaces") or [])
    known_names = {item["name"] for item in known}
    known_ips = {item["ip"] for item in known}
    taken = set(known_names)
    default_parent = next(
        (item["name"] for item in known if item.get("kind") == "router"),
        "Router" if "Router" in known_names else "",
    )
    new_group = _safe(cfg.get("new_group")) or "مكتشف"

    vlan_parent = {
        v["name"]: v.get("interface")
        for v in data.get("vlan", [])
        if v.get("name") and v.get("interface")
    }
    ports = port_parents(data.get("eth", []), known, cfg.get("port_map"))

    host_port = {}
    for host in data.get("hosts", []):
        mac = _mac(host.get("mac-address"))
        interface = host.get("on-interface")
        if mac and interface:
            host_port[mac] = _resolve(interface, vlan_parent)

    leases = [l for l in data.get("leases", []) if l.get("address")]
    dynamic_ips = {
        l["address"] for l in leases
        if _bool(l.get("dynamic")) and _valid_ip(l["address"])
    }
    lease_name = {
        l["address"]: (l.get("host-name") or l.get("comment"))
        for l in leases if _valid_ip(l["address"])
    }

    out = []

    def parent_of(port):
        parent = ports.get(port)
        return parent if parent in known_names or parent in taken else default_parent

    def add(ip, base, kind, group, parent):
        if not _valid_ip(ip) or ip in known_ips:
            return
        last = ip.split(".")
        name = _safe(base) or f"Dev-{last[-2]}-{last[-1]}"
        if name in taken:
            name = f"{name}-{last[-1]}"
        while name in taken:
            name += "_"
        taken.add(name)
        known_ips.add(ip)
        out.append({
            "name": name,
            "ip": ip,
            "kind": kind,
            "parent": parent,
            "group": _safe(group) or new_group,
        })

    for entry in data.get("arp", []):
        ip = str(entry.get("address") or "").strip()
        mac = _mac(entry.get("mac-address"))
        interface = entry.get("interface")
        if not ip or not mac or not _valid_ip(ip):
            continue
        if _bool(entry.get("invalid")) or _bool(entry.get("disabled")):
            continue
        if entry.get("complete") is not None and not _bool(entry.get("complete"), True):
            continue
        if interface in exclude or (only and interface not in only):
            continue
        if ip in dynamic_ips:
            continue
        add(ip, lease_name.get(ip), "device", new_group, parent_of(host_port.get(mac)))

    for neighbor in data.get("neigh", []):
        match = IP_RE.search(str(neighbor.get("address") or neighbor.get("address4") or ""))
        if not match:
            continue
        platform = (str(neighbor.get("platform") or "") + " " + str(neighbor.get("board") or "")).lower()
        kind = "switch" if ("mikrotik" in platform or "switch" in platform) else "neighbor"
        port = _resolve(neighbor.get("interface"), vlan_parent)
        add(match.group(0), neighbor.get("identity"), kind, "السويتشات", parent_of(port))

    return out
