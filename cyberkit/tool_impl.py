from __future__ import annotations

import ipaddress
import json
import os
import re
import socket
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cyberkit.core.exec import run as exec_run
from cyberkit.core.reporting import finish_run
from cyberkit.core.toolcheck import is_installed
from cyberkit.core.validators import is_valid_cidr, is_valid_ip, is_valid_url
from cyberkit.tooling import (
    build_parser,
    check_requirements,
    complete,
    create_run,
    fail,
    load_lines,
    rate_sleep,
    run_command,
    write_note,
    write_payload,
)


@dataclass(slots=True)
class HTTPResult:
    url: str
    final_url: str
    status: int
    headers: dict[str, str]
    body: str


def _read_url(url: str, timeout: int = 10, method: str = "GET") -> HTTPResult:
    request = urllib.request.Request(url, method=method, headers={"User-Agent": "CyberKit/0.1"})
    with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
        body = response.read(4096).decode("utf-8", errors="replace") if method != "HEAD" else ""
        headers = {key.lower(): value for key, value in response.headers.items()}
        return HTTPResult(
            url=url,
            final_url=response.geturl(),
            status=response.status,
            headers=headers,
            body=body,
        )


def _parse_title(html: str) -> str | None:
    match = re.search(r"<title[^>]*>(.*?)</title>", html, flags=re.IGNORECASE | re.DOTALL)
    if not match:
        return None
    return re.sub(r"\s+", " ", match.group(1)).strip()


def _target_hosts(value: str, limit: int = 1024) -> list[str]:
    value = value.strip()
    if is_valid_cidr(value):
        network = ipaddress.ip_network(value, strict=False)
        return [str(host) for host in list(network.hosts())[:limit]]
    if "," in value:
        return [piece.strip() for piece in value.split(",") if piece.strip()]
    return [value]


def _query_dns(name: str, record_type: str, timeout: int) -> list[str]:
    record_type = record_type.upper()
    if is_installed("dig"):
        completed = exec_run(["dig", "+short", name, record_type], timeout=timeout)
        if completed.returncode == 0:
            return [line.strip() for line in completed.stdout.splitlines() if line.strip()]
    elif is_installed("nslookup"):
        completed = exec_run(["nslookup", "-type=" + record_type, name], timeout=timeout)
        if completed.returncode == 0:
            lines: list[str] = []
            for line in completed.stdout.splitlines():
                text = line.strip()
                if "=" in text:
                    lines.append(text.split("=", 1)[1].strip())
                elif ":" in text and "nameserver" in text.lower():
                    lines.append(text.split(":", 1)[1].strip())
            if lines:
                return lines
    elif record_type in {"A", "AAAA"}:
        family = socket.AF_INET if record_type == "A" else socket.AF_INET6
        try:
            infos = socket.getaddrinfo(name, None, family=family)
        except socket.gaierror:
            return []
        return sorted({info[4][0] for info in infos})
    return []


def _safe_load_json(path: Path) -> Any:
    if not path.exists():
        raise FileNotFoundError(path)
    return json.loads(path.read_text(encoding="utf-8"))


def _parse_nmap_xml_text(xml_text: str) -> dict[str, Any]:
    root = ET.fromstring(xml_text)
    hosts: list[dict[str, Any]] = []
    for host in root.findall("host"):
        addresses = [item.attrib.get("addr") for item in host.findall("address") if item.attrib.get("addr")]
        ports: list[dict[str, Any]] = []
        for node in host.findall("ports/port"):
            state = node.find("state")
            service = node.find("service")
            ports.append(
                {
                    "port": int(node.attrib.get("portid", "0")),
                    "protocol": node.attrib.get("protocol", ""),
                    "state": state.attrib.get("state", "") if state is not None else "",
                    "service": service.attrib.get("name", "") if service is not None else "",
                    "product": service.attrib.get("product", "") if service is not None else "",
                    "version": service.attrib.get("version", "") if service is not None else "",
                }
            )
        hosts.append({"addresses": addresses, "ports": ports})
    return {"hosts": hosts}


def _parse_spf_record(record: str) -> dict[str, Any]:
    tokens = record.split()
    mechanisms = [token for token in tokens[1:] if token and not token.startswith("redirect=")]
    return {
        "record": record,
        "mechanisms": mechanisms,
        "has_plus_all": "+all" in mechanisms,
        "has_softfail": "~all" in mechanisms,
        "has_hardfail": "-all" in mechanisms,
    }


def _parse_tag_value_record(record: str) -> dict[str, str]:
    output: dict[str, str] = {}
    for chunk in [piece.strip() for piece in record.split(";") if piece.strip()]:
        if "=" not in chunk:
            continue
        key, value = chunk.split("=", 1)
        output[key.strip()] = value.strip()
    return output


def _load_targets(positional: list[str], file_path: str | None) -> list[str]:
    targets = [item for item in positional if item]
    if file_path:
        targets.extend(load_lines(Path(file_path)))
    return targets


def handle_host_resolve(meta: dict[str, Any], argv: list[str]) -> int:
    parser = build_parser(
        meta,
        "Resolve A/AAAA records for hostnames.",
        ["host-resolve example.com", "host-resolve --family both example.com internal.local"],
    )
    parser.add_argument("targets", nargs="+", help="Hostnames or IPs.")
    parser.add_argument("--family", choices=["a", "aaaa", "both"], default="both")
    args = parser.parse_args(argv)

    run = create_run(meta, argv)
    results: list[dict[str, Any]] = []
    families: list[int] = []
    if args.family in {"a", "both"}:
        families.append(socket.AF_INET)
    if args.family in {"aaaa", "both"}:
        families.append(socket.AF_INET6)

    for target in args.targets:
        row: dict[str, Any] = {"target": target, "a": [], "aaaa": [], "error": None}
        for family in families:
            try:
                infos = socket.getaddrinfo(target, None, family=family)
                addresses = sorted({info[4][0] for info in infos})
                if family == socket.AF_INET:
                    row["a"] = addresses
                else:
                    row["aaaa"] = addresses
            except socket.gaierror as exc:
                row["error"] = str(exc)
        results.append(row)

    write_payload(run, {"tool": meta["id"], "results": results}, print_json=args.json)
    return complete(run, f"Resolved {len(results)} target(s).")


def handle_reverse_dns_sweep(meta: dict[str, Any], argv: list[str]) -> int:
    parser = build_parser(
        meta,
        "Reverse DNS sweep for CIDR/IP lists with rate limiting.",
        ["reverse-dns-sweep 192.168.1.0/24 --rate 20", "reverse-dns-sweep --input-file ips.txt"],
    )
    parser.add_argument("target", nargs="?", default="", help="CIDR, IP, or comma-separated list.")
    parser.add_argument("--input-file", help="File with one IP per line.")
    parser.add_argument("--rate", type=float, default=10.0, help="Queries per second.")
    parser.add_argument("--limit", type=int, default=256, help="CIDR host limit.")
    args = parser.parse_args(argv)

    targets: list[str] = []
    if args.target:
        targets.extend(_target_hosts(args.target, limit=args.limit))
    if args.input_file:
        targets.extend(load_lines(Path(args.input_file)))
    if not targets:
        return fail(meta, "No targets provided.")

    run = create_run(meta, argv)
    results = []
    for ip in targets:
        if not is_valid_ip(ip):
            results.append({"ip": ip, "ptr": None, "error": "not-an-ip"})
            continue
        try:
            ptr = socket.gethostbyaddr(ip)[0]
            results.append({"ip": ip, "ptr": ptr, "error": None})
        except (socket.herror, socket.gaierror) as exc:
            results.append({"ip": ip, "ptr": None, "error": str(exc)})
        rate_sleep(args.rate)

    write_payload(run, {"tool": meta["id"], "results": results}, print_json=args.json)
    return complete(run, f"Checked {len(results)} IP(s).")


def handle_whois_summary(meta: dict[str, Any], argv: list[str]) -> int:
    parser = build_parser(
        meta,
        "Run WHOIS and extract registrar/date summary fields.",
        ["whois-summary example.com", "whois-summary 8.8.8.8"],
    )
    parser.add_argument("target", help="Domain or IP.")
    args = parser.parse_args(argv)

    if not is_installed("whois"):
        return fail(meta, "Missing dependency: whois")

    run = create_run(meta, argv)
    completed = run_command(run, ["whois", args.target], timeout=args.timeout, dry_run_flag=args.dry_run)
    if completed is None:
        return complete(run, "Dry run complete.")
    if completed.returncode != 0:
        finish_run(run, status="error", summary="WHOIS command failed")
        return fail(meta, "WHOIS command failed")

    raw = completed.stdout
    write_note(run, "Raw WHOIS output stored in stdout.log.")
    summary: dict[str, Any] = {
        "target": args.target,
        "registrar": None,
        "creation_date": None,
        "updated_date": None,
        "expiry_date": None,
        "nameservers": [],
    }

    registrar = re.search(r"(?im)^Registrar:\\s*(.+)$", raw)
    created = re.search(r"(?im)^Creation Date:\\s*(.+)$", raw)
    updated = re.search(r"(?im)^Updated Date:\\s*(.+)$", raw)
    expiry = re.search(r"(?im)^(Registry Expiry Date|Expiration Date):\\s*(.+)$", raw)
    nameservers = re.findall(r"(?im)^Name Server:\\s*(.+)$", raw)

    if registrar:
        summary["registrar"] = registrar.group(1).strip()
    if created:
        summary["creation_date"] = created.group(1).strip()
    if updated:
        summary["updated_date"] = updated.group(1).strip()
    if expiry:
        summary["expiry_date"] = expiry.group(2).strip()
    if nameservers:
        summary["nameservers"] = [item.strip() for item in nameservers]

    write_payload(run, {"tool": meta["id"], "summary": summary}, print_json=args.json)
    return complete(run, "WHOIS summary complete.")


def handle_asn_lookup(meta: dict[str, Any], argv: list[str]) -> int:
    parser = build_parser(
        meta,
        "Map IP addresses to ASN details using WHOIS data.",
        ["asn-lookup 1.1.1.1", "asn-lookup 1.1.1.1 8.8.8.8"],
    )
    parser.add_argument("ips", nargs="+", help="IP addresses.")
    args = parser.parse_args(argv)

    if not is_installed("whois"):
        return fail(meta, "Missing dependency: whois")

    run = create_run(meta, argv)
    rows: list[dict[str, Any]] = []
    for ip in args.ips:
        if not is_valid_ip(ip):
            rows.append({"ip": ip, "asn": None, "org": None, "error": "invalid-ip"})
            continue
        completed = exec_run(["whois", ip], timeout=args.timeout)
        asn_match = re.search(r"(?im)^(origin|originas|aut-num):\\s*(AS?\\d+)", completed.stdout)
        org_match = re.search(r"(?im)^(org-name|orgname|descr):\\s*(.+)$", completed.stdout)
        rows.append(
            {
                "ip": ip,
                "asn": asn_match.group(2) if asn_match else None,
                "org": org_match.group(2).strip() if org_match else None,
                "error": None if completed.returncode == 0 else "whois-failed",
            }
        )

    write_payload(run, {"tool": meta["id"], "results": rows}, print_json=args.json)
    return complete(run, f"Processed {len(rows)} IP(s).")


def handle_local_net_inventory(meta: dict[str, Any], argv: list[str]) -> int:
    parser = build_parser(
        meta,
        "Collect interfaces, routes, DNS, ARP, and listening sockets.",
        ["local-net-inventory"],
    )
    args = parser.parse_args(argv)
    run = create_run(meta, argv)

    def run_text(cmd: list[str]) -> str:
        completed = exec_run(cmd, timeout=args.timeout)
        return completed.stdout if completed.returncode == 0 else completed.stderr

    interfaces_json = run_text(["ip", "-j", "addr"]) if is_installed("ip") else ""
    routes = run_text(["ip", "route"]) if is_installed("ip") else "ip command not available"
    arp = run_text(["ip", "neigh"]) if is_installed("ip") else "ip command not available"
    listening = run_text(["ss", "-lntu"]) if is_installed("ss") else "ss command not available"
    resolv = Path("/etc/resolv.conf")
    resolv_conf = resolv.read_text(encoding="utf-8", errors="replace") if resolv.exists() else ""

    payload = {
        "tool": meta["id"],
        "interfaces": json.loads(interfaces_json) if interfaces_json.strip().startswith("[") else interfaces_json,
        "routes": routes.splitlines(),
        "arp": arp.splitlines(),
        "listening": listening.splitlines(),
        "resolv_conf": resolv_conf.splitlines(),
    }
    write_payload(run, payload, print_json=args.json)
    return complete(run, "Collected local network inventory.")


def handle_arp_table_audit(meta: dict[str, Any], argv: list[str]) -> int:
    parser = build_parser(meta, "Audit ARP table and flag duplicate mappings.", ["arp-table-audit"])
    args = parser.parse_args(argv)
    if not is_installed("ip"):
        return fail(meta, "Missing dependency: ip")

    run = create_run(meta, argv)
    completed = exec_run(["ip", "neigh"], timeout=args.timeout)
    lines = [line.strip() for line in completed.stdout.splitlines() if line.strip()]

    mapping: dict[str, list[str]] = {}
    for line in lines:
        parts = line.split()
        if len(parts) < 5 or "lladdr" not in parts:
            continue
        ip = parts[0]
        mac = parts[parts.index("lladdr") + 1]
        mapping.setdefault(mac, []).append(ip)

    duplicates = {mac: ips for mac, ips in mapping.items() if len(set(ips)) > 1}
    write_payload(
        run,
        {
            "tool": meta["id"],
            "entries": len(mapping),
            "duplicate_mac_entries": duplicates,
            "raw_lines": lines,
        },
        print_json=args.json,
    )
    return complete(run, f"Analysed {len(lines)} ARP entries.")


def handle_service_banner_grab(meta: dict[str, Any], argv: list[str]) -> int:
    parser = build_parser(
        meta,
        "Safe TCP banner grabbing for common ports.",
        ["service-banner-grab example.com --ports 22,25,80"],
    )
    parser.add_argument("host")
    parser.add_argument("--ports", default="22,25,80,443")
    args = parser.parse_args(argv)

    run = create_run(meta, argv)
    ports = [int(item.strip()) for item in args.ports.split(",") if item.strip()]
    results: list[dict[str, Any]] = []
    for port in ports:
        try:
            with socket.create_connection((args.host, port), timeout=args.timeout) as sock:
                sock.settimeout(args.timeout)
                banner = sock.recv(1024).decode("utf-8", errors="replace").strip()
            results.append({"port": port, "open": True, "banner": banner})
        except OSError as exc:
            results.append({"port": port, "open": False, "banner": "", "error": str(exc)})

    write_payload(run, {"tool": meta["id"], "target": args.host, "results": results}, print_json=args.json)
    return complete(run, f"Checked {len(ports)} ports.")


def handle_http_probe(meta: dict[str, Any], argv: list[str]) -> int:
    parser = build_parser(
        meta,
        "Probe URLs, follow redirects, and capture summary details.",
        ["http-probe https://example.com", "http-probe --input-file urls.txt"],
    )
    parser.add_argument("urls", nargs="*")
    parser.add_argument("--input-file")
    args = parser.parse_args(argv)

    targets = _load_targets(args.urls, args.input_file)
    if not targets:
        return fail(meta, "No URLs provided.")

    run = create_run(meta, argv)
    rows: list[dict[str, Any]] = []
    for url in targets:
        if not is_valid_url(url):
            rows.append({"url": url, "error": "invalid-url"})
            continue
        try:
            result = _read_url(url, timeout=args.timeout)
            rows.append(
                {
                    "url": url,
                    "final_url": result.final_url,
                    "status": result.status,
                    "server": result.headers.get("server"),
                    "title": _parse_title(result.body),
                }
            )
        except Exception as exc:  # pragma: no cover
            rows.append({"url": url, "error": str(exc)})

    write_payload(run, {"tool": meta["id"], "results": rows}, print_json=args.json)
    return complete(run, f"Probed {len(rows)} URL(s).")


def handle_subdomain_cert_transparency(meta: dict[str, Any], argv: list[str]) -> int:
    parser = build_parser(
        meta,
        "Query crt.sh and collect subdomain candidates.",
        ["subdomain-cert-transparency example.com --max-results 100"],
    )
    parser.add_argument("domain")
    parser.add_argument("--max-results", type=int, default=200)
    args = parser.parse_args(argv)

    run = create_run(meta, argv)
    query_url = f"https://crt.sh/?q=%25.{urllib.parse.quote(args.domain)}&output=json"
    try:
        result = _read_url(query_url, timeout=args.timeout)
        parsed = json.loads(result.body)
    except Exception as exc:  # pragma: no cover
        finish_run(run, status="error", summary="CT query failed")
        return fail(meta, f"Unable to query crt.sh: {exc}")

    subdomains: set[str] = set()
    for row in parsed[: args.max_results]:
        value = str(row.get("name_value", ""))
        for entry in value.splitlines():
            normalized = entry.strip().lstrip("*.")
            if normalized.endswith(args.domain):
                subdomains.add(normalized)

    payload = {"tool": meta["id"], "domain": args.domain, "subdomains": sorted(subdomains)}
    write_payload(run, payload, print_json=args.json)
    return complete(run, f"Collected {len(subdomains)} subdomain candidate(s).")


def handle_ssh_known_hosts_audit(meta: dict[str, Any], argv: list[str]) -> int:
    parser = build_parser(
        meta,
        "Audit known_hosts for duplicates and weak key types.",
        ["ssh-known-hosts-audit", "ssh-known-hosts-audit --path ~/.ssh/known_hosts"],
    )
    parser.add_argument("--path", default=str(Path.home() / ".ssh" / "known_hosts"))
    args = parser.parse_args(argv)

    path = Path(os.path.expanduser(args.path))
    if not path.exists():
        return fail(meta, f"File not found: {path}")

    run = create_run(meta, argv)
    lines = [
        line
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines()
        if line and not line.startswith("#")
    ]
    host_counter: Counter[str] = Counter()
    weak_entries: list[dict[str, str]] = []
    for line in lines:
        parts = line.split()
        if len(parts) < 3:
            continue
        host_field, key_type = parts[0], parts[1]
        for host in host_field.split(","):
            host_counter[host] += 1
        if key_type == "ssh-dss":
            weak_entries.append({"host": host_field, "key_type": key_type})

    duplicates = sorted([host for host, count in host_counter.items() if count > 1])
    payload = {
        "tool": meta["id"],
        "path": str(path),
        "entries": len(lines),
        "duplicate_hosts": duplicates,
        "weak_entries": weak_entries,
    }
    write_payload(run, payload, print_json=args.json)
    return complete(run, f"Audited {len(lines)} known_hosts entries.")


def handle_nmap_wrapper(meta: dict[str, Any], argv: list[str]) -> int:
    parser = build_parser(
        meta,
        "Run nmap with safe defaults and parse XML output.",
        [f"{meta['id']} 192.168.1.0/24", f"{meta['id']} scanme.nmap.org --ports 1-1024"],
    )
    parser.add_argument("target")
    parser.add_argument("--ports", default="", help="Optional port range/list override.")
    parser.add_argument("--allow-sudo", action="store_true")
    args = parser.parse_args(argv)

    missing = check_requirements(meta)
    if missing:
        return fail(meta, f"Missing dependency: {', '.join(missing)}")

    run = create_run(meta, argv)
    xml_path = run.run_dir / "nmap.xml"
    profile = meta.get("profile", "quick")
    cmd = ["nmap", "-Pn", "-T2"]
    if profile == "quick":
        cmd.extend(["--top-ports", "100"])
    elif profile == "service":
        cmd.extend(["-sV", "--version-light"])
    if args.ports:
        cmd.extend(["-p", args.ports])
    cmd.extend([args.target, "-oX", str(xml_path)])

    completed = run_command(
        run,
        cmd,
        timeout=max(args.timeout, 30),
        dry_run_flag=args.dry_run,
        allow_sudo=args.allow_sudo,
    )
    if completed is None:
        return complete(run, "Dry run complete.")
    if completed.returncode != 0:
        finish_run(run, status="error", summary="nmap scan failed")
        return fail(meta, "nmap scan failed")

    try:
        parsed = _parse_nmap_xml_text(xml_path.read_text(encoding="utf-8", errors="replace"))
    except Exception as exc:
        finish_run(run, status="error", summary="Unable to parse nmap XML")
        return fail(meta, f"Unable to parse nmap XML: {exc}")

    write_payload(
        run,
        {"tool": meta["id"], "target": args.target, "hosts": parsed["hosts"]},
        print_json=args.json,
    )
    return complete(run, "nmap run complete.")


def handle_nmap_to_json(meta: dict[str, Any], argv: list[str]) -> int:
    parser = build_parser(
        meta,
        "Convert nmap XML file to JSON summary.",
        ["nmap-to-json scan.xml", "nmap-to-json reports/nmap.xml --json"],
    )
    parser.add_argument("xml_file")
    args = parser.parse_args(argv)

    xml_path = Path(args.xml_file)
    if not xml_path.exists():
        return fail(meta, f"File not found: {xml_path}")

    run = create_run(meta, argv)
    try:
        parsed = _parse_nmap_xml_text(xml_path.read_text(encoding="utf-8", errors="replace"))
    except Exception as exc:
        finish_run(run, status="error", summary="XML parse failed")
        return fail(meta, f"Unable to parse XML: {exc}")

    write_payload(run, {"tool": meta["id"], "source": str(xml_path), **parsed}, print_json=args.json)
    return complete(run, "Converted XML to JSON summary.")


def handle_port_diff(meta: dict[str, Any], argv: list[str]) -> int:
    parser = build_parser(meta, "Diff two scan JSON summaries and show open/closed changes.", ["port-diff before.json after.json"])
    parser.add_argument("baseline")
    parser.add_argument("current")
    args = parser.parse_args(argv)

    run = create_run(meta, argv)

    def host_port_set(payload: dict[str, Any]) -> set[tuple[str, int, str]]:
        output: set[tuple[str, int, str]] = set()
        for host in payload.get("hosts", []):
            addresses = host.get("addresses", [])
            identity = addresses[0] if addresses else "unknown"
            for port in host.get("ports", []):
                output.add((identity, int(port.get("port", 0)), str(port.get("protocol", "tcp"))))
        return output

    baseline_payload = _safe_load_json(Path(args.baseline))
    current_payload = _safe_load_json(Path(args.current))
    before = host_port_set(baseline_payload)
    after = host_port_set(current_payload)

    opened = sorted(after - before)
    closed = sorted(before - after)
    write_payload(
        run,
        {
            "tool": meta["id"],
            "opened": [{"host": host, "port": port, "protocol": proto} for host, port, proto in opened],
            "closed": [{"host": host, "port": port, "protocol": proto} for host, port, proto in closed],
        },
        print_json=args.json,
    )
    return complete(run, f"Opened: {len(opened)}, Closed: {len(closed)}")


def handle_tcp_connect_scan(meta: dict[str, Any], argv: list[str]) -> int:
    parser = build_parser(
        meta,
        "Pure Python TCP connect scan for small scopes.",
        ["tcp-connect-scan 192.168.1.10 --ports 22,80,443"],
    )
    parser.add_argument("target")
    parser.add_argument("--ports", default="22,80,443")
    parser.add_argument("--limit-hosts", type=int, default=64)
    args = parser.parse_args(argv)

    run = create_run(meta, argv)
    hosts = _target_hosts(args.target, limit=args.limit_hosts)
    ports = [int(piece.strip()) for piece in args.ports.split(",") if piece.strip()]
    results = []
    for host in hosts:
        open_ports = []
        errors: list[dict[str, Any]] = []
        for port in ports:
            try:
                with socket.create_connection((host, port), timeout=args.timeout):
                    open_ports.append(port)
            except OSError as exc:
                errors.append({"port": port, "error": str(exc)})
        results.append({"host": host, "open_ports": open_ports, "errors": errors})

    write_payload(run, {"tool": meta["id"], "results": results}, print_json=args.json)
    return complete(run, f"Scanned {len(hosts)} host(s).")


def handle_udp_lite_check(meta: dict[str, Any], argv: list[str]) -> int:
    parser = build_parser(
        meta,
        "Small UDP checks for DNS/NTP/SNMP service presence.",
        ["udp-lite-check 8.8.8.8 --ports 53,123,161"],
    )
    parser.add_argument("target")
    parser.add_argument("--ports", default="53,123,161")
    args = parser.parse_args(argv)

    run = create_run(meta, argv)
    ports = [int(piece.strip()) for piece in args.ports.split(",") if piece.strip()]
    results = []
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(args.timeout)
        try:
            sock.sendto(b"\x00", (args.target, port))
            data, _addr = sock.recvfrom(1024)
            results.append({"port": port, "status": "response", "bytes": len(data)})
        except TimeoutError:
            results.append({"port": port, "status": "no-response", "bytes": 0})
        except OSError as exc:
            results.append({"port": port, "status": f"error: {exc}", "bytes": 0})
        finally:
            sock.close()

    write_payload(run, {"tool": meta["id"], "target": args.target, "results": results}, print_json=args.json)
    return complete(run, f"Checked {len(results)} UDP port(s).")


def handle_traceroute_report(meta: dict[str, Any], argv: list[str]) -> int:
    parser = build_parser(meta, "Run traceroute/mtr and capture hop output.", ["traceroute-report example.com"])
    parser.add_argument("target")
    args = parser.parse_args(argv)

    command: list[str] | None = None
    if is_installed("traceroute"):
        command = ["traceroute", "-n", args.target]
    elif is_installed("tracepath"):
        command = ["tracepath", args.target]
    elif is_installed("mtr"):
        command = ["mtr", "-r", "-c", "5", args.target]
    if command is None:
        return fail(meta, "Missing dependency: traceroute/tracepath/mtr")

    run = create_run(meta, argv)
    completed = run_command(run, command, timeout=max(args.timeout, 30), dry_run_flag=args.dry_run)
    if completed is None:
        return complete(run, "Dry run complete.")

    write_payload(
        run,
        {
            "tool": meta["id"],
            "target": args.target,
            "command": command,
            "lines": completed.stdout.splitlines(),
        },
        print_json=args.json,
    )
    status = "ok" if completed.returncode == 0 else "error"
    finish_run(run, status=status, summary="Traceroute command completed")
    return 0 if completed.returncode == 0 else 1


def handle_mtu_path_check(meta: dict[str, Any], argv: list[str]) -> int:
    parser = build_parser(
        meta,
        "PMTU style check with ping and DF.",
        ["mtu-path-check 8.8.8.8", "mtu-path-check example.com --sizes 1200,1300,1400,1472"],
    )
    parser.add_argument("target")
    parser.add_argument("--sizes", default="1200,1300,1400,1472")
    args = parser.parse_args(argv)

    if not is_installed("ping"):
        return fail(meta, "Missing dependency: ping")

    run = create_run(meta, argv)
    sizes = [int(piece.strip()) for piece in args.sizes.split(",") if piece.strip()]
    rows = []
    for size in sizes:
        command = ["ping", "-M", "do", "-c", "1", "-s", str(size), args.target]
        completed = exec_run(command, timeout=args.timeout)
        rows.append(
            {
                "size": size,
                "ok": completed.returncode == 0,
                "tail": completed.stdout.splitlines()[-1:] if completed.stdout else [],
            }
        )

    write_payload(run, {"tool": meta["id"], "target": args.target, "tests": rows}, print_json=args.json)
    return complete(run, f"Tested {len(rows)} MTU packet sizes.")


def handle_pcap_snapshot(meta: dict[str, Any], argv: list[str]) -> int:
    parser = build_parser(
        meta,
        "Take a short tcpdump packet capture snapshot.",
        ["pcap-snapshot --interface eth0 --packets 200 --filter 'tcp port 443'"],
    )
    parser.add_argument("--interface", default="any")
    parser.add_argument("--packets", type=int, default=100)
    parser.add_argument("--filter", default="")
    parser.add_argument("--allow-sudo", action="store_true")
    args = parser.parse_args(argv)

    if not is_installed("tcpdump"):
        return fail(meta, "Missing dependency: tcpdump")

    run = create_run(meta, argv)
    capture_path = run.run_dir / "capture.pcap"
    command = ["tcpdump", "-i", args.interface, "-c", str(max(1, args.packets)), "-w", str(capture_path)]
    if args.filter:
        command.extend(args.filter.split())
    completed = run_command(
        run,
        command,
        timeout=max(args.timeout, 60),
        dry_run_flag=args.dry_run,
        allow_sudo=args.allow_sudo,
    )
    if completed is None:
        return complete(run, "Dry run complete.")

    write_payload(
        run,
        {
            "tool": meta["id"],
            "capture_file": str(capture_path),
            "packets_requested": args.packets,
            "returncode": completed.returncode,
        },
        print_json=args.json,
    )
    status = "ok" if completed.returncode == 0 else "error"
    finish_run(run, status=status, summary="pcap snapshot command completed")
    return 0 if completed.returncode == 0 else 1


def handle_pcap_summary(meta: dict[str, Any], argv: list[str]) -> int:
    parser = build_parser(meta, "Summarise pcap files with tshark.", ["pcap-summary capture.pcap"])
    parser.add_argument("pcap")
    args = parser.parse_args(argv)

    if not is_installed("tshark"):
        return fail(meta, "Missing dependency: tshark")
    pcap_path = Path(args.pcap)
    if not pcap_path.exists():
        return fail(meta, f"File not found: {pcap_path}")

    run = create_run(meta, argv)
    command = ["tshark", "-r", str(pcap_path), "-q", "-z", "conv,ip", "-z", "io,phs"]
    completed = run_command(run, command, timeout=max(args.timeout, 30), dry_run_flag=args.dry_run)
    if completed is None:
        return complete(run, "Dry run complete.")

    write_payload(
        run,
        {"tool": meta["id"], "pcap": str(pcap_path), "summary_lines": completed.stdout.splitlines()},
        print_json=args.json,
    )
    status = "ok" if completed.returncode == 0 else "error"
    finish_run(run, status=status, summary="tshark summary completed")
    return 0 if completed.returncode == 0 else 1


def handle_http_security_headers(meta: dict[str, Any], argv: list[str]) -> int:
    parser = build_parser(meta, "Check key HTTP security headers.", ["http-security-headers https://example.com"])
    parser.add_argument("url")
    args = parser.parse_args(argv)
    if not is_valid_url(args.url):
        return fail(meta, "Invalid URL.")

    run = create_run(meta, argv)
    required_headers = [
        "strict-transport-security",
        "content-security-policy",
        "x-frame-options",
        "x-content-type-options",
        "referrer-policy",
        "permissions-policy",
    ]
    try:
        result = _read_url(args.url, timeout=args.timeout)
    except Exception as exc:  # pragma: no cover
        finish_run(run, status="error", summary="Request failed")
        return fail(meta, str(exc))

    findings = {
        key: {"present": key in result.headers, "value": result.headers.get(key)}
        for key in required_headers
    }
    write_payload(
        run,
        {"tool": meta["id"], "url": args.url, "status": result.status, "headers": findings},
        print_json=args.json,
    )
    return complete(run, "Header audit complete.")


def handle_tls_cert_inspect(meta: dict[str, Any], argv: list[str]) -> int:
    parser = build_parser(
        meta,
        "Pull TLS certificate details from a server.",
        ["tls-cert-inspect example.com", "tls-cert-inspect example.com --port 443"],
    )
    parser.add_argument("host")
    parser.add_argument("--port", type=int, default=443)
    args = parser.parse_args(argv)

    run = create_run(meta, argv)
    context = ssl.create_default_context()
    try:
        with socket.create_connection((args.host, args.port), timeout=args.timeout) as sock:
            with context.wrap_socket(sock, server_hostname=args.host) as wrapped:
                cert = wrapped.getpeercert()
                cipher = wrapped.cipher()
    except OSError as exc:
        finish_run(run, status="error", summary="TLS connection failed")
        return fail(meta, str(exc))

    payload = {
        "tool": meta["id"],
        "host": args.host,
        "port": args.port,
        "subject": cert.get("subject", []),
        "issuer": cert.get("issuer", []),
        "notBefore": cert.get("notBefore"),
        "notAfter": cert.get("notAfter"),
        "subjectAltName": cert.get("subjectAltName", []),
        "cipher": cipher,
    }
    write_payload(run, payload, print_json=args.json)
    return complete(run, "TLS certificate inspection complete.")


def handle_tls_config_wrapper(meta: dict[str, Any], argv: list[str]) -> int:
    parser = build_parser(
        meta,
        "Wrapper around sslscan/testssl with parsed key findings.",
        ["tls-config-wrapper example.com:443"],
    )
    parser.add_argument("target")
    args = parser.parse_args(argv)

    command: list[str] | None = None
    if is_installed("sslscan"):
        command = ["sslscan", args.target]
    elif is_installed("testssl.sh"):
        command = ["testssl.sh", "--quiet", args.target]
    if command is None:
        return fail(meta, "Missing dependency: sslscan or testssl.sh")

    run = create_run(meta, argv)
    completed = run_command(run, command, timeout=max(args.timeout, 60), dry_run_flag=args.dry_run)
    if completed is None:
        return complete(run, "Dry run complete.")

    lowered = completed.stdout.lower()
    payload = {
        "tool": meta["id"],
        "target": args.target,
        "findings": {
            "deprecated_tls": any(tag in lowered for tag in ["tlsv1.0", "tlsv1.1", "sslv3"]),
            "weak_cipher_mentions": len(re.findall(r"(3des|rc4|des)", lowered)),
        },
    }
    write_payload(run, payload, print_json=args.json)
    status = "ok" if completed.returncode == 0 else "error"
    finish_run(run, status=status, summary="TLS config wrapper completed")
    return 0 if completed.returncode == 0 else 1


def handle_robots_sitemap_fetch(meta: dict[str, Any], argv: list[str]) -> int:
    parser = build_parser(meta, "Fetch robots.txt and sitemap references.", ["robots-sitemap-fetch https://example.com"])
    parser.add_argument("base_url")
    args = parser.parse_args(argv)
    if not is_valid_url(args.base_url):
        return fail(meta, "Invalid base URL.")

    run = create_run(meta, argv)
    robots_url = args.base_url.rstrip("/") + "/robots.txt"
    try:
        robots = _read_url(robots_url, timeout=args.timeout)
    except Exception as exc:  # pragma: no cover
        finish_run(run, status="error", summary="Unable to fetch robots.txt")
        return fail(meta, str(exc))

    lines = robots.body.splitlines()
    sitemaps = [line.split(":", 1)[1].strip() for line in lines if line.lower().startswith("sitemap:")]
    paths = [
        line.split(":", 1)[1].strip()
        for line in lines
        if line.lower().startswith(("allow:", "disallow:")) and ":" in line
    ]
    write_payload(
        run,
        {"tool": meta["id"], "robots_url": robots_url, "status": robots.status, "sitemaps": sitemaps, "paths": paths},
        print_json=args.json,
    )
    return complete(run, "Fetched robots/sitemap information.")


def handle_content_discovery_lite(meta: dict[str, Any], argv: list[str]) -> int:
    parser = build_parser(
        meta,
        "Rate-limited content discovery with a safe path list.",
        ["content-discovery-lite https://example.com --rate 2"],
    )
    parser.add_argument("base_url")
    parser.add_argument("--rate", type=float, default=2.0)
    parser.add_argument(
        "--paths",
        default="/.well-known/security.txt,/robots.txt,/sitemap.xml,/admin,/login,/health,/status",
    )
    args = parser.parse_args(argv)
    if not is_valid_url(args.base_url):
        return fail(meta, "Invalid base URL.")

    run = create_run(meta, argv)
    base = args.base_url.rstrip("/")
    paths = [path.strip() for path in args.paths.split(",") if path.strip()]
    results = []
    for path in paths:
        url = base + path
        try:
            response = _read_url(url, timeout=args.timeout)
            results.append({"path": path, "status": response.status, "final_url": response.final_url})
        except urllib.error.HTTPError as exc:
            results.append({"path": path, "status": exc.code, "error": str(exc)})
        except Exception as exc:  # pragma: no cover
            results.append({"path": path, "status": None, "error": str(exc)})
        rate_sleep(args.rate)

    write_payload(
        run,
        {"tool": meta["id"], "base_url": args.base_url, "results": results},
        print_json=args.json,
    )
    return complete(run, f"Checked {len(results)} path(s).")


def handle_cookie_audit(meta: dict[str, Any], argv: list[str]) -> int:
    parser = build_parser(meta, "Audit Set-Cookie flags and attributes.", ["cookie-audit https://example.com/login"])
    parser.add_argument("url")
    args = parser.parse_args(argv)
    if not is_valid_url(args.url):
        return fail(meta, "Invalid URL.")

    run = create_run(meta, argv)
    request = urllib.request.Request(args.url, headers={"User-Agent": "CyberKit/0.1"})
    try:
        with urllib.request.urlopen(request, timeout=args.timeout) as response:  # noqa: S310
            set_cookies = response.headers.get_all("Set-Cookie") or []
    except Exception as exc:  # pragma: no cover
        finish_run(run, status="error", summary="Request failed")
        return fail(meta, str(exc))

    cookies = []
    for raw in set_cookies:
        lowered = raw.lower()
        cookies.append(
            {
                "raw": raw,
                "secure": "secure" in lowered,
                "httponly": "httponly" in lowered,
                "samesite": "samesite=" in lowered,
            }
        )
    write_payload(run, {"tool": meta["id"], "url": args.url, "cookies": cookies}, print_json=args.json)
    return complete(run, f"Analysed {len(cookies)} cookie header(s).")


def handle_http_methods_check(meta: dict[str, Any], argv: list[str]) -> int:
    parser = build_parser(meta, "Probe HTTP methods with safe limits.", ["http-methods-check https://example.com"])
    parser.add_argument("url")
    parser.add_argument("--methods", default="OPTIONS,GET,HEAD,POST")
    args = parser.parse_args(argv)
    if not is_valid_url(args.url):
        return fail(meta, "Invalid URL.")

    run = create_run(meta, argv)
    methods = [piece.strip().upper() for piece in args.methods.split(",") if piece.strip()]
    results = []
    for method in methods:
        request = urllib.request.Request(args.url, method=method, headers={"User-Agent": "CyberKit/0.1"})
        try:
            with urllib.request.urlopen(request, timeout=args.timeout) as response:  # noqa: S310
                results.append({"method": method, "status": response.status})
        except urllib.error.HTTPError as exc:
            results.append({"method": method, "status": exc.code})
        except Exception as exc:  # pragma: no cover
            results.append({"method": method, "status": None, "error": str(exc)})

    write_payload(run, {"tool": meta["id"], "url": args.url, "results": results}, print_json=args.json)
    return complete(run, f"Checked {len(results)} method(s).")


def handle_web_tech_fingerprint(meta: dict[str, Any], argv: list[str]) -> int:
    parser = build_parser(meta, "Basic web tech fingerprint from headers and HTML markers.", ["web-tech-fingerprint https://example.com"])
    parser.add_argument("url")
    args = parser.parse_args(argv)
    if not is_valid_url(args.url):
        return fail(meta, "Invalid URL.")

    run = create_run(meta, argv)
    try:
        response = _read_url(args.url, timeout=args.timeout)
    except Exception as exc:  # pragma: no cover
        finish_run(run, status="error", summary="Request failed")
        return fail(meta, str(exc))

    body = response.body.lower()
    payload = {
        "tool": meta["id"],
        "url": args.url,
        "server": response.headers.get("server"),
        "x_powered_by": response.headers.get("x-powered-by"),
        "markers": {
            "wordpress": "wp-content" in body,
            "drupal": "drupal-settings-json" in body,
            "jquery": "jquery" in body,
            "bootstrap": "bootstrap" in body,
        },
    }
    write_payload(run, payload, print_json=args.json)
    return complete(run, "Fingerprint complete.")


def handle_redirect_chain_report(meta: dict[str, Any], argv: list[str]) -> int:
    parser = build_parser(meta, "Show redirect hops and final destination.", ["redirect-chain-report http://example.com"])
    parser.add_argument("url")
    parser.add_argument("--max-hops", type=int, default=10)
    args = parser.parse_args(argv)
    if not is_valid_url(args.url):
        return fail(meta, "Invalid URL.")

    run = create_run(meta, argv)
    current = args.url
    hops: list[dict[str, Any]] = []
    for _ in range(args.max_hops):
        request = urllib.request.Request(current, method="GET", headers={"User-Agent": "CyberKit/0.1"})
        opener = urllib.request.build_opener(urllib.request.HTTPHandler(), urllib.request.HTTPSHandler())
        try:
            with opener.open(request, timeout=args.timeout) as response:  # noqa: S310
                status = getattr(response, "status", None)
                location = response.headers.get("Location")
                hops.append({"url": current, "status": status, "location": location})
                if status not in {301, 302, 303, 307, 308} or not location:
                    break
                current = urllib.parse.urljoin(current, location)
        except urllib.error.HTTPError as exc:
            location = exc.headers.get("Location") if exc.headers else None
            hops.append({"url": current, "status": exc.code, "location": location})
            if exc.code in {301, 302, 303, 307, 308} and location:
                current = urllib.parse.urljoin(current, location)
                continue
            break
        except Exception as exc:  # pragma: no cover
            hops.append({"url": current, "status": None, "error": str(exc)})
            break

    write_payload(run, {"tool": meta["id"], "hops": hops, "final_url": current}, print_json=args.json)
    return complete(run, f"Captured {len(hops)} redirect hop(s).")


def handle_openapi_discovery(meta: dict[str, Any], argv: list[str]) -> int:
    parser = build_parser(meta, "Locate likely OpenAPI/Swagger endpoints.", ["openapi-discovery https://example.com"])
    parser.add_argument("base_url")
    parser.add_argument("--rate", type=float, default=2.0)
    args = parser.parse_args(argv)
    if not is_valid_url(args.base_url):
        return fail(meta, "Invalid base URL.")

    run = create_run(meta, argv)
    paths = [
        "/openapi.json",
        "/swagger.json",
        "/v1/openapi.json",
        "/api/openapi.json",
        "/swagger/v1/swagger.json",
        "/docs",
        "/api-docs",
    ]
    base = args.base_url.rstrip("/")
    results = []
    for path in paths:
        url = base + path
        try:
            response = _read_url(url, timeout=args.timeout)
            content_type = response.headers.get("content-type", "")
            likely = "json" in content_type.lower() or "openapi" in response.body.lower() or "swagger" in response.body.lower()
            results.append({"path": path, "status": response.status, "likely_openapi": likely})
        except urllib.error.HTTPError as exc:
            results.append({"path": path, "status": exc.code, "likely_openapi": False})
        except Exception as exc:  # pragma: no cover
            results.append({"path": path, "status": None, "error": str(exc), "likely_openapi": False})
        rate_sleep(args.rate)

    write_payload(run, {"tool": meta["id"], "base_url": args.base_url, "results": results}, print_json=args.json)
    return complete(run, "OpenAPI discovery complete.")


def handle_dns_records_snapshot(meta: dict[str, Any], argv: list[str]) -> int:
    parser = build_parser(meta, "Collect A/AAAA/CNAME/MX/TXT/NS records.", ["dns-records-snapshot example.com"])
    parser.add_argument("domain")
    args = parser.parse_args(argv)

    run = create_run(meta, argv)
    record_types = ["A", "AAAA", "CNAME", "MX", "TXT", "NS"]
    records = {kind: _query_dns(args.domain, kind, args.timeout) for kind in record_types}
    write_payload(run, {"tool": meta["id"], "domain": args.domain, "records": records}, print_json=args.json)
    return complete(run, "DNS snapshot complete.")


def _first_spf_record(domain: str, timeout: int) -> str | None:
    for record in _query_dns(domain, "TXT", timeout):
        normalized = record.strip('"')
        if normalized.lower().startswith("v=spf1"):
            return normalized
    return None


def handle_spf_check(meta: dict[str, Any], argv: list[str]) -> int:
    parser = build_parser(meta, "Parse SPF and flag risky mechanisms.", ["spf-check example.com"])
    parser.add_argument("domain")
    args = parser.parse_args(argv)

    run = create_run(meta, argv)
    record = _first_spf_record(args.domain, args.timeout)
    if record is None:
        write_payload(run, {"tool": meta["id"], "domain": args.domain, "spf_found": False}, print_json=args.json)
        return complete(run, "No SPF record found.")

    write_payload(
        run,
        {"tool": meta["id"], "domain": args.domain, "spf_found": True, "analysis": _parse_spf_record(record)},
        print_json=args.json,
    )
    return complete(run, "SPF analysis complete.")


def handle_dmarc_check(meta: dict[str, Any], argv: list[str]) -> int:
    parser = build_parser(meta, "Parse DMARC policy and reporting tags.", ["dmarc-check example.com"])
    parser.add_argument("domain")
    args = parser.parse_args(argv)

    run = create_run(meta, argv)
    records = _query_dns(f"_dmarc.{args.domain}", "TXT", args.timeout)
    dmarc = None
    for record in records:
        normalized = record.strip('"')
        if normalized.lower().startswith("v=dmarc1"):
            dmarc = normalized
            break

    payload: dict[str, Any] = {"tool": meta["id"], "domain": args.domain, "dmarc_found": dmarc is not None}
    if dmarc is not None:
        payload["record"] = dmarc
        payload["tags"] = _parse_tag_value_record(dmarc)
    write_payload(run, payload, print_json=args.json)
    return complete(run, "DMARC analysis complete.")


def handle_dkim_selector_check(meta: dict[str, Any], argv: list[str]) -> int:
    parser = build_parser(
        meta,
        "Check common DKIM selectors.",
        ["dkim-selector-check example.com", "dkim-selector-check example.com --selectors default,google,selector1"],
    )
    parser.add_argument("domain")
    parser.add_argument("--selectors", default="default,selector1,selector2,google,mail")
    args = parser.parse_args(argv)

    run = create_run(meta, argv)
    selectors = [item.strip() for item in args.selectors.split(",") if item.strip()]
    results = []
    for selector in selectors:
        fqdn = f"{selector}._domainkey.{args.domain}"
        records = _query_dns(fqdn, "TXT", args.timeout)
        results.append({"selector": selector, "fqdn": fqdn, "found": bool(records), "records": records})

    write_payload(run, {"tool": meta["id"], "domain": args.domain, "results": results}, print_json=args.json)
    return complete(run, f"Checked {len(results)} selector(s).")


def handle_dnssec_check(meta: dict[str, Any], argv: list[str]) -> int:
    parser = build_parser(meta, "Check DNSSEC indicators (DS/DNSKEY/RRSIG).", ["dnssec-check example.com"])
    parser.add_argument("domain")
    args = parser.parse_args(argv)
    if not is_installed("dig"):
        return fail(meta, "Missing dependency: dig")

    run = create_run(meta, argv)
    completed = exec_run(["dig", "+dnssec", args.domain], timeout=args.timeout)
    lines = completed.stdout.splitlines()
    payload = {
        "tool": meta["id"],
        "domain": args.domain,
        "has_rrsig": any("RRSIG" in line for line in lines),
        "has_dnskey": any("DNSKEY" in line for line in lines),
        "has_ds": any(" DS " in line or line.endswith(" DS") for line in lines),
    }
    write_payload(run, payload, print_json=args.json)
    return complete(run, "DNSSEC check complete.")


def handle_mx_health(meta: dict[str, Any], argv: list[str]) -> int:
    parser = build_parser(meta, "Check MX hosts for resolution and SMTP reachability.", ["mx-health example.com"])
    parser.add_argument("domain")
    args = parser.parse_args(argv)

    run = create_run(meta, argv)
    mx_records = _query_dns(args.domain, "MX", args.timeout)
    hosts = []
    for record in mx_records:
        parts = record.split()
        hosts.append(parts[-1].rstrip("."))

    results = []
    for host in hosts:
        row: dict[str, Any] = {
            "mx_host": host,
            "resolves": bool(_query_dns(host, "A", args.timeout) or _query_dns(host, "AAAA", args.timeout)),
            "connect_25": False,
            "starttls_hint": False,
        }
        try:
            with socket.create_connection((host, 25), timeout=args.timeout) as sock:
                sock.settimeout(args.timeout)
                banner = sock.recv(1024).decode("utf-8", errors="replace")
                row["connect_25"] = True
                row["banner"] = banner.strip()
                sock.sendall(b"EHLO cyberkit.local\r\n")
                response = sock.recv(2048).decode("utf-8", errors="replace")
                row["starttls_hint"] = "STARTTLS" in response.upper()
        except OSError as exc:
            row["error"] = str(exc)
        results.append(row)

    write_payload(run, {"tool": meta["id"], "domain": args.domain, "mx": results}, print_json=args.json)
    return complete(run, f"Checked {len(results)} MX host(s).")


def _generate_typos(domain: str, limit: int = 20) -> list[str]:
    if "." not in domain:
        return []
    label, suffix = domain.split(".", 1)
    variants = set()
    for idx in range(len(label)):
        variants.add(label[:idx] + label[idx + 1 :] + "." + suffix)
    for idx in range(len(label) - 1):
        chars = list(label)
        chars[idx], chars[idx + 1] = chars[idx + 1], chars[idx]
        variants.add("".join(chars) + "." + suffix)
    return sorted([item for item in variants if item and item != domain])[:limit]


def handle_domain_typo_monitor(meta: dict[str, Any], argv: list[str]) -> int:
    parser = build_parser(
        meta,
        "Generate minimal typo variants and resolution-check them.",
        ["domain-typo-monitor example.com --max-variants 20"],
    )
    parser.add_argument("domain")
    parser.add_argument("--max-variants", type=int, default=20)
    parser.add_argument("--rate", type=float, default=5.0)
    args = parser.parse_args(argv)

    run = create_run(meta, argv)
    variants = _generate_typos(args.domain, limit=args.max_variants)
    checks = []
    for variant in variants:
        a = _query_dns(variant, "A", args.timeout)
        aaaa = _query_dns(variant, "AAAA", args.timeout)
        checks.append({"domain": variant, "resolves": bool(a or aaaa), "a": a, "aaaa": aaaa})
        rate_sleep(args.rate)

    write_payload(run, {"tool": meta["id"], "domain": args.domain, "variants": checks}, print_json=args.json)
    return complete(run, f"Checked {len(checks)} typo variant(s).")


def handle_ssh_config_audit(meta: dict[str, Any], argv: list[str]) -> int:
    parser = build_parser(meta, "Audit sshd_config for insecure settings.", ["ssh-config-audit --path /etc/ssh/sshd_config"])
    parser.add_argument("--path", default="/etc/ssh/sshd_config")
    args = parser.parse_args(argv)

    config_path = Path(args.path)
    if not config_path.exists():
        return fail(meta, f"File not found: {config_path}")

    run = create_run(meta, argv)
    settings: dict[str, str] = {}
    for line in config_path.read_text(encoding="utf-8", errors="replace").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        parts = stripped.split(None, 1)
        if len(parts) == 2:
            settings[parts[0].lower()] = parts[1].strip()

    checks = {
        "permitrootlogin": ("yes", "Set PermitRootLogin no."),
        "passwordauthentication": ("yes", "Set PasswordAuthentication no when possible."),
        "x11forwarding": ("yes", "Set X11Forwarding no unless required."),
    }
    findings = []
    for key, (bad_value, recommendation) in checks.items():
        value = settings.get(key)
        if value is not None and value.lower() == bad_value:
            findings.append({"setting": key, "value": value, "recommendation": recommendation})

    write_payload(
        run,
        {"tool": meta["id"], "path": str(config_path), "settings": settings, "findings": findings},
        print_json=args.json,
    )
    return complete(run, f"Generated {len(findings)} finding(s).")


def handle_sudoers_audit(meta: dict[str, Any], argv: list[str]) -> int:
    parser = build_parser(meta, "Read-only sudoers audit for risky rules.", ["sudoers-audit"])
    parser.add_argument("--path", default="/etc/sudoers")
    args = parser.parse_args(argv)

    files = [Path(args.path)]
    sudoers_dir = Path("/etc/sudoers.d")
    if sudoers_dir.exists():
        files.extend(sorted(path for path in sudoers_dir.iterdir() if path.is_file()))

    run = create_run(meta, argv)
    risky = []
    for file_path in files:
        if not file_path.exists():
            continue
        for idx, line in enumerate(file_path.read_text(encoding="utf-8", errors="replace").splitlines(), start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            lowered = stripped.lower()
            if "nopasswd" in lowered or (" all=(all" in lowered and " all" in lowered):
                risky.append({"file": str(file_path), "line": idx, "rule": stripped})

    write_payload(
        run,
        {"tool": meta["id"], "files_scanned": [str(path) for path in files], "risky_rules": risky},
        print_json=args.json,
    )
    return complete(run, f"Found {len(risky)} potentially risky rule(s).")


def handle_world_writable_finder(meta: dict[str, Any], argv: list[str]) -> int:
    parser = build_parser(
        meta,
        "Find world-writable files/directories with exclusions.",
        ["world-writable-finder /var/www --exclude /var/www/cache"],
    )
    parser.add_argument("paths", nargs="+")
    parser.add_argument("--exclude", action="append", default=[])
    parser.add_argument("--max-results", type=int, default=2000)
    args = parser.parse_args(argv)

    run = create_run(meta, argv)
    exclude_prefixes = [os.path.abspath(item) for item in args.exclude]
    findings: list[dict[str, Any]] = []

    def is_excluded(path: str) -> bool:
        absolute = os.path.abspath(path)
        return any(absolute.startswith(prefix) for prefix in exclude_prefixes)

    for root in args.paths:
        for current_root, dirnames, filenames in os.walk(root):
            if is_excluded(current_root):
                dirnames[:] = []
                continue
            for name in [*dirnames, *filenames]:
                full_path = os.path.join(current_root, name)
                if is_excluded(full_path):
                    continue
                try:
                    mode = os.stat(full_path, follow_symlinks=False).st_mode
                except OSError:
                    continue
                if mode & 0o002:
                    findings.append({"path": full_path, "mode": oct(mode & 0o777)})
                    if len(findings) >= args.max_results:
                        break
            if len(findings) >= args.max_results:
                break
        if len(findings) >= args.max_results:
            break

    write_payload(run, {"tool": meta["id"], "count": len(findings), "findings": findings}, print_json=args.json)
    return complete(run, f"Found {len(findings)} world-writable path(s).")


def handle_stub(meta: dict[str, Any], argv: list[str]) -> int:
    parser = build_parser(meta, str(meta.get("summary", "Tool placeholder.")), [f"{meta['id']} --help"])
    parser.add_argument("extras", nargs="*")
    args = parser.parse_args(argv)

    run = create_run(meta, argv)
    write_payload(
        run,
        {
            "tool": meta["id"],
            "status": "stub",
            "message": "Scaffolded tool. Expand implementation as needed.",
            "args": args.extras,
        },
        print_json=args.json,
    )
    return complete(run, "Stub executed.")


HANDLERS = {
    "host_resolve": handle_host_resolve,
    "reverse_dns_sweep": handle_reverse_dns_sweep,
    "whois_summary": handle_whois_summary,
    "asn_lookup": handle_asn_lookup,
    "local_net_inventory": handle_local_net_inventory,
    "arp_table_audit": handle_arp_table_audit,
    "service_banner_grab": handle_service_banner_grab,
    "http_probe": handle_http_probe,
    "subdomain_cert_transparency": handle_subdomain_cert_transparency,
    "ssh_known_hosts_audit": handle_ssh_known_hosts_audit,
    "nmap_wrapper": handle_nmap_wrapper,
    "nmap_to_json": handle_nmap_to_json,
    "port_diff": handle_port_diff,
    "tcp_connect_scan": handle_tcp_connect_scan,
    "udp_lite_check": handle_udp_lite_check,
    "traceroute_report": handle_traceroute_report,
    "mtu_path_check": handle_mtu_path_check,
    "pcap_snapshot": handle_pcap_snapshot,
    "pcap_summary": handle_pcap_summary,
    "http_security_headers": handle_http_security_headers,
    "tls_cert_inspect": handle_tls_cert_inspect,
    "tls_config_wrapper": handle_tls_config_wrapper,
    "robots_sitemap_fetch": handle_robots_sitemap_fetch,
    "content_discovery_lite": handle_content_discovery_lite,
    "cookie_audit": handle_cookie_audit,
    "http_methods_check": handle_http_methods_check,
    "web_tech_fingerprint": handle_web_tech_fingerprint,
    "redirect_chain_report": handle_redirect_chain_report,
    "openapi_discovery": handle_openapi_discovery,
    "dns_records_snapshot": handle_dns_records_snapshot,
    "spf_check": handle_spf_check,
    "dmarc_check": handle_dmarc_check,
    "dkim_selector_check": handle_dkim_selector_check,
    "dnssec_check": handle_dnssec_check,
    "mx_health": handle_mx_health,
    "domain_typo_monitor": handle_domain_typo_monitor,
    "ssh_config_audit": handle_ssh_config_audit,
    "sudoers_audit": handle_sudoers_audit,
    "world_writable_finder": handle_world_writable_finder,
    "stub": handle_stub,
}


def execute(meta: dict[str, Any], argv: list[str] | None = None) -> int:
    args = argv if argv is not None else sys.argv[1:]
    handler = HANDLERS.get(str(meta.get("handler", "stub")), handle_stub)
    return handler(meta, list(args))


__all__ = [
    "execute",
    "_parse_nmap_xml_text",
    "_parse_spf_record",
    "_parse_tag_value_record",
]
