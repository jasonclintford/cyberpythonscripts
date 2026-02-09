from __future__ import annotations

from pathlib import Path


TOOL_SPECS: list[dict[str, object]] = [
    # information_gathering (full)
    {"file": "tools/information_gathering/host_resolve.py", "id": "host-resolve", "name": "Host Resolve", "category": "information_gathering", "summary": "Resolve A/AAAA records for hostnames.", "risk": "low", "requires": [], "handler": "host_resolve"},
    {"file": "tools/information_gathering/reverse_dns_sweep.py", "id": "reverse-dns-sweep", "name": "Reverse DNS Sweep", "category": "information_gathering", "summary": "Reverse lookup for IP list or CIDR with rate limiting.", "risk": "low", "requires": [], "handler": "reverse_dns_sweep"},
    {"file": "tools/information_gathering/whois_summary.py", "id": "whois-summary", "name": "WHOIS Summary", "category": "information_gathering", "summary": "WHOIS query with parsed registrar/date summary.", "risk": "low", "requires": ["whois"], "handler": "whois_summary"},
    {"file": "tools/information_gathering/asn_lookup.py", "id": "asn-lookup", "name": "ASN Lookup", "category": "information_gathering", "summary": "Map IP addresses to ASN from local WHOIS data.", "risk": "low", "requires": ["whois"], "handler": "asn_lookup"},
    {"file": "tools/information_gathering/local_net_inventory.py", "id": "local-net-inventory", "name": "Local Net Inventory", "category": "information_gathering", "summary": "Collect interfaces, routes, DNS, ARP, and listening sockets.", "risk": "low", "requires": ["ip", "ss"], "handler": "local_net_inventory"},
    {"file": "tools/information_gathering/arp_table_audit.py", "id": "arp-table-audit", "name": "ARP Table Audit", "category": "information_gathering", "summary": "Snapshot ARP table and flag duplicate mappings.", "risk": "low", "requires": ["ip"], "handler": "arp_table_audit"},
    {"file": "tools/information_gathering/service_banner_grab.py", "id": "service-banner-grab", "name": "Service Banner Grab", "category": "information_gathering", "summary": "Safe TCP connect banner grab for selected ports.", "risk": "medium", "requires": [], "handler": "service_banner_grab"},
    {"file": "tools/information_gathering/http_probe.py", "id": "http-probe", "name": "HTTP Probe", "category": "information_gathering", "summary": "Probe URLs and capture status, redirects, and title.", "risk": "medium", "requires": [], "handler": "http_probe"},
    {"file": "tools/information_gathering/subdomain_cert_transparency.py", "id": "subdomain-cert-transparency", "name": "Subdomain Cert Transparency", "category": "information_gathering", "summary": "Query certificate transparency logs for subdomain hints.", "risk": "medium", "requires": [], "handler": "subdomain_cert_transparency"},
    {"file": "tools/information_gathering/ssh_known_hosts_audit.py", "id": "ssh-known-hosts-audit", "name": "SSH Known Hosts Audit", "category": "information_gathering", "summary": "Parse known_hosts and flag weak/duplicate entries.", "risk": "low", "requires": [], "handler": "ssh_known_hosts_audit"},
    # network_scanning (full)
    {"file": "tools/network_scanning/nmap_quick.py", "id": "nmap-quick", "name": "Nmap Quick", "category": "network_scanning", "summary": "Fast top-ports nmap scan with safe defaults.", "risk": "medium", "requires": ["nmap"], "handler": "nmap_wrapper", "profile": "quick"},
    {"file": "tools/network_scanning/nmap_service_enum.py", "id": "nmap-service-enum", "name": "Nmap Service Enum", "category": "network_scanning", "summary": "Service/version enumeration with controlled timing.", "risk": "medium", "requires": ["nmap"], "handler": "nmap_wrapper", "profile": "service"},
    {"file": "tools/network_scanning/nmap_to_json.py", "id": "nmap-to-json", "name": "Nmap To JSON", "category": "network_scanning", "summary": "Convert nmap XML to JSON summary.", "risk": "low", "requires": [], "handler": "nmap_to_json"},
    {"file": "tools/network_scanning/port_diff.py", "id": "port-diff", "name": "Port Diff", "category": "network_scanning", "summary": "Diff two scan outputs and show changes.", "risk": "low", "requires": [], "handler": "port_diff"},
    {"file": "tools/network_scanning/tcp_connect_scan.py", "id": "tcp-connect-scan", "name": "TCP Connect Scan", "category": "network_scanning", "summary": "Pure Python TCP connect scan for small scopes.", "risk": "medium", "requires": [], "handler": "tcp_connect_scan"},
    {"file": "tools/network_scanning/udp_lite_check.py", "id": "udp-lite-check", "name": "UDP Lite Check", "category": "network_scanning", "summary": "Small UDP checks for DNS/NTP/SNMP presence.", "risk": "medium", "requires": [], "handler": "udp_lite_check"},
    {"file": "tools/network_scanning/traceroute_report.py", "id": "traceroute-report", "name": "Traceroute Report", "category": "network_scanning", "summary": "Run traceroute/mtr and summarise hops.", "risk": "medium", "requires": ["traceroute"], "handler": "traceroute_report"},
    {"file": "tools/network_scanning/mtu_path_check.py", "id": "mtu-path-check", "name": "MTU Path Check", "category": "network_scanning", "summary": "PMTU check with ping DF probes.", "risk": "medium", "requires": ["ping"], "handler": "mtu_path_check"},
    {"file": "tools/network_scanning/pcap_snapshot.py", "id": "pcap-snapshot", "name": "PCAP Snapshot", "category": "network_scanning", "summary": "Short tcpdump capture with safe defaults.", "risk": "medium", "requires": ["tcpdump"], "handler": "pcap_snapshot"},
    {"file": "tools/network_scanning/pcap_summary.py", "id": "pcap-summary", "name": "PCAP Summary", "category": "network_scanning", "summary": "Summarise pcap conversations and protocols via tshark.", "risk": "low", "requires": ["tshark"], "handler": "pcap_summary"},
    # web_audit (full)
    {"file": "tools/web_audit/http_security_headers.py", "id": "http-security-headers", "name": "HTTP Security Headers", "category": "web_audit", "summary": "Check major HTTP security headers.", "risk": "low", "requires": [], "handler": "http_security_headers"},
    {"file": "tools/web_audit/tls_cert_inspect.py", "id": "tls-cert-inspect", "name": "TLS Cert Inspect", "category": "web_audit", "summary": "Inspect certificate expiry/SAN/key details.", "risk": "low", "requires": [], "handler": "tls_cert_inspect"},
    {"file": "tools/web_audit/tls_config_wrapper.py", "id": "tls-config-wrapper", "name": "TLS Config Wrapper", "category": "web_audit", "summary": "Wrapper around sslscan/testssl with parsed findings.", "risk": "medium", "requires": ["sslscan"], "handler": "tls_config_wrapper"},
    {"file": "tools/web_audit/robots_sitemap_fetch.py", "id": "robots-sitemap-fetch", "name": "Robots Sitemap Fetch", "category": "web_audit", "summary": "Fetch robots.txt and sitemap URLs.", "risk": "low", "requires": [], "handler": "robots_sitemap_fetch"},
    {"file": "tools/web_audit/content_discovery_lite.py", "id": "content-discovery-lite", "name": "Content Discovery Lite", "category": "web_audit", "summary": "Safe, rate-limited path discovery.", "risk": "medium", "requires": [], "handler": "content_discovery_lite"},
    {"file": "tools/web_audit/cookie_audit.py", "id": "cookie-audit", "name": "Cookie Audit", "category": "web_audit", "summary": "Check Secure/HttpOnly/SameSite cookie flags.", "risk": "low", "requires": [], "handler": "cookie_audit"},
    {"file": "tools/web_audit/http_methods_check.py", "id": "http-methods-check", "name": "HTTP Methods Check", "category": "web_audit", "summary": "Probe OPTIONS and common methods safely.", "risk": "medium", "requires": [], "handler": "http_methods_check"},
    {"file": "tools/web_audit/web_tech_fingerprint.py", "id": "web-tech-fingerprint", "name": "Web Tech Fingerprint", "category": "web_audit", "summary": "Basic fingerprint from headers and HTML markers.", "risk": "low", "requires": [], "handler": "web_tech_fingerprint"},
    {"file": "tools/web_audit/redirect_chain_report.py", "id": "redirect-chain-report", "name": "Redirect Chain Report", "category": "web_audit", "summary": "Show redirect hops and final destination.", "risk": "low", "requires": [], "handler": "redirect_chain_report"},
    {"file": "tools/web_audit/openapi_discovery.py", "id": "openapi-discovery", "name": "OpenAPI Discovery", "category": "web_audit", "summary": "Discover likely OpenAPI/Swagger endpoints.", "risk": "low", "requires": [], "handler": "openapi_discovery"},
    # dns_email (full)
    {"file": "tools/dns_email/dns_records_snapshot.py", "id": "dns-records-snapshot", "name": "DNS Records Snapshot", "category": "dns_email", "summary": "Collect A/AAAA/CNAME/MX/TXT/NS records.", "risk": "low", "requires": ["dig"], "handler": "dns_records_snapshot"},
    {"file": "tools/dns_email/spf_check.py", "id": "spf-check", "name": "SPF Check", "category": "dns_email", "summary": "Parse SPF and flag risky mechanisms.", "risk": "low", "requires": ["dig"], "handler": "spf_check"},
    {"file": "tools/dns_email/dmarc_check.py", "id": "dmarc-check", "name": "DMARC Check", "category": "dns_email", "summary": "Parse DMARC policy and report tags.", "risk": "low", "requires": ["dig"], "handler": "dmarc_check"},
    {"file": "tools/dns_email/dkim_selector_check.py", "id": "dkim-selector-check", "name": "DKIM Selector Check", "category": "dns_email", "summary": "Check common DKIM selectors for TXT records.", "risk": "low", "requires": ["dig"], "handler": "dkim_selector_check"},
    {"file": "tools/dns_email/dnssec_check.py", "id": "dnssec-check", "name": "DNSSEC Check", "category": "dns_email", "summary": "Validate DNSSEC indicators via dig +dnssec.", "risk": "low", "requires": ["dig"], "handler": "dnssec_check"},
    {"file": "tools/dns_email/mx_health.py", "id": "mx-health", "name": "MX Health", "category": "dns_email", "summary": "Check MX resolution, port 25 reachability, and STARTTLS hint.", "risk": "medium", "requires": ["dig"], "handler": "mx_health"},
    {"file": "tools/dns_email/domain_typo_monitor.py", "id": "domain-typo-monitor", "name": "Domain Typo Monitor", "category": "dns_email", "summary": "Generate minimal typo variants and check resolution.", "risk": "low", "requires": ["dig"], "handler": "domain_typo_monitor"},
    # host_hardening first 3 (full)
    {"file": "tools/host_hardening/ssh_config_audit.py", "id": "ssh-config-audit", "name": "SSH Config Audit", "category": "host_hardening", "summary": "Audit sshd_config for insecure options.", "risk": "low", "requires": [], "handler": "ssh_config_audit"},
    {"file": "tools/host_hardening/sudoers_audit.py", "id": "sudoers-audit", "name": "Sudoers Audit", "category": "host_hardening", "summary": "Identify risky sudoers NOPASSWD/ALL rules.", "risk": "low", "requires": [], "handler": "sudoers_audit"},
    {"file": "tools/host_hardening/world_writable_finder.py", "id": "world-writable-finder", "name": "World Writable Finder", "category": "host_hardening", "summary": "Find world-writable files in selected paths.", "risk": "low", "requires": [], "handler": "world_writable_finder"},
]

STUB_SPECS: list[dict[str, object]] = [
    # host_hardening remaining
    {"file": "tools/host_hardening/suid_sgid_finder.py", "id": "suid-sgid-finder", "name": "SUID SGID Finder", "category": "host_hardening", "summary": "List SUID/SGID binaries and compare with baseline.", "risk": "low", "requires": []},
    {"file": "tools/host_hardening/listening_services_audit.py", "id": "listening-services-audit", "name": "Listening Services Audit", "category": "host_hardening", "summary": "Summarise listening ports and owning processes.", "risk": "low", "requires": ["ss"]},
    {"file": "tools/host_hardening/firewall_status_audit.py", "id": "firewall-status-audit", "name": "Firewall Status Audit", "category": "host_hardening", "summary": "Detect firewall backend status and rule counts.", "risk": "low", "requires": []},
    {"file": "tools/host_hardening/user_account_audit.py", "id": "user-account-audit", "name": "User Account Audit", "category": "host_hardening", "summary": "Audit local users, shell access, and account state.", "risk": "low", "requires": []},
    {"file": "tools/host_hardening/cron_audit.py", "id": "cron-audit", "name": "Cron Audit", "category": "host_hardening", "summary": "Enumerate cron jobs and writable-path risks.", "risk": "low", "requires": []},
    {"file": "tools/host_hardening/kernel_params_audit.py", "id": "kernel-params-audit", "name": "Kernel Params Audit", "category": "host_hardening", "summary": "Flag risky sysctl settings from baseline checks.", "risk": "low", "requires": []},
    {"file": "tools/host_hardening/file_integrity_baseline.py", "id": "file-integrity-baseline", "name": "File Integrity Baseline", "category": "host_hardening", "summary": "Create and verify deterministic hash baseline.", "risk": "low", "requires": []},
    # logs_monitoring
    {"file": "tools/logs_monitoring/auth_log_failed_logins.py", "id": "auth-log-failed-logins", "name": "Auth Log Failed Logins", "category": "logs_monitoring", "summary": "Summarise failed SSH logins by IP/user.", "risk": "low", "requires": []},
    {"file": "tools/logs_monitoring/auth_log_success_logins.py", "id": "auth-log-success-logins", "name": "Auth Log Success Logins", "category": "logs_monitoring", "summary": "Summarise successful logins and anomalies.", "risk": "low", "requires": []},
    {"file": "tools/logs_monitoring/sudo_usage_report.py", "id": "sudo-usage-report", "name": "Sudo Usage Report", "category": "logs_monitoring", "summary": "Extract and summarise sudo usage events.", "risk": "low", "requires": []},
    {"file": "tools/logs_monitoring/apache_access_summary.py", "id": "apache-access-summary", "name": "Apache Access Summary", "category": "logs_monitoring", "summary": "Top endpoints/status/UA from Apache logs.", "risk": "low", "requires": []},
    {"file": "tools/logs_monitoring/nginx_access_summary.py", "id": "nginx-access-summary", "name": "Nginx Access Summary", "category": "logs_monitoring", "summary": "Top endpoints/status/UA from Nginx logs.", "risk": "low", "requires": []},
    {"file": "tools/logs_monitoring/journalctl_export.py", "id": "journalctl-export", "name": "Journalctl Export", "category": "logs_monitoring", "summary": "Export bounded systemd logs for reporting.", "risk": "low", "requires": ["journalctl"]},
    {"file": "tools/logs_monitoring/ioc_grep.py", "id": "ioc-grep", "name": "IOC Grep", "category": "logs_monitoring", "summary": "Search logs for IOC indicators from list.", "risk": "low", "requires": []},
    {"file": "tools/logs_monitoring/systemd_failed_units.py", "id": "systemd-failed-units", "name": "Systemd Failed Units", "category": "logs_monitoring", "summary": "Report failed services and last errors.", "risk": "low", "requires": ["systemctl"]},
    {"file": "tools/logs_monitoring/resource_spikes.py", "id": "resource-spikes", "name": "Resource Spikes", "category": "logs_monitoring", "summary": "Summarise CPU/memory spikes from telemetry.", "risk": "low", "requires": []},
    # forensics
    {"file": "tools/forensics/hash_file.py", "id": "hash-file", "name": "Hash File", "category": "forensics", "summary": "Compute file hashes with metadata.", "risk": "low", "requires": []},
    {"file": "tools/forensics/hash_tree.py", "id": "hash-tree", "name": "Hash Tree", "category": "forensics", "summary": "Deterministic directory hash manifest.", "risk": "low", "requires": []},
    {"file": "tools/forensics/exif_extract.py", "id": "exif-extract", "name": "Exif Extract", "category": "forensics", "summary": "Extract metadata via exiftool fallback logic.", "risk": "low", "requires": ["exiftool"]},
    {"file": "tools/forensics/pdf_metadata.py", "id": "pdf-metadata", "name": "PDF Metadata", "category": "forensics", "summary": "Extract PDF metadata and structure hints.", "risk": "low", "requires": []},
    {"file": "tools/forensics/office_triage.py", "id": "office-triage", "name": "Office Triage", "category": "forensics", "summary": "Safe office file triage with optional oletools.", "risk": "low", "requires": []},
    {"file": "tools/forensics/disk_image_verify.py", "id": "disk-image-verify", "name": "Disk Image Verify", "category": "forensics", "summary": "Verify image hashes and chain-of-custody metadata.", "risk": "low", "requires": []},
    {"file": "tools/forensics/strings_plus.py", "id": "strings-plus", "name": "Strings Plus", "category": "forensics", "summary": "Extract strings with context and entropy hints.", "risk": "low", "requires": ["strings"]},
    {"file": "tools/forensics/timeline_lite.py", "id": "timeline-lite", "name": "Timeline Lite", "category": "forensics", "summary": "Generate filesystem timeline by mtime/ctime/atime.", "risk": "low", "requires": []},
    {"file": "tools/forensics/pcap_ioc_extract.py", "id": "pcap-ioc-extract", "name": "PCAP IOC Extract", "category": "forensics", "summary": "Extract DNS/SNI/HTTP hosts from PCAP.", "risk": "low", "requires": ["tshark"]},
    # malware_triage
    {"file": "tools/malware_triage/yara_scan.py", "id": "yara-scan", "name": "YARA Scan", "category": "malware_triage", "summary": "Run YARA rules against file trees and summarise hits.", "risk": "low", "requires": ["yara"]},
    {"file": "tools/malware_triage/pe_header_report.py", "id": "pe-header-report", "name": "PE Header Report", "category": "malware_triage", "summary": "Parse PE header fields when parser available.", "risk": "low", "requires": []},
    {"file": "tools/malware_triage/elf_header_report.py", "id": "elf-header-report", "name": "ELF Header Report", "category": "malware_triage", "summary": "Summarise ELF sections/imports via readelf.", "risk": "low", "requires": ["readelf"]},
    {"file": "tools/malware_triage/file_entropy.py", "id": "file-entropy", "name": "File Entropy", "category": "malware_triage", "summary": "Compute Shannon entropy for suspicious blobs.", "risk": "low", "requires": []},
    {"file": "tools/malware_triage/suspicious_imports.py", "id": "suspicious-imports", "name": "Suspicious Imports", "category": "malware_triage", "summary": "Highlight suspicious PE/ELF imports.", "risk": "low", "requires": []},
    {"file": "tools/malware_triage/sandbox_package.py", "id": "sandbox-package", "name": "Sandbox Package", "category": "malware_triage", "summary": "Create safe malware submission bundles without upload.", "risk": "low", "requires": []},
    # crypto_pki
    {"file": "tools/crypto_pki/cert_expiry_scan.py", "id": "cert-expiry-scan", "name": "Cert Expiry Scan", "category": "crypto_pki", "summary": "Check certificate expiry windows across hosts.", "risk": "low", "requires": []},
    {"file": "tools/crypto_pki/ssh_key_audit.py", "id": "ssh-key-audit", "name": "SSH Key Audit", "category": "crypto_pki", "summary": "Audit SSH key type, size, and permissions.", "risk": "low", "requires": []},
    {"file": "tools/crypto_pki/jwt_inspect.py", "id": "jwt-inspect", "name": "JWT Inspect", "category": "crypto_pki", "summary": "Decode JWT header/payload and flag weak patterns.", "risk": "low", "requires": []},
    {"file": "tools/crypto_pki/tls_cipher_hints.py", "id": "tls-cipher-hints", "name": "TLS Cipher Hints", "category": "crypto_pki", "summary": "Parse scanner output for deprecated protocols/ciphers.", "risk": "low", "requires": []},
    {"file": "tools/crypto_pki/pgp_key_inventory.py", "id": "pgp-key-inventory", "name": "PGP Key Inventory", "category": "crypto_pki", "summary": "List GPG keys, expiry, trust, and fingerprints.", "risk": "low", "requires": ["gpg"]},
    {"file": "tools/crypto_pki/hash_identify.py", "id": "hash-identify", "name": "Hash Identify", "category": "crypto_pki", "summary": "Heuristic identify hash algorithm candidates.", "risk": "low", "requires": []},
    # containers_cloud
    {"file": "tools/containers_cloud/docker_socket_risk.py", "id": "docker-socket-risk", "name": "Docker Socket Risk", "category": "containers_cloud", "summary": "Detect docker socket exposure and group risk.", "risk": "low", "requires": []},
    {"file": "tools/containers_cloud/docker_image_inventory.py", "id": "docker-image-inventory", "name": "Docker Image Inventory", "category": "containers_cloud", "summary": "List images, tags, dates, and sizes.", "risk": "low", "requires": ["docker"]},
    {"file": "tools/containers_cloud/container_runtime_check.py", "id": "container-runtime-check", "name": "Container Runtime Check", "category": "containers_cloud", "summary": "Detect container runtime status and config.", "risk": "low", "requires": []},
    {"file": "tools/containers_cloud/trivy_wrapper.py", "id": "trivy-wrapper", "name": "Trivy Wrapper", "category": "containers_cloud", "summary": "Run trivy scan and parse top findings.", "risk": "low", "requires": ["trivy"]},
    {"file": "tools/containers_cloud/kubeconfig_audit.py", "id": "kubeconfig-audit", "name": "Kubeconfig Audit", "category": "containers_cloud", "summary": "Audit kubeconfig contexts and permissions.", "risk": "low", "requires": []},
    {"file": "tools/containers_cloud/sbom_generate.py", "id": "sbom-generate", "name": "SBOM Generate", "category": "containers_cloud", "summary": "Generate SBOM using syft when available.", "risk": "low", "requires": ["syft"]},
    # reporting
    {"file": "tools/reporting/report_init.py", "id": "report-init", "name": "Report Init", "category": "reporting", "summary": "Create case folder with metadata and notes template.", "risk": "low", "requires": []},
    {"file": "tools/reporting/report_md.py", "id": "report-md", "name": "Report Markdown", "category": "reporting", "summary": "Convert JSON results to markdown report.", "risk": "low", "requires": []},
    {"file": "tools/reporting/report_html.py", "id": "report-html", "name": "Report HTML", "category": "reporting", "summary": "Generate simple HTML report from run artifacts.", "risk": "low", "requires": []},
    {"file": "tools/reporting/baseline_compare.py", "id": "baseline-compare", "name": "Baseline Compare", "category": "reporting", "summary": "Compare two baselines and summarise drift.", "risk": "low", "requires": []},
    {"file": "tools/reporting/evidence_packager.py", "id": "evidence-packager", "name": "Evidence Packager", "category": "reporting", "summary": "Zip case folder with manifest and checksums.", "risk": "low", "requires": []},
    # misc
    {"file": "tools/misc/tool_versions.py", "id": "tool-versions", "name": "Tool Versions", "category": "misc", "summary": "Print versions of common external utilities.", "risk": "low", "requires": []},
    {"file": "tools/misc/public_ip.py", "id": "public-ip", "name": "Public IP", "category": "misc", "summary": "Fetch public IP from a simple endpoint.", "risk": "low", "requires": []},
    {"file": "tools/misc/time_sync_check.py", "id": "time-sync-check", "name": "Time Sync Check", "category": "misc", "summary": "Check NTP/chrony sync status and drift.", "risk": "low", "requires": []},
    {"file": "tools/misc/dns_resolver_health.py", "id": "dns-resolver-health", "name": "DNS Resolver Health", "category": "misc", "summary": "Test resolver latency and correctness.", "risk": "low", "requires": []},
    {"file": "tools/misc/safe_download_hash.py", "id": "safe-download-hash", "name": "Safe Download Hash", "category": "misc", "summary": "Allowlisted download-and-hash workflow.", "risk": "low", "requires": []},
]


def render_module(spec: dict[str, object]) -> str:
    module = [
        "from __future__ import annotations",
        "",
        "from cyberkit.tool_impl import execute",
        "",
        "TOOL_META = {",
        f"    'id': '{spec['id']}',",
        f"    'name': '{spec['name']}',",
        f"    'category': '{spec['category']}',",
        f"    'summary': '{spec['summary']}',",
        f"    'risk': '{spec['risk']}',",
        f"    'requires': {spec['requires']},",
        "    'supports_json': True,",
        f"    'default_output': '{spec['id']}/result.json',",
        f"    'handler': '{spec.get('handler', 'stub')}',",
        "}",
        "",
    ]
    if "profile" in spec:
        module.extend(
            [
                "TOOL_META['profile'] = " + repr(spec["profile"]),
                "",
            ]
        )
    module.extend(
        [
            "",
            "def main(argv: list[str] | None = None) -> int:",
            "    return execute(TOOL_META, argv)",
            "",
            "",
            "if __name__ == '__main__':",
            "    raise SystemExit(main())",
            "",
        ]
    )
    return "\n".join(module)


def main() -> None:
    for spec in [*TOOL_SPECS, *STUB_SPECS]:
        path = Path(str(spec["file"]))
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(render_module(spec), encoding="utf-8")


if __name__ == "__main__":
    main()
