# CyberKit Tool Catalogue

Total tools: **93**

## containers_cloud

| id | name | risk | requires | summary |
|---|---|---|---|---|
| `container-runtime-check` | Container Runtime Check | low | - | Detect container runtime status and config. |
| `docker-image-inventory` | Docker Image Inventory | low | docker | List images, tags, dates, and sizes. |
| `docker-socket-risk` | Docker Socket Risk | low | - | Detect docker socket exposure and group risk. |
| `kubeconfig-audit` | Kubeconfig Audit | low | - | Audit kubeconfig contexts and permissions. |
| `sbom-generate` | SBOM Generate | low | syft | Generate SBOM using syft when available. |
| `trivy-wrapper` | Trivy Wrapper | low | trivy | Run trivy scan and parse top findings. |

## crypto_pki

| id | name | risk | requires | summary |
|---|---|---|---|---|
| `cert-expiry-scan` | Cert Expiry Scan | low | - | Check certificate expiry windows across hosts. |
| `hash-identify` | Hash Identify | low | - | Heuristic identify hash algorithm candidates. |
| `jwt-inspect` | JWT Inspect | low | - | Decode JWT header/payload and flag weak patterns. |
| `pgp-key-inventory` | PGP Key Inventory | low | gpg | List GPG keys, expiry, trust, and fingerprints. |
| `ssh-key-audit` | SSH Key Audit | low | - | Audit SSH key type, size, and permissions. |
| `tls-cipher-hints` | TLS Cipher Hints | low | - | Parse scanner output for deprecated protocols/ciphers. |

## dns_email

| id | name | risk | requires | summary |
|---|---|---|---|---|
| `dkim-selector-check` | DKIM Selector Check | low | dig | Check common DKIM selectors for TXT records. |
| `dmarc-check` | DMARC Check | low | dig | Parse DMARC policy and report tags. |
| `dns-records-snapshot` | DNS Records Snapshot | low | dig | Collect A/AAAA/CNAME/MX/TXT/NS records. |
| `dnssec-check` | DNSSEC Check | low | dig | Validate DNSSEC indicators via dig +dnssec. |
| `domain-typo-monitor` | Domain Typo Monitor | low | dig | Generate minimal typo variants and check resolution. |
| `mx-health` | MX Health | medium | dig | Check MX resolution, port 25 reachability, and STARTTLS hint. |
| `spf-check` | SPF Check | low | dig | Parse SPF and flag risky mechanisms. |

## forensics

| id | name | risk | requires | summary |
|---|---|---|---|---|
| `disk-image-verify` | Disk Image Verify | low | - | Verify image hashes and chain-of-custody metadata. |
| `exif-extract` | Exif Extract | low | exiftool | Extract metadata via exiftool fallback logic. |
| `hash-file` | Hash File | low | - | Compute file hashes with metadata. |
| `hash-tree` | Hash Tree | low | - | Deterministic directory hash manifest. |
| `office-triage` | Office Triage | low | - | Safe office file triage with optional oletools. |
| `pcap-ioc-extract` | PCAP IOC Extract | low | tshark | Extract DNS/SNI/HTTP hosts from PCAP. |
| `pdf-metadata` | PDF Metadata | low | - | Extract PDF metadata and structure hints. |
| `strings-plus` | Strings Plus | low | strings | Extract strings with context and entropy hints. |
| `timeline-lite` | Timeline Lite | low | - | Generate filesystem timeline by mtime/ctime/atime. |

## host_hardening

| id | name | risk | requires | summary |
|---|---|---|---|---|
| `cron-audit` | Cron Audit | low | - | Enumerate cron jobs and writable-path risks. |
| `file-integrity-baseline` | File Integrity Baseline | low | - | Create and verify deterministic hash baseline. |
| `firewall-status-audit` | Firewall Status Audit | low | - | Detect firewall backend status and rule counts. |
| `kernel-params-audit` | Kernel Params Audit | low | - | Flag risky sysctl settings from baseline checks. |
| `listening-services-audit` | Listening Services Audit | low | ss | Summarise listening ports and owning processes. |
| `ssh-config-audit` | SSH Config Audit | low | - | Audit sshd_config for insecure options. |
| `sudoers-audit` | Sudoers Audit | low | - | Identify risky sudoers NOPASSWD/ALL rules. |
| `suid-sgid-finder` | SUID SGID Finder | low | - | List SUID/SGID binaries and compare with baseline. |
| `user-account-audit` | User Account Audit | low | - | Audit local users, shell access, and account state. |
| `world-writable-finder` | World Writable Finder | low | - | Find world-writable files in selected paths. |

## information_gathering

| id | name | risk | requires | summary |
|---|---|---|---|---|
| `arp-table-audit` | ARP Table Audit | low | ip | Snapshot ARP table and flag duplicate mappings. |
| `asn-lookup` | ASN Lookup | low | whois | Map IP addresses to ASN from local WHOIS data. |
| `host-resolve` | Host Resolve | low | - | Resolve A/AAAA records for hostnames. |
| `http-probe` | HTTP Probe | medium | - | Probe URLs and capture status, redirects, and title. |
| `local-net-inventory` | Local Net Inventory | low | ip, ss | Collect interfaces, routes, DNS, ARP, and listening sockets. |
| `reverse-dns-sweep` | Reverse DNS Sweep | low | - | Reverse lookup for IP list or CIDR with rate limiting. |
| `service-banner-grab` | Service Banner Grab | medium | - | Safe TCP connect banner grab for selected ports. |
| `ssh-known-hosts-audit` | SSH Known Hosts Audit | low | - | Parse known_hosts and flag weak/duplicate entries. |
| `subdomain-cert-transparency` | Subdomain Cert Transparency | medium | - | Query certificate transparency logs for subdomain hints. |
| `whois-summary` | WHOIS Summary | low | whois | WHOIS query with parsed registrar/date summary. |

## logs_monitoring

| id | name | risk | requires | summary |
|---|---|---|---|---|
| `apache-access-summary` | Apache Access Summary | low | - | Top endpoints/status/UA from Apache logs. |
| `auth-log-failed-logins` | Auth Log Failed Logins | low | - | Summarise failed SSH logins by IP/user. |
| `auth-log-success-logins` | Auth Log Success Logins | low | - | Summarise successful logins and anomalies. |
| `ioc-grep` | IOC Grep | low | - | Search logs for IOC indicators from list. |
| `journalctl-export` | Journalctl Export | low | journalctl | Export bounded systemd logs for reporting. |
| `nginx-access-summary` | Nginx Access Summary | low | - | Top endpoints/status/UA from Nginx logs. |
| `resource-spikes` | Resource Spikes | low | - | Summarise CPU/memory spikes from telemetry. |
| `sudo-usage-report` | Sudo Usage Report | low | - | Extract and summarise sudo usage events. |
| `systemd-failed-units` | Systemd Failed Units | low | systemctl | Report failed services and last errors. |

## malware_triage

| id | name | risk | requires | summary |
|---|---|---|---|---|
| `elf-header-report` | ELF Header Report | low | readelf | Summarise ELF sections/imports via readelf. |
| `file-entropy` | File Entropy | low | - | Compute Shannon entropy for suspicious blobs. |
| `pe-header-report` | PE Header Report | low | - | Parse PE header fields when parser available. |
| `sandbox-package` | Sandbox Package | low | - | Create safe malware submission bundles without upload. |
| `suspicious-imports` | Suspicious Imports | low | - | Highlight suspicious PE/ELF imports. |
| `yara-scan` | YARA Scan | low | yara | Run YARA rules against file trees and summarise hits. |

## misc

| id | name | risk | requires | summary |
|---|---|---|---|---|
| `dns-resolver-health` | DNS Resolver Health | low | - | Test resolver latency and correctness. |
| `public-ip` | Public IP | low | - | Fetch public IP from a simple endpoint. |
| `safe-download-hash` | Safe Download Hash | low | - | Allowlisted download-and-hash workflow. |
| `time-sync-check` | Time Sync Check | low | - | Check NTP/chrony sync status and drift. |
| `tool-versions` | Tool Versions | low | - | Print versions of common external utilities. |

## network_scanning

| id | name | risk | requires | summary |
|---|---|---|---|---|
| `mtu-path-check` | MTU Path Check | medium | ping | PMTU check with ping DF probes. |
| `nmap-quick` | Nmap Quick | medium | nmap | Fast top-ports nmap scan with safe defaults. |
| `nmap-service-enum` | Nmap Service Enum | medium | nmap | Service/version enumeration with controlled timing. |
| `nmap-to-json` | Nmap To JSON | low | - | Convert nmap XML to JSON summary. |
| `pcap-snapshot` | PCAP Snapshot | medium | tcpdump | Short tcpdump capture with safe defaults. |
| `pcap-summary` | PCAP Summary | low | tshark | Summarise pcap conversations and protocols via tshark. |
| `port-diff` | Port Diff | low | - | Diff two scan outputs and show changes. |
| `tcp-connect-scan` | TCP Connect Scan | medium | - | Pure Python TCP connect scan for small scopes. |
| `traceroute-report` | Traceroute Report | medium | traceroute | Run traceroute/mtr and summarise hops. |
| `udp-lite-check` | UDP Lite Check | medium | - | Small UDP checks for DNS/NTP/SNMP presence. |

## reporting

| id | name | risk | requires | summary |
|---|---|---|---|---|
| `baseline-compare` | Baseline Compare | low | - | Compare two baselines and summarise drift. |
| `evidence-packager` | Evidence Packager | low | - | Zip case folder with manifest and checksums. |
| `report-html` | Report HTML | low | - | Generate simple HTML report from run artifacts. |
| `report-init` | Report Init | low | - | Create case folder with metadata and notes template. |
| `report-md` | Report Markdown | low | - | Convert JSON results to markdown report. |

## web_audit

| id | name | risk | requires | summary |
|---|---|---|---|---|
| `content-discovery-lite` | Content Discovery Lite | medium | - | Safe, rate-limited path discovery. |
| `cookie-audit` | Cookie Audit | low | - | Check Secure/HttpOnly/SameSite cookie flags. |
| `http-methods-check` | HTTP Methods Check | medium | - | Probe OPTIONS and common methods safely. |
| `http-security-headers` | HTTP Security Headers | low | - | Check major HTTP security headers. |
| `openapi-discovery` | OpenAPI Discovery | low | - | Discover likely OpenAPI/Swagger endpoints. |
| `redirect-chain-report` | Redirect Chain Report | low | - | Show redirect hops and final destination. |
| `robots-sitemap-fetch` | Robots Sitemap Fetch | low | - | Fetch robots.txt and sitemap URLs. |
| `tls-cert-inspect` | TLS Cert Inspect | low | - | Inspect certificate expiry/SAN/key details. |
| `tls-config-wrapper` | TLS Config Wrapper | medium | sslscan | Wrapper around sslscan/testssl with parsed findings. |
| `web-tech-fingerprint` | Web Tech Fingerprint | low | - | Basic fingerprint from headers and HTML markers. |
