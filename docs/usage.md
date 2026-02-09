# Usage

Use only on systems you own or have explicit permission to test.

## CLI Commands

### Doctor
```bash
cyberkit doctor
```
Checks Python/runtime environment, dependency availability, and a capability matrix.

### Browse
```bash
cyberkit browse
```
Interactive category + tool selection and argument prompt.

### List/Search/Info
```bash
cyberkit list
cyberkit list --category web_audit --risk low
cyberkit search cert
cyberkit info tls-cert-inspect
```

### Run
```bash
cyberkit run host-resolve -- example.com
cyberkit run nmap-quick -- 192.168.1.0/24
cyberkit run http-security-headers -- https://example.com
```

Request JSON output from tools that support it:
```bash
cyberkit run host-resolve --json -- example.com
```

### Reports
```bash
cyberkit report open host-resolve-20260209T120000Z
```

### Tool Catalogue
```bash
cyberkit update-catalogue
```
Regenerates `docs/tool-catalogue.md` from discovered metadata.

## Standalone Tool Invocation
Each tool is directly executable:
```bash
python tools/network_scanning/nmap_quick.py --help
python tools/dns_email/spf_check.py example.com
```
