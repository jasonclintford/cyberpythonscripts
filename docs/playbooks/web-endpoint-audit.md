# Playbook: Web Endpoint Audit

Use only on systems you own or have explicit permission to test.

1. Resolve and probe:
   - `cyberkit run host-resolve -- app.example`
   - `cyberkit run http-probe -- https://app.example`
2. Security header and TLS checks:
   - `cyberkit run http-security-headers -- https://app.example`
   - `cyberkit run tls-cert-inspect -- app.example`
3. Surface mapping:
   - `cyberkit run robots-sitemap-fetch -- https://app.example`
   - `cyberkit run content-discovery-lite -- https://app.example`
   - `cyberkit run openapi-discovery -- https://app.example`
4. Cookie and method posture:
   - `cyberkit run cookie-audit -- https://app.example/login`
   - `cyberkit run http-methods-check -- https://app.example`
5. Consolidate:
   `cyberkit run report-md -- <path-to-results.json>`
