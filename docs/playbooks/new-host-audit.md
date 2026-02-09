# Playbook: New Host Audit

Use only on systems you own or have explicit permission to test.

1. Validate environment:
   `cyberkit doctor`
2. Inventory local and network context:
   - `cyberkit run local-net-inventory`
   - `cyberkit run host-resolve -- target.example`
3. Baseline network exposure:
   - `cyberkit run nmap-quick -- target.example`
   - `cyberkit run nmap-service-enum -- target.example`
4. Compare future scans:
   - `cyberkit run nmap-to-json -- reports/nmap-quick/<run>/nmap.xml`
   - `cyberkit run port-diff -- baseline.json current.json`
5. Review report:
   `cyberkit report open <run-id>`
