# Playbook: Incident Triage Lite

Use only on systems you own or have explicit permission to test.

1. Preserve volatile context:
   - `cyberkit run local-net-inventory`
   - `cyberkit run pcap-snapshot -- --interface any --packets 300`
2. Log-focused review:
   - `cyberkit run auth-log-failed-logins`
   - `cyberkit run auth-log-success-logins`
   - `cyberkit run sudo-usage-report`
3. File/system triage:
   - `cyberkit run hash-tree -- /important/path`
   - `cyberkit run world-writable-finder -- /`
4. Create package:
   `cyberkit run evidence-packager -- <case-folder>`
