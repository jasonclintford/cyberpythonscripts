# CyberKit

CyberKit is a Python utility suite for defensive security and authorised security assessment workflows.

## Safety
Use only on systems you own or have explicit permission to test.

## Install

### pipx
```bash
pipx install .
```

### pip (editable)
```bash
python -m pip install -e .
```

## Quick Start
```bash
cyberkit doctor
cyberkit list
cyberkit search dns
cyberkit info nmap-quick
cyberkit run host-resolve -- example.com
cyberkit browse
```

## Report Layout
Each run writes to:
`reports/<tool-id>/<timestamp>/`

Common files:
- `run.json`
- `stdout.log` / `stderr.log` for external commands
- `result.json` (tool output payload)

## Tool Coverage
- 93 tools discovered through registry metadata.
- First 40 tools are fully implemented per project spec.
- Remaining tools are scaffolded with metadata/help and executable stubs.

See:
- `docs/usage.md`
- `docs/tool-catalogue.md`
- `docs/playbooks/`
