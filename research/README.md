# research/

Earlier experiments kept for reference. **None of this is used by the firewall** or
installed by `install.sh`; scripts here expect to be run from this folder.

| Path | What |
|---|---|
| `dns_scorer/` | the first standalone DNS scorer (a systemd timer over AdGuard's log), replaced by `agents/ghost_dns` |
| `src/ai_firewall/`, `scripts/`, `config/` | an offline log-analysis CLI and Windows endpoint heuristics (PowerShell) |
| `scanner/`, `third_party/thrember/`, `models/`, `run_pe_*.sh` | a PE-file malware classifier (LightGBM on EMBER-style features) |

`third_party/thrember` is Apache 2.0; see its own `LICENSE`.
