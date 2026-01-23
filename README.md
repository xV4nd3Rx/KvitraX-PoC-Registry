# KvitraX PoC Registry

Versioned PoC dataset collected from GitHub for CVE research and threat intelligence.

## Structure
- `YYYY/` — year folder
- `YYYY/CVE-YYYY-NNNNN.json` — one CVE entry with PoC sources

## How data is collected
PoC entries are discovered via automated GitHub searches using CVE identifiers
and heuristic matching. Results are periodically aggregated and committed as
structured JSON files.

## Disclaimer
PoC repositories may contain malicious or unsafe code.
This project does NOT host exploit code and provides links for research purposes only.
Use at your own risk.

## License
Dataset structure and aggregation are licensed under the MIT License.
Individual PoC repositories are subject to their own licenses.
