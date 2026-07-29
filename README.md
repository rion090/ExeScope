# ExeScope — Automated Malware Analysis Risk Scorer

ExeScope is a lightweight Python tool that analyzes sandboxed execution artifacts — **Regshot** registry diffs and **Procmon** process/file activity logs — to generate a heuristic risk score for a suspicious executable. It was built as part of a mini-project to explore practical malware triage without relying on commercial sandboxing suites.

## How it works

1. A suspicious executable is run inside an isolated **VMware** virtual machine (never on a host/production system).
2. **Regshot** captures a before/after diff of the Windows registry.
3. **Procmon** captures live process, file, and registry activity during execution.
4. Both outputs are exported from the VM to the host machine.
5. `analyzer.py` parses both files and flags behaviors commonly associated with malicious activity, producing a combined risk score and severity rating.

## What it detects

**From Regshot (registry diff):**
- Persistence mechanisms via `Run`/`RunOnce` registry keys
- Modifications to system directories (`System32`)
- Changes to security-relevant settings (firewall, Windows Defender)

**From Procmon (process/file activity):**
- Registry value writes (`RegSetValue` operations)
- High-volume file write activity (potential dropper/payload behavior)
- Processes interacting with `System32`

Each detected behavior contributes to a weighted risk score, which is combined into an overall rating:

| Total Risk Score | Rating |
|---|---|
| ≥ 10 | HIGH |
| 5–9 | MEDIUM |
| < 5 | LOW |

## Requirements

- Python 3.x (standard library only — no external dependencies)
- A Regshot output file (`.txt`, UTF-16 encoded)
- A Procmon export (`.csv`) containing at minimum the `Operation`, `Path`, and `Process Name` columns

## Usage

```bash
python analyzer.py
```

You'll be prompted for:
- The path to your Regshot `.txt` file
- The path to your Procmon `.csv` export

The tool prints a combined report to the console, listing all findings by source (registry vs. process/file activity) along with the overall risk level.

## Sample output

```
====== COMBINED MALWARE ANALYSIS REPORT ======

Registry Analysis:
- Persistence detected (Run key)
- System directory modification

Process & File Activity:
- High file write activity detected
- Processes interacting with System32: sample.exe

Overall Risk Level: HIGH
==============================================
```

## Sample files

The `/samples` folder contains example Regshot and Procmon outputs from a test run against a benign 7-Zip installer, included for reference and to demonstrate expected input formatting.

## Limitations & planned improvements

This is an early-stage, ongoing project. Current limitations and planned work include:
- Expanding the registry/behavior signature set beyond the current keyword-based checks
- Weighting refinements based on behavior severity rather than flat point values
- Automated ingestion directly from the VM (currently a manual export/copy step)
- Support for additional artifact sources (network activity, dropped file hashing)
- Structured (JSON/HTML) report output alongside the console report

## Disclaimer

This tool is intended strictly for educational and controlled sandbox analysis. Never execute untrusted or suspicious binaries outside an isolated virtual machine with no network access to production systems or shared resources.
