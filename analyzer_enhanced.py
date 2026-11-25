import csv
import os
import re
import hashlib
import json
import base64
import urllib.request
import urllib.error
from pathlib import Path
from collections import defaultdict


# ============================================================
# EXISTING ANALYSIS FUNCTIONS
# Risk-scoring rules are intentionally unchanged.
# ============================================================

def analyze_regshot(file_path):
    with open(file_path, 'r', encoding='utf-16', errors='ignore') as f:
        data = f.read().lower()

    findings = []
    risk = 0

    if "currentversion\\run" in data:
        findings.append("Persistence detected (Run key)")
        risk += 3

    if "system32" in data:
        findings.append("System directory modification")
        risk += 3

    if "firewall" in data or "defender" in data:
        findings.append("Security settings modified")
        risk += 4

    return findings, risk


def analyze_procmon(file_path):
    findings = []
    risk = 0

    try:
        with open(file_path, newline='', encoding='utf-8', errors='ignore') as csvfile:
            reader = csv.DictReader(csvfile)

            file_writes = 0
            suspicious_process = set()

            for row in reader:
                operation = row.get("Operation", "").lower()
                path = row.get("Path", "").lower()
                process = row.get("Process Name", "").lower()

                if "writefile" in operation:
                    file_writes += 1

                if "system32" in path:
                    suspicious_process.add(process)

                if "regsetvalue" in operation:
                    risk += 1

            if file_writes > 20:
                findings.append("High file write activity detected")
                risk += 2

            if suspicious_process:
                findings.append(
                    f"Processes interacting with System32: {', '.join(suspicious_process)}"
                )
                risk += 3

    except Exception:
        findings.append("ProcMon analysis failed or file format incorrect")

    return findings, risk


# ============================================================
# NEW FEATURE 1: YARA MAPPING
# Requires: pip install yara-python
# Put .yar / .yara rule files inside the yara_rules folder.
# ============================================================

def run_yara_scan(sample_path, rules_dir="yara_rules"):
    results = []

    if not sample_path:
        return ["Skipped: no EXE/DLL sample supplied."]

    if not os.path.isfile(sample_path):
        return [f"Skipped: sample file not found: {sample_path}"]

    rule_files = list(Path(rules_dir).glob("*.yar")) + list(Path(rules_dir).glob("*.yara"))

    if not rule_files:
        return [f"No YARA rule files found in '{rules_dir}'."]

    try:
        import yara
    except ImportError:
        return ["YARA unavailable. Install it using: pip install yara-python"]

    try:
        filepaths = {f"rule_{i}": str(path) for i, path in enumerate(rule_files)}
        rules = yara.compile(filepaths=filepaths)
        matches = rules.match(sample_path, timeout=30)

        if not matches:
            return ["No YARA rules matched the supplied sample."]

        for match in matches:
            family = match.meta.get("family", "Not specified")
            category = match.meta.get("category", "Not specified")
            description = match.meta.get("description", "No description provided")

            results.append(
                f"Rule: {match.rule} | Family: {family} | "
                f"Category: {category} | Description: {description}"
            )

    except Exception as error:
        results.append(f"YARA scan error: {error}")

    return results


# ============================================================
# NEW FEATURE 2: MITRE ATT&CK BEHAVIOR MAPPING
# These are heuristic mappings based on observed log evidence.
# They are not proof that an attacker used a technique.
# ============================================================

def map_mitre_attack(reg_data, proc_data):
    mappings = []

    def add(technique_id, name, evidence):
        mappings.append({
            "id": technique_id,
            "name": name,
            "evidence": evidence
        })

    reg_lower = reg_data.lower()
    proc_lower = proc_data.lower()

    if "currentversion\\run" in reg_lower:
        add(
            "T1547.001",
            "Registry Run Keys / Startup Folder",
            "RegShot contains a CurrentVersion\\Run registry key."
        )

    if "firewall" in reg_lower or "defender" in reg_lower:
        add(
            "T1562.001",
            "Disable or Modify Tools",
            "RegShot contains references to Firewall or Windows Defender changes."
        )

    if "regsetvalue" in proc_lower:
        add(
            "T1112",
            "Modify Registry",
            "ProcMon records RegSetValue operations."
        )

    if "currentversion\\run" in proc_lower:
        add(
            "T1547.001",
            "Registry Run Keys / Startup Folder",
            "ProcMon contains activity involving a CurrentVersion\\Run key."
        )

    if "firewall" in proc_lower or "defender" in proc_lower:
        add(
            "T1562.001",
            "Disable or Modify Tools",
            "ProcMon paths contain Firewall or Defender references."
        )

    # Remove duplicate technique/evidence pairs.
    unique = {}
    for item in mappings:
        key = (item["id"], item["evidence"])
        unique[key] = item

    return list(unique.values())


# ============================================================
# NEW FEATURE 3: IOC EXTRACTION AND NORMALIZATION
# Extracts indicators from the supplied logs and sample.
# ============================================================

def extract_iocs(reg_data, proc_data, sample_path=None):
    combined = reg_data + "\n" + proc_data

    iocs = defaultdict(set)

    # IPv4 addresses (basic syntax validation included).
    ip_pattern = r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"
    for value in re.findall(ip_pattern, combined):
        parts = value.split(".")
        if all(0 <= int(part) <= 255 for part in parts):
            iocs["IP addresses"].add(value)

    # URLs.
    url_pattern = r"https?://[^\s\"'<>]+"
    for value in re.findall(url_pattern, combined, re.IGNORECASE):
        iocs["URLs"].add(value.rstrip(".,);]"))

    # Domains.
    domain_pattern = (
        r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
        r"[a-zA-Z]{2,}\b"
    )
    for value in re.findall(domain_pattern, combined):
        iocs["Domains"].add(value.lower())

    # Windows file paths.
    path_pattern = r"[A-Za-z]:\\(?:[^\\/:*?\"<>|\r\n]+\\)*[^\\/:*?\"<>|\r\n]*"
    for value in re.findall(path_pattern, combined):
        iocs["File paths"].add(value.strip().rstrip(".,;"))

    # Registry keys.
    registry_pattern = (
        r"(?:HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKLM|HKCU)"
        r"\\[^\r\n,;\"']+"
    )
    for value in re.findall(registry_pattern, combined, re.IGNORECASE):
        iocs["Registry keys"].add(value.strip().rstrip(".,;"))

    # Mutex names, when explicitly present in log text.
    mutex_pattern = r"(?i)\bmutex\b\s*[:=]\s*([^\s,;]+)"
    for value in re.findall(mutex_pattern, combined):
        iocs["Mutexes"].add(value.strip())

    # Hash the supplied sample without uploading it.
    if sample_path and os.path.isfile(sample_path):
        md5_hash = hashlib.md5()
        sha256_hash = hashlib.sha256()

        with open(sample_path, "rb") as sample:
            for chunk in iter(lambda: sample.read(1024 * 1024), b""):
                md5_hash.update(chunk)
                sha256_hash.update(chunk)

        iocs["MD5 hashes"].add(md5_hash.hexdigest())
        iocs["SHA256 hashes"].add(sha256_hash.hexdigest())

    return {kind: sorted(values) for kind, values in iocs.items() if values}


# ============================================================
# NEW FEATURE 3B: OPTIONAL VIRUSTOTAL CORRELATION
# Set VT_API_KEY as an environment variable.
# Only indicator lookups are performed; samples are NOT uploaded.
# ============================================================

def virustotal_lookup(iocs):
    api_key = os.getenv("VT_API_KEY")

    if not api_key:
        return ["Skipped: set the VT_API_KEY environment variable to enable lookups."]

    indicators = []
    for category in ("SHA256 hashes", "MD5 hashes", "IP addresses", "Domains", "URLs"):
        for value in iocs.get(category, []):
            indicators.append((category, value))

    if not indicators:
        return ["No supported hash, IP, domain or URL indicators available."]

    results = []

    # Keep the initial run short and avoid excessive API requests.
    for category, value in indicators[:10]:
        try:
            if category == "URLs":
                indicator_id = base64.urlsafe_b64encode(
                    value.encode()
                ).decode().rstrip("=")
            else:
                indicator_id = value

            endpoint = f"https://www.virustotal.com/api/v3/{'files' if 'hash' in category.lower() else 'ip_addresses' if category == 'IP addresses' else 'domains' if category == 'Domains' else 'urls'}/{indicator_id}"

            request = urllib.request.Request(
                endpoint,
                headers={"x-apikey": api_key}
            )

            with urllib.request.urlopen(request, timeout=8) as response:
                data = json.loads(response.read().decode("utf-8"))

            stats = data.get("data", {}).get("attributes", {}).get(
                "last_analysis_stats", {}
            )

            if stats:
                results.append(
                    f"{category}: {value} | "
                    f"Malicious: {stats.get('malicious', 0)} | "
                    f"Suspicious: {stats.get('suspicious', 0)} | "
                    f"Harmless: {stats.get('harmless', 0)}"
                )
            else:
                results.append(f"{category}: {value} | Reputation data unavailable.")

        except urllib.error.HTTPError as error:
            if error.code == 404:
                results.append(f"{category}: {value} | Not found in VirusTotal.")
            elif error.code == 401:
                results.append("VirusTotal authentication failed. Check VT_API_KEY.")
                break
            elif error.code == 429:
                results.append("VirusTotal rate limit reached. Remaining lookups skipped.")
                break
            else:
                results.append(f"{category}: {value} | Lookup failed (HTTP {error.code}).")
        except Exception:
            results.append(f"{category}: {value} | Lookup unavailable.")

    return results


# ============================================================
# UPDATED REPORT GENERATION
# Existing risk formula and thresholds are unchanged.
# ============================================================

def generate_report(reg_file, proc_file, sample_path=None, rules_dir="yara_rules"):
    reg_findings, reg_risk = analyze_regshot(reg_file)
    proc_findings, proc_risk = analyze_procmon(proc_file)

    # Keep the original risk calculation exactly as it was.
    total_risk = reg_risk + proc_risk

    if total_risk >= 10:
        level = "HIGH"
    elif total_risk >= 5:
        level = "MEDIUM"
    else:
        level = "LOW"

    # Read source logs for the new reporting modules.
    with open(reg_file, "r", encoding="utf-16", errors="ignore") as f:
        reg_data = f.read()

    with open(proc_file, "r", encoding="utf-8", errors="ignore", newline="") as f:
        proc_data = f.read()

    yara_results = run_yara_scan(sample_path, rules_dir)
    mitre_results = map_mitre_attack(reg_data, proc_data)
    iocs = extract_iocs(reg_data, proc_data, sample_path)
    ti_results = virustotal_lookup(iocs)

    report = []
    report.append("\n====== COMBINED MALWARE ANALYSIS REPORT ======\n")

    report.append("REGISTRY ANALYSIS:")
    report.extend(["- " + item for item in reg_findings] or ["- No findings."])

    report.append("\nPROCESS & FILE ACTIVITY:")
    report.extend(["- " + item for item in proc_findings] or ["- No findings."])

    report.append("\nYARA ANALYSIS:")
    report.extend(["- " + item for item in yara_results])

    report.append("\nMITRE ATT&CK MAPPING:")
    if mitre_results:
        for item in mitre_results:
            report.append(
                f"- {item['id']} | {item['name']} | Evidence: {item['evidence']}"
            )
    else:
        report.append("- No mapped techniques based on the implemented behavior rules.")

    report.append("\nINDICATORS OF COMPROMISE:")
    if iocs:
        for category, values in iocs.items():
            report.append(f"{category}:")
            report.extend(["- " + value for value in values])
    else:
        report.append("- No IOCs extracted from the supplied inputs.")

    report.append("\nTHREAT INTELLIGENCE CORRELATION:")
    report.extend(["- " + item for item in ti_results])

    report.append("\nRISK ASSESSMENT:")
    report.append(f"Original Risk Score: {total_risk}")
    report.append(f"Overall Risk Level: {level}")
    report.append("\nNote: YARA matches, ATT&CK mappings and threat-intelligence results are supporting evidence, not standalone proof of malware identity or compromise.")
    report.append("\n==============================================\n")

    final_report = "\n".join(report)
    print(final_report)

    with open("malware_analysis_report.txt", "w", encoding="utf-8") as f:
        f.write(final_report)

    print("Report saved as malware_analysis_report.txt")


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":
    reg_path = input("Enter RegShot file path: ").strip().strip('"')
    proc_path = input("Enter ProcMon CSV file path: ").strip().strip('"')
    sample_path = input("Enter EXE/DLL sample path (or press Enter to skip): ").strip().strip('"')

    generate_report(
        reg_path,
        proc_path,
        sample_path if sample_path else None
    )
