import csv

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

                # File activity
                if "writefile" in operation:
                    file_writes += 1

                # Suspicious locations
                if "system32" in path:
                    suspicious_process.add(process)

                # Registry activity
                if "regsetvalue" in operation:
                    risk += 1

            if file_writes > 20:
                findings.append("High file write activity detected")
                risk += 2

            if suspicious_process:
                findings.append(f"Processes interacting with System32: {', '.join(suspicious_process)}")
                risk += 3

    except Exception as e:
        findings.append("ProcMon analysis failed or file format incorrect")

    return findings, risk


def generate_report(reg_file, proc_file):
    reg_findings, reg_risk = analyze_regshot(reg_file)
    proc_findings, proc_risk = analyze_procmon(proc_file)

    total_risk = reg_risk + proc_risk

    if total_risk >= 10:
        level = "HIGH"
    elif total_risk >= 5:
        level = "MEDIUM"
    else:
        level = "LOW"

    print("\n====== COMBINED MALWARE ANALYSIS REPORT ======\n")

    print("Registry Analysis:")
    for f in reg_findings:
        print("- " + f)

    print("\nProcess & File Activity:")
    for f in proc_findings:
        print("- " + f)

    print(f"\nOverall Risk Level: {level}")
    print("==============================================\n")


# --- Run ---
reg_path = input("Enter RegShot file path: ")
proc_path = input("Enter ProcMon CSV file path: ")

generate_report(reg_path, proc_path)