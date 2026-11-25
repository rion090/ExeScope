
rule Suspicious_Registry_Persistence
{
    meta:
        description = "Detects strings associated with registry persistence"
        category = "Persistence"
        family = "Generic"
        author = "Malware Analysis Orchestrator"

    strings:
        $run1 = "CurrentVersion\\Run" ascii wide
        $run2 = "CurrentVersion\\RunOnce" ascii wide
        $reg = "reg add" ascii wide

    condition:
        2 of them
}
