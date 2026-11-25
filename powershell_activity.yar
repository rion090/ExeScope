
rule Suspicious_PowerShell_Activity
{
    meta:
        description = "Detects potentially suspicious PowerShell execution patterns"
        category = "Execution"
        family = "Generic"
        author = "Malware Analysis Orchestrator"

    strings:
        $ps1 = "powershell.exe" ascii wide
        $ps2 = "EncodedCommand" ascii wide
        $ps3 = "FromBase64String" ascii wide
        $ps4 = "DownloadString" ascii wide

    condition:
        2 of them
}
