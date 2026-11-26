
rule Generic_Worm_Detection
{
    meta:
        description = "Detects strings associated with worm-like propagation"
        category = "Worm"
        family = "Generic"
        author = "ExeScope Malware Analysis"

    strings:
        $s1 = "autorun.inf" ascii wide nocase
        $s2 = "WScript.Network" ascii wide nocase
        $s3 = "FileSystemObject" ascii wide nocase
        $s4 = "DriveType" ascii wide nocase
        $s5 = "net view" ascii wide nocase
        $s6 = "net use" ascii wide nocase
        $s7 = "CopyFile" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and 3 of them
}
