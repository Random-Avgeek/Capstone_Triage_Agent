/* Auto-Generated Defense Signature */
rule AutoTriage_Lab01_04_bin
{
    meta:
        description = "Remediation signature for Lab01-04.bin"
        sha256 = "0fa1498340fca6c562cfa389ad3e93395f44c72fd128d7ba08579a69aaf3b126"
        threat_level = "High"
    strings:
        $str_0 = "program" ascii wide
        $str_1 = "cannot" ascii wide
        $str_2 = ".rdata" ascii wide
        $str_3 = "CloseHandle" ascii wide
        $str_4 = "OpenProcess" ascii wide
        $str_5 = "GetCurrentProcess" ascii wide
        $str_6 = "CreateRemoteThread" ascii wide
        $str_7 = "GetProcAddress" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 55296 and 2 of ($str_*)
}
