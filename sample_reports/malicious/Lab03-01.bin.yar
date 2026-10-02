/* Auto-Generated Defense Signature */
rule AutoTriage_Lab03_01_bin
{
    meta:
        description = "Remediation signature for Lab03-01.bin"
        sha256 = "eb84360ca4e33b8bb60df47ab5ce962501ef3420bc7aab90655fd507d2ffcedd"
        threat_level = "High"
    strings:
        $str_0 = "program" ascii wide
        $str_1 = "cannot" ascii wide
        $str_2 = "ExitProcess" ascii wide
        $str_3 = "kernel32.dll" ascii wide
        $str_4 = "ws2_32" ascii wide
        $str_5 = "CONNECT" ascii wide
        $str_6 = "HTTP/1.0" ascii wide
        $str_7 = "advapi32" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 10752 and 2 of ($str_*)
}
