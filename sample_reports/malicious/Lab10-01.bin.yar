/* Auto-Generated Defense Signature */
rule AutoTriage_Lab10_01_bin
{
    meta:
        description = "Remediation signature for Lab10-01.bin"
        sha256 = "e55cfa92acc2fac8b3b41002ebbef343bfdb61abf876e9c713f323e143d5e451"
        threat_level = "High"
    strings:
        $str_0 = "program" ascii wide
        $str_1 = "cannot" ascii wide
        $str_2 = ".rdata" ascii wide
        $str_3 = "SSPVSS" ascii wide
        $str_4 = "DSUVWh" ascii wide
        $str_5 = "VC20XC00U" ascii wide
        $str_6 = "runtime" ascii wide
        $str_7 = "DOMAIN" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 43008 and 2 of ($str_*)
}
