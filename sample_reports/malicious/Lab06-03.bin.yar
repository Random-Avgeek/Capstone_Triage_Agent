/* Auto-Generated Defense Signature */
rule AutoTriage_Lab06_03_bin
{
    meta:
        description = "Remediation signature for Lab06-03.bin"
        sha256 = "75eb05679a0a988dddf8badfc6d5996cc7e372c73e1023dde59efbaab6ece655"
        threat_level = "High"
    strings:
        $str_0 = "program" ascii wide
        $str_1 = "cannot" ascii wide
        $str_2 = "VRichA9" ascii wide
        $str_3 = ".rdata" ascii wide
        $str_4 = "HHtpHHtl" ascii wide
        $str_5 = "SSPVSS" ascii wide
        $str_6 = "DSUVWh" ascii wide
        $str_7 = "VC20XC00U" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 61440 and 2 of ($str_*)
}
