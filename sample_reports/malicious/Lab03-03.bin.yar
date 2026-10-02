/* Auto-Generated Defense Signature */
rule AutoTriage_Lab03_03_bin
{
    meta:
        description = "Remediation signature for Lab03-03.bin"
        sha256 = "ae8a1c7eb64c42ea2a04f97523ebf0844c27029eb040d910048b680f884b9dce"
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
        uint16(0) == 0x5A4D and filesize < 79872 and 2 of ($str_*)
}
