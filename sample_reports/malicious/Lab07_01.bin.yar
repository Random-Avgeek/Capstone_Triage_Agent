/* Auto-Generated Defense Signature */
rule AutoTriage_Lab07_01_bin
{
    meta:
        description = "Remediation signature for Lab07_01.bin"
        sha256 = "0c98769e42b364711c478226ef199bfbba90db80175eb1b8cd565aa694c09852"
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
        uint16(0) == 0x5A4D and filesize < 36864 and 2 of ($str_*)
}
