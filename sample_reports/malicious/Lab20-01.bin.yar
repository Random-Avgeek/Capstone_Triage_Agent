/* Auto-Generated Defense Signature */
rule AutoTriage_Lab20_01_bin
{
    meta:
        description = "Remediation signature for Lab20-01.bin"
        sha256 = "e18cda6cdd07678b264b9c462b4c7ae31d522296b331767c492a51ea17403387"
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
