/* Auto-Generated Defense Signature */
rule AutoTriage_Lab20_02_bin
{
    meta:
        description = "Remediation signature for Lab20-02.bin"
        sha256 = "49d5cc85b8f66cdb238ed1d4bb46709b975f1627acfc934385271ed3be6f77d1"
        threat_level = "High"
    strings:
        $str_0 = "program" ascii wide
        $str_1 = "cannot" ascii wide
        $str_2 = ".rdata" ascii wide
        $str_3 = "HHtpHHtl" ascii wide
        $str_4 = "SSPVSS" ascii wide
        $str_5 = "DSUVWh" ascii wide
        $str_6 = "VC20XC00U" ascii wide
        $str_7 = "ppxxxx" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 49152 and 2 of ($str_*)
}
