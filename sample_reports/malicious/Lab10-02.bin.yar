/* Auto-Generated Defense Signature */
rule AutoTriage_Lab10_02_bin
{
    meta:
        description = "Remediation signature for Lab10-02.bin"
        sha256 = "20bf5d516f3f3ef4c9453437211486b73d519ff97d8659851012adff8e84e0a9"
        threat_level = "High"
    strings:
        $str_0 = "program" ascii wide
        $str_1 = "cannot" ascii wide
        $str_2 = ".rdata" ascii wide
        $str_3 = "HHtpHHtl" ascii wide
        $str_4 = "SSPVSS" ascii wide
        $str_5 = "DSUVWh" ascii wide
        $str_6 = "VC20XC00U" ascii wide
        $str_7 = "VWuBhhT" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 49152 and 2 of ($str_*)
}
