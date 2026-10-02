/* Auto-Generated Defense Signature */
rule AutoTriage_Lab09_01_bin
{
    meta:
        description = "Remediation signature for Lab09-01.bin"
        sha256 = "6ac06dfa543dca43327d55a61d0aaed25f3c90cce791e0555e3e306d47107859"
        threat_level = "High"
    strings:
        $str_0 = "program" ascii wide
        $str_1 = "cannot" ascii wide
        $str_2 = "6KRich" ascii wide
        $str_3 = ".rdata" ascii wide
        $str_4 = "HHtpHHtl" ascii wide
        $str_5 = "DSUVWh" ascii wide
        $str_6 = "SSPVSS" ascii wide
        $str_7 = "VC20XC00U" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 92160 and 2 of ($str_*)
}
