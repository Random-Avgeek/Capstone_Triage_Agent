/* Auto-Generated Defense Signature */
rule AutoTriage_Lab09_03_bin
{
    meta:
        description = "Remediation signature for Lab09-03.bin"
        sha256 = "1fc6a471b2a46cd882246d5bdc9d5954bf8efacf68b4e549a9756e6616848884"
        threat_level = "High"
    strings:
        $str_0 = "program" ascii wide
        $str_1 = "cannot" ascii wide
        $str_2 = ".rdata" ascii wide
        $str_3 = "SSPVSS" ascii wide
        $str_4 = "DSUVWh" ascii wide
        $str_5 = "VC20XC00U" ascii wide
        $str_6 = "__GLOBAL_HEAP_SELECTED" ascii wide
        $str_7 = "__MSVCRT_HEAP_SELECT" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 55296 and 2 of ($str_*)
}
