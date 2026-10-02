/* Auto-Generated Defense Signature */
rule AutoTriage_Lab06_04_bin
{
    meta:
        description = "Remediation signature for Lab06-04.bin"
        sha256 = "cce96e5cb884c565c75960c41f53a7b56cef1a3ff5b9893cd81c390fd0c35ef3"
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
        uint16(0) == 0x5A4D and filesize < 61440 and 2 of ($str_*)
}
