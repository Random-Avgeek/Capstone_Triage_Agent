/* Auto-Generated Defense Signature */
rule AutoTriage_Lab06_02_bin
{
    meta:
        description = "Remediation signature for Lab06-02.bin"
        sha256 = "b71777edbf21167c96d20ff803cbcb25d24b94b3652db2f286dcd6efd3d8416a"
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
