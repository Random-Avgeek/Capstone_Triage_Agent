/* Auto-Generated Defense Signature */
rule AutoTriage_Lab19_02_bin
{
    meta:
        description = "Remediation signature for Lab19-02.bin"
        sha256 = "3ba837e827a5a20cf51ec82972b5e5fe028708932bfe1e58fd1224ef2fe5bb75"
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
