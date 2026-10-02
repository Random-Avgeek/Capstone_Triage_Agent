/* Auto-Generated Defense Signature */
rule AutoTriage_shellcode_launcher_bin
{
    meta:
        description = "Remediation signature for shellcode_launcher.bin"
        sha256 = "5edacaca676c927246d9cf5706bb5917025ca8409c24e2af0953bbd2fcc4b8a4"
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
        uint16(0) == 0x5A4D and filesize < 73728 and 2 of ($str_*)
}
