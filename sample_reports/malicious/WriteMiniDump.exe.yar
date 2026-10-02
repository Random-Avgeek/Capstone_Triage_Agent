/* Auto-Generated Defense Signature */
rule AutoTriage_WriteMiniDump_exe
{
    meta:
        description = "Remediation signature for WriteMiniDump.exe"
        sha256 = "f29c7a4a0d45c020a0cb93db1147cb81e913ef83b4e840cbba7c87b2da3a363b"
        threat_level = "High"
    strings:
        $str_0 = ".rdata" ascii wide
        $str_1 = "PQSUVW" ascii wide
        $str_2 = "PQRWVS" ascii wide
        $str_3 = "t_SUVW" ascii wide
        $str_4 = "VRh8vC" ascii wide
        $str_5 = "tQPhPvC" ascii wide
        $str_6 = "tQPhTvC" ascii wide
        $str_7 = "xQRPhXvC" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 426684 and 2 of ($str_*)
}
