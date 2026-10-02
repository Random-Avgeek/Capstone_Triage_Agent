/* Auto-Generated Defense Signature */
rule AutoTriage_Lab18_04_bin
{
    meta:
        description = "Remediation signature for Lab18-04.bin"
        sha256 = "b8a5d54e5b8ae63d8f59bb3b1c8782e76154093fea83708ae657184c922eee0e"
        threat_level = "High"
    strings:
        $str_0 = "program" ascii wide
        $str_1 = "cannot" ascii wide
        $str_2 = "6KRich" ascii wide
        $str_3 = ".rdata" ascii wide
        $str_4 = ".aspack" ascii wide
        $str_5 = ".adata" ascii wide
        $str_6 = "MnqRZT" ascii wide
        $str_7 = "ZJ-Qf/" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 46080 and 2 of ($str_*)
}
