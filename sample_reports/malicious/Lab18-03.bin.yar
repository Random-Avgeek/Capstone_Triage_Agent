/* Auto-Generated Defense Signature */
rule AutoTriage_Lab18_03_bin
{
    meta:
        description = "Remediation signature for Lab18-03.bin"
        sha256 = "b756a02776b6b33394b255ba99f4cc0379cccbe080f36fd80034a5a6e2ffaa3e"
        threat_level = "High"
    strings:
        $str_0 = "program" ascii wide
        $str_1 = "cannot" ascii wide
        $str_2 = "spafcHf" ascii wide
        $str_3 = "purXvuixt" ascii wide
        $str_4 = "SpfMZk" ascii wide
        $str_5 = "32.dql" ascii wide
        $str_6 = "ObjFcI" ascii wide
        $str_7 = "8HOEjM" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 18432 and 2 of ($str_*)
}
