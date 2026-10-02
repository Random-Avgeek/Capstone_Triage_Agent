/* Auto-Generated Defense Signature */
rule AutoTriage_Lab21_02_bin
{
    meta:
        description = "Remediation signature for Lab21-02.bin"
        sha256 = "f82543bccf128322625e26c1f824246377c6fc25af55a4f859012b69b3d4e168"
        threat_level = "High"
    strings:
        $str_0 = "program" ascii wide
        $str_1 = "cannot" ascii wide
        $str_2 = ".rdata" ascii wide
        $str_3 = "URPQQhpD" ascii wide
        $str_4 = "PPPPPPPP" ascii wide
        $str_5 = "CorExitProcess" ascii wide
        $str_6 = "FlsFree" ascii wide
        $str_7 = "FlsSetValue" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 264192 and 2 of ($str_*)
}
