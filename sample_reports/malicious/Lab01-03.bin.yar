/* Auto-Generated Defense Signature */
rule AutoTriage_Lab01_03_bin
{
    meta:
        description = "Remediation signature for Lab01-03.bin"
        sha256 = "7983a582939924c70e3da2da80fd3352ebc90de7b8c4c427d484ff4f050f0aec"
        threat_level = "High"
    strings:
        $str_0 = "Windows" ascii wide
        $str_1 = "Program" ascii wide
        $str_2 = ".rdata" ascii wide
        $str_3 = "KERNEL32.dll" ascii wide
        $str_4 = "LoadLibraryA" ascii wide
        $str_5 = "GetProcAddress" ascii wide
        $str_6 = "ole32.vd" ascii wide
        $str_7 = "OLEAUTLA" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 7128 and 2 of ($str_*)
}
