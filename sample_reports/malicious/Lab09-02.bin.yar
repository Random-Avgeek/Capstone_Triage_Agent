/* Auto-Generated Defense Signature */
rule AutoTriage_Lab09_02_bin
{
    meta:
        description = "Remediation signature for Lab09-02.bin"
        sha256 = "f153dfacec09dd69809c3bbf68270a38ee3701f44220c7bf181c14a68c138133"
        threat_level = "High"
    strings:
        $str_0 = "program" ascii wide
        $str_1 = "cannot" ascii wide
        $str_2 = ".rdata" ascii wide
        $str_3 = "SSPVSS" ascii wide
        $str_4 = "DSUVWh" ascii wide
        $str_5 = "VC20XC00U" ascii wide
        $str_6 = "runtime" ascii wide
        $str_7 = "DOMAIN" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 36864 and 2 of ($str_*)
}
