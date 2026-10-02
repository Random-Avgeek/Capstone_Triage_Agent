/* Auto-Generated Defense Signature */
rule AutoTriage_Lab20_03_bin
{
    meta:
        description = "Remediation signature for Lab20-03.bin"
        sha256 = "d9ea48b83700f61cc63b43ffcc25e16fe71ec974f74b51bae238d56533cd132c"
        threat_level = "High"
    strings:
        $str_0 = "program" ascii wide
        $str_1 = "cannot" ascii wide
        $str_2 = ".rdata" ascii wide
        $str_3 = "QRPPPPPP" ascii wide
        $str_4 = "QQSVWd" ascii wide
        $str_5 = "uRFGHt" ascii wide
        $str_6 = "HHtpHHtl" ascii wide
        $str_7 = "SSPVSS" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 129024 and 2 of ($str_*)
}
