/*
   YARA Rule Set
   Author: [Daffi]
   Date: [8 Mei 2024]
   Identifier: redline
   Description: Rules for detecting APT Volt Typhoon.
*/

rule volt_typhoon_strings {
    strings:
        $str1 = "CustomFRPClient"
        $str2 = "HACKTOOL_FRPClient"
        $str3 = "EncryptJSP"
        $str4 = "contact@cyber.gc.ca"
        $str5 = "incidents@ncsc.govt.nz"
    condition:
        any of ($str*)
}

rule volt_typhoon_hashes {
    strings:
        $hash1 = "ef09b8ff86c276e9b475a6ae6b54f08ed77e09e169f7fc0872eb1d427ee27d31"
        $hash2 = "d6ebde42457fe4b2a927ce53fc36f465f0000da931cfab9b79a36083e914ceca"
        $hash3 = "d6ab36cb58c6c8c3527e788fc9239d8dcc97468b6999cf9ccd8a815c8b4a80af"
        $hash4 = "e453e6efc5a002709057d8648dbe9998a49b9a12291dee390bb61c98a58b6e95"
        $hash5 = "7939f67375e6b14dfa45ec70356e91823d12f28bbd84278992b99e0d2c12ace5"
        $hash6 = "fd41134e8ead1c18ccad27c62a260aa6"
        $hash7 = "3a97d9b6f17754dcd38ca7fc89caab04"
        $hash8 = "b1de37bf229890ac181bdef1ad8ee0c2"
        $hash9 = "04423659f175a6878b26ac7d6b6e47c6fd9194d1"
        $hash10 = "ffb1d8ea3039d3d5eb7196d27f5450cac0ea4f34"
        $hash11 = "ffdb3cc7ab5b01d276d23ac930eb21ffe3202d11"
        $hash12 = "edc0c63065e88ec96197c8d7a40662a15a812a9583dc6c82b18ecd7e43b13b70"
        $hash13 = "eaef901b31b5835035b75302f94fee27288ce46971c6db6221ecbea9ba7ff9d0"
        $hash14 = "99b80c5ac352081a64129772ed5e1543d94cad708ba2adc46dc4ab7a0bd563f1"
        $hash15 = "433331fe1a3ff11ea362fc772b67da38"
        $hash16 = "472ccfb865c81704562ea95870f60c08ef00bcd2ca1d7f09352398c05be5d05d"
        $hash17 = "93ce3b6d2a18829c0212542751b309dacbdc8c1d950611efe2319aa715f3a066"
        $hash18 = "3e9fc13fab3f8d8120bd01604ee50ff65a40121955a4150a6d2c007d34807642"
        $hash19 = "3a9d8bb85fbcfe92bae79d5ab18e4bca9eaf36cea70086e8d1ab85336c83945f"
        $hash20 = "6036390a2c81301a23c9452288e39cb34e577483d121711b6ba6230b29a3c9ff"
        $hash21 = "d17317e1d5716b09cee904b8463a203"
    condition:
        any of ($hash*)
}
