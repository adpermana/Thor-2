rule braincipher_ransom {
    meta:
        description = "detect specific malware files and suspicious domains/IPs"
        author = "SEE"
        reference = "evidence"
        date = "2024-06-24"
        score = 85
        customer = "D21"
        license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
        tags = "malware, detection, custom, YARA"
        minimum_yara = "1.7"

    strings:
        $md5_1 = "9cb96848386327410ca588b6cd5f6401"
        $md5_2 = "deb2e0756d331362d57ad9fe408c4ff3"
        $md5_3 = "eebb7935dfe2a521bd5253c7e4660fb4"
        $md5_4 = "4182f37b9ba1fa315268c669b5335dde"
        $md5_5 = "9497aece91e1ccc495ca26ae284600b9"
        $md5_6 = "a26d44e42214aa23f02336675aa9ae2b"
        $md5_7 = "a6050a995a44a5e6059a4414d44d1688"
        $md5_8 = "2774db09c14fa8c3f323bd7dbc859f7d"
        $md5_9 = "a3325bb20e930fce6a33664f06c9e458"
        $md5_10 = "448276c2ecf90f1b2af9cd80066503f6"
        $md5_11 = "2d3b207c8a48148296156e5725426c7f"
        $md5_12 = "8c330d024de08691299eeb6d0e293154"
        $md5_13 = "d0faea9bbc7c213fefd136809f48056d"
        $md5_14 = "e5368d0041fa7e26126534a6079855d1"
        $md5_15 = "7e76110827e70eabab8576972738002c"
        $md5_16 = "590542a43ad538eed88b19e8afacd361"
        $md5_17 = "dcde2248d19c778a41aa165866dd52d0"
        $md5_18 = "a0b9388c5f18e27266a31f8c5765b263"
        $md5_19 = "ad51946b1659ed61b76ff4e599e36683"
        $md5_20 = "35da3b727567fab0c7c8426f1261c7f5"
        $md5_21 = "405a7bca024d33d7d6464129c1b58451"
        $md5_22 = "448f1796fe8de02194b21c0715e0a5f6"
        $md5_23 = "9c5698924d4d1881efaf88651a304cb3"

        $sha1_1 = "6c1b646e002e45688d750e5feb47fc3d6f514b77"
        $sha1_2 = "870865aad7c7cccafbca0c1f50f7eecaedbd4bf1"
        $sha1_3 = "968c4ae64dcb71c9eeffd812ef38a69d5548b3bb"
        $sha1_4 = "2c13da0c10638a5200fed99dcdcf0dc77a599073"
        $sha1_5 = "a005d8ce0c1ea8901c1b4ea86c40f4925bd2c6da"
        $sha1_6 = "217cdee6ffe007ee4926fa82cdc22990a014ae9c"
        $sha1_7 = "617f4509e6caea1b1099c9c5e9cccb9176dd1b67"
        $sha1_8 = "d8d4d446bf51f6b4e70e41665cf12718152282c5"
        $sha1_9 = "d05902aae8bb149258a9869e3dd9ba89d5611e4b"
        $sha1_10 = "3d49a618eff7437a2e897c789187cfca4e1aaec3"
        $sha1_11 = "ad464eb7cf5c19c8a443ab5b590440b32dbc618f"
        $sha1_12 = "5b19a1a2b2ed89ce5d50b1771896cb8550fa2a71"
        $sha1_13 = "21fc39e324b46f20ba3724c3d54330eb8a39bda0"
        $sha1_14 = "d9fb545f03f2baf696b4c0e5dee8afe7963c298c"
        $sha1_15 = "5d133e73a873b7615b4c6798aa0dd9827fa43a81"
        $sha1_16 = "559daa05a70676c85305ce886bc6c6612882d417"
        $sha1_17 = "7ec84be84fe23f0b0093b647538737e1f19ebb03"
        $sha1_18 = "906f7e94f841d464d4da144f7c858fa2160e36db"
        $sha1_19 = "dfe2439424886e8acf9fa3ffde6caaf7bfdd583e"
        $sha1_20 = "b71557d67bcd427ef928efce7b6a6529226415e6"
        $sha1_21 = "22b64e211d96d773c510ac82e7a73f8debf4e4cd"
        $sha1_22 = "935c0b39837319fda571aa800b67d997b79c3198"
        $sha1_23 = "c60a0b99729eb6d95c2d9f8b76b9714411a3a751"

        $sha256_1 = "07612eed1e0341bcff08870f8a47df488318cee57bd1fb64709c0a5dc8635340"
        $sha256_2 = "0ed5729655b3f09c29878e1cc10de55e0cbfae7ac344f574d471827c256cf086"
        $sha256_3 = "1ddacee1d25936970279557169037a335b362f86c3797ded625d68077bd0145c"
        $sha256_4 = "6e07da23603fbe5b26755df5b8fec19cadf1f7001b1558ea4f12e20271263417"
        $sha256_5 = "917e115cc403e29b4388e0d175cbfac3e7e40ca1742299fbdb353847db2de7c2"
        $sha256_6 = "eb82946fa0de261e92f8f60aa878c9fef9ebb34fdababa66995403b110118b12"
        $sha256_7 = "a74612ae5234d1a8f1263545400668097f9eb6a01dfb8037bc61ca9cae82c5b8"
        $sha256_8 = "1b63f83f06dbd9125a6983a36e0dbd64026bb4f535e97c5df67c1563d91eff89"
        $sha256_9 = "09a2585d0ed5e0fadf3085eb3ec987b52bce14e1de186c2845f246109023e1f1"
        $sha256_10 = "e45119b3f1ef743939926ae6c268362740628dd1ad4bf10242356db60b9a28f2"
        $sha256_11 = "5819efd141b6388ab1c36df5e1beacbeabc9f88cf1ce49d14c765d5173331006"
        $sha256_12 = "7df4fa3979cbfbfe9df03c07a3534296c05be5f88fc1118c645e241dc1983282"
        $sha256_13 = "972d142a9d87969e328f5248684960c672535c576f02af90369bc0ee37ca9b50"
        $sha256_14 = "edfe2b923bfb5d1088de1611401f5c35ece91581e71503a5631647ac51f7d796"
        $sha256_15 = "d52368dc00c3dd9176addc801474f217628d30906dd87dce5a64ad220a33ba5a"
        $sha256_16 = "8e24b76e7f51e8473f299db69c795e8336377d1659c7b2ca23d500ff34ee88ef"
        $sha256_17 = "bfd7ca7c22e4652b6b8f08a0e8979353f0dc21380738e81285988d33328f6d73"
        $sha256_18 = "cd2663b348668c6ba0bf1e0ee9f5abe5a25a0d92d04e628e5ca2542a05c42e3b"
        $sha256_19 = "4fb80a9ed5c9d20ac9f63ff1d2ec1169e7ea5f2039474036e295cd6dc2a728a3"
        $sha256_20 = "9074fd40ea6a0caa892e6361a6a4e834c2e51e6e98d1ffcda7a9a537594a6917"
        $sha256_21 = "313117e723dda6ea3911faacd23f4405003fb651c73de8deff10b9eb5b4a058a"
        $sha256_22 = "07a191254362664b3993479a277199f7ea5ee723b6c25803914eedb50250acf4"
        $sha256_23 = "89027f1449be9ba1e56dd82d13a947cb3ca319adfe9782f4874fbdc26dc59d09"
        $sha256_24 = "092c3ec01883d3b4b131985b3971f7e2e523252b75f9c2470e0821505c4a3a83"

        $domain1 = "tvpress.com"
        $subdomain1_pattern = /([a-zA-Z0-9-]+\.)+tvpress\.com/
        $domain2 = "btloader.com"
        $subdomain2_pattern = /([a-zA-Z0-9-]+\.)+btloader\.com/
        $domain3 = "iyfbodn.com"
        $subdomain3_pattern = /([a-zA-Z0-9-]+\.)+iyfbodn\.com/
        $domain4 = "sbdtds.com"
        $subdomain4_pattern = /([a-zA-Z0-9-]+\.)+sbdtds\.com/
        $domain5 = "securesearchnow.com"
        $subdomain5_pattern = /([a-zA-Z0-9-]+\.)+securesearchnow\.com/
        $domain6 = "vultusercontent.com"
        $subdomain6_pattern = /([a-zA-Z0-9-]+\.)+vultusercontent\.com/

        $ip1 = "209.250.254.15"
        $ip2 = "64.176.55.90"
        $ip3 = "184.25.191.235"
        $ip4 = "20.99.133.109"
        $ip5 = "20.99.186.246"

        $url1 = "http://mybmtbgd7aprdnw2ekxht5qap5daam2wch25coqerrq2zdioanob34ad.onion"

        $email1 = "brain.support@cyberfear.com"

        // Example byte patterns
        $byte_pattern1 = { 8b 75 0c ad 35 ff 5f 03 10 50 e8 6f fe ff ff 85 c0 0f 84 23 01 00 00 8b 7d 08 83 c7 04 }
        $byte_pattern2 = { 83 c4 f4 56 c7 45 fc 00 00 00 00 c7 45 f8 00 00 00 00 e8 46 ed fe ff 8b c8 8d 45 f4 50 51 ff 15 2c 57 42 00 89 45 f8 83 7d f8 00 74 2b 83 7d f4 02 72 25 8b 75 f8 }
        $byte_pattern3 = { 8b c1 33 d2 f7 f6 8a c1 8a 14 17 02 54 05 00 02 d3 8a 5c 15 00 8a 54 1d 00 86 54 05 00 88 54 1d 00 41 81 f9 00 03 00 00 75 d6 5d 33 c9 8b 7d 0c be 40 00 00 00 55 8b 6d 10 }

    condition:
        uint16(0) == 0x5a4d and filesize < 1800KB and (2 of ($md5*, $sha1*, $sha256*, $domain*, $subdomain1_pattern, $subdomain2_pattern, $subdomain3_pattern, $subdomain4_pattern, $subdomain5_pattern, $subdomain6_pattern, $ip*, $url1, $email1) or any of ($byte_pattern1, $byte_pattern2, $byte_pattern3))
}
