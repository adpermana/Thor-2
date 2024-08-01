// Source: https://github.com/advanced-threat-research/Yara-Rules/blob/master/malware/MALW_Eicar.yar

rule eicar : refined
{
	meta:
		description = "Rule to detect Eicar pattern"
		author = "Marc Rivero | @seifreed"
		hash1 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
		weight = 10

	strings:
		$s1 = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*" fullword ascii

	condition:
		all of them
}
