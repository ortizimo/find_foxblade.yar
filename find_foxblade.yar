// NOTE: Dubbed HermeticWiper by SentinelLabs, but is has a different hashes we've not seen yet

import "hash"

rule find_foxblade
{					
	meta:
		author = "Saulo 'Sal' Ortiz, Sr. Cyber Forensics Analyst, ATG"
		description = "Searches for FoxBlade used against Ukraine"
		date = "2022-03-08"
		version = "1.0"
		in_the_wild = "True"
								 				
	condition:
		hash.md5(0, filesize) == "f1a33b2be4c6215a1c39b45e391a3e85"
}
