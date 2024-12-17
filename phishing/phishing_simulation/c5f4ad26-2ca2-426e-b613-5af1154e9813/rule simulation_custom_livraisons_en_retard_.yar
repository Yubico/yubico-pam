rule simulation_custom_livraisons_en_retard_
{

	meta:

		description = "This is a customer authorized simulation beginning 12/17/2024 running for three days."
		action = "yara-close"
		category = "phishing_simulation"
		customer_guid = "c5f4ad26-2ca2-426e-b613-5af1154e9813"
		yara_close_comment = "This is a customer authorized phishing simulation beginning 12/17/2024, per guidance from the customer on 12/16/2024."

	strings:
		
		$sender_1 = "info@mail.post.com" nocase
		$subject_1 = "Postes Canada : Votre colis est en route et un message important concernant les livraisons en retard" nocase
	condition:
	
		1 of ($subject_*) and $sender_1
}
