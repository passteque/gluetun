package providers

const (
	// Custom is the VPN provider name for custom
	// VPN configurations.
	Airvpn                = "airvpn"
	Azirevpn              = "azirevpn"
	Custom                = "custom"
	Cyberghost            = "cyberghost"
	Example               = "example"
	Expressvpn            = "expressvpn"
	Fastestvpn            = "fastestvpn"
	Giganews              = "giganews"
	HideMyAss             = "hidemyass"
	Ipvanish              = "ipvanish"
	Ivpn                  = "ivpn"
	Mullvad               = "mullvad"
	Nordvpn               = "nordvpn"
	Perfectprivacy        = "perfect privacy"
	Privado               = "privado"
	PrivateInternetAccess = "private internet access"
	Privatevpn            = "privatevpn"
	Protonvpn             = "protonvpn"
	Purevpn               = "purevpn"
	SlickVPN              = "slickvpn"
	Surfshark             = "surfshark"
	Torguard              = "torguard"
	VPNSecure             = "vpnsecure"
	VPNUnlimited          = "vpn unlimited"
	Vyprvpn               = "vyprvpn"
	Windscribe            = "windscribe"
)

// All returns all the providers except the custom provider.
func All() []string {
	return []string{
		Airvpn,
		Azirevpn,
		Cyberghost,
		Expressvpn,
		Fastestvpn,
		Giganews,
		HideMyAss,
		Ipvanish,
		Ivpn,
		Mullvad,
		Nordvpn,
		Perfectprivacy,
		Privado,
		PrivateInternetAccess,
		Privatevpn,
		Protonvpn,
		Purevpn,
		SlickVPN,
		Surfshark,
		Torguard,
		VPNSecure,
		VPNUnlimited,
		Vyprvpn,
		Windscribe,
	}
}

func AllWithCustom() []string {
	allProviders := All()
	allProvidersWithCustom := make([]string, len(allProviders)+1)
	copy(allProvidersWithCustom, allProviders)
	allProvidersWithCustom[len(allProvidersWithCustom)-1] = Custom
	return allProvidersWithCustom
}
