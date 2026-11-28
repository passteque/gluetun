package ghostpath

import (
	"github.com/qdm12/gluetun/internal/configuration/settings"
	"github.com/qdm12/gluetun/internal/constants/openvpn"
	"github.com/qdm12/gluetun/internal/models"
	"github.com/qdm12/gluetun/internal/provider/utils"
)

// The CA, client certificate and client private key below are shared by all
// Ghost Path VPN users and servers. They are the same in every OpenVPN
// configuration file downloaded from https://ghostpath.com/servers, which does
// not require an account. Users are authenticated with their username and password.
func (p *Provider) OpenVPNConfig(connection models.Connection,
	settings settings.OpenVPN, ipv6Supported bool,
) (lines []string) {
	//nolint:mnd
	providerSettings := utils.OpenVPNProviderSettings{
		AuthUserPass:  true,
		RemoteCertTLS: true,
		Ciphers:       []string{openvpn.AES256cbc},
		Ping:          10,
		// The shared client certificate is a 1024 bit RSA key and the
		// certificates are signed with SHA-1, which OpenSSL 3 rejects
		// by default ("ee key too small"). The server requires this
		// certificate, so the certificate profile must be relaxed.
		ExtraLines: []string{
			"tls-cert-profile insecure",
			// The servers do not push the default route, so the client
			// must request all the traffic to go through the tunnel.
			"redirect-gateway",
		},
		CAs:  []string{"MIIESDCCAzCgAwIBAgIJAKHK5bbBPSU2MA0GCSqGSIb3DQEBBQUAMHUxCzAJBgNVBAYTAlVTMQwwCgYDVQQIEwNWUE4xDDAKBgNVBAcTA1ZQTjEMMAoGA1UEChMDVlBOMQwwCgYDVQQLEwNWUE4xDDAKBgNVBAMTA1ZQTjEMMAoGA1UEKRMDVlBOMRIwEAYJKoZIhvcNAQkBFgNWUE4wHhcNMjIwMjE0MjEzNDQwWhcNMzIwMjEyMjEzNDQwWjB1MQswCQYDVQQGEwJVUzEMMAoGA1UECBMDVlBOMQwwCgYDVQQHEwNWUE4xDDAKBgNVBAoTA1ZQTjEMMAoGA1UECxMDVlBOMQwwCgYDVQQDEwNWUE4xDDAKBgNVBCkTA1ZQTjESMBAGCSqGSIb3DQEJARYDVlBOMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwUl1XkfGo3c1uFsvgbO3C3yvu0+cHs9IUSsju5U9cPNCo53mqRHU/qntCC+ldIDKN+dNWn7eURIDszy+flutkgucs0qgETy5fzpXnVMtiKmMiOYWiJDor7j7QivRaxoT/O2fyjxvVCL8gMa60ekWSGBT6isYY8t8BnwTPVP0KvDm36wdaqLmubhf2XGvka/hhNx0SXMmz2x3OJ8BcoypZVLLk/+Qm6DJh1KxyDi4kI+jBC41QuaKKDNwb0kth1304eqZoUeCXtGkzl91y76ODAfdqzXf9WYJdgkXpOm53Cg7FtB42AqPRqHJVwYxDnQyrFwy4a3CWqFJnKtxJM/WlwIDAQABo4HaMIHXMB0GA1UdDgQWBBRSzxAtISfbSRPr0fmhwNZc8kOeKzCBpwYDVR0jBIGfMIGcgBRSzxAtISfbSRPr0fmhwNZc8kOeK6F5pHcwdTELMAkGA1UEBhMCVVMxDDAKBgNVBAgTA1ZQTjEMMAoGA1UEBxMDVlBOMQwwCgYDVQQKEwNWUE4xDDAKBgNVBAsTA1ZQTjEMMAoGA1UEAxMDVlBOMQwwCgYDVQQpEwNWUE4xEjAQBgkqhkiG9w0BCQEWA1ZQToIJAKHK5bbBPSU2MAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEFBQADggEBAGuKFW765F3D5wax5IFSQbEtr+rVHgjR8jiYTzxOCmbLaU4oj6phOhfQJiTTADQYgCIC/DN0HsAEEqrKkwEn8KdAoNiAWfqCV/eqnK83y7yRDGx6/zfsch+PAzKZouMJLrvR9RYbHq7m3adZv84YLge7FE1JqFk1j6rSa4dUUnGQPrQgr9Sasnz8O8KK45XH6fqKrsd4p485n+BXPDzWVsHl4M5dqQV7qUZTazbzzh4NyP5/RQ6Oh5jqMN7po4qiqWv1pu0EKDxUG6gcECc2cTQwHhIOPeCGdHS7uuI2FlLnHaCUFBgi8zTsZxaeaPuPch5M7Zxbdg0GBhS2SmNi+io="}, //nolint:lll
		Cert: "MIIDizCCAvSgAwIBAgIBAjANBgkqhkiG9w0BAQUFADB0MQswCQYDVQQGEwJVUzELMAkGA1UECBMCQ0ExDDAKBgNVBAcTA1ZQTjEMMAoGA1UEChMDVlBOMQwwCgYDVQQLEwNWUE4xDDAKBgNVBAMTA1ZQTjEMMAoGA1UEKRMDVlBOMRIwEAYJKoZIhvcNAQkBFgNWUE4wHhcNMTIwMzAzMDIxMjU3WhcNMjIwMzAxMDIxMjU3WjB3MQswCQYDVQQGEwJVUzELMAkGA1UECBMCQ0ExDDAKBgNVBAcTA1ZQTjEMMAoGA1UEChMDVlBOMQwwCgYDVQQLEwNWUE4xDzANBgNVBAMTBmNsaWVudDEMMAoGA1UEKRMDVlBOMRIwEAYJKoZIhvcNAQkBFgNWUE4wgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAMqp/gXrFASElUb7kFDInvlb6ZT8Vfm1QdiBD3AfvzqVisV9cPDue/mvDyn1JYOHrswUrkmSYATBsV3eDyJfc77TYiKqn0afCtSK7CeJ0syDwm9cCRqjbQV7NjF3hSgUg0JSHFOlTQMxo8DFunEAzSjUhgVIZQyPSQYCe8tcNcKpAgMBAAGjggEoMIIBJDAJBgNVHRMEAjAAMC0GCWCGSAGG+EIBDQQgFh5FYXN5LVJTQSBHZW5lcmF0ZWQgQ2VydGlmaWNhdGUwHQYDVR0OBBYEFOdEvdvwdzDQnrhX5q1cyfoXB/tgMIGmBgNVHSMEgZ4wgZuAFJsrzuK057ufwAZ6dBZ4FPknUfFgoXikdjB0MQswCQYDVQQGEwJVUzELMAkGA1UECBMCQ0ExDDAKBgNVBAcTA1ZQTjEMMAoGA1UEChMDVlBOMQwwCgYDVQQLEwNWUE4xDDAKBgNVBAMTA1ZQTjEMMAoGA1UEKRMDVlBOMRIwEAYJKoZIhvcNAQkBFgNWUE6CCQDPAa5NqVK9CjATBgNVHSUEDDAKBggrBgEFBQcDAjALBgNVHQ8EBAMCB4AwDQYJKoZIhvcNAQEFBQADgYEAmI8mqE20A2xJmCthBHUMdj39qUpXBhRk7XZQ1YyBXCAngt/a0sfjMIGQJsDFNh4sCplN0mHBGqX74G3sSiTa07mhGNhqg196LKfbBchNn2NnHaCqjO0NG9Q2c/0tt47DyOfo7QOTcRzApO3W6SOcPCBLaRihohUmnv1i2kGhJbw=",                                                                                                                                                                                                                                                                       //nolint:lll
		Key:  "MIICeAIBADANBgkqhkiG9w0BAQEFAASCAmIwggJeAgEAAoGBAMqp/gXrFASElUb7kFDInvlb6ZT8Vfm1QdiBD3AfvzqVisV9cPDue/mvDyn1JYOHrswUrkmSYATBsV3eDyJfc77TYiKqn0afCtSK7CeJ0syDwm9cCRqjbQV7NjF3hSgUg0JSHFOlTQMxo8DFunEAzSjUhgVIZQyPSQYCe8tcNcKpAgMBAAECgYEAsHf5M1oQ4iY4fciLT2yB0QvRhuN6UacdINKwiKd8Mh0I6xJhh8mBtlZS0+wcsD0zXY0cff+xEDNAqEW10+5dr11YzYpViacZRMQnrzBEYcTSqlfHXg2PZxu4c08ndwDxjm03Vgg5RKvQnGRMRy4lH/HPOiAkb9oJgR0R5sccZgECQQDmfVZF2UBn4u2scjfcPl4XsUrPO8eyie995c7s7Cz1TDiecLCesjLRf97RexfhhwNJurfCZUWNJ9hkq5hUGzvJAkEA4Rg/ziL74sBh+jT62TaAqnmHDWZlrfCfKtlm1z4TQ5E6WpjKNXN3qfKW069QGnRjZn8zuPwgMpBPXeaTjHH/4QJBAJslbvchX7sOA1H6qCM2T/u+uU55PNivBGhIUlskNrb/EXWFAT4xUQe3/PIg21hRmyL77kmKBaEYWw6YerbShhECQQCX2Rb6BamszyGJfAIZVGY6Gp+bz48aZy/I5T42R/8Q3sDh6x7GLi30rN1I0oSURB3mQDtxOEy0L5wK+Yhh/2mhAkAGXya9wUOcSz96jUgnMfiVoBT3BNszzn/HLKCipCPd/eR3FEvpfmNN+olkd09cONMDKCcWCfHad9moALon0bIV",                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       //nolint:lll
	}
	return utils.OpenVPNConfig(providerSettings, connection, settings, ipv6Supported)
}
