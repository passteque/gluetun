package cryptostorm

import (
	"github.com/qdm12/gluetun/internal/configuration/settings"
	"github.com/qdm12/gluetun/internal/constants/openvpn"
	"github.com/qdm12/gluetun/internal/models"
	"github.com/qdm12/gluetun/internal/provider/utils"
)

func (p *Provider) OpenVPNConfig(connection models.Connection,
	settings settings.OpenVPN, ipv6Supported bool,
) (lines []string) {
	providerSettings := utils.OpenVPNProviderSettings{
		RemoteCertTLS:  true,
		AuthUserPass:   true,
		Ciphers:        []string{openvpn.AES256gcm},
		VerifyX509Type: "name",
		TLSCrypt:       "4875d729589689955012a2ee77f180ecb815c4a336c719c11241a058dafaae00806bbc21d5f1abad085341a3fca4b4f93949151c2979b4ee4390e8d9443acb0061d537f1e9157e45f542c3648f56330505f3eaff97ef82ee063b9d88bb9d5aa0060428455b51a2a4fd929d9af4b94adcb0a4acaa14ff62a9b0f4f9f0b3f01e71fc98a6c60e8584f4deb3de793a5a7bc27014c9369f9724bc810ef0d191b3020478eead725b3ae6aaef2e1030a197e417421f159ed54eb2629afcfb337cf9a0025bf1d5c0d820fffb219d0b4214043d2df27ed367b522945a5dadc748e2ca379e3971789dbdf609b3d9bfe866361b28e3c90589baa925157ad833093a5a7bede5", //nolint:lll
		CAs:            []string{"MIICCzCCAW2gAwIBAgIUMRTTJ6nuPjmSxaRfbw5f+dZ9d/gwCgYIKoZIzj0EAwQwGTEXMBUGA1UEAwwOY3J5cHRvc3Rvcm0gQ0EwHhcNMTgwOTE3MjAwODU4WhcNMzgwOTE3MjAwODU4WjAZMRcwFQYDVQQDDA5jcnlwdG9zdG9ybSBDQTCBmzAQBgcqhkjOPQIBBgUrgQQAIwOBhgAEARKu20PBrr226TP6mQQGtzCqQqBKfGaA05Ml5nrGSV6wzBQDQga4/cPepGrE/tpzRX72KSfZD6nJfQLYen7kdc3PAEvWFBhCovq7e4L6xJ5qV5aMf89QjNhJ/xn//dlxE8Z6UfIx63dJX9q3EHNxateU84lDkbCrqckkckcZF4C1a9Ooo1AwTjAdBgNVHQ4EFgQUdaVDaoi48Yf2RugXqJ4yJ4Z4utgwHwYDVR0jBBgwFoAUdaVDaoi48Yf2RugXqJ4yJ4Z4utgwDAYDVR0TBAUwAwEB/zAKBggqhkjOPQQDBAOBiwAwgYcCQVcCw/8OVpNqltDYczqHmX4sMRsZTY0iIzl1rYY/0/ZPIvzjlMFnouHwb8asJZRMBNECq7u9PCbG3jdu6lYtcCm+AkIB3IYYKuXLKW7ucdttNODBqH2Rail+9oBWTV2ZFKVVwELlKadHx9UvAcpAaV1alkN80CgI2tad2/qVdpSIQpfVvTI="}, //nolint:lll
	}
	return utils.OpenVPNConfig(providerSettings, connection, settings, ipv6Supported)
}
