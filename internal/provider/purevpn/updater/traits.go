package updater

import "strings"

// inferPureVPNTraits infers the server traits from the tokens of its first
// hostname label, for example `us2-udp-qr-pf` is a quantum-resistant server
// accepting port forwarding over UDP.
// The p2p trait is only found in the old hostnames (jumptoserver.com), the
// current inventory only exposes it as a country-level feature, and it means
// the servers are optimized for file sharing rather than port forwarding.
func inferPureVPNTraits(hostname string) (portForward, quantumResistant, obfuscated, p2p bool) {
	labels := strings.Split(strings.ToLower(hostname), ".")
	if len(labels) == 0 {
		return false, false, false, false
	}

	for token := range strings.SplitSeq(labels[0], "-") {
		switch token {
		case "pf":
			portForward = true
		case "qr":
			quantumResistant = true
		case "obf":
			obfuscated = true
		case "p2p":
			p2p = true
		}
	}

	return portForward, quantumResistant, obfuscated, p2p
}
