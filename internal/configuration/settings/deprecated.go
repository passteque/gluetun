package settings

import (
	"slices"

	"github.com/qdm12/gosettings/reader"
	"golang.org/x/exp/maps"
)

func readObsolete(r *reader.Reader) (warnings []string) {
	keyToMessage := map[string]string{
		"DOT_VERBOSITY":                "DOT_VERBOSITY is obsolete, use LOG_LEVEL instead.",
		"DOT_VERBOSITY_DETAILS":        "DOT_VERBOSITY_DETAILS is obsolete because it was specific to Unbound.",
		"DOT_VALIDATION_LOGLEVEL":      "DOT_VALIDATION_LOGLEVEL is obsolete because DNSSEC validation is not implemented.",
		"HEALTH_VPN_DURATION_INITIAL":  "HEALTH_VPN_DURATION_INITIAL is obsolete",
		"HEALTH_VPN_DURATION_ADDITION": "HEALTH_VPN_DURATION_ADDITION is obsolete",
		"DNS_SERVER":                   "DNS_SERVER is obsolete because the forwarding server is always enabled.",
		"DOT":                          "DOT is obsolete because the forwarding server is always enabled.",
		"DNS_KEEP_NAMESERVER": "DNS_KEEP_NAMESERVER is obsolete because the forwarding server is always used and " +
			"forwards local names to private DNS resolvers found in /etc/resolv.conf",
	}
	sortedKeys := maps.Keys(keyToMessage)
	slices.Sort(sortedKeys)
	warnings = make([]string, 0, len(keyToMessage))
	for _, key := range sortedKeys {
		if r.Get(key) != nil {
			warnings = append(warnings, keyToMessage[key])
		}
	}
	return warnings
}
