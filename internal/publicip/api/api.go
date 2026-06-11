package api

import (
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
)

type Provider string

const (
	Cloudflare  Provider = "cloudflare"
	IfConfigCo  Provider = "ifconfigco"
	IPInfo      Provider = "ipinfo"
	IP2Location Provider = "ip2location"
)

const echoipPrefix = "echoip#"

type NameToken struct {
	Name  string
	Token string
}

func New(nameTokenPairs []NameToken, client *http.Client) (
	fetchers []Fetcher, err error,
) {
	fetchers = make([]Fetcher, len(nameTokenPairs))
	for i, nameTokenPair := range nameTokenPairs {
		provider, err := ParseProvider(nameTokenPair.Name)
		if err != nil {
			return nil, fmt.Errorf("parsing API name: %w", err)
		}
		switch {
		case provider == Cloudflare:
			fetchers[i] = newCloudflare(client)
		case provider == IfConfigCo:
			const ifConfigCoURL = "https://ifconfig.co"
			fetchers[i] = newEchoip(client, ifConfigCoURL)
		case provider == IPInfo:
			fetchers[i] = newIPInfo(client, nameTokenPair.Token)
		case provider == IP2Location:
			fetchers[i] = newIP2Location(client, nameTokenPair.Token)
		case strings.HasPrefix(string(provider), echoipPrefix):
			url := strings.TrimPrefix(string(provider), echoipPrefix)
			fetchers[i] = newEchoip(client, url)
		default:
			panic("provider not valid: " + provider)
		}
	}
	return fetchers, nil
}

var regexEchoipURL = regexp.MustCompile(`^http(s|):\/\/.+$`)

func ParseProvider(s string) (provider Provider, err error) {
	possibleProviders := []Provider{
		Cloudflare,
		IfConfigCo,
		IP2Location,
		IPInfo,
	}
	stringToProvider := make(map[string]Provider, len(possibleProviders))
	for _, provider := range possibleProviders {
		stringToProvider[string(provider)] = provider
	}
	provider, ok := stringToProvider[strings.ToLower(s)]
	if ok {
		return provider, nil
	}

	customPrefixToURLRegex := map[string]*regexp.Regexp{
		echoipPrefix: regexEchoipURL,
	}
	for prefix, urlRegex := range customPrefixToURLRegex {
		match, err := checkCustomURL(s, prefix, urlRegex)
		if !match {
			continue
		} else if err != nil {
			return "", err
		}
		return Provider(s), nil
	}

	providerStrings := make([]string, 0, len(stringToProvider)+len(customPrefixToURLRegex))
	for _, providerString := range slices.Sorted(maps.Keys(stringToProvider)) {
		providerStrings = append(providerStrings, `"`+providerString+`"`)
	}
	for _, prefix := range slices.Sorted(maps.Keys(customPrefixToURLRegex)) {
		providerStrings = append(providerStrings, "a custom "+prefix+" url")
	}

	return "", fmt.Errorf("API name is not valid: %q can only be %s",
		s, orStrings(providerStrings))
}

func checkCustomURL(s, prefix string, regex *regexp.Regexp) (match bool, err error) {
	if !strings.HasPrefix(s, prefix) {
		return false, nil
	}
	s = strings.TrimPrefix(s, prefix)
	_, err = url.Parse(s)
	if err != nil {
		return true, fmt.Errorf("%s custom URL is not valid: %w", prefix, err)
	}

	if regex.MatchString(s) {
		return true, nil
	}

	return true, fmt.Errorf("%s custom URL is not valid: "+
		"%q does not match regular expression: %s", prefix, s, regex)
}

func orStrings(strings []string) (result string) {
	return joinStrings(strings, "or")
}

func joinStrings(strings []string, lastJoin string) (result string) {
	if len(strings) == 0 {
		return ""
	}

	result = strings[0]
	for i := 1; i < len(strings); i++ {
		if i < len(strings)-1 {
			result += ", " + strings[i]
		} else {
			result += " " + lastJoin + " " + strings[i]
		}
	}

	return result
}
