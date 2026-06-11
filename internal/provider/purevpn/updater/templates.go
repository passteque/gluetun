package updater

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
)

const (
	atomAuthPath               = "auth/v1/accessToken"
	speedtestWithoutPSKAPIPath = "speedtest/v4/serversWithoutPsk"
)

var (
	atomAPIBaseURLRegex  = regexp.MustCompile(`AtomApi,\s*"BASE_URL",\s*"([^"]+)"`)
	atomSecretRegex      = regexp.MustCompile(`ATOM_SECRET["']?\s*[:=]\s*["']([A-Za-z0-9_-]{12,})["']`)
	cryptoKeyRegex       = regexp.MustCompile(`\bp\s*=\s*"([^"]+)"`)
	controlCharRegex     = regexp.MustCompile(`[[:cntrl:]]`)
	configFieldNeedle    = []byte(`"configuration":"`)
	defaultAtomSecret    = "MkvGuMCi6nabLqnjATh3HxN1Hh3iZI"
)

type openVPNTemplate struct {
	Version       string `json:"version"`
	Configuration string `json:"configuration"`
}

func fetchOpenVPNTemplates(ctx context.Context, httpClient *http.Client,
	asarContent, inventoryContent []byte, username, password string,
) (templates []openVPNTemplate, err error) {
	atomSecret := resolveAtomSecret(asarContent)

	endpointsContent, _, err := extractFirstFileFromAsar(asarContent,
		inventoryEndpointsAsarPath,
		"node_modules/atom-sdk/node_modules/inventory/node_modules/utils/lib/constants/end-points.js")
	if err != nil {
		return nil, fmt.Errorf("extracting endpoints JS from app.asar: %w", err)
	}
	atomAPIBaseURL, err := parseAtomAPIBaseURL(endpointsContent)
	if err != nil {
		return nil, fmt.Errorf("parsing atom API base URL: %w", err)
	}

	cryptoContent, _, err := extractFirstFileFromAsar(asarContent,
		"node_modules/atom-sdk/node_modules/utils/src/crypto.js",
		"node_modules/atom-sdk/node_modules/utils/lib/crypto.js")
	if err != nil {
		return nil, fmt.Errorf("extracting crypto JS from app.asar: %w", err)
	}
	cryptoKeyBase64, err := parseCryptoKeyBase64(cryptoContent)
	if err != nil {
		return nil, fmt.Errorf("parsing crypto key from app.asar: %w", err)
	}

	inventoryVersions, err := parseInventoryConfigurationVersions(inventoryContent)
	if err != nil {
		return nil, fmt.Errorf("parsing configuration versions from inventory: %w", err)
	}
	versionSet := make(map[string]struct{}, len(inventoryVersions))
	for _, version := range inventoryVersions {
		versionSet[version] = struct{}{}
	}

	hts, _, err := parseInventoryJSON(inventoryContent)
	if err != nil {
		return nil, fmt.Errorf("parsing inventory hosts: %w", err)
	}
	countrySlugs := countrySlugsFromHosts(hts)
	if len(countrySlugs) == 0 {
		return nil, fmt.Errorf("no country slugs found in inventory hosts")
	}

	accessToken, resellerID, err := fetchAccessToken(ctx, httpClient, atomAPIBaseURL, atomSecret)
	if err != nil {
		return nil, fmt.Errorf("fetching atom API access token: %w", err)
	}

	encryptedPassword, err := encryptForAtom(password, cryptoKeyBase64)
	if err != nil {
		return nil, fmt.Errorf("encrypting password: %w", err)
	}

	templatesByVersion := make(map[string]string, len(versionSet))
	for _, countrySlug := range countrySlugs {
		responseBody, err := fetchSpeedtestServersWithoutPSK(ctx, httpClient, atomAPIBaseURL, accessToken,
			resellerID, username, encryptedPassword, countrySlug)
		if err != nil {
			continue
		}

		servers, err := parseSpeedtestServers(responseBody)
		if err != nil {
			continue
		}
		for _, server := range servers {
			version := strings.TrimSpace(server.ConfigurationVersion)
			configuration := strings.TrimSpace(server.Configuration)
			if version == "" || configuration == "" {
				continue
			}
			if len(versionSet) > 0 {
				if _, needed := versionSet[version]; !needed {
					continue
				}
			}
			if _, exists := templatesByVersion[version]; exists {
				continue
			}
			templatesByVersion[version] = configuration
		}

		if len(versionSet) > 0 && len(templatesByVersion) == len(versionSet) {
			break
		}
	}

	versions := make([]string, 0, len(templatesByVersion))
	for version := range templatesByVersion {
		versions = append(versions, version)
	}
	sort.Strings(versions)

	templates = make([]openVPNTemplate, 0, len(versions))
	for _, version := range versions {
		templates = append(templates, openVPNTemplate{
			Version:       version,
			Configuration: templatesByVersion[version],
		})
	}

	return templates, nil
}

func resolveAtomSecret(asarContent []byte) (atomSecret string) {
	if extracted := parseAtomSecretFromContent(asarContent); extracted != "" {
		return extracted
	}

	return defaultAtomSecret
}

func parseAtomSecretFromContent(content []byte) (atomSecret string) {
	match := atomSecretRegex.FindSubmatch(content)
	if len(match) != 2 {
		return ""
	}
	return strings.TrimSpace(string(match[1]))
}

func parseAtomAPIBaseURL(content []byte) (baseURL string, err error) {
	match := atomAPIBaseURLRegex.FindSubmatch(content)
	if len(match) != 2 {
		return "", fmt.Errorf("atom API base URL not found")
	}
	baseURL = strings.TrimSpace(string(match[1]))
	if baseURL == "" {
		return "", fmt.Errorf("atom API base URL is empty")
	}
	if !strings.HasSuffix(baseURL, "/") {
		baseURL += "/"
	}
	return baseURL, nil
}

func parseCryptoKeyBase64(content []byte) (keyBase64 string, err error) {
	match := cryptoKeyRegex.FindSubmatch(content)
	if len(match) != 2 {
		return "", fmt.Errorf("crypto key not found")
	}
	keyBase64 = strings.TrimSpace(string(match[1]))
	if keyBase64 == "" {
		return "", fmt.Errorf("crypto key is empty")
	}
	return keyBase64, nil
}

func fetchAccessToken(ctx context.Context, httpClient *http.Client,
	baseURL, atomSecret string,
) (accessToken, resellerID string, err error) {
	payload := map[string]string{
		"secretKey": atomSecret,
		"grantType": "secret",
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return "", "", fmt.Errorf("marshalling auth request: %w", err)
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+atomAuthPath, bytes.NewReader(data))
	if err != nil {
		return "", "", fmt.Errorf("creating auth request: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")

	response, err := httpClient.Do(request)
	if err != nil {
		return "", "", fmt.Errorf("doing auth request: %w", err)
	}
	defer response.Body.Close()

	responseData := map[string]any{}
	if err := json.NewDecoder(response.Body).Decode(&responseData); err != nil {
		return "", "", fmt.Errorf("decoding auth response: %w", err)
	}

	bodyMap, _ := responseData["body"].(map[string]any)
	accessToken = strings.TrimSpace(fmt.Sprint(bodyMap["accessToken"]))
	resellerID = strings.TrimSpace(fmt.Sprint(bodyMap["resellerId"]))
	if accessToken == "" || resellerID == "" {
		return "", "", fmt.Errorf("access token or reseller id missing in auth response")
	}

	return accessToken, resellerID, nil
}

func encryptForAtom(plainText, keyBase64 string) (encrypted string, err error) {
	key, err := base64.StdEncoding.DecodeString(keyBase64)
	if err != nil {
		return "", fmt.Errorf("decoding base64 key: %w", err)
	}
	if len(key) != 16 && len(key) != 32 {
		return "", fmt.Errorf("invalid key length: %d", len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("creating AES cipher: %w", err)
	}
	iv := key[:aes.BlockSize]
	plainBytes := []byte(plainText)
	padded := pkcs7Pad(plainBytes, aes.BlockSize)

	cipherText := make([]byte, len(padded))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(cipherText, padded)

	return base64.StdEncoding.EncodeToString(cipherText), nil
}

func pkcs7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	if padding == 0 {
		padding = blockSize
	}
	padded := make([]byte, len(data)+padding)
	copy(padded, data)
	for i := len(data); i < len(padded); i++ {
		padded[i] = byte(padding)
	}
	return padded
}

type speedtestServer struct {
	ConfigurationVersion string `json:"configuration_version"`
	Configuration        string `json:"configuration"`
}

func fetchSpeedtestServersWithoutPSK(ctx context.Context, httpClient *http.Client,
	baseURL, accessToken, resellerID, username, encryptedPassword, countrySlug string,
) (responseBody []byte, err error) {
	payload := map[string]any{
		"sCountrySlug":   countrySlug,
		"iMultiPort":     0,
		"sProtocolSlug1": "udp",
		"sProtocolSlug2": "tcp",
		"sProtocolSlug3": "",
		"iMcs":           1,
		"iResellerId":    resellerID,
		"sDeviceType":    "linux",
		"sUsername":      username,
		"sPassword":      encryptedPassword,
		"aServerFilter":  []string{},
		"iNatting":       0,
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshalling speedtest request: %w", err)
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodPost,
		baseURL+speedtestWithoutPSKAPIPath, bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("creating speedtest request: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-AccessToken", accessToken)

	response, err := httpClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("doing speedtest request: %w", err)
	}
	defer response.Body.Close()

	return ioReadAllAndSanitize(response)
}

func ioReadAllAndSanitize(response *http.Response) ([]byte, error) {
	var responseBody bytes.Buffer
	if _, err := responseBody.ReadFrom(response.Body); err != nil {
		return nil, fmt.Errorf("reading speedtest response body: %w", err)
	}
	return sanitizeSpeedtestResponseJSON(responseBody.Bytes()), nil
}

func sanitizeSpeedtestResponseJSON(content []byte) []byte {
	if json.Valid(content) {
		return content
	}

	result := make([]byte, 0, len(content)+1024)
	for index := 0; index < len(content); {
		relative := bytes.Index(content[index:], configFieldNeedle)
		if relative == -1 {
			result = append(result, content[index:]...)
			break
		}
		start := index + relative
		result = append(result, content[index:start]...)
		result = append(result, configFieldNeedle...)
		valueStart := start + len(configFieldNeedle)
		valueEnd := valueStart
		for valueEnd < len(content) {
			if content[valueEnd] == '"' && (valueEnd == valueStart || content[valueEnd-1] != '\\') {
				break
			}
			valueEnd++
		}
		if valueEnd >= len(content) {
			result = append(result, content[valueStart:]...)
			break
		}
		escaped := strings.Trim(strconvQuote(string(content[valueStart:valueEnd])), `"`)
		result = append(result, escaped...)
		result = append(result, '"')
		index = valueEnd + 1
	}
	return result
}

func strconvQuote(value string) string {
	value = controlCharRegex.ReplaceAllString(value, "")
	return strconv.Quote(value)
}

func parseSpeedtestServers(content []byte) (servers []speedtestServer, err error) {
	var response struct {
		Body any `json:"body"`
	}
	if err := json.Unmarshal(content, &response); err != nil {
		return nil, fmt.Errorf("unmarshalling speedtest response: %w", err)
	}

	bodyBytes, err := json.Marshal(response.Body)
	if err != nil {
		return nil, fmt.Errorf("marshalling speedtest body: %w", err)
	}

	if err := json.Unmarshal(bodyBytes, &servers); err == nil && len(servers) > 0 {
		return servers, nil
	}

	var bodyObject struct {
		Servers []speedtestServer `json:"servers"`
	}
	if err := json.Unmarshal(bodyBytes, &bodyObject); err == nil {
		return bodyObject.Servers, nil
	}

	return nil, nil
}

func countrySlugsFromHosts(hts hostToServer) (countrySlugs []string) {
	set := make(map[string]struct{})
	for host := range hts {
		countrySlug := parsePureVPNCountrySlug(host)
		if countrySlug == "" {
			continue
		}
		if _, ok := set[countrySlug]; ok {
			continue
		}
		set[countrySlug] = struct{}{}
		countrySlugs = append(countrySlugs, countrySlug)
	}

	sort.Strings(countrySlugs)

	// Pulling from the largest geographies first tends to recover all active
	// configuration versions with fewer requests.
	prioritized := []string{"us", "uk", "de", "fr", "nl", "sg", "jp", "au", "ca"}
	sort.SliceStable(countrySlugs, func(i, j int) bool {
		iIndex := slices.Index(prioritized, countrySlugs[i])
		jIndex := slices.Index(prioritized, countrySlugs[j])
		if iIndex == -1 {
			iIndex = len(prioritized) + i
		}
		if jIndex == -1 {
			jIndex = len(prioritized) + j
		}
		return iIndex < jIndex
	})

	return countrySlugs
}

func parsePureVPNCountrySlug(hostname string) (countrySlug string) {
	firstLabel := hostname
	if dotIndex := strings.IndexByte(hostname, '.'); dotIndex > -1 {
		firstLabel = hostname[:dotIndex]
	}

	twoMinusIndex := strings.Index(firstLabel, "2-")
	if twoMinusIndex <= 0 {
		return ""
	}

	locationCode := strings.ToLower(firstLabel[:twoMinusIndex])
	if len(locationCode) < 2 {
		return ""
	}
	return locationCode[:2]
}
