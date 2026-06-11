package updater

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

type apiServer struct {
	country  string
	city     string
	hostname string
}

const apiURL = "https://support.fastestvpn.com/wp-admin/admin-ajax.php"

// The API URL and requests are shamelessly taken from network operations
// done on the page https://support.fastestvpn.com/vpn-servers/
func fetchAPIServers(ctx context.Context, client *http.Client, protocol string) (
	servers []apiServer, err error,
) {
	form := url.Values{
		"action":   []string{"vpn_servers"},
		"protocol": []string{protocol},
	}
	body := strings.NewReader(form.Encode())

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, apiURL, body)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// request.Header.Set("User-Agent", "curl/8.9.0")
	// request.Header.Set("Accept", "*/*")

	response, err := client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("sending request: %w", err)
	}

	if response.StatusCode != http.StatusOK {
		_ = response.Body.Close()
		return nil, fmt.Errorf("HTTP status code not OK: %d", response.StatusCode)
	}

	data, err := io.ReadAll(response.Body)
	if err != nil {
		_ = response.Body.Close()
		return nil, fmt.Errorf("reading response body: %w", err)
	}

	err = response.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("closing response body: %w", err)
	}

	const usualMaxNumber = 100
	servers = make([]apiServer, 0, usualMaxNumber)

	for {
		trBlock := getNextTRBlock(data)
		if trBlock == nil {
			break
		}
		data = data[len(trBlock):]

		var server apiServer

		const numberOfTDBlocks = 3
		for i := range numberOfTDBlocks {
			tdBlock := getNextTDBlock(trBlock)
			if tdBlock == nil {
				return nil, fmt.Errorf("data is malformed: expected 3 <td> blocks in <tr> block %q",
					string(trBlock))
			}
			trBlock = trBlock[len(tdBlock):]

			const startToken, endToken = "<td>", "</td>"
			tdBlockData := string(tdBlock[len(startToken) : len(tdBlock)-len(endToken)])
			const countryIndex, cityIndex, hostnameIndex = 0, 1, 2
			switch i {
			case countryIndex:
				server.country = tdBlockData
			case cityIndex:
				server.city = tdBlockData
			case hostnameIndex:
				server.hostname = tdBlockData
			}
		}
		servers = append(servers, server)
	}

	return servers, nil
}

func getNextTRBlock(data []byte) (trBlock []byte) {
	const startToken, endToken = "<tr>", "</tr>"
	return getNextBlock(data, startToken, endToken)
}

func getNextTDBlock(data []byte) (tdBlock []byte) {
	const startToken, endToken = "<td>", "</td>"
	return getNextBlock(data, startToken, endToken)
}

func getNextBlock(data []byte, startToken, endToken string) (nextBlock []byte) {
	i := bytes.Index(data, []byte(startToken))
	if i == -1 {
		return nil
	}

	nextBlock = data[i:]
	i = bytes.Index(nextBlock[len(startToken):], []byte(endToken))
	if i == -1 {
		return nil
	}
	nextBlock = nextBlock[:i+len(startToken)+len(endToken)]
	return nextBlock
}
