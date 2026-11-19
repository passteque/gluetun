package updater

import (
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_extractDebURL(t *testing.T) {
	t.Parallel()

	file, err := os.Open("testdata/index.html.gz")
	require.NoError(t, err)
	defer file.Close()

	gzipReader, err := gzip.NewReader(file)
	require.NoError(t, err)
	defer gzipReader.Close()

	html, err := io.ReadAll(gzipReader)
	require.NoError(t, err)

	debURLs, err := extractDebURL(string(html), "https://www.purevpn.com/download/linux-vpn")
	require.NoError(t, err)

	const want = "https://dhnx3d2u57yhc.cloudfront.net/cross-platform/linux-gui/2.9.0/PureVPN_amd64.deb"

	assert.Equal(t, want, debURLs)
}

func Test_fetchURL(t *testing.T) {
	t.Parallel()

	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/file.deb":
			_, _ = writer.Write([]byte("content"))
		case "/redirect_http":
			http.Redirect(writer, request, "http://127.0.0.1/file.deb", http.StatusFound)
		case "/redirect_internal":
			http.Redirect(writer, request, "https://169.254.169.254/file.deb", http.StatusFound)
		default:
			http.NotFound(writer, request)
		}
	}))
	t.Cleanup(server.Close)

	testCases := map[string]struct {
		rawURL     string
		content    string
		errMessage string
	}{
		"allowed_url": {
			rawURL:  server.URL + "/file.deb",
			content: "content",
		},
		"http_url": {
			rawURL:     strings.Replace(server.URL, "https://", "http://", 1) + "/file.deb",
			errMessage: `checking URL: URL scheme "http" is not https`,
		},
		"redirect_to_http": {
			rawURL:     server.URL + "/redirect_http",
			errMessage: `checking redirect URL: URL scheme "http" is not https`,
		},
		"redirect_to_disallowed_host": {
			rawURL:     server.URL + "/redirect_internal",
			errMessage: `checking redirect URL: URL host "169.254.169.254" is not allowed`,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			body, err := fetchURL(t.Context(), server.Client(), testCase.rawURL, "127.0.0.1")

			if testCase.errMessage != "" {
				assert.ErrorContains(t, err, testCase.errMessage)
				return
			}
			require.NoError(t, err)
			defer body.Close()
			content, err := io.ReadAll(body)
			require.NoError(t, err)
			assert.Equal(t, testCase.content, string(content))
		})
	}
}

func Test_checkURL(t *testing.T) {
	t.Parallel()

	allowedHosts := []string{"dhnx3d2u57yhc.cloudfront.net"}

	testCases := map[string]struct {
		rawURL     string
		errMessage string
	}{
		"allowed_host": {
			rawURL: "https://dhnx3d2u57yhc.cloudfront.net/cross-platform/linux-gui/2.9.0/PureVPN_amd64.deb",
		},
		"purevpn_domain": {
			rawURL: "https://purevpn.com/file.deb",
		},
		"purevpn_subdomain": {
			rawURL: "https://download.purevpn.com/file.deb",
		},
		"uppercase_host": {
			rawURL: "https://WWW.PureVPN.com/file.deb",
		},
		"http_scheme": {
			rawURL:     "http://dhnx3d2u57yhc.cloudfront.net/file.deb",
			errMessage: `URL scheme "http" is not https`,
		},
		"other_cloudfront_subdomain": {
			rawURL:     "https://d1234567890abc.cloudfront.net/file.deb",
			errMessage: `URL host "d1234567890abc.cloudfront.net" is not allowed`,
		},
		"allowed_host_subdomain": {
			rawURL:     "https://evil.dhnx3d2u57yhc.cloudfront.net/file.deb",
			errMessage: `URL host "evil.dhnx3d2u57yhc.cloudfront.net" is not allowed`,
		},
		"internal_ip_address": {
			rawURL:     "https://169.254.169.254/file.deb",
			errMessage: `URL host "169.254.169.254" is not allowed`,
		},
		"localhost": {
			rawURL:     "https://localhost:8000/file.deb",
			errMessage: `URL host "localhost" is not allowed`,
		},
		"purevpn_domain_as_subdomain_prefix": {
			rawURL:     "https://purevpn.com.example.com/file.deb",
			errMessage: `URL host "purevpn.com.example.com" is not allowed`,
		},
		"purevpn_domain_as_name_suffix": {
			rawURL:     "https://evilpurevpn.com/file.deb",
			errMessage: `URL host "evilpurevpn.com" is not allowed`,
		},
		"malformed_url": {
			rawURL:     "https://%zz/file.deb",
			errMessage: "parsing URL",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			err := checkURL(testCase.rawURL, allowedHosts)

			if testCase.errMessage != "" {
				assert.ErrorContains(t, err, testCase.errMessage)
				return
			}
			assert.NoError(t, err)
		})
	}
}
