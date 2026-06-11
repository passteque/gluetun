package html

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/html"
)

func parseTestHTML(t *testing.T, htmlString string) *html.Node {
	t.Helper()
	rootNode, err := html.Parse(strings.NewReader(htmlString))
	require.NoError(t, err)
	return rootNode
}

type roundTripFunc func(r *http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func Test_Fetch(t *testing.T) {
	t.Parallel()

	canceledCtx, cancel := context.WithCancel(context.Background())
	cancel()

	testCases := map[string]struct {
		ctx            context.Context
		url            string
		responseStatus int
		responseBody   io.ReadCloser
		rootNode       *html.Node
		errMessage     string
	}{
		"context canceled": {
			ctx:        canceledCtx,
			url:        "https://example.com/path",
			errMessage: `Get "https://example.com/path": context canceled`,
		},
		"response status not ok": {
			ctx:            context.Background(),
			url:            "https://example.com/path",
			responseStatus: http.StatusNotFound,
			errMessage:     `HTTP status code not OK: 404 Not Found`,
		},
		"success": {
			ctx:            context.Background(),
			url:            "https://example.com/path",
			responseStatus: http.StatusOK,
			rootNode:       parseTestHTML(t, "some body"),
			responseBody:   io.NopCloser(strings.NewReader("some body")),
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			client := &http.Client{
				Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
					assert.Equal(t, http.MethodGet, r.Method)
					assert.Equal(t, r.URL.String(), testCase.url)

					ctxErr := r.Context().Err()
					if ctxErr != nil {
						return nil, ctxErr
					}

					return &http.Response{
						StatusCode: testCase.responseStatus,
						Status:     http.StatusText(testCase.responseStatus),
						Body:       testCase.responseBody,
					}, nil
				}),
			}

			rootNode, err := Fetch(testCase.ctx, client, testCase.url)

			if testCase.errMessage != "" {
				assert.EqualError(t, err, testCase.errMessage)
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, testCase.rootNode, rootNode)
		})
	}
}
