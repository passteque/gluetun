package restrictednet

import (
	"context"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_newHTTPSClient_usesRootCAs(t *testing.T) {
	t.Parallel()

	rootCAs := x509.NewCertPool()
	dial := func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("unexpected dial")
	}
	client := newHTTPSClient("pia-server", dial, rootCAs)

	transport, ok := client.Transport.(*http.Transport)
	require.True(t, ok)
	assert.Same(t, rootCAs, transport.TLSClientConfig.RootCAs)
}

func Test_Client_OpenHTTPSWithRootCAs_requiresRootCAs(t *testing.T) {
	t.Parallel()

	_, _, err := new(Client).OpenHTTPSWithRootCAs(t.Context(), "pia-server", netip.AddrPort{}, nil)
	assert.EqualError(t, err, "root certificate pool is not set")
}
