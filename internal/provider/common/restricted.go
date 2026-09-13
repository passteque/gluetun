package common

import (
	"context"
	"crypto/x509"
	"net/http"
	"net/netip"
)

type RestrictedClient interface {
	OpenHTTPSByHostname(ctx context.Context, hostname string) (
		httpClient *http.Client, cleanup func() error, err error)
	OpenHTTPSWithRootCAs(ctx context.Context, destinationTLSName string,
		destinationAddrPort netip.AddrPort, rootCAs *x509.CertPool) (
		httpClient *http.Client, cleanup func() error, err error)
}
