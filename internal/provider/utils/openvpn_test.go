package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestWrapOpenvpnCAs(t *testing.T) {
	t.Parallel()

	lines := WrapOpenvpnCAs([]string{"cert1", "cert2"})

	assert.Equal(t, []string{
		"<ca>",
		"-----BEGIN CERTIFICATE-----",
		"cert1",
		"-----END CERTIFICATE-----",
		"-----BEGIN CERTIFICATE-----",
		"cert2",
		"-----END CERTIFICATE-----",
		"</ca>",
	}, lines)
}

func TestWrapOpenvpnCA(t *testing.T) {
	t.Parallel()

	lines := WrapOpenvpnCA("cert1")

	assert.Equal(t, []string{
		"<ca>",
		"-----BEGIN CERTIFICATE-----",
		"cert1",
		"-----END CERTIFICATE-----",
		"</ca>",
	}, lines)
}
