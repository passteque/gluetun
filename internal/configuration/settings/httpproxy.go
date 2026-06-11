package settings

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/qdm12/gosettings"
	"github.com/qdm12/gosettings/reader"
	"github.com/qdm12/gosettings/validate"
	"github.com/qdm12/gotree"
)

// HTTPProxy contains settings to configure the HTTP proxy.
type HTTPProxy struct {
	// User is the username to use for the HTTP proxy.
	// It cannot be nil in the internal state.
	User *string
	// Password is the password to use for the HTTP proxy.
	// It cannot be nil in the internal state.
	Password *string
	// ListeningAddress is the listening address
	// of the HTTP proxy server.
	// It cannot be the empty string in the internal state.
	ListeningAddress string
	// Enabled is true if the HTTP proxy server should run,
	// and false otherwise. It cannot be nil in the
	// internal state.
	Enabled *bool
	// Stealth is true if the HTTP proxy server should hide
	// each request has been proxied to the destination.
	// It cannot be nil in the internal state.
	Stealth *bool
	// Log is true if the HTTP proxy server should log
	// each request/response. It cannot be nil in the
	// internal state.
	Log *bool
	// ReadHeaderTimeout is the HTTP header read timeout duration
	// of the HTTP server. It defaults to 1 second if left unset.
	ReadHeaderTimeout time.Duration
	// ReadTimeout is the HTTP read timeout duration
	// of the HTTP server. It defaults to 3 seconds if left unset.
	ReadTimeout time.Duration
}

func (h HTTPProxy) validate() (err error) {
	// Do not validate user and password
	err = validate.ListeningAddress(h.ListeningAddress, os.Getuid())
	if err != nil {
		return fmt.Errorf("server listening address is not valid: %w", err)
	}

	return nil
}

func (h *HTTPProxy) copy() (copied HTTPProxy) {
	return HTTPProxy{
		User:              gosettings.CopyPointer(h.User),
		Password:          gosettings.CopyPointer(h.Password),
		ListeningAddress:  h.ListeningAddress,
		Enabled:           gosettings.CopyPointer(h.Enabled),
		Stealth:           gosettings.CopyPointer(h.Stealth),
		Log:               gosettings.CopyPointer(h.Log),
		ReadHeaderTimeout: h.ReadHeaderTimeout,
		ReadTimeout:       h.ReadTimeout,
	}
}

// overrideWith overrides fields of the receiver
// settings object with any field set in the other
// settings.
func (h *HTTPProxy) overrideWith(other HTTPProxy) {
	h.User = gosettings.OverrideWithPointer(h.User, other.User)
	h.Password = gosettings.OverrideWithPointer(h.Password, other.Password)
	h.ListeningAddress = gosettings.OverrideWithComparable(h.ListeningAddress, other.ListeningAddress)
	h.Enabled = gosettings.OverrideWithPointer(h.Enabled, other.Enabled)
	h.Stealth = gosettings.OverrideWithPointer(h.Stealth, other.Stealth)
	h.Log = gosettings.OverrideWithPointer(h.Log, other.Log)
	h.ReadHeaderTimeout = gosettings.OverrideWithComparable(h.ReadHeaderTimeout, other.ReadHeaderTimeout)
	h.ReadTimeout = gosettings.OverrideWithComparable(h.ReadTimeout, other.ReadTimeout)
}

func (h *HTTPProxy) setDefaults() {
	h.User = gosettings.DefaultPointer(h.User, "")
	h.Password = gosettings.DefaultPointer(h.Password, "")
	h.ListeningAddress = gosettings.DefaultComparable(h.ListeningAddress, ":8888")
	h.Enabled = gosettings.DefaultPointer(h.Enabled, false)
	h.Stealth = gosettings.DefaultPointer(h.Stealth, false)
	h.Log = gosettings.DefaultPointer(h.Log, false)
	const defaultReadHeaderTimeout = time.Second
	h.ReadHeaderTimeout = gosettings.DefaultComparable(h.ReadHeaderTimeout, defaultReadHeaderTimeout)
	const defaultReadTimeout = 3 * time.Second
	h.ReadTimeout = gosettings.DefaultComparable(h.ReadTimeout, defaultReadTimeout)
}

func (h HTTPProxy) String() string {
	return h.toLinesNode().String()
}

func (h HTTPProxy) toLinesNode() (node *gotree.Node) {
	node = gotree.New("HTTP proxy settings:")
	node.Appendf("Enabled: %s", gosettings.BoolToYesNo(h.Enabled))
	if !*h.Enabled {
		return node
	}

	node.Appendf("Listening address: %s", h.ListeningAddress)
	node.Appendf("User: %s", *h.User)
	node.Appendf("Password: %s", gosettings.ObfuscateKey(*h.Password))
	node.Appendf("Stealth mode: %s", gosettings.BoolToYesNo(h.Stealth))
	node.Appendf("Log: %s", gosettings.BoolToYesNo(h.Log))
	node.Appendf("Read header timeout: %s", h.ReadHeaderTimeout)
	node.Appendf("Read timeout: %s", h.ReadTimeout)

	return node
}

func (h *HTTPProxy) read(r *reader.Reader) (err error) {
	h.User = r.Get("HTTPPROXY_USER",
		reader.RetroKeys("PROXY_USER", "TINYPROXY_USER"),
		reader.ForceLowercase(false))

	h.Password = r.Get("HTTPPROXY_PASSWORD",
		reader.RetroKeys("PROXY_PASSWORD", "TINYPROXY_PASSWORD"),
		reader.ForceLowercase(false))

	h.ListeningAddress, err = readHTTProxyListeningAddress(r)
	if err != nil {
		return err
	}

	h.Enabled, err = r.BoolPtr("HTTPPROXY", reader.RetroKeys("PROXY", "TINYPROXY"))
	if err != nil {
		return err
	}

	h.Stealth, err = r.BoolPtr("HTTPPROXY_STEALTH")
	if err != nil {
		return err
	}

	h.Log, err = readHTTProxyLog(r)
	if err != nil {
		return err
	}

	return nil
}

func readHTTProxyListeningAddress(r *reader.Reader) (listeningAddress string, err error) {
	// Retro-compatible keys using a port only
	port, err := r.Uint16Ptr("",
		reader.RetroKeys("HTTPPROXY_PORT", "TINYPROXY_PORT", "PROXY_PORT"),
		reader.IsRetro("HTTPPROXY_LISTENING_ADDRESS"))
	if err != nil {
		return "", err
	} else if port != nil {
		return fmt.Sprintf(":%d", *port), nil
	}
	const currentKey = "HTTPPROXY_LISTENING_ADDRESS"
	return r.String(currentKey), nil
}

func readHTTProxyLog(r *reader.Reader) (enabled *bool, err error) {
	const currentKey = "HTTPPROXY_LOG"
	// Retro-compatible keys using different boolean verbs
	value := r.String("",
		reader.RetroKeys("PROXY_LOG", "TINYPROXY_LOG"),
		reader.IsRetro(currentKey))
	switch strings.ToLower(value) {
	case "":
		return r.BoolPtr(currentKey)
	case "on", "info", "connect", "notice":
		return ptrTo(true), nil
	case "disabled", "no", "off":
		return ptrTo(false), nil
	default:
		return nil, fmt.Errorf("HTTP retro-compatible proxy log setting: value is unknown: %s", value)
	}
}
