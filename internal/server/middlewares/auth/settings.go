package auth

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"

	"github.com/qdm12/gosettings"
	"github.com/qdm12/gosettings/validate"
	"github.com/qdm12/gotree"
)

type Settings struct {
	// Roles is a list of roles with their associated authentication
	// and routes.
	Roles []Role
}

// SetDefaultRole sets a default role to apply to all routes without a
// previously user-defined role assigned to. Note the role argument
// routes are ignored. This should be called BEFORE calling [Settings.SetDefaults].
func (s *Settings) SetDefaultRole(jsonRole string) error {
	var role Role
	decoder := json.NewDecoder(bytes.NewBufferString(jsonRole))
	decoder.DisallowUnknownFields()
	err := decoder.Decode(&role)
	if err != nil {
		return fmt.Errorf("decoding default role: %w", err)
	}
	if role.Auth == "" {
		return nil // no default role to set
	}
	err = role.Validate()
	if err != nil {
		return fmt.Errorf("validating default role: %w", err)
	}

	authenticatedRoutes := make(map[string]struct{}, len(validRoutes))
	for _, role := range s.Roles {
		for _, route := range role.Routes {
			authenticatedRoutes[route] = struct{}{}
		}
	}

	if len(authenticatedRoutes) == len(validRoutes) {
		return nil
	}

	unauthenticatedRoutes := make([]string, 0, len(validRoutes))
	for route := range validRoutes {
		_, authenticated := authenticatedRoutes[route]
		if !authenticated {
			unauthenticatedRoutes = append(unauthenticatedRoutes, route)
		}
	}

	slices.Sort(unauthenticatedRoutes)
	role.Routes = unauthenticatedRoutes
	s.Roles = append(s.Roles, role)
	return nil
}

func (s Settings) Validate() (err error) {
	for i, role := range s.Roles {
		err = role.Validate()
		if err != nil {
			return fmt.Errorf("role %s (%d of %d): %w",
				role.Name, i+1, len(s.Roles), err)
		}
	}

	return nil
}

const (
	AuthNone   = "none"
	AuthAPIKey = "apikey"
	AuthBasic  = "basic"
)

// Role contains the role name, authentication method name and
// routes that the role can access.
type Role struct {
	// Name is the role name and is only used for documentation
	// and in the authentication middleware debug logs.
	Name string `json:"name"`
	// Auth is the authentication method to use, which can be 'none', 'basic' or 'apikey'.
	Auth string `json:"auth"`
	// APIKey is the API key to use when using the 'apikey' authentication.
	APIKey string `json:"apikey"`
	// Username for HTTP Basic authentication method.
	Username string `json:"username"`
	// Password for HTTP Basic authentication method.
	Password string `json:"password"`
	// Routes is a list of routes that the role can access in the format
	// "HTTP_METHOD PATH", for example "GET /v1/vpn/status"
	Routes []string `json:"-"`
}

var (
	ErrMethodNotSupported = errors.New("authentication method not supported")
	ErrAPIKeyEmpty        = errors.New("api key is empty")
	ErrBasicUsernameEmpty = errors.New("username is empty")
	ErrBasicPasswordEmpty = errors.New("password is empty")
	ErrRouteNotSupported  = errors.New("route not supported by the control server")
)

func (r Role) Validate() (err error) {
	err = validate.IsOneOf(r.Auth, AuthNone, AuthAPIKey, AuthBasic)
	if err != nil {
		return fmt.Errorf("%w: %s", ErrMethodNotSupported, r.Auth)
	}

	switch {
	case r.Auth == AuthAPIKey && r.APIKey == "":
		return fmt.Errorf("for role %s: %w", r.Name, ErrAPIKeyEmpty)
	case r.Auth == AuthBasic && r.Username == "":
		return fmt.Errorf("for role %s: %w", r.Name, ErrBasicUsernameEmpty)
	case r.Auth == AuthBasic && r.Password == "":
		return fmt.Errorf("for role %s: %w", r.Name, ErrBasicPasswordEmpty)
	}

	for i, route := range r.Routes {
		_, ok := validRoutes[route]
		if !ok {
			return fmt.Errorf("route %d of %d: %w: %s",
				i+1, len(r.Routes), ErrRouteNotSupported, route)
		}
	}

	return nil
}

// WARNING: do not mutate programmatically.
var validRoutes = map[string]struct{}{ //nolint:gochecknoglobals
	http.MethodGet + " /openvpn/actions/restart":  {},
	http.MethodGet + " /openvpn/portforwarded":    {},
	http.MethodGet + " /openvpn/settings":         {},
	http.MethodGet + " /unbound/actions/restart":  {},
	http.MethodGet + " /updater/restart":          {},
	http.MethodGet + " /v1/version":               {},
	http.MethodGet + " /v1/vpn/status":            {},
	http.MethodPut + " /v1/vpn/status":            {},
	http.MethodGet + " /v1/vpn/settings":          {},
	http.MethodPut + " /v1/vpn/settings":          {},
	http.MethodGet + " /v1/openvpn/status":        {},
	http.MethodPut + " /v1/openvpn/status":        {},
	http.MethodGet + " /v1/openvpn/portforwarded": {},
	http.MethodGet + " /v1/openvpn/settings":      {},
	http.MethodGet + " /v1/dns/status":            {},
	http.MethodPut + " /v1/dns/status":            {},
	http.MethodGet + " /v1/updater/status":        {},
	http.MethodPut + " /v1/updater/status":        {},
	http.MethodGet + " /v1/publicip/ip":           {},
	http.MethodGet + " /v1/portforward":           {},
	http.MethodPut + " /v1/portforward":           {},
}

func (r Role) ToLinesNode() (node *gotree.Node) {
	node = gotree.New("Role " + r.Name)
	node.Appendf("Authentication method: %s", r.Auth)
	switch r.Auth {
	case AuthNone:
	case AuthBasic:
		node.Appendf("Username: %s", r.Username)
		node.Appendf("Password: %s", gosettings.ObfuscateKey(r.Password))
	case AuthAPIKey:
		node.Appendf("API key: %s", gosettings.ObfuscateKey(r.APIKey))
	default:
		panic("missing code for authentication method: " + r.Auth)
	}
	node.Appendf("Number of routes covered: %d", len(r.Routes))
	return node
}
