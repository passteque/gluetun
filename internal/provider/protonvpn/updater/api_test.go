package updater

import (
	"context"
	crand "crypto/rand"
	"encoding/base64"
	"encoding/json"
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	srp "github.com/ProtonMail/go-srp"
	"github.com/pquerna/otp/totp"
	"github.com/qdm12/gluetun/internal/provider/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

const (
	testSRPVersion        = 4
	testSRPBitLength      = 2048
	testUsername          = "jakubqa"
	testPassword          = "abc123"
	testSaltB64           = "yKlc5/CvObfoiw=="
	testSRPSession        = "a1b2c3d4"
	testUID               = "c54b0e2c5e6a4f8b9d0e1f2a3b4c5d6e"
	testSessionID         = "b7c5e9d2a1f34860a8b2c4d6e8f0a1b3"
	testUnauthToken       = "unauth-cookie-token"
	testInitialToken      = "initial-auth-token"      //nolint:gosec
	testFinalToken        = "final-auth-token"        //nolint:gosec
	testTOTPSecret        = "JBSWY3DPEHPK3PXP"        //nolint:gosec
	testTOTPSecretOther   = "JBSWY3DPEHPK3PXS"        //nolint:gosec
	testTOTPSecretLower   = "jbswy3dpehpk3pxp"        //nolint:gosec
	testTOTPSecretSpaces  = "JBSWY3DP EHPK3PXP"       //nolint:gosec
	testTOTPSecretHyphens = "JBSW-Y3DP-EHPK-3PXP"     //nolint:gosec
	testVerificationToken = "test-verification-token" //nolint:gosec
	testRotatedSessionID  = "rotated-session-id"
	// testAuthResponseToken is the AUTH-<uid> token set by the auth response
	// when two-factor authentication is enabled.
	testAuthResponseToken = "auth-response-token"
	// testRefreshedToken is the AUTH-<uid> token set by the session refresh
	// response.
	testRefreshedToken = "refreshed-session-token"
)

// testModulusClearSign is a PGP clear-signed SRP modulus signed by Proton's
// public key, taken from the ProtonMail/go-srp tests.
//
//nolint:lll
const testModulusClearSign = `-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA256

W2z5HBi8RvsfYzZTS7qBaUxxPhsfHJFZpu3Kd6s1JafNrCCH9rfvPLrfuqocxWPgWDH2R8neK7PkNvjxto9TStuY5z7jAzWRvFWN9cQhAKkdWgy0JY6ywVn22+HFpF4cYesHrqFIKUPDMSSIlWjBVmEJZ/MusD44ZT29xcPrOqeZvwtCffKtGAIjLYPZIEbZKnDM1Dm3q2K/xS5h+xdhjnndhsrkwm9U9oyA2wxzSXFL+pdfj2fOdRwuR5nW0J2NFrq3kJjkRmpO/Genq1UW+TEknIWAb6VzJJJA244K/H8cnSx2+nSNZO3bbo6Ys228ruV9A8m6DhxmS+bihN3ttQ==
-----BEGIN PGP SIGNATURE-----
Version: ProtonMail
Comment: https://protonmail.com

wl4EARYIABAFAlwB1j0JEDUFhcTpUY8mAAD8CgEAnsFnF4cF0uSHKkXa1GIa
GO86yMV4zDZEZcDSJo0fgr8A/AlupGN9EdHlsrZLmTA1vhIx+rOgxdEff28N
kvNM7qIK
=q6vu
-----END PGP SIGNATURE-----`

// newSRPTestServer creates a Proton SRP server for the test credentials and
// returns it along with its base64-encoded challenge.
func newSRPTestServer(t *testing.T) (server *srp.Server, challenge string) {
	t.Helper()

	// The SRP server expects the verifier v = 2^x mod N, where x is the
	// password hash. It is computed with a dummy server ephemeral since the
	// verifier does not depend on it.
	dummyChallenge := base64.StdEncoding.EncodeToString(make([]byte, 256))
	srpAuth, err := srp.NewAuth(testSRPVersion, testUsername, []byte(testPassword),
		testSaltB64, testModulusClearSign, dummyChallenge)
	require.NoError(t, err)
	verifier, err := srpAuth.GenerateVerifier(testSRPBitLength)
	require.NoError(t, err)

	server, err = srp.NewServerFromSigned(testModulusClearSign, verifier, testSRPBitLength)
	require.NoError(t, err)

	serverEphemeral, err := server.GenerateChallenge()
	require.NoError(t, err)

	return server, base64.StdEncoding.EncodeToString(serverEphemeral)
}

// generateTestProofs generates the SRP proofs for the test credentials
// against the given base64-encoded challenge.
func generateTestProofs(t *testing.T, challenge string) (proofs *srp.Proofs) {
	t.Helper()

	srpAuth, err := srp.NewAuth(testSRPVersion, testUsername, []byte(testPassword),
		testSaltB64, testModulusClearSign, challenge)
	require.NoError(t, err)

	proofs, err = srpAuth.GenerateProofs(testSRPBitLength)
	require.NoError(t, err)

	return proofs
}

// testProtonAPI is a minimal mock of the Proton account API endpoints used by
// the apiClient authentication flow.
type testProtonAPI struct {
	// twoFAMask is returned in the `TwoFactor` and `2FA.Enabled` fields of the
	// auth response.
	twoFAMask uint
	// totpSecret is the secret registered on the account, used to validate the
	// submitted TOTP code.
	totpSecret string
	// hasVPNScope makes the scopes endpoint report the "vpn" scope.
	hasVPNScope bool
	// authChallengeRequests is the number of auth requests that should receive
	// a human verification challenge.
	authChallengeRequests int
	// twoFARejectWith200 makes the two-factor endpoint respond with HTTP 200
	// and an error code (no cookie), like Proton does for an invalid code.
	twoFARejectWith200 bool
	// twoFAWithoutNewCookie makes the two-factor endpoint not set a new
	// AUTH-<uid> cookie on success, like current Proton does (the existing
	// session cookie is upgraded server-side).
	twoFAWithoutNewCookie bool
	// rotatedSessionID, when set, is the Session-Id the two-factor response
	// sets, and that the scopes request must carry.
	rotatedSessionID string
	// setAuthCookieOnAuth makes the auth response set a new AUTH-<uid> cookie
	// (testAuthResponseToken) when two-factor authentication is enabled.
	setAuthCookieOnAuth bool
	// requiredLogicalsToken, when set, is the only AUTH-<uid> token the
	// logical servers endpoint accepts (others get an insufficient scope
	// error), like the real API does.
	requiredLogicalsToken string
	// refreshFails makes the session refresh endpoint fail.
	refreshFails bool
	// finalToken is the AUTH-<uid> token the scopes request must carry.
	finalToken string
	// mu protects authChallengeRequests and challenged.
	mu sync.Mutex
	// challenged reports whether a challenge was served, so the retried
	// request can be checked for the verification headers.
	challenged bool
}

// takeChallenge reports whether the next auth request should receive a human
// verification challenge, and consumes it.
func (api *testProtonAPI) takeChallenge() (take bool) {
	api.mu.Lock()
	defer api.mu.Unlock()
	if api.authChallengeRequests > 0 {
		api.authChallengeRequests--
		api.challenged = true
		take = true
	}
	return take
}

// wasChallenged reports whether a challenge was served so far.
func (api *testProtonAPI) wasChallenged() (challenged bool) {
	api.mu.Lock()
	defer api.mu.Unlock()
	return api.challenged
}

func (api *testProtonAPI) handler(t *testing.T, srpServer *srp.Server) http.Handler {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/core/v4/auth", api.handleAuth(t, srpServer))
	mux.HandleFunc("POST /api/core/v4/auth/2fa", api.handleAuth2FA(t))
	mux.HandleFunc("GET /api/core/v4/auth/scopes", api.handleScopes(t))
	mux.HandleFunc("POST /api/auth/refresh", api.handleRefresh(t))
	mux.HandleFunc("GET /api/vpn/v1/logicals", api.handleLogicals(t))
	return mux
}

// handleAuth validates the SRP proofs and responds like the Proton API,
// reporting the configured two-factor authentication status.
func (api *testProtonAPI) handleAuth(t *testing.T, srpServer *srp.Server) http.HandlerFunc {
	t.Helper()
	return func(writer http.ResponseWriter, request *http.Request) {
		defer request.Body.Close()

		// Simulate a human verification challenge.
		if api.takeChallenge() {
			writer.Header().Set("Content-Type", "application/json")
			writer.WriteHeader(http.StatusUnprocessableEntity)
			_ = json.NewEncoder(writer).Encode(map[string]any{
				"Code":  9001,
				"Error": "For security reasons, please complete CAPTCHA.",
				"Details": map[string]any{
					"HumanVerificationToken":   testVerificationToken,
					"HumanVerificationMethods": []string{"captcha"},
					"WebUrl":                   "https://verify.proton.me/?methods=captcha&token=" + testVerificationToken,
				},
			})
			return
		}

		// A retried request after a challenge must carry the human
		// verification token headers.
		if api.wasChallenged() {
			assert.Equal(t, testVerificationToken,
				request.Header.Get("x-pm-human-verification-token"))
			assert.Equal(t, "captcha",
				request.Header.Get("x-pm-human-verification-token-type"))
		}

		var body struct {
			ClientEphemeral string `json:"ClientEphemeral"`
			ClientProof     string `json:"ClientProof"`
		}
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		clientEphemeral, err := base64.StdEncoding.DecodeString(body.ClientEphemeral)
		if err != nil {
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		clientProof, err := base64.StdEncoding.DecodeString(body.ClientProof)
		if err != nil {
			writer.WriteHeader(http.StatusBadRequest)
			return
		}

		serverProof, err := srpServer.VerifyProofs(clientEphemeral, clientProof)
		if err != nil {
			writer.WriteHeader(http.StatusUnauthorized)
			return
		}

		writer.Header().Set("Content-Type", "application/json")
		if api.twoFAMask == 0 || api.setAuthCookieOnAuth {
			token := testInitialToken
			if api.setAuthCookieOnAuth {
				token = testAuthResponseToken
			}
			writer.Header().Add("Set-Cookie", "AUTH-"+testUID+"="+token+"; Path=/; Domain=proton.me")
		}
		scopes := []string{"vpn"}
		if api.twoFAMask != 0 {
			// When 2FA is enabled, the auth response only contains the partial
			// scopes of the session before 2FA is completed.
			scopes = []string{"self", "parent", "user", "twofactor"}
		}
		_ = json.NewEncoder(writer).Encode(map[string]any{
			"Code":        1000,
			"UID":         testUID,
			"Scopes":      scopes,
			"ServerProof": base64.StdEncoding.EncodeToString(serverProof),
			"TwoFactor":   api.twoFAMask,
			"2FA": map[string]any{
				"Enabled": api.twoFAMask,
				"FIDO2":   nil,
				"TOTP":    api.twoFAMask & 1,
			},
		})
	}
}

// handleAuth2FA validates the submitted TOTP code against the account secret
// and sets the final AUTH-<uid> cookie on success.
func (api *testProtonAPI) handleAuth2FA(t *testing.T) http.HandlerFunc {
	t.Helper()
	return func(writer http.ResponseWriter, request *http.Request) {
		defer request.Body.Close()

		// The request must carry the cookie from the auth response if one was
		// set, otherwise the unauthenticated session cookie.
		expectedToken := testUnauthToken
		if api.setAuthCookieOnAuth {
			expectedToken = testAuthResponseToken
		}
		assert.Contains(t, request.Header.Get("Cookie"), "AUTH-"+testUID+"="+expectedToken)

		if api.twoFARejectWith200 {
			writer.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(writer).Encode(map[string]any{
				"Code":    8002,
				"Error":   "invalid two-factor code",
				"Details": map[string]string{"TwoFactorCode": "The provided code is invalid."},
			})
			return
		}

		var body struct {
			TwoFactorCode string `json:"TwoFactorCode"`
		}
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			writer.WriteHeader(http.StatusBadRequest)
			return
		}

		if !totp.Validate(body.TwoFactorCode, api.totpSecret) {
			writer.Header().Set("Content-Type", "application/json")
			writer.WriteHeader(http.StatusUnprocessableEntity)
			_ = json.NewEncoder(writer).Encode(map[string]any{
				"Code":    8002,
				"Error":   "invalid two-factor code",
				"Details": map[string]string{"TwoFactorCode": "The provided code is invalid."},
			})
			return
		}

		writer.Header().Set("Content-Type", "application/json")
		if !api.twoFAWithoutNewCookie {
			writer.Header().Add("Set-Cookie", "AUTH-"+testUID+"="+testFinalToken+"; Path=/; Domain=proton.me")
		}
		if api.rotatedSessionID != "" {
			sessionIDCookie := "Session-Id=" + api.rotatedSessionID + "; Domain=proton.me"
			sessionIDCookie += "; Path=/; HttpOnly; SameSite=None; Secure"
			writer.Header().Add("Set-Cookie", sessionIDCookie)
		}
		_ = json.NewEncoder(writer).Encode(map[string]any{
			"Code":   1000,
			"UID":    testUID,
			"Scopes": []string{"vpn"},
		})
	}
}

// handleRefresh re-issues the session cookie for the current session state,
// like the real API does for the session refresh endpoint.
func (api *testProtonAPI) handleRefresh(t *testing.T) http.HandlerFunc {
	t.Helper()
	return func(writer http.ResponseWriter, request *http.Request) {
		defer request.Body.Close()
		writer.Header().Set("Content-Type", "application/json")
		if api.refreshFails {
			writer.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(writer).Encode(map[string]any{
				"Code":  9104,
				"Error": "Inactive session",
			})
			return
		}
		// The real API sets the refresh cookie with a non-standard path.
		writer.Header().Add("Set-Cookie",
			"AUTH-"+testUID+"="+testRefreshedToken+"; Path=/api/auth/refresh; Domain=proton.me")
		_ = json.NewEncoder(writer).Encode(map[string]any{"Code": 1000})
	}
}

// handleLogicals serves the logical servers endpoint, enforcing the "vpn"
// scope on the session token like the real API does.
func (api *testProtonAPI) handleLogicals(t *testing.T) http.HandlerFunc {
	t.Helper()
	return func(writer http.ResponseWriter, request *http.Request) {
		if api.requiredLogicalsToken != "" &&
			!strings.Contains(request.Header.Get("Cookie"),
				"AUTH-"+testUID+"="+api.requiredLogicalsToken) {
			writer.Header().Set("Content-Type", "application/json")
			writer.WriteHeader(http.StatusForbidden)
			body := `{"Code":9106,"Error":"Access token does not have sufficient scope",` +
				`"Details":{"MissingScopes":["vpn"]}}`
			_, _ = writer.Write([]byte(body))
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"LogicalServers":[]}`))
	}
}

// handleScopes returns the scopes of the authenticated session.
func (api *testProtonAPI) handleScopes(t *testing.T) http.HandlerFunc {
	t.Helper()
	return func(writer http.ResponseWriter, request *http.Request) {
		// The request must carry the authenticated session cookie.
		if api.finalToken != "" {
			assert.Contains(t, request.Header.Get("Cookie"), "AUTH-"+testUID+"="+api.finalToken)
		}
		// The request must carry the rotated Session-Id if one was set.
		if api.rotatedSessionID != "" {
			assert.Contains(t, request.Header.Get("Cookie"), "Session-Id="+api.rotatedSessionID)
		}

		scopes := []string{"self", "parent", "user", "twofactor"}
		if api.hasVPNScope {
			scopes = append(scopes, "vpn")
		}
		writer.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(writer).Encode(map[string]any{"Scopes": scopes})
	}
}

// warningContaining is a gomock matcher matching a warning string containing
// the given substring.
type warningContaining struct {
	substring string
}

func (m warningContaining) Matches(x any) bool {
	value, isString := x.(string)
	return isString && strings.Contains(value, m.substring)
}

func (m warningContaining) String() string {
	return "string containing " + m.substring
}

func TestAuth(t *testing.T) {
	t.Parallel()
	// A TOTP code valid for the test secret at the current time, and one
	// valid for the other secret (hence invalid for the test account).
	validTOTPCode, err := totp.GenerateCode(testTOTPSecret, time.Now())
	require.NoError(t, err)
	require.True(t, totp.Validate(validTOTPCode, testTOTPSecret))
	invalidTOTPCode, err := totp.GenerateCode(testTOTPSecretOther, time.Now())
	require.NoError(t, err)

	testCases := map[string]struct {
		twoFAMask             uint
		totpSecret            string
		totpCode              string
		hasVPNScope           bool
		challengeAuthRequests int
		twoFARejectWith200    bool
		twoFAWithoutNewCookie bool
		rotatedSessionID      string
		setAuthCookieOnAuth   bool
		requiredLogicalsToken string
		refreshFails          bool
		expectedWarnings      int
		expectedErr           string
		expectedFetchErr      string
		expectedToken         string
	}{
		"2FA_disabled": {
			expectedToken: testInitialToken,
		},
		"2FA_disabled_and_human_verification_challenge_solved": {
			challengeAuthRequests: 1,
			expectedWarnings:      1,
			expectedToken:         testInitialToken,
		},
		"2FA_disabled_and_human_verification_challenge_not_solved": {
			challengeAuthRequests: 99,
			expectedWarnings:      1,
			expectedErr:           "Unprocessable Entity",
		},
		"2FA_TOTP_enabled_new_cookie_from_two_factor_response": {
			twoFAMask:     1,
			totpSecret:    testTOTPSecret,
			hasVPNScope:   true,
			expectedToken: testFinalToken,
		},
		"2FA_TOTP_enabled_cookie_set_by_auth_response": {
			// The two-factor response sets no new cookie; the cookie set by
			// the auth response carries the full scopes once two-factor
			// completes, so it is kept and accepted by the resource API.
			twoFAMask:             1,
			totpSecret:            testTOTPSecret,
			hasVPNScope:           true,
			twoFAWithoutNewCookie: true,
			setAuthCookieOnAuth:   true,
			requiredLogicalsToken: testAuthResponseToken,
			expectedToken:         testAuthResponseToken,
		},
		"2FA_TOTP_enabled_no_new_cookie_session_cookie_refreshed_on_insufficient_scope": {
			// Current Proton behavior: neither the auth response nor the
			// two-factor response sets a new AUTH-<uid> cookie (the session
			// cookie is upgraded server-side), and the two-factor response
			// rotates the Session-Id. The pre-authentication session cookie
			// does not carry the "vpn" scope, so the resource API rejects it
			// and the session cookie is re-issued via the session refresh
			// endpoint, then the request is retried.
			twoFAMask:             1,
			totpSecret:            testTOTPSecret,
			hasVPNScope:           true,
			twoFAWithoutNewCookie: true,
			rotatedSessionID:      testRotatedSessionID,
			requiredLogicalsToken: testRefreshedToken,
			expectedToken:         testUnauthToken,
		},
		"2FA_TOTP_enabled_no_new_cookie_session_refresh_fails": {
			twoFAMask:             1,
			totpSecret:            testTOTPSecret,
			hasVPNScope:           true,
			twoFAWithoutNewCookie: true,
			requiredLogicalsToken: testRefreshedToken,
			refreshFails:          true,
			expectedToken:         testUnauthToken,
			expectedFetchErr:      "re-issuing it failed",
		},
		"2FA_TOTP_enabled_and_account_without_VPN_scope": {
			twoFAMask:   1,
			totpSecret:  testTOTPSecret,
			expectedErr: "VPN scope not found in scopes",
		},
		"2FA_TOTP_enabled_and_no_TOTP_secret_or_code": {
			twoFAMask:   1,
			expectedErr: "please set the TOTP secret or provide the 6-digit TOTP code",
		},
		"2FA_TOTP_enabled_temporary_code_provided": {
			twoFAMask:     1,
			totpCode:      validTOTPCode,
			hasVPNScope:   true,
			expectedToken: testFinalToken,
		},
		"2FA_TOTP_enabled_temporary_code_and_secret_secret_takes_precedence": {
			twoFAMask:     1,
			totpSecret:    testTOTPSecret,
			totpCode:      invalidTOTPCode,
			hasVPNScope:   true,
			expectedToken: testFinalToken,
		},
		"2FA_TOTP_enabled_temporary_code_malformed": {
			twoFAMask:   1,
			totpCode:    "12345",
			expectedErr: "the TOTP code must be the 6-digit temporary code",
		},
		"2FA_TOTP_enabled_temporary_code_invalid": {
			twoFAMask:   1,
			totpCode:    invalidTOTPCode,
			expectedErr: "invalid two-factor code",
		},
		"2FA_TOTP_enabled_and_invalid_TOTP_secret": {
			twoFAMask:   1,
			totpSecret:  testTOTPSecret[:8] + "0" + testTOTPSecret[8:],
			expectedErr: "generating TOTP code",
		},
		"2FA_TOTP_enabled_and_different_TOTP_secret": {
			twoFAMask:   1,
			totpSecret:  testTOTPSecretOther,
			expectedErr: "invalid two-factor code",
		},
		"2FA_TOTP_enabled_and_two_factor_rejected_with_success_status": {
			twoFAMask:          1,
			totpSecret:         testTOTPSecret,
			twoFARejectWith200: true,
			expectedErr:        "response code 8002 is not expected success code 1000",
		},
		"2FA_FIDO2_enabled_and_TOTP_secret_set": {
			twoFAMask:   2,
			totpSecret:  testTOTPSecret,
			expectedErr: "FIDO2 two-factor authentication is enabled",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			srpServer, challenge := newSRPTestServer(t)
			proofs := generateTestProofs(t, challenge)

			testAPI := &testProtonAPI{
				twoFAMask:             testCase.twoFAMask,
				totpSecret:            testTOTPSecret,
				hasVPNScope:           testCase.hasVPNScope,
				authChallengeRequests: testCase.challengeAuthRequests,
				twoFARejectWith200:    testCase.twoFARejectWith200,
				twoFAWithoutNewCookie: testCase.twoFAWithoutNewCookie,
				rotatedSessionID:      testCase.rotatedSessionID,
				setAuthCookieOnAuth:   testCase.setAuthCookieOnAuth,
				requiredLogicalsToken: testCase.requiredLogicalsToken,
				refreshFails:          testCase.refreshFails,
				finalToken:            testCase.expectedToken,
			}
			server := httptest.NewServer(testAPI.handler(t, srpServer))
			defer server.Close()

			ctrl := gomock.NewController(t)
			warner := common.NewMockWarner(ctrl)
			if testCase.expectedWarnings > 0 {
				warner.EXPECT().Warn(warningContaining{substring: testVerificationToken}).
					Times(testCase.expectedWarnings)
			}

			var seed [32]byte
			_, _ = crand.Read(seed[:])
			client := &apiClient{
				apiURLBase: server.URL + "/api",
				httpClient: server.Client(),
				appVersion: "web-account@1.2.3.4",
				userAgent:  "test",
				generator:  rand.NewChaCha8(seed),
				warner:     warner,
				// Keep the human verification wait short for the tests.
				humanVerificationWait: 10 * time.Millisecond,
			}

			unauthCookie := cookie{
				uid:       testUID,
				token:     testUnauthToken,
				sessionID: testSessionID,
			}

			authCookie, err := client.auth(context.Background(), unauthCookie,
				testUsername, testSRPSession, testCase.totpSecret, testCase.totpCode, proofs)

			if testCase.expectedErr != "" {
				assert.ErrorContains(t, err, testCase.expectedErr)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, cookie{
				uid:       testUID,
				token:     testCase.expectedToken,
				sessionID: testSessionID,
			}, authCookie)

			data, err := client.fetchServers(context.Background(), authCookie)
			if testCase.expectedFetchErr != "" {
				assert.ErrorContains(t, err, testCase.expectedFetchErr)
				return
			}
			require.NoError(t, err)
			assert.Empty(t, data.LogicalServers)
		})
	}
}

func TestFetchServersOnce(t *testing.T) {
	t.Parallel()

	ipv4, err := netip.ParseAddr("84.17.63.8")
	require.NoError(t, err)
	ipv6, err := netip.ParseAddr("2a02:6ea0:d702::10")
	require.NoError(t, err)
	ipv4Only, err := netip.ParseAddr("1.2.3.4")
	require.NoError(t, err)
	ipv6Only, err := netip.ParseAddr("2001:db8::1")
	require.NoError(t, err)

	testCases := map[string]struct {
		serversJSON string
		expected    []physicalServer
	}{
		"ipv4_and_ipv6_entry_addresses": {
			//nolint:lll
			serversJSON: `[{"EntryIP":"84.17.63.8","EntryIPv6":"2a02:6ea0:d702::10","ExitIP":"84.17.63.8","Domain":"node-us-58.protonvpn.net","X25519PublicKey":"test-key","Status":1}]`,
			expected: []physicalServer{
				{
					EntryIP: ipv4, EntryIPv6: ipv6, ExitIP: ipv4,
					Domain: "node-us-58.protonvpn.net", X25519PublicKey: "test-key", Status: 1,
				},
			},
		},
		"ipv4_only_entry_address": {
			serversJSON: `[{"EntryIP":"1.2.3.4","ExitIP":"1.2.3.4",` +
				`"Domain":"node-us-59.protonvpn.net","X25519PublicKey":"test-key","Status":1}]`,
			expected: []physicalServer{
				{
					EntryIP: ipv4Only, ExitIP: ipv4Only,
					Domain: "node-us-59.protonvpn.net", X25519PublicKey: "test-key", Status: 1,
				},
			},
		},
		"ipv6_only_entry_address": {
			serversJSON: `[{"EntryIPv6":"2001:db8::1","ExitIP":"1.2.3.4",` +
				`"Domain":"node-us-60.protonvpn.net","X25519PublicKey":"test-key","Status":1}]`,
			expected: []physicalServer{
				{
					EntryIPv6: ipv6Only, ExitIP: ipv4Only,
					Domain: "node-us-60.protonvpn.net", X25519PublicKey: "test-key", Status: 1,
				},
			},
		},
		"null_entry_addresses": {
			serversJSON: `[{"EntryIP":null,"EntryIPv6":null,"ExitIP":"1.2.3.4",` +
				`"Domain":"node-us-61.protonvpn.net","X25519PublicKey":"test-key","Status":1}]`,
			expected: []physicalServer{
				{
					ExitIP: ipv4Only,
					Domain: "node-us-61.protonvpn.net", X25519PublicKey: "test-key", Status: 1,
				},
			},
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			logicalsJSON := `{"LogicalServers":[{"Name":"US#81","ExitCountry":"US",` +
				`"Servers":` + testCase.serversJSON + `,"Features":8,"Tier":2}]}`

			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				assert.Equal(t, http.MethodGet, request.Method)
				assert.Equal(t, "/api/vpn/v1/logicals", request.URL.Path)
				assert.Equal(t, "1", request.URL.Query().Get("WithIpV6"))
				writer.Header().Set("Content-Type", "application/json")
				_, _ = writer.Write([]byte(logicalsJSON))
			}))
			defer server.Close()

			var seed [32]byte
			_, _ = crand.Read(seed[:])
			client := &apiClient{
				apiURLBase: server.URL + "/api",
				httpClient: server.Client(),
				generator:  rand.NewChaCha8(seed),
			}

			data, err := client.fetchServersOnce(context.Background(), cookie{})
			require.NoError(t, err)
			require.Len(t, data.LogicalServers, 1)
			assert.Equal(t, testCase.expected, data.LogicalServers[0].Servers)
		})
	}
}

func TestIpToServers(t *testing.T) {
	t.Parallel()

	ipv4 := netip.MustParseAddr("84.17.63.8")
	ipv6 := netip.MustParseAddr("2a02:6ea0:d702::10")
	ipv6Other := netip.MustParseAddr("2001:db8::2")

	testCases := map[string]struct {
		entryIPv4   netip.Addr
		entryIPv6   netip.Addr
		expectedIPs []netip.Addr
	}{
		"ipv4_and_ipv6_entry_addresses": {
			entryIPv4:   ipv4,
			entryIPv6:   ipv6,
			expectedIPs: []netip.Addr{ipv4, ipv6},
		},
		"ipv4_only_entry_address": {
			entryIPv4:   ipv4,
			expectedIPs: []netip.Addr{ipv4},
		},
		"ipv6_only_entry_address": {
			entryIPv6:   ipv6,
			expectedIPs: []netip.Addr{ipv6},
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			ipToServer := make(ipToServers)
			ipToServer.add("Country", "Region", "City", "name", "hostname", "pubkey",
				false, testCase.entryIPv4, testCase.entryIPv6, features{})

			servers := ipToServer.toServersSlice()
			require.Len(t, servers, 2)
			assert.Equal(t, testCase.expectedIPs, servers[0].IPs)
			assert.Equal(t, testCase.expectedIPs, servers[1].IPs)
		})
	}

	t.Run("same_entry_address_added_once", func(t *testing.T) {
		t.Parallel()

		ipToServer := make(ipToServers)
		ipToServer.add("Country", "Region", "City", "name", "hostname", "pubkey",
			false, ipv4, ipv6, features{})
		ipToServer.add("Country", "Region", "City", "name", "hostname", "pubkey",
			false, ipv4, ipv6Other, features{})

		assert.Equal(t, 1, len(ipToServer))
	})
}

func TestNormalizeTOTPSecret(t *testing.T) {
	t.Parallel()
	testCases := map[string]struct {
		secret      string
		expected    string
		expectedErr string
	}{
		"plain_base32_secret": {
			secret:   testTOTPSecret,
			expected: testTOTPSecret,
		},
		"lowercase_base32_secret": {
			secret:   testTOTPSecretLower,
			expected: testTOTPSecretLower,
		},
		"secret_with_spaces": {
			secret:   testTOTPSecretSpaces,
			expected: testTOTPSecret,
		},
		"secret_with_hyphens": {
			secret:   testTOTPSecretHyphens,
			expected: testTOTPSecret,
		},
		"secret_with_surrounding_spaces": {
			secret:   "  " + testTOTPSecret + "  ",
			expected: testTOTPSecret,
		},
		"secret_with_newlines": {
			secret:   testTOTPSecret[:8] + "\n" + testTOTPSecret[8:],
			expected: testTOTPSecret,
		},
		"secret_with_non_breaking_spaces": {
			secret:   testTOTPSecret[:8] + "\u00A0" + testTOTPSecret[8:],
			expected: testTOTPSecret,
		},
		"secret_with_underscores": {
			secret:   testTOTPSecret[:8] + "_" + testTOTPSecret[8:],
			expected: testTOTPSecret,
		},
		"secret_with_base32_padding": {
			secret:   testTOTPSecret + "====",
			expected: testTOTPSecret,
		},
		"secret_with_secret_prefix": {
			secret:   "secret=" + testTOTPSecret,
			expected: testTOTPSecret,
		},
		"otpauth_URL": {
			secret:   "otpauth://totp/Proton:alice@example.com?secret=" + testTOTPSecret + "&issuer=Proton",
			expected: testTOTPSecret,
		},
		"empty_secret": {
			secret:   "",
			expected: "",
		},
		"secret_with_only_non_base32_characters": {
			secret:   "!!",
			expected: "",
		},
		"secret_with_invalid_base32_digits": {
			secret:      testTOTPSecret[:8] + "0" + testTOTPSecret[8:],
			expectedErr: "not part of the base32 alphabet",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			normalized, err := normalizeTOTPSecret(testCase.secret)
			if testCase.expectedErr != "" {
				assert.ErrorContains(t, err, testCase.expectedErr)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, testCase.expected, normalized)
		})
	}
}

func TestGenerateTOTPCode(t *testing.T) {
	t.Parallel()
	// A fixed time in the middle of a 30-second TOTP period so that the
	// expected code can be computed deterministically.
	const testTimeUnix = 1735732815
	now := time.Unix(testTimeUnix, 0)
	expectedCode, err := totp.GenerateCode(testTOTPSecret, now)
	require.NoError(t, err)

	testCases := map[string]struct {
		secret      string
		expected    string
		expectedErr string
	}{
		"base32_secret": {
			secret:   testTOTPSecret,
			expected: expectedCode,
		},
		"base32_secret_with_spaces": {
			secret:   testTOTPSecretSpaces,
			expected: expectedCode,
		},
		"base32_secret_with_newlines": {
			secret:   testTOTPSecret[:8] + "\n" + testTOTPSecret[8:],
			expected: expectedCode,
		},
		"otpauth_URL": {
			secret:   "otpauth://totp/Proton:alice@example.com?secret=" + testTOTPSecret + "&issuer=Proton",
			expected: expectedCode,
		},
		"empty_secret": {
			secret:      "",
			expectedErr: "TOTP secret is empty",
		},
		"whitespace_only_secret": {
			secret:      "  \t ",
			expectedErr: "TOTP secret is empty",
		},
		"secret_with_only_non_base32_characters": {
			secret:      "!!",
			expectedErr: "TOTP secret is empty",
		},
		"secret_with_invalid_base32_digits": {
			secret:      testTOTPSecret[:8] + "0" + testTOTPSecret[8:],
			expectedErr: "not part of the base32 alphabet",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			code, err := generateTOTPCode(testCase.secret, now)

			if testCase.expectedErr != "" {
				assert.ErrorContains(t, err, testCase.expectedErr)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, testCase.expected, code)
		})
	}
}

func TestNormalizeTOTPCode(t *testing.T) {
	t.Parallel()
	testCases := map[string]struct {
		code        string
		expected    string
		expectedErr string
	}{
		"6_digits": {
			code:     "123456",
			expected: "123456",
		},
		"6_digits_with_surrounding_spaces": {
			code:     "  123456  ",
			expected: "123456",
		},
		"6_digits_with_newline": {
			code:     "12345\n6",
			expected: "123456",
		},
		"too_short": {
			code:        "12345",
			expectedErr: "the TOTP code must be the 6-digit temporary code",
		},
		"too_long": {
			code:        "1234567",
			expectedErr: "the TOTP code must be the 6-digit temporary code",
		},
		"letters": {
			code:        "abcdef",
			expectedErr: "the TOTP code must be the 6-digit temporary code",
		},
		"mixed_digits_and_letters": {
			code:        "12345a",
			expectedErr: "the TOTP code must be the 6-digit temporary code",
		},
		"empty": {
			code:        "",
			expectedErr: "the TOTP code must be the 6-digit temporary code",
		},
		"whitespace_only": {
			code:        "   ",
			expectedErr: "the TOTP code must be the 6-digit temporary code",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			normalized, err := normalizeTOTPCode(testCase.code)
			if testCase.expectedErr != "" {
				assert.ErrorContains(t, err, testCase.expectedErr)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, testCase.expected, normalized)
		})
	}
}
