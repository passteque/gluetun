package updater

import (
	"bytes"
	"context"
	crand "crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"time"

	srp "github.com/ProtonMail/go-srp"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"github.com/qdm12/gluetun/internal/provider/common"
)

// apiClient is a minimal Proton v4 API client which can handle all the
// oddities of Proton's authentication flow they want to keep hidden
// from the public.
type apiClient struct {
	apiURLBase string
	httpClient *http.Client
	appVersion string
	userAgent  string
	generator  *rand.ChaCha8
	warner     common.Warner
	// sessionID is the latest Session-Id cookie seen in responses. Proton
	// rotates it as the session progresses (e.g. when two-factor
	// authentication completes), and subsequent requests must carry it.
	sessionID string
	// humanVerificationWait is the duration to wait after Proton asks for
	// a human verification, for the user to complete it in a browser.
	humanVerificationWait time.Duration
}

// newAPIClient returns an [apiClient] with sane defaults matching Proton's
// insane expectations.
func newAPIClient(ctx context.Context, httpClient *http.Client, warner common.Warner) (
	client *apiClient, err error,
) {
	var seed [32]byte
	_, _ = crand.Read(seed[:])
	generator := rand.NewChaCha8(seed)

	// Pick a random user agent from this list. Because I'm not going to tell
	// Proton shit on where all these funny requests are coming from, given their
	// unhelpfulness in figuring out their authentication flow.
	userAgents := [...]string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:143.0) Gecko/20100101 Firefox/143.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:143.0) Gecko/20100101 Firefox/143.0",
		"Mozilla/5.0 (X11; Linux x86_64; rv:143.0) Gecko/20100101 Firefox/143.0",
	}
	userAgent := userAgents[generator.Uint64()%uint64(len(userAgents))]

	appVersion, err := getMostRecentStableTag(ctx, httpClient)
	if err != nil {
		return nil, fmt.Errorf("getting most recent version for proton app: %w", err)
	}

	const defaultHumanVerificationWait = 20 * time.Second
	return &apiClient{
		apiURLBase:            "https://account.proton.me/api",
		httpClient:            httpClient,
		appVersion:            appVersion,
		userAgent:             userAgent,
		generator:             generator,
		warner:                warner,
		humanVerificationWait: defaultHumanVerificationWait,
	}, nil
}

// request executes the request returned by newRequest and transparently
// handles Proton's human verification challenge (HTTP 422 with error code
// 9001).
//
// When challenged, the user is asked to open the verification URL in a
// browser to complete the verification, the client waits, then retries the
// request once with the human verification token headers.
//
// The verification is attached to the session, so the request must be
// retried within the same session: newRequest must return a fresh request
// carrying the same data on each call.
func (c *apiClient) request(ctx context.Context, newRequest func() (*http.Request, error)) (
	response *http.Response, err error,
) {
	request, err := newRequest()
	if err != nil {
		return nil, err
	}
	response, body, err := c.doRequest(request)
	if err != nil {
		return nil, err
	}

	verification, isChallenge := humanVerificationFromResponse(response, body)
	if !isChallenge {
		return response, nil
	}

	c.warner.Warn("Proton is asking for human verification to continue authentication, " +
		"please open the following URL in a browser and complete it: " + verification.webURL +
		". The process will retry with this verification complete automatically in " +
		c.humanVerificationWait.String())

	timer := time.NewTimer(c.humanVerificationWait)
	select {
	case <-ctx.Done():
		timer.Stop()
		return nil, ctx.Err()
	case <-timer.C:
	}

	request, err = newRequest()
	if err != nil {
		return nil, err
	}
	const (
		// Header names, not credentials.
		humanVerificationTokenHeader     = "x-pm-human-verification-token"      //nolint:gosec
		humanVerificationTokenTypeHeader = "x-pm-human-verification-token-type" //nolint:gosec
	)
	request.Header.Set(humanVerificationTokenHeader, verification.token)
	request.Header.Set(humanVerificationTokenTypeHeader, verification.tokenType)

	response, _, err = c.doRequest(request)
	return response, err
}

// doRequest performs the request, reads the response body, restoring it for
// the caller, and tracks the latest Session-Id cookie, which Proton rotates
// as the session progresses.
func (c *apiClient) doRequest(request *http.Request) (
	response *http.Response, body []byte, err error,
) {
	defer func() {
		if response != nil {
			_ = response.Body.Close()
		}
	}()
	// The request URL is hardcoded at the call sites, never user input.
	response, err = c.httpClient.Do(request) //nolint:gosec
	if err != nil {
		return nil, nil, err
	}

	body, err = io.ReadAll(response.Body)
	if err != nil {
		return nil, nil, fmt.Errorf("reading response body: %w", err)
	}
	// Restore the body for the caller.
	response.Body = io.NopCloser(bytes.NewReader(body))

	for _, responseCookie := range response.Cookies() {
		if responseCookie.Name == "Session-Id" {
			c.sessionID = responseCookie.Value
		}
	}
	return response, body, nil
}

// humanVerification carries the data of a Proton human verification
// challenge.
type humanVerification struct {
	token     string
	tokenType string
	webURL    string
}

// humanVerificationFromResponse inspects a response for a Proton human
// verification challenge (HTTP 422 with error code 9001).
func humanVerificationFromResponse(response *http.Response, body []byte) (
	verification humanVerification, ok bool,
) {
	if response.StatusCode != http.StatusUnprocessableEntity {
		return humanVerification{}, false
	}

	var errorBody struct {
		Code    uint `json:"Code"`
		Details struct {
			HumanVerificationToken   string   `json:"HumanVerificationToken"`
			HumanVerificationMethods []string `json:"HumanVerificationMethods"`
			WebURL                   string   `json:"WebUrl"`
		} `json:"Details"`
	}
	err := json.Unmarshal(body, &errorBody)
	if err != nil {
		return humanVerification{}, false
	}

	const humanVerificationCode = 9001
	if errorBody.Code != humanVerificationCode || errorBody.Details.HumanVerificationToken == "" {
		return humanVerification{}, false
	}

	tokenType := "captcha"
	if len(errorBody.Details.HumanVerificationMethods) > 0 {
		tokenType = errorBody.Details.HumanVerificationMethods[0]
	}

	return humanVerification{
		token:     errorBody.Details.HumanVerificationToken,
		tokenType: tokenType,
		webURL:    errorBody.Details.WebURL,
	}, true
}

// setHeaders sets the minimal necessary headers for Proton API requests
// to succeed without being blocked by their "security" measures.
// See for example [getMostRecentStableTag] on how the app version must
// be set to a recent version or they block your request. "SeCuRiTy"...
func (c *apiClient) setHeaders(request *http.Request, cookie cookie) {
	if c.sessionID != "" {
		cookie.sessionID = c.sessionID
	}
	request.Header.Set("Cookie", cookie.String())
	request.Header.Set("User-Agent", c.userAgent)
	request.Header.Set("x-pm-appversion", c.appVersion)
	request.Header.Set("x-pm-locale", "en_US")
	request.Header.Set("x-pm-uid", cookie.uid)
}

// authenticate performs the full Proton authentication flow
// to obtain an authenticated cookie (uid, token and session ID).
// If the account has TOTP two-factor authentication enabled, totpSecret must
// be the account's TOTP secret (base32 string or otpauth:// URL), or
// totpCode the temporary 6-digit code shown in the authenticator app. The
// TOTP secret takes precedence when both are set.
func (c *apiClient) authenticate(ctx context.Context, email, password, totpSecret, totpCode string,
) (authCookie cookie, err error) {
	sessionID, err := c.getSessionID(ctx)
	if err != nil {
		return cookie{}, fmt.Errorf("getting session ID: %w", err)
	}

	tokenType, accessToken, refreshToken, uid, err := c.getUnauthSession(ctx, sessionID)
	if err != nil {
		return cookie{}, fmt.Errorf("getting unauthenticated session data: %w", err)
	}

	cookieToken, err := c.cookieToken(ctx, sessionID, tokenType, accessToken, refreshToken, uid)
	if err != nil {
		return cookie{}, fmt.Errorf("getting cookie token: %w", err)
	}

	unauthCookie := cookie{
		uid:       uid,
		token:     cookieToken,
		sessionID: sessionID,
	}
	username, modulusPGPClearSigned, serverEphemeralBase64, saltBase64,
		srpSessionHex, version, err := c.authInfo(ctx, email, unauthCookie)
	if err != nil {
		return cookie{}, fmt.Errorf("getting auth information: %w", err)
	}

	// Prepare SRP proof generator using Proton's official SRP parameters and hashing.
	srpAuth, err := srp.NewAuth(version, username, []byte(password),
		saltBase64, modulusPGPClearSigned, serverEphemeralBase64)
	if err != nil {
		return cookie{}, fmt.Errorf("initializing SRP auth: %w", err)
	}

	// Generate SRP proofs (A, M1) with the usual 2048-bit modulus.
	const modulusBits = 2048
	proofs, err := srpAuth.GenerateProofs(modulusBits)
	if err != nil {
		return cookie{}, fmt.Errorf("generating SRP proofs: %w", err)
	}

	authCookie, err = c.auth(ctx, unauthCookie, email, srpSessionHex, totpSecret, totpCode, proofs)
	if err != nil {
		return cookie{}, fmt.Errorf("authentifying: %w", err)
	}

	return authCookie, nil
}

func (c *apiClient) getSessionID(ctx context.Context) (sessionID string, err error) {
	const url = "https://account.proton.me/vpn"
	response, err := c.request(ctx, func() (*http.Request, error) {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, fmt.Errorf("creating request: %w", err)
		}
		return request, nil
	})
	if err != nil {
		return "", err
	}
	err = response.Body.Close()
	if err != nil {
		return "", fmt.Errorf("closing response body: %w", err)
	}

	for _, cookie := range response.Cookies() {
		if cookie.Name == "Session-Id" {
			return cookie.Value, nil
		}
	}

	return "", errors.New("session ID not found in cookies")
}

func (c *apiClient) getUnauthSession(ctx context.Context, sessionID string) (
	tokenType, accessToken, refreshToken, uid string, err error,
) {
	unauthCookie := cookie{
		sessionID: sessionID,
	}
	response, err := c.request(ctx, func() (*http.Request, error) {
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.apiURLBase+"/auth/v4/sessions", nil)
		if err != nil {
			return nil, fmt.Errorf("creating request: %w", err)
		}
		c.setHeaders(request, unauthCookie)
		return request, nil
	})
	if err != nil {
		return "", "", "", "", err
	}
	defer response.Body.Close()

	responseBody, err := io.ReadAll(response.Body)
	if err != nil {
		return "", "", "", "", fmt.Errorf("reading response body: %w", err)
	} else if response.StatusCode != http.StatusOK {
		return "", "", "", "", buildError(response.StatusCode, responseBody)
	}

	var data struct {
		Code         uint     `json:"Code"`         // 1000 on success
		AccessToken  string   `json:"AccessToken"`  // 32-chars lowercase and digits
		RefreshToken string   `json:"RefreshToken"` // 32-chars lowercase and digits
		TokenType    string   `json:"TokenType"`    // "Bearer"
		Scopes       []string `json:"Scopes"`       // should be [] for our usage
		UID          string   `json:"UID"`          // 32-chars lowercase and digits
		LocalID      uint     `json:"LocalID"`      // 0 in my case
	}

	err = json.Unmarshal(responseBody, &data)
	if err != nil {
		return "", "", "", "", fmt.Errorf("decoding response body: %w", err)
	}

	const successCode = 1000
	switch {
	case data.Code != successCode:
		return "", "", "", "", fmt.Errorf("response code %d is not expected success code %d",
			data.Code, successCode)
	case data.AccessToken == "":
		return "", "", "", "", errors.New("access token is empty in response")
	case data.RefreshToken == "":
		return "", "", "", "", errors.New("refresh token is empty in response")
	case data.TokenType == "":
		return "", "", "", "", errors.New("token type is empty in response")
	case data.UID == "":
		return "", "", "", "", errors.New("UID is empty in response")
	}
	// Ignore Scopes and LocalID fields, we don't use them.

	return data.TokenType, data.AccessToken, data.RefreshToken, data.UID, nil
}

func (c *apiClient) cookieToken(ctx context.Context, sessionID, tokenType, accessToken,
	refreshToken, uid string,
) (cookieToken string, err error) {
	type requestBodySchema struct {
		GrantType    string `json:"GrantType"`    // "refresh_token"
		Persistent   uint   `json:"Persistent"`   // 0
		RedirectURI  string `json:"RedirectURI"`  // "https://protonmail.com"
		RefreshToken string `json:"RefreshToken"` // 32-chars lowercase and digits
		ResponseType string `json:"ResponseType"` // "token"
		State        string `json:"State"`        // 24-chars letters and digits
		UID          string `json:"UID"`          // 32-chars lowercase and digits
	}
	requestBody := requestBodySchema{
		GrantType:    "refresh_token",
		Persistent:   0,
		RedirectURI:  "https://protonmail.com",
		RefreshToken: refreshToken,
		ResponseType: "token",
		State:        generateLettersDigits(c.generator, 24), //nolint:mnd
		UID:          uid,
	}

	unauthCookie := cookie{
		uid:       uid,
		sessionID: sessionID,
	}
	response, err := c.request(ctx, func() (*http.Request, error) {
		buffer := bytes.NewBuffer(nil)
		encoder := json.NewEncoder(buffer)
		if err := encoder.Encode(requestBody); err != nil { //nolint:gosec
			return nil, fmt.Errorf("encoding request body: %w", err)
		}
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.apiURLBase+"/core/v4/auth/cookies", buffer)
		if err != nil {
			return nil, fmt.Errorf("creating request: %w", err)
		}
		c.setHeaders(request, unauthCookie)
		request.Header.Set("Authorization", tokenType+" "+accessToken)
		return request, nil
	})
	if err != nil {
		return "", err
	}
	defer response.Body.Close()

	responseBody, err := io.ReadAll(response.Body)
	if err != nil {
		return "", fmt.Errorf("reading response body: %w", err)
	} else if response.StatusCode != http.StatusOK {
		return "", buildError(response.StatusCode, responseBody)
	}

	var cookies struct {
		Code           uint   `json:"Code"`           // 1000 on success
		UID            string `json:"UID"`            // should match request UID
		LocalID        uint   `json:"LocalID"`        // 0
		RefreshCounter uint   `json:"RefreshCounter"` // 1
	}
	err = json.Unmarshal(responseBody, &cookies)
	if err != nil {
		return "", fmt.Errorf("decoding response body: %w", err)
	}

	const successCode = 1000
	switch {
	case cookies.Code != successCode:
		return "", fmt.Errorf("response code %d is not expected success code %d",
			cookies.Code, successCode)
	case cookies.UID != requestBody.UID:
		return "", fmt.Errorf("UID %s in response does not match request UID %s",
			cookies.UID, requestBody.UID)
	}
	// Ignore LocalID and RefreshCounter fields, we don't use them.

	for _, cookie := range response.Cookies() {
		if cookie.Name == "AUTH-"+uid {
			return cookie.Value, nil
		}
	}

	return "", errors.New("auth cookie not found")
}

// authInfo fetches SRP parameters for the account.
func (c *apiClient) authInfo(ctx context.Context, email string, unauthCookie cookie) (
	username, modulusPGPClearSigned, serverEphemeralBase64, saltBase64, srpSessionHex string,
	version int, err error,
) {
	type requestBodySchema struct {
		Intent   string `json:"Intent"` // "Proton"
		Username string `json:"Username"`
	}
	requestBody := requestBodySchema{
		Intent:   "Proton",
		Username: email,
	}

	response, err := c.request(ctx, func() (*http.Request, error) {
		buffer := bytes.NewBuffer(nil)
		encoder := json.NewEncoder(buffer)
		if err := encoder.Encode(requestBody); err != nil {
			return nil, fmt.Errorf("encoding request body: %w", err)
		}
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.apiURLBase+"/core/v4/auth/info", buffer)
		if err != nil {
			return nil, fmt.Errorf("creating request: %w", err)
		}
		c.setHeaders(request, unauthCookie)
		request.Header.Set("Content-Type", "application/json")
		return request, nil
	})
	if err != nil {
		return "", "", "", "", "", 0, err
	}
	defer response.Body.Close()

	responseBody, err := io.ReadAll(response.Body)
	if err != nil {
		return "", "", "", "", "", 0, fmt.Errorf("reading response body: %w", err)
	} else if response.StatusCode != http.StatusOK {
		return "", "", "", "", "", 0, buildError(response.StatusCode, responseBody)
	}

	var info struct {
		Code            uint   `json:"Code"`              // 1000 on success
		Modulus         string `json:"Modulus"`           // PGP clearsigned modulus string
		ServerEphemeral string `json:"ServerEphemeral"`   // base64
		Version         *uint  `json:"Version,omitempty"` // 4 as of 2025-10-26
		Salt            string `json:"Salt"`              // base64
		SRPSession      string `json:"SRPSession"`        // hexadecimal
		Username        string `json:"Username"`          // user without @domain.com. Mine has its first letter capitalized.
	}
	err = json.Unmarshal(responseBody, &info)
	if err != nil {
		return "", "", "", "", "", 0, fmt.Errorf("decoding response body: %w", err)
	}

	const successCode = 1000
	switch {
	case info.Code != successCode:
		return "", "", "", "", "", 0, fmt.Errorf("response code %d is not expected success code %d",
			info.Code, successCode)
	case info.Modulus == "":
		return "", "", "", "", "", 0, errors.New("modulus is empty in response")
	case info.ServerEphemeral == "":
		return "", "", "", "", "", 0, errors.New("server ephemeral is empty in response")
	case info.Salt == "":
		return "", "", "", "", "", 0, errors.New("salt is empty in response")
	case info.SRPSession == "":
		return "", "", "", "", "", 0, errors.New("SRP session is empty in response")
	case info.Username == "":
		return "", "", "", "", "", 0, errors.New("username is empty in response")
	case info.Version == nil:
		return "", "", "", "", "", 0, errors.New("version is missing in response")
	}

	version = int(*info.Version) //nolint:gosec
	return info.Username, info.Modulus, info.ServerEphemeral, info.Salt,
		info.SRPSession, version, nil
}

type cookie struct {
	uid       string
	token     string
	sessionID string
}

func (c *cookie) String() string {
	s := ""
	if c.token != "" {
		s += fmt.Sprintf("AUTH-%s=%s; ", c.uid, c.token)
	}
	if c.sessionID != "" {
		s += fmt.Sprintf("Session-Id=%s; ", c.sessionID)
	}
	if c.token != "" {
		s += "Tag=default; iaas=W10; Domain=proton.me; Feature=VPNDashboard:A"
	}
	return s
}

// auth performs the SRP proof submission to obtain the authentication cookie.
// If the account has two-factor authentication enabled, the TOTP code
// generated from totpSecret (or totpCode, the temporary 6-digit code, if no
// secret is set) is submitted to the two-factor authentication endpoint to
// complete the authentication.
func (c *apiClient) auth(ctx context.Context, unauthCookie cookie,
	username, srpSession, totpSecret, totpCode string,
	proofs *srp.Proofs,
) (authCookie cookie, err error) {
	clientEphemeral := base64.StdEncoding.EncodeToString(proofs.ClientEphemeral)
	clientProof := base64.StdEncoding.EncodeToString(proofs.ClientProof)

	type requestBodySchema struct {
		ClientEphemeral string            `json:"ClientEphemeral"`   // base64(A)
		ClientProof     string            `json:"ClientProof"`       // base64(M1)
		Payload         map[string]string `json:"Payload,omitempty"` // not sure
		SRPSession      string            `json:"SRPSession"`        // hexadecimal
		Username        string            `json:"Username"`          // user@protonmail.com
	}
	requestBody := requestBodySchema{
		ClientEphemeral: clientEphemeral,
		ClientProof:     clientProof,
		SRPSession:      srpSession,
		Username:        username,
	}

	response, err := c.request(ctx, func() (*http.Request, error) {
		buffer := bytes.NewBuffer(nil)
		encoder := json.NewEncoder(buffer)
		if err := encoder.Encode(requestBody); err != nil {
			return nil, fmt.Errorf("encoding request body: %w", err)
		}
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.apiURLBase+"/core/v4/auth", buffer)
		if err != nil {
			return nil, fmt.Errorf("creating request: %w", err)
		}
		c.setHeaders(request, unauthCookie)
		request.Header.Set("Content-Type", "application/json")
		return request, nil
	})
	if err != nil {
		return cookie{}, err
	}
	defer response.Body.Close()

	responseBody, err := io.ReadAll(response.Body)
	if err != nil {
		return cookie{}, fmt.Errorf("reading response body: %w", err)
	} else if response.StatusCode != http.StatusOK {
		return cookie{}, buildError(response.StatusCode, responseBody)
	}

	// twoFAStatus is the bitmask of two-factor authentication methods enabled
	// on the account, as returned by Proton in the `TwoFactor` and `2FA.Enabled`
	// fields of the auth response.
	type twoFAStatus uint

	const (
		twoFADisabled twoFAStatus = iota // 0
		twoFAHasTOTP                     // 1, TOTP bit.
		twoFAHasFIDO2                    // 2, FIDO2 bit.
	)

	type twoFAInfo struct {
		Enabled twoFAStatus `json:"Enabled"`
		FIDO2   struct {
			AuthenticationOptions any   `json:"AuthenticationOptions"`
			RegisteredKeys        []any `json:"RegisteredKeys"`
		} `json:"FIDO2"`
		TOTP uint `json:"TOTP"`
	}

	var auth struct {
		Code              uint        `json:"Code"`         // 1000 on success
		LocalID           uint        `json:"LocalID"`      // 7 in my case
		Scopes            []string    `json:"Scopes"`       // this should contain "vpn". Same as `Scope` field value.
		UID               string      `json:"UID"`          // same as `Uid` field value
		UserID            string      `json:"UserID"`       // base64
		EventID           string      `json:"EventID"`      // base64
		PasswordMode      uint        `json:"PasswordMode"` // 1 in my case
		ServerProof       string      `json:"ServerProof"`  // base64(M2)
		TwoFactor         twoFAStatus `json:"TwoFactor"`    // 0 if 2FA not required
		TwoFA             twoFAInfo   `json:"2FA"`
		TemporaryPassword uint        `json:"TemporaryPassword"` // 0 in my case
	}

	err = json.Unmarshal(responseBody, &auth)
	if err != nil {
		return cookie{}, fmt.Errorf("decoding response body: %w", err)
	}

	m2, err := base64.StdEncoding.DecodeString(auth.ServerProof)
	if err != nil {
		return cookie{}, fmt.Errorf("decoding server proof: %w", err)
	}
	if !bytes.Equal(m2, proofs.ExpectedServerProof) {
		return cookie{}, fmt.Errorf("server proof from server %x is not expected proof %x",
			m2, proofs.ExpectedServerProof)
	}

	const successCode = 1000
	switch {
	case auth.Code != successCode:
		return cookie{}, fmt.Errorf("response code %d is not expected success code %d",
			auth.Code, successCode)
	case auth.UID != unauthCookie.uid:
		return cookie{}, fmt.Errorf("UID %s in response does not match request UID %s",
			auth.UID, unauthCookie.uid)
	}

	// If two-factor authentication is required, submit the TOTP code to the
	// two-factor authentication endpoint to complete the authentication.
	//
	// When 2FA is enabled, the response only contains the partial scopes of
	// the session before 2FA (e.g. [self parent user twofactor]), and the
	// "vpn" scope is only granted once 2FA is complete, so the "vpn" scope
	// check is deferred to checkVPNScope.
	twoFAMask := auth.TwoFactor | auth.TwoFA.Enabled
	if twoFAMask != twoFADisabled {
		switch {
		case twoFAMask&twoFAHasTOTP != 0:
			code, err := twoFactorCode(totpSecret, totpCode, time.Now())
			if err != nil {
				return cookie{}, err
			}
			authCookie, err = c.auth2FA(ctx, unauthCookie, response, code)
			if err != nil {
				return cookie{}, err
			}

			return c.checkVPNScope(ctx, authCookie)
		case twoFAMask&twoFAHasFIDO2 != 0:
			return cookie{}, errors.New("FIDO2 two-factor authentication is enabled on this account, " +
				"which is not supported, please enable TOTP two-factor authentication instead")
		default:
			return cookie{}, fmt.Errorf("unknown two-factor authentication method %d", twoFAMask)
		}
	}

	// Without 2FA, the response directly grants the full session, so check
	// that the account has the "vpn" scope.
	if !slices.Contains(auth.Scopes, "vpn") {
		return cookie{}, fmt.Errorf("VPN scope not found in scopes %v", auth.Scopes)
	}

	token, found := authCookieFromResponse(response, unauthCookie.uid)
	if !found {
		return cookie{}, fmt.Errorf("auth cookie not found in HTTP headers %s, response body: %s",
			httpHeadersToString(response.Header), responseBody)
	}
	authCookie = unauthCookie
	authCookie.token = token

	return authCookie, nil
}

// auth2FA submits the TOTP code to complete two-factor authentication.
// The request carries the AUTH-<uid> token from the auth response if it sets
// one, otherwise it falls back to the unauthenticated token.
func (c *apiClient) auth2FA(ctx context.Context, unauthCookie cookie,
	authResponse *http.Response, totpCode string,
) (authCookie cookie, err error) {
	type requestBodySchema struct {
		TwoFactorCode string `json:"TwoFactorCode"`
	}
	twoFACookie := unauthCookie
	if token, ok := authCookieFromResponse(authResponse, unauthCookie.uid); ok {
		twoFACookie.token = token
	}

	response, err := c.request(ctx, func() (*http.Request, error) {
		buffer := bytes.NewBuffer(nil)
		encoder := json.NewEncoder(buffer)
		if err := encoder.Encode(requestBodySchema{TwoFactorCode: totpCode}); err != nil {
			return nil, fmt.Errorf("encoding request body: %w", err)
		}
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.apiURLBase+"/core/v4/auth/2fa", buffer)
		if err != nil {
			return nil, fmt.Errorf("creating request: %w", err)
		}
		c.setHeaders(request, twoFACookie)
		request.Header.Set("Content-Type", "application/json")
		return request, nil
	})
	if err != nil {
		return cookie{}, err
	}
	defer response.Body.Close()

	responseBody, err := io.ReadAll(response.Body)
	if err != nil {
		return cookie{}, fmt.Errorf("reading response body: %w", err)
	} else if response.StatusCode != http.StatusOK {
		return cookie{}, buildError(response.StatusCode, responseBody)
	}

	var twoFA struct {
		Code uint   `json:"Code"` // 1000 on success
		UID  string `json:"UID"`
	}
	err = json.Unmarshal(responseBody, &twoFA)
	if err != nil {
		return cookie{}, fmt.Errorf("decoding response body: %w", err)
	}

	const successCode = 1000
	switch {
	case twoFA.Code != successCode:
		return cookie{}, fmt.Errorf("response code %d is not expected success code %d: %s",
			twoFA.Code, successCode, responseBody)
	case twoFA.UID != "" && twoFA.UID != unauthCookie.uid:
		return cookie{}, fmt.Errorf("UID %s in response does not match request UID %s",
			twoFA.UID, unauthCookie.uid)
	}

	// A successful two-factor response does not set a new AUTH-<uid> cookie:
	// Proton upgrades the session server-side. The cookie set by the
	// authentication response carries the full scopes once two-factor
	// completes, so keep it; use the two-factor response cookie instead if
	// it sets a new one.
	authCookie = unauthCookie
	if token, found := authCookieFromResponse(authResponse, unauthCookie.uid); found {
		authCookie.token = token
	}
	if token, found := authCookieFromResponse(response, unauthCookie.uid); found {
		authCookie.token = token
	}

	return authCookie, nil
}

// refreshSessionToken re-issues the AUTH-<uid> session cookie for the
// current session state, like Proton's web clients do on stale session
// errors (POST auth/refresh).
func (c *apiClient) refreshSessionToken(ctx context.Context, authCookie cookie) (
	token string, err error,
) {
	response, err := c.request(ctx, func() (*http.Request, error) {
		request, err := http.NewRequestWithContext(ctx,
			http.MethodPost, c.apiURLBase+"/auth/refresh", nil)
		if err != nil {
			return nil, fmt.Errorf("creating request: %w", err)
		}
		c.setHeaders(request, authCookie)
		return request, nil
	})
	if err != nil {
		return "", err
	}
	defer response.Body.Close()

	responseBody, err := io.ReadAll(response.Body)
	if err != nil {
		return "", fmt.Errorf("reading response body: %w", err)
	} else if response.StatusCode != http.StatusOK {
		return "", buildError(response.StatusCode, responseBody)
	}

	token, found := authCookieFromResponse(response, authCookie.uid)
	if !found {
		return "", errors.New("auth cookie not found in response")
	}
	return token, nil
}

// checkVPNScope queries the scopes of the authenticated session and checks
// that the account has the "vpn" scope.
func (c *apiClient) checkVPNScope(ctx context.Context, authCookie cookie) (cookie, error) {
	response, err := c.request(ctx, func() (*http.Request, error) {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, c.apiURLBase+"/core/v4/auth/scopes", nil)
		if err != nil {
			return nil, fmt.Errorf("creating request: %w", err)
		}
		c.setHeaders(request, authCookie)
		return request, nil
	})
	if err != nil {
		return cookie{}, fmt.Errorf("executing request: %w", err)
	}
	defer response.Body.Close()

	responseBody, err := io.ReadAll(response.Body)
	if err != nil {
		return cookie{}, fmt.Errorf("reading response body: %w", err)
	} else if response.StatusCode != http.StatusOK {
		return cookie{}, buildError(response.StatusCode, responseBody)
	}

	var scopes struct {
		Scopes []string `json:"Scopes"`
	}
	err = json.Unmarshal(responseBody, &scopes)
	if err != nil {
		return cookie{}, fmt.Errorf("decoding response body: %w", err)
	}

	if !slices.Contains(scopes.Scopes, "vpn") {
		return cookie{}, fmt.Errorf("VPN scope not found in scopes %v", scopes.Scopes)
	}

	return authCookie, nil
}

// authCookieFromResponse extracts the value of the AUTH-<uid> cookie from the
// Set-Cookie HTTP response headers.
func authCookieFromResponse(response *http.Response, uid string) (token string, found bool) {
	prefix := "AUTH-" + uid + "="
	for _, setCookieHeader := range response.Header.Values("Set-Cookie") {
		for _, part := range strings.Split(setCookieHeader, ";") {
			if strings.HasPrefix(part, prefix) {
				return strings.TrimPrefix(part, prefix), true
			}
		}
	}
	return "", false
}

// generateLettersDigits mimicing Proton's own random string generator:
// https://github.com/ProtonMail/WebClients/blob/e4d7e4ab9babe15b79a131960185f9f8275512cd/packages/utils/generateLettersDigits.ts
func generateLettersDigits(rng *rand.ChaCha8, length uint) string {
	const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	return generateFromCharset(rng, length, charset)
}

func generateFromCharset(rng *rand.ChaCha8, length uint, charset string) string {
	result := make([]byte, length)
	randomBytes := make([]byte, length)
	_, _ = rng.Read(randomBytes)
	for i := range length {
		result[i] = charset[int(randomBytes[i])%len(charset)]
	}
	return string(result)
}

func httpHeadersToString(headers http.Header) string {
	var builder strings.Builder
	first := true
	for key, values := range headers {
		for _, value := range values {
			if !first {
				builder.WriteString(", ")
			}
			fmt.Fprintf(&builder, "%s: %s", key, value)
			first = false
		}
	}
	return builder.String()
}

// twoFactorCode returns the two-factor code to submit to Proton: the TOTP
// secret takes precedence and the code is generated from it, otherwise the
// user-provided temporary code is used as-is.
func twoFactorCode(totpSecret, totpCode string, now time.Time) (code string, err error) {
	switch {
	case totpSecret != "":
		code, err = generateTOTPCode(totpSecret, now)
		if err != nil {
			return "", fmt.Errorf("generating TOTP code: %w", err)
		}
		return code, nil
	case totpCode != "":
		return normalizeTOTPCode(totpCode)
	default:
		return "", errors.New("two-factor authentication is enabled on this account, " +
			"please set the TOTP secret or provide the 6-digit TOTP code")
	}
}

// generateTOTPCode returns the TOTP code for the given time, generated from
// the given secret, which can be either a base32 string or an otpauth:// URL.
func generateTOTPCode(secret string, now time.Time) (code string, err error) {
	normalizedSecret, err := normalizeTOTPSecret(secret)
	if err != nil {
		return "", err
	}
	if normalizedSecret == "" {
		return "", errors.New("the TOTP secret is empty, please provide the base32 secret or the " +
			"full otpauth:// URL shown when enabling two-factor authentication in Proton")
	}
	code, err = totp.GenerateCode(normalizedSecret, now)
	if err != nil {
		return "", fmt.Errorf("the TOTP secret is not a valid base32 string: %w", err)
	}
	return code, nil
}

// normalizeTOTPCode validates a user-provided temporary TOTP code: it must
// be the 6-digit code shown in the authenticator app. Whitespace is
// stripped from the code.
func normalizeTOTPCode(code string) (normalized string, err error) {
	code = strings.Join(strings.Fields(code), "")
	const codeLength = 6
	invalid := len(code) != codeLength
	for _, r := range code {
		if r < '0' || r > '9' {
			invalid = true
			break
		}
	}
	if invalid {
		return "", fmt.Errorf("the TOTP code must be the 6-digit temporary code shown in your "+
			"authenticator app, got %q", code)
	}
	return code, nil
}

// normalizeTOTPSecret extracts the base32 secret from an otpauth:// URL if
// needed, and removes formatting characters which are commonly present in
// copied secrets.
func normalizeTOTPSecret(secret string) (normalized string, err error) {
	secret = strings.TrimSpace(secret)
	if strings.HasPrefix(secret, "otpauth://") {
		key, err := otp.NewKeyFromURL(secret)
		if err != nil {
			return "", fmt.Errorf("parsing otpauth URL: %w", err)
		}
		secret = key.Secret()
	}
	// If the user copied just the "secret=..." query parameter, strip the
	// prefix. A base32 secret never contains "=", so this is unambiguous.
	if strings.HasPrefix(strings.ToLower(secret), "secret=") {
		secret = secret[len("secret="):]
	}

	// Keep only base32 alphabet characters (A-Z, 2-7), dropping any
	// formatting characters (spaces, newlines, hyphens, underscores,
	// base32 padding, and even invisible Unicode characters which can be
	// picked up when copying from a web page).
	var builder strings.Builder
	hasInvalidDigit := false
	for _, r := range secret {
		switch {
		case (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '2' && r <= '7'):
			builder.WriteRune(r)
		case (r >= '0' && r <= '1') || (r >= '8' && r <= '9'):
			// Digits 0, 1, 8 and 9 are not part of the base32 alphabet.
			hasInvalidDigit = true
		}
	}

	if hasInvalidDigit {
		return "", errors.New("the TOTP secret contains the digits 0, 1, 8 or 9 which are not " +
			"part of the base32 alphabet, please check that you copied the secret " +
			"(and not a 6-digit TOTP code) correctly")
	}

	return builder.String(), nil
}

type apiData struct {
	LogicalServers []logicalServer `json:"LogicalServers"`
}

type logicalServer struct {
	Name        string           `json:"Name"`
	ExitCountry string           `json:"ExitCountry"`
	Region      *string          `json:"Region"`
	City        *string          `json:"City"`
	Servers     []physicalServer `json:"Servers"`
	Features    uint16           `json:"Features"`
	Tier        *uint8           `json:"Tier,omitempty"`
}

type physicalServer struct {
	EntryIP         netip.Addr `json:"EntryIP,omitempty"`   // IPv4 entry address, invalid if not set
	EntryIPv6       netip.Addr `json:"EntryIPv6,omitempty"` // IPv6 entry address, invalid if not set
	ExitIP          netip.Addr `json:"ExitIP"`
	Domain          string     `json:"Domain"`
	Status          uint8      `json:"Status"`
	X25519PublicKey string     `json:"X25519PublicKey"`
}

// fetchServers fetches the logical servers, re-issuing the session cookie
// and retrying once when the session cookie does not carry the "vpn" scope
// yet, which happens when it was issued before the two-factor
// authentication completion.
func (c *apiClient) fetchServers(ctx context.Context, cookie cookie) (
	data apiData, err error,
) {
	data, err = c.fetchServersOnce(ctx, cookie)
	if err == nil {
		return data, nil
	}
	if !isInsufficientScopeError(err) {
		return data, err
	}
	// Re-issue the session cookie for the current session state, like
	// Proton's web clients do on stale session errors.
	refreshedToken, refreshErr := c.refreshSessionToken(ctx, cookie)
	if refreshErr != nil {
		return data, fmt.Errorf("session cookie does not have the \"vpn\" scope, "+
			"and re-issuing it failed: %w", refreshErr)
	}
	cookie.token = refreshedToken
	return c.fetchServersOnce(ctx, cookie)
}

func (c *apiClient) fetchServersOnce(ctx context.Context, cookie cookie) (
	data apiData, err error,
) {
	response, err := c.request(ctx, func() (*http.Request, error) {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, c.apiURLBase+"/vpn/v1/logicals?WithIpV6=1", nil)
		if err != nil {
			return nil, err
		}
		c.setHeaders(request, cookie)
		return request, nil
	})
	if err != nil {
		return data, err
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(response.Body)
		return data, buildError(response.StatusCode, b)
	}

	decoder := json.NewDecoder(response.Body)
	if err := decoder.Decode(&data); err != nil {
		return data, fmt.Errorf("decoding response body: %w", err)
	}

	return data, nil
}

// apiError is a Proton API error: a response with a non-200 status code and
// the response body, so the Proton error code can be extracted.
type apiError struct {
	httpCode int
	body     []byte
}

func (e *apiError) Error() string {
	prettyCode := http.StatusText(e.httpCode)
	var protonError struct {
		Code    *int              `json:"Code,omitempty"`
		Error   *string           `json:"Error,omitempty"`
		Details map[string]string `json:"Details"`
	}
	decoder := json.NewDecoder(bytes.NewReader(e.body))
	decoder.DisallowUnknownFields()
	err := decoder.Decode(&protonError)
	if err != nil || protonError.Error == nil || protonError.Code == nil {
		return fmt.Sprintf("HTTP status code not OK: %s: %s", prettyCode, e.body)
	}

	details := make([]string, 0, len(protonError.Details))
	for key, value := range protonError.Details {
		details = append(details, fmt.Sprintf("%s: %s", key, value))
	}

	return fmt.Sprintf("HTTP status code not OK: %s: %s (code %d with details: %s)",
		prettyCode, *protonError.Error, *protonError.Code, strings.Join(details, ", "))
}

func buildError(httpCode int, body []byte) error {
	return &apiError{httpCode: httpCode, body: body}
}

// isInsufficientScopeError reports whether the error is a Proton "access
// token does not have sufficient scope" error (code 9106).
func isInsufficientScopeError(err error) bool {
	var apiErr *apiError
	if !errors.As(err, &apiErr) {
		return false
	}
	var protonError struct {
		Code *int `json:"Code"`
	}
	if jsonErr := json.Unmarshal(apiErr.body, &protonError); jsonErr != nil || protonError.Code == nil {
		return false
	}
	const insufficientScopeCode = 9106
	return *protonError.Code == insufficientScopeCode
}
