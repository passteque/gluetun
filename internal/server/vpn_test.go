package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func Test_VPNHandler_PatchSettings_rejects_unknown_field_when_payload_uses_legacy_names(t *testing.T) {
	t.Parallel()

	const body = `{"Provider":{"ServerSelection":{"Countries":["Netherlands"]}}}`
	request := httptest.NewRequestWithContext(t.Context(), http.MethodPut, "/v1/vpn/settings", strings.NewReader(body))
	response := httptest.NewRecorder()
	ctrl := gomock.NewController(t)
	looper := NewMockVPNLooper(ctrl)
	handler := &vpnHandler{looper: looper}

	handler.patchSettings(response, request)

	require.Equal(t, http.StatusBadRequest, response.Code)
	assert.Contains(t, response.Body.String(), `json: unknown field "ServerSelection"`)
	assert.NotContains(t, response.Body.String(), "settings left unchanged")
}
