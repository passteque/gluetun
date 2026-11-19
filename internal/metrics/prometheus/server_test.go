package prometheus

import (
	"errors"
	"io"
	"net/http"
	"testing"
	"time"

	dto "github.com/prometheus/client_model/go"
	"github.com/qdm12/gluetun/internal/configuration/settings"
	"github.com/qdm12/goservices"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	gomock "go.uber.org/mock/gomock"
	"google.golang.org/protobuf/proto"
)

type noopLogger struct{}

func (noopLogger) Info(string)  {}
func (noopLogger) Error(string) {}

func Test_New(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		settings   settings.Prometheus
		errMessage string
	}{
		"valid settings": {
			settings: settings.Prometheus{
				ListeningAddress: "127.0.0.1:0",
			},
		},
		"invalid listening address": {
			settings: settings.Prometheus{
				ListeningAddress: "127.0.0.1:x",
			},
			errMessage: "listening address is not valid",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			gatherer := NewMockGatherer(ctrl)

			server, err := New(testCase.settings, gatherer, noopLogger{})

			if testCase.errMessage != "" {
				assert.ErrorContains(t, err, testCase.errMessage)
				assert.Nil(t, server)
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, "prometheus http server", server.String())
		})
	}
}

func Test_New_Serve(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	gatherer := NewMockGatherer(ctrl)
	testCounterFamily := &dto.MetricFamily{
		Name: new("gluetun_test_counter"),
		Help: new("A test counter."),
		Type: dto.MetricType_COUNTER.Enum(),
		Metric: []*dto.Metric{
			{Counter: &dto.Counter{Value: proto.Float64(42)}},
		},
	}
	gatherer.EXPECT().Gather().Return([]*dto.MetricFamily{testCounterFamily}, nil).Times(1)

	server, err := New(settings.Prometheus{
		ListeningAddress: "127.0.0.1:0",
	}, gatherer, noopLogger{})
	require.NoError(t, err)

	t.Cleanup(func() {
		stopErr := server.Stop()
		if stopErr != nil && !errors.Is(stopErr, goservices.ErrAlreadyStopped) {
			assert.NoError(t, stopErr)
		}
	})

	_, err = server.Start(t.Context())
	require.NoError(t, err)

	const clientTimeout = 3 * time.Second
	client := &http.Client{Timeout: clientTimeout}
	metricsURL := "http://" + server.GetAddress() + "/metrics"
	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, metricsURL, nil)
	require.NoError(t, err)
	response, err := client.Do(request)
	require.NoError(t, err)
	defer response.Body.Close()
	assert.Equal(t, http.StatusOK, response.StatusCode)
	body, err := io.ReadAll(response.Body)
	require.NoError(t, err)
	assert.Contains(t, string(body), "# TYPE gluetun_test_counter counter")
	assert.Contains(t, string(body), "gluetun_test_counter 42")

	err = server.Stop()
	assert.NoError(t, err)
	err = server.Stop()
	assert.ErrorIs(t, err, goservices.ErrAlreadyStopped)
}
