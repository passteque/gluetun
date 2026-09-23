package service

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	gomock "go.uber.org/mock/gomock"
)

func Test_Service_Stop(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		ports          []uint16
		listeningPorts []uint16
		// keepPortRunning is true if the keep port goroutine is expected
		// to be running, i.e. keepPortCancel and keepPortDoneCh are set.
		keepPortRunning bool
		// keepPortCrashed is true if the keep port goroutine has crashed,
		// i.e. keepPortDoneCh is already closed.
		keepPortCrashed bool
		// expectedFileContent is the port file content expected after Stop.
		expectedFileContent string
	}{
		"already stopped": {
			expectedFileContent: "1234",
		},
		// Regression test for https://github.com/qdm12/gluetun/issues/3451
		// where ports were set at runtime by SetPortsForwarded
		// while port forwarding is disabled, such as with providers
		// without internal port forwarding code support, then Stop
		// panicked on the nil keep port cancel function.
		"ports set without keep port goroutine": {
			ports:               []uint16{5914},
			expectedFileContent: "",
		},
		"multiple ports set without keep port goroutine": {
			ports:               []uint16{5914, 5915},
			expectedFileContent: "",
		},
		"ports set with redirection and without keep port goroutine": {
			ports:               []uint16{5914},
			listeningPorts:      []uint16{6000},
			expectedFileContent: "",
		},
		"keep port goroutine running": {
			keepPortRunning:     true,
			expectedFileContent: "",
		},
		"keep port goroutine crashed": {
			keepPortRunning:     true,
			keepPortCrashed:     true,
			expectedFileContent: "1234",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)

			portFilePath := filepath.Join(t.TempDir(), "forwarded_port")
			const initialFileContent = "1234"
			const filePerms = 0o644
			assert.NoError(t, os.WriteFile(portFilePath,
				[]byte(initialFileContent), filePerms))

			portAllower := NewMockPortAllower(ctrl)
			logger := NewMockLogger(ctrl)

			listeningPorts := testCase.listeningPorts
			if listeningPorts == nil {
				listeningPorts = []uint16{0} // disabled
			}
			settings := Settings{
				Enabled:        new(true),
				Filepath:       portFilePath,
				Interface:      "tun0",
				ListeningPorts: listeningPorts,
			}
			srv := New(settings, nil, nil, portAllower, logger, nil,
				os.Getuid(), os.Getgid())
			srv.ports = testCase.ports
			keepPortDoneCh := simulateKeepPortGoroutine(srv,
				testCase.keepPortRunning, testCase.keepPortCrashed)

			cleanupExpected := len(testCase.ports) > 0 ||
				(testCase.keepPortRunning && !testCase.keepPortCrashed)
			if cleanupExpected {
				logger.EXPECT().Info("stopping").Times(1)
				logger.EXPECT().Info("clearing port file " + portFilePath).Times(1)
				for _, port := range testCase.ports {
					portAllower.EXPECT().
						RemoveAllowedPort(context.Background(), port).
						Return(nil).Times(1)
					redirectionExpected := !slices.Equal(listeningPorts, []uint16{0})
					if redirectionExpected {
						const destinationPort = uint16(0) // 0 to clear the redirection
						portAllower.EXPECT().
							RedirectPort(context.Background(), "tun0", port, destinationPort).
							Return(nil).Times(1)
					}
				}
			}

			err := srv.Stop()

			assert.NoError(t, err)
			if testCase.keepPortRunning && !testCase.keepPortCrashed {
				select {
				case <-keepPortDoneCh:
				default:
					t.Fatal("keep port goroutine was not stopped")
				}
			}
			fileData, readErr := os.ReadFile(portFilePath)
			assert.NoError(t, readErr)
			assert.Equal(t, testCase.expectedFileContent, string(fileData))
		})
	}
}

// simulateKeepPortGoroutine sets the service keep port cancel and done
// channel as if the Start call had launched the keep port goroutine.
// If crashed is true, the done channel is immediately closed to simulate
// the goroutine having exited. It returns the done channel, nil otherwise.
func simulateKeepPortGoroutine(srv *Service, running, crashed bool) (doneCh chan struct{}) {
	if !running {
		return nil
	}
	keepPortCtx, keepPortCancel := context.WithCancel(context.Background())
	doneCh = make(chan struct{})
	srv.keepPortCancel = keepPortCancel
	srv.keepPortDoneCh = doneCh
	if crashed {
		close(doneCh)
		return doneCh
	}
	go func() {
		defer close(doneCh)
		<-keepPortCtx.Done()
	}()
	return doneCh
}
