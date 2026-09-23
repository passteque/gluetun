package updater

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/qdm12/gluetun/internal/constants/vpn"
	"github.com/qdm12/gluetun/internal/models"
	"github.com/qdm12/gluetun/internal/provider/common"
	"github.com/qdm12/gluetun/internal/updater/resolver"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func Test_Updater_GetServers(t *testing.T) {
	t.Parallel()
	testCases := map[string]struct {
		// Inputs
		minServers int

		// Mocks
		warnerBuilder func(ctrl *gomock.Controller) common.Warner

		// Unzip
		unzipContents map[string][]byte
		unzipErr      error

		// Resolution
		expectResolve    bool
		resolverSettings resolver.ParallelSettings
		hostToIPs        map[string][]netip.Addr
		resolveWarnings  []string
		resolveErr       error

		// Output
		servers []models.Server
		err     error
	}{
		"unzipper error": {
			warnerBuilder: func(_ *gomock.Controller) common.Warner { return nil },
			unzipErr:      errors.New("dummy"),
			err:           errors.New("dummy"),
		},
		"not enough unzip contents": {
			minServers:    1,
			warnerBuilder: func(_ *gomock.Controller) common.Warner { return nil },
			unzipContents: map[string][]byte{},
			err:           errors.New("not enough servers found: 0 and expected at least 1"),
		},
		"no openvpn file": {
			minServers:    1,
			warnerBuilder: func(_ *gomock.Controller) common.Warner { return nil },
			unzipContents: map[string][]byte{"somefile.txt": {}},
			err:           errors.New("not enough servers found: 0 and expected at least 1"),
		},
		"invalid proto": {
			minServers: 1,
			warnerBuilder: func(ctrl *gomock.Controller) common.Warner {
				warner := common.NewMockWarner(ctrl)
				warner.EXPECT().Warn("unknown protocol: invalid in badproto.ovpn")
				return warner
			},
			unzipContents: map[string][]byte{"badproto.ovpn": []byte(`proto invalid`)},
			err:           errors.New("not enough servers found: 0 and expected at least 1"),
		},
		"no host": {
			minServers: 1,
			warnerBuilder: func(ctrl *gomock.Controller) common.Warner {
				warner := common.NewMockWarner(ctrl)
				warner.EXPECT().Warn("remote host not found in nohost.ovpn")
				return warner
			},
			unzipContents: map[string][]byte{"nohost.ovpn": []byte(``)},
			err:           errors.New("not enough servers found: 0 and expected at least 1"),
		},
		"multiple hosts": {
			minServers: 1,
			warnerBuilder: func(ctrl *gomock.Controller) common.Warner {
				warner := common.NewMockWarner(ctrl)
				warner.EXPECT().Warn("only using the first host \"hosta\" and discarding 1 other hosts")
				return warner
			},
			unzipContents: map[string][]byte{
				"ipvanish-CA-City-A-hosta.ovpn": []byte("remote hosta\nremote hostb"),
			},
			expectResolve: true,
			resolverSettings: resolver.ParallelSettings{
				Hosts:        []string{"hosta"},
				MaxFailRatio: 0.1,
				Repeat: resolver.RepeatSettings{
					MaxDuration:     20 * time.Second,
					BetweenDuration: time.Second,
					MaxNoNew:        2,
					MaxFails:        2,
					SortIPs:         true,
				},
			},
			err: errors.New("not enough servers found: 0 and expected at least 1"),
		},
		"resolve error": {
			warnerBuilder: func(ctrl *gomock.Controller) common.Warner {
				warner := common.NewMockWarner(ctrl)
				warner.EXPECT().Warn("resolve warning")
				return warner
			},
			unzipContents: map[string][]byte{
				"ipvanish-CA-City-A-hosta.ovpn": []byte("remote hosta"),
			},
			expectResolve: true,
			resolverSettings: resolver.ParallelSettings{
				Hosts:        []string{"hosta"},
				MaxFailRatio: 0.1,
				Repeat: resolver.RepeatSettings{
					MaxDuration:     20 * time.Second,
					BetweenDuration: time.Second,
					MaxNoNew:        2,
					MaxFails:        2,
					SortIPs:         true,
				},
			},
			resolveWarnings: []string{"resolve warning"},
			resolveErr:      errors.New("dummy"),
			err:             errors.New("dummy"),
		},
		"filename parsing error": {
			minServers: 1,
			warnerBuilder: func(ctrl *gomock.Controller) common.Warner {
				warner := common.NewMockWarner(ctrl)
				warner.EXPECT().Warn("country code is unknown: unknown in ipvanish-unknown-City-A-hosta.ovpn")
				return warner
			},
			unzipContents: map[string][]byte{
				"ipvanish-unknown-City-A-hosta.ovpn": []byte("remote hosta"),
			},
			err: errors.New("not enough servers found: 0 and expected at least 1"),
		},
		"success": {
			minServers: 1,
			warnerBuilder: func(ctrl *gomock.Controller) common.Warner {
				warner := common.NewMockWarner(ctrl)
				warner.EXPECT().Warn("resolve warning")
				return warner
			},
			unzipContents: map[string][]byte{
				"ipvanish-CA-City-A-hosta.ovpn": []byte("remote hosta"),
				"ipvanish-LU-City-B-hostb.ovpn": []byte("remote hostb"),
			},
			expectResolve: true,
			resolverSettings: resolver.ParallelSettings{
				Hosts:        []string{"hosta", "hostb"},
				MaxFailRatio: 0.1,
				Repeat: resolver.RepeatSettings{
					MaxDuration:     20 * time.Second,
					BetweenDuration: time.Second,
					MaxNoNew:        2,
					MaxFails:        2,
					SortIPs:         true,
				},
			},
			hostToIPs: map[string][]netip.Addr{
				"hosta": {netip.AddrFrom4([4]byte{1, 1, 1, 1}), netip.AddrFrom4([4]byte{2, 2, 2, 2})},
				"hostb": {netip.AddrFrom4([4]byte{3, 3, 3, 3}), netip.AddrFrom4([4]byte{4, 4, 4, 4})},
			},
			resolveWarnings: []string{"resolve warning"},
			servers: []models.Server{
				{
					VPN:      vpn.OpenVPN,
					Country:  "Canada",
					City:     "City A",
					Hostname: "hosta",
					UDP:      true,
					IPs:      []netip.Addr{netip.AddrFrom4([4]byte{1, 1, 1, 1}), netip.AddrFrom4([4]byte{2, 2, 2, 2})},
				},
				{
					VPN:      vpn.OpenVPN,
					Country:  "Luxembourg",
					City:     "City B",
					Hostname: "hostb",
					UDP:      true,
					IPs:      []netip.Addr{netip.AddrFrom4([4]byte{3, 3, 3, 3}), netip.AddrFrom4([4]byte{4, 4, 4, 4})},
				},
			},
		},
	}
	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)

			ctx := context.Background()

			unzipper := common.NewMockUnzipper(ctrl)
			const zipURL = "https://configs.ipvanish.com/openvpn/v2.6.0-0/configs.zip"
			// Context is wrapped with User-Agent for ipvanish, so use Any() for the ctx arg
			unzipper.EXPECT().FetchAndExtract(gomock.Any(), zipURL).
				Return(testCase.unzipContents, testCase.unzipErr)

			parallelResolver := common.NewMockParallelResolver(ctrl)
			if testCase.expectResolve {
				parallelResolver.EXPECT().Resolve(gomock.Any(), testCase.resolverSettings).
					Return(testCase.hostToIPs, testCase.resolveWarnings, testCase.resolveErr)
			}

			updater := &Updater{
				unzipper:         unzipper,
				warner:           testCase.warnerBuilder(ctrl),
				parallelResolver: parallelResolver,
			}

			servers, err := updater.FetchServers(ctx, testCase.minServers)

			assert.Equal(t, testCase.servers, servers)
			if testCase.err != nil {
				require.Error(t, err)
				assert.Equal(t, testCase.err.Error(), err.Error())
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
