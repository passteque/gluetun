package iptables

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_filterData(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		cmdOutput  string
		filtered   string
		errMessage string
	}{
		"empty": {},
		"unsupported_revision": {
			cmdOutput:  "-A INPUT -j ACCEPT [unsupported revision]",
			errMessage: "mismatch container iptables-save and kernel: " +
				"-A INPUT -j ACCEPT [unsupported revision]",
		},
		"no_docker_chains": {
			cmdOutput: "*filter\n" +
				":INPUT DROP [0:0]\n" +
				"-A INPUT -i lo -j ACCEPT\n" +
				"COMMIT",
			filtered: "*filter\n" +
				":INPUT DROP [0:0]\n" +
				"-A INPUT -i lo -j ACCEPT\n" +
				"COMMIT",
		},
		"docker_output_and_postrouting_chains_and_jumps_filtered_out": {
			cmdOutput: "*nat\n" +
				":PREROUTING ACCEPT [2:120]\n" +
				":OUTPUT ACCEPT [0:0]\n" +
				":POSTROUTING ACCEPT [0:0]\n" +
				":DEFAULT_OUTPUT - [0:0]\n" +
				":DEFAULT_POSTROUTING - [0:0]\n" +
				":DOCKER_OUTPUT - [0:0]\n" +
				":DOCKER_POSTROUTING - [0:0]\n" +
				"-A OUTPUT -j DEFAULT_OUTPUT\n" +
				"-A POSTROUTING -j DEFAULT_POSTROUTING\n" +
				"-A DEFAULT_OUTPUT -d 127.0.0.11/32 -j DOCKER_OUTPUT\n" +
				"-A DEFAULT_POSTROUTING -d 127.0.0.11/32 -j DOCKER_POSTROUTING\n" +
				"-A DOCKER_OUTPUT -d 127.0.0.11/32 -p tcp -m tcp --dport 53 -j DNAT --to-destination 127.0.0.11:39001\n" +
				"-A DOCKER_POSTROUTING -d 127.0.0.11/32 -p tcp -m tcp --dport 53 -j SNAT --to-source :39001\n" +
				"COMMIT",
			filtered: "*nat\n" +
				":PREROUTING ACCEPT [2:120]\n" +
				":OUTPUT ACCEPT [0:0]\n" +
				":POSTROUTING ACCEPT [0:0]\n" +
				":DEFAULT_OUTPUT - [0:0]\n" +
				":DEFAULT_POSTROUTING - [0:0]\n" +
				"-A OUTPUT -j DEFAULT_OUTPUT\n" +
				"-A POSTROUTING -j DEFAULT_POSTROUTING\n" +
				"COMMIT",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			filtered, err := filterData([]byte(testCase.cmdOutput))

			if testCase.errMessage != "" {
				assert.EqualError(t, err, testCase.errMessage)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, testCase.filtered, filtered)
		})
	}
}
