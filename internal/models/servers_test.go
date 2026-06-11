package models

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/qdm12/gluetun/internal/constants/providers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_AllServers_MarshalJSON(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		allServers *AllServers
		dataString string
		errMessage string
	}{
		"no provider": {
			allServers: &AllServers{
				ProviderToServers: map[string]Servers{},
			},
			dataString: `{"version":0}`,
		},
		"two providers": {
			allServers: &AllServers{
				Version: 1,
				ProviderToServers: map[string]Servers{
					providers.Cyberghost: {
						Version:   1,
						Timestamp: 1000,
						Servers: []Server{
							{Country: "A"},
							{Country: "B"},
						},
					},
					providers.Privado: {
						Version:   2,
						Timestamp: 2000,
						Servers: []Server{
							{City: "C"},
							{City: "D"},
						},
					},
				},
			},
			dataString: `{"version":1,` +
				`"cyberghost":{"version":1,"timestamp":1000,"servers":[{"country":"A"},{"country":"B"}]},` +
				`"privado":{"version":2,"timestamp":2000,"servers":[{"city":"C"},{"city":"D"}]}}`,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			data, err := testCase.allServers.MarshalJSON()
			if testCase.errMessage != "" {
				assert.EqualError(t, err, testCase.errMessage)
			} else {
				assert.NoError(t, err)
			}
			require.Equal(t, testCase.dataString, string(data))

			data, err = json.Marshal(testCase.allServers)
			if testCase.errMessage != "" {
				assert.EqualError(t, err, testCase.errMessage)
			} else {
				assert.NoError(t, err)
			}
			require.Equal(t, testCase.dataString, string(data))

			buffer := bytes.NewBuffer(nil)
			encoder := json.NewEncoder(buffer)
			// encoder.SetIndent("", "  ")
			err = encoder.Encode(testCase.allServers)
			require.NoError(t, err)
			assert.Equal(t, testCase.dataString+"\n", buffer.String())
		})
	}
}

func Test_AllServers_UnmarshalJSON(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		dataString string
		allServers AllServers
		errMessage string
	}{
		"empty": {
			dataString: "{}",
			allServers: AllServers{},
		},
		"two known providers": {
			dataString: `{"version":1,` +
				`"cyberghost":{"version":1,"timestamp":1000,"servers":[{"country":"A"},{"country":"B"}]},` +
				`"privado":{"version":2,"timestamp":2000,"servers":[{"city":"C"},{"city":"D"}]}}`,
			allServers: AllServers{
				Version: 1,
				ProviderToServers: map[string]Servers{
					providers.Cyberghost: {
						Version:   1,
						Timestamp: 1000,
						Servers: []Server{
							{Country: "A"},
							{Country: "B"},
						},
					},
					providers.Privado: {
						Version:   2,
						Timestamp: 2000,
						Servers: []Server{
							{City: "C"},
							{City: "D"},
						},
					},
				},
			},
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			data := []byte(testCase.dataString)
			var allServers AllServers

			err := json.Unmarshal(data, &allServers)

			if testCase.errMessage != "" {
				assert.EqualError(t, err, testCase.errMessage)
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, testCase.allServers, allServers)
		})
	}
}

func Test_AllServers_JSON_Marshal_Unmarshal(t *testing.T) {
	t.Parallel()

	allServers := &AllServers{
		Version: 1,
		ProviderToServers: map[string]Servers{
			providers.Cyberghost: {
				Version:   1,
				Timestamp: 1000,
				Servers: []Server{
					{Country: "A"},
					{Country: "B"},
				},
			},
			providers.Privado: {
				Version:   2,
				Timestamp: 2000,
				Servers: []Server{
					{City: "C"},
					{City: "D"},
				},
			},
		},
	}

	buffer := bytes.NewBuffer(nil)
	encoder := json.NewEncoder(buffer)
	encoder.SetIndent("", "  ")

	err := encoder.Encode(allServers)
	require.NoError(t, err)

	decoder := json.NewDecoder(buffer)
	var result AllServers
	err = decoder.Decode(&result)
	require.NoError(t, err)

	assert.Equal(t, allServers, &result)
}
