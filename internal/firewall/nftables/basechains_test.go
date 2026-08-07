package nftables

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func Test_SetBaseChainsPolicy_ErrorCases(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	testCases := map[string]struct {
		policy string
		want   bool // want error
		errIs  error
	}{
		"accept policy": {
			policy: "ACCEPT",
			want:   false,
		},
		"accept lowercase": {
			policy: "accept",
			want:   false,
		},
		"drop policy": {
			policy: "DROP",
			want:   false,
		},
		"drop lowercase": {
			policy: "drop",
			want:   false,
		},
		"unknown policy": {
			policy: "UNKNOWN",
			want:   true,
			errIs:  ErrPolicyUnknown,
		},
		"empty policy": {
			policy: "",
			want:   true,
			errIs:  ErrPolicyUnknown,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			logger := NewMockLogger(ctrl)
			fw := New(logger)

			err := fw.SetBaseChainsPolicy(ctx, tc.policy)

			if tc.want {
				assert.Error(t, err)
				if tc.errIs != nil {
					assert.ErrorIs(t, err, tc.errIs)
				}
			} else if err != nil {
				// Valid policies may still fail if nftables isn't available in test env
				// Just check we didn't get the unknown policy error
				assert.NotErrorIs(t, err, ErrPolicyUnknown)
			}
		})
	}
}

func Test_SetIPv4AllPolicies(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	ctrl := gomock.NewController(t)
	logger := NewMockLogger(ctrl)
	fw := New(logger)

	// SetIPv4AllPolicies delegates to SetBaseChainsPolicy
	// Test with an invalid policy to verify delegation
	err := fw.SetIPv4AllPolicies(ctx, "INVALID")
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrPolicyUnknown)
}

func Test_SetIPv6AllPolicies(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	ctrl := gomock.NewController(t)
	logger := NewMockLogger(ctrl)
	fw := New(logger)

	// SetIPv6AllPolicies delegates to SetBaseChainsPolicy
	// Test with an invalid policy to verify delegation
	err := fw.SetIPv6AllPolicies(ctx, "INVALID")
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrPolicyUnknown)
}
