package cleanup

import (
	"errors"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

func Test_Cleanups(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)

	var ACloseCalled, BCloseCalled, CCloseCalled bool
	var (
		AErr error
		BErr = errors.New("B failed")
		CErr = errors.New("C failed")
	)

	var cleanups Cleanups
	cleanups.Add("cleaning up A", 5, func() error {
		ACloseCalled = true
		return AErr
	})

	cleanups.Add("cleaning up B", 3, func() error {
		BCloseCalled = true
		return BErr
	})

	cleanups.Add("cleaning up C", 2, func() error {
		CCloseCalled = true
		return CErr
	})

	logger := NewMockLogger(ctrl)
	prevCall := logger.EXPECT().Debug("cleaning up C...")
	prevCall = logger.EXPECT().Error("failed cleaning up C: C failed").After(prevCall)
	prevCall = logger.EXPECT().Debug("cleaning up B...").After(prevCall)
	prevCall = logger.EXPECT().Error("failed cleaning up B: B failed").After(prevCall)
	logger.EXPECT().Debug("cleaning up A...").After(prevCall)

	cleanups.Cleanup(logger)

	cleanups.Cleanup(logger) // run twice should not close already closed

	for _, cleanup := range cleanups {
		assert.True(t, cleanup.done)
	}

	assert.True(t, ACloseCalled)
	assert.True(t, BCloseCalled)
	assert.True(t, CCloseCalled)
}
