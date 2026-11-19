package settings

import (
	"encoding/binary"
	"math/rand/v2"

	gomock "go.uber.org/mock/gomock"
)

type sourceKeyValue struct {
	key   string
	value string
}

func newMockSource(ctrl *gomock.Controller, keyValues []sourceKeyValue) *MockSource {
	source := NewMockSource(ctrl)
	var previousCall *gomock.Call
	for _, keyValue := range keyValues {
		transformedKey := keyValue.key
		keyTransformCall := source.EXPECT().KeyTransform(keyValue.key).Return(transformedKey)
		if previousCall != nil {
			keyTransformCall.After(previousCall)
		}
		isSet := keyValue.value != ""
		previousCall = source.EXPECT().Get(transformedKey).
			Return(keyValue.value, isSet).After(keyTransformCall)
		if isSet {
			previousCall = source.EXPECT().KeyTransform(keyValue.key).
				Return(transformedKey).After(previousCall)
			previousCall = source.EXPECT().String().
				Return("mock source").After(previousCall)
		}
	}
	return source
}

func generate32Bytes() []byte {
	b := make([]byte, 32)
	for i := 0; i < len(b); i += 8 {
		binary.LittleEndian.PutUint64(b[i:], rand.Uint64()) //nolint:gosec
	}
	return b
}
