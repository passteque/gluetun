//go:build integration

package restrictednet

func ptrTo[T any](value T) *T {
	return &value
}
