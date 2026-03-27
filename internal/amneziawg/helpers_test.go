package amneziawg

func ptrTo[T any](v T) *T {
	return &v
}
