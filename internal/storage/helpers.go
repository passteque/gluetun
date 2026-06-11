package storage

import "fmt"

func panicOnProviderMissingHardcoded(provider string) {
	panic(fmt.Sprintf("provider %s not found in hardcoded servers map", provider))
}
