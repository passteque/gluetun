package updater

import (
	"time"

	"github.com/qdm12/gluetun/internal/updater/resolver"
)

func parallelResolverSettings(hosts []string) (settings resolver.ParallelSettings) {
	const (
		maxFailRatio    = 1.0
		maxDuration     = 20 * time.Second
		betweenDuration = time.Second
		maxNoNew        = 2
		maxFails        = 2
	)
	return resolver.ParallelSettings{
		Hosts:        hosts,
		MaxFailRatio: maxFailRatio,
		Repeat: resolver.RepeatSettings{
			MaxDuration:     maxDuration,
			BetweenDuration: betweenDuration,
			MaxNoNew:        maxNoNew,
			MaxFails:        maxFails,
			SortIPs:         true,
		},
	}
}
