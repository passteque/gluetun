package updater

import (
	"net/http"

	"github.com/qdm12/gluetun/internal/provider/common"
)

type Updater struct {
	client           *http.Client
	ipFetcher        common.IPFetcher
	unzipper         common.Unzipper
	parallelResolver common.ParallelResolver
	warner           common.Warner
}

func New(client *http.Client, ipFetcher common.IPFetcher, unzipper common.Unzipper,
	warner common.Warner, parallelResolver common.ParallelResolver,
) *Updater {
	if client == nil {
		client = http.DefaultClient
	}

	return &Updater{
		client:           client,
		ipFetcher:        ipFetcher,
		unzipper:         unzipper,
		parallelResolver: parallelResolver,
		warner:           warner,
	}
}
