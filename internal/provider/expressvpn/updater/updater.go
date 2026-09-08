package updater

import (
	"net/http"

	"github.com/qdm12/gluetun/internal/provider/common"
)

type Updater struct {
	httpClient       *http.Client
	unzipper         common.Unzipper
	parallelResolver common.ParallelResolver
	warner           common.Warner
}

func New(httpClient *http.Client, unzipper common.Unzipper,
	warner common.Warner, parallelResolver common.ParallelResolver,
) *Updater {
	return &Updater{
		httpClient:       httpClient,
		unzipper:         unzipper,
		parallelResolver: parallelResolver,
		warner:           warner,
	}
}
