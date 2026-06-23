package updater

import (
	"net/http"

	"github.com/qdm12/gluetun/internal/provider/common"
)

type Updater struct {
	client           *http.Client
	unzipper         common.Unzipper
	parallelResolver common.ParallelResolver
	logger           common.Warner
}

func New(client *http.Client, unzipper common.Unzipper,
	warner common.Warner, parallelResolver common.ParallelResolver,
) *Updater {
	return &Updater{
		client:           client,
		unzipper:         unzipper,
		parallelResolver: parallelResolver,
		logger:           warner,
	}
}
