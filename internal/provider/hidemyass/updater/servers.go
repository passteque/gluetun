package updater

import (
	"context"
	"errors"

	"github.com/qdm12/gluetun/internal/models"
)

func (u *Updater) FetchServers(_ context.Context, _ int) (
	servers []models.Server, err error,
) {
	return nil, errors.New("hidemyass servers are no longer available")
}
