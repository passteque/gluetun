package updater

import (
	"net/http"
)

type Updater struct {
	client *http.Client
}

func New(client *http.Client) *Updater {
	return &Updater{
		client: client,
	}
}
