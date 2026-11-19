package updater

import (
	"net/http"

	"github.com/qdm12/gluetun/internal/provider/common"
)

type Updater struct {
	client     *http.Client
	email      string
	password   string
	totpSecret string
	totpCode   string
	warner     common.Warner
}

func New(client *http.Client, warner common.Warner, email, password, totpSecret, totpCode string) *Updater {
	return &Updater{
		client:     client,
		email:      email,
		password:   password,
		totpSecret: totpSecret,
		totpCode:   totpCode,
		warner:     warner,
	}
}
