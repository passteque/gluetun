package updater

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/qdm12/gluetun/internal/constants/providers"
	"github.com/qdm12/gluetun/internal/provider/common"
	"github.com/qdm12/gluetun/internal/updater/unzip"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

type Updater struct {
	providers            Providers
	preferDirectDownload bool

	// state
	storage Storage

	// Functions for tests
	logger   Logger
	timeNow  func() time.Time
	client   *http.Client
	unzipper Unzipper
}

func New(httpClient *http.Client, storage Storage,
	providers Providers, logger Logger, preferDirectDownload bool,
) *Updater {
	unzipper := unzip.New(httpClient)
	return &Updater{
		providers:            providers,
		storage:              storage,
		logger:               logger,
		timeNow:              time.Now,
		client:               httpClient,
		unzipper:             unzipper,
		preferDirectDownload: preferDirectDownload,
	}
}

func (u *Updater) UpdateServers(ctx context.Context, providers []string,
	minRatio float64,
) (err error) {
	var manifest manifest
	if u.preferDirectDownload {
		manifest, err = u.fetchManifest(ctx)
		if err != nil {
			return fmt.Errorf("fetching remote manifest: %w", err)
		}
	}

	caser := cases.Title(language.English)
	for _, providerName := range providers {
		u.logger.Info("updating " + caser.String(providerName) + " servers...")

		fetcher := u.providers.Get(providerName)
		// TODO support servers offering only TCP or only UDP
		// for NordVPN and PureVPN
		err := u.updateProvider(ctx, fetcher, manifest, minRatio)
		switch {
		case err == nil:
			continue
		case errors.Is(err, common.ErrCredentialsMissing):
			u.logger.Warn(err.Error() + " - skipping update for " + providerName)
			continue
		case len(providers) == 1:
			// return the only error for the single provider.
			return err
		case ctx.Err() != nil:
			// stop updating other providers if context is done
			return ctx.Err()
		default: // error encountered updating one of multiple providers
			// Log the error and continue updating the next provider.
			u.logger.Error(err.Error())
		}
	}

	return nil
}

type manifest struct {
	providerToFilepath map[string]string
}

func (u *Updater) fetchManifest(ctx context.Context) (m manifest, err error) {
	const serversManifestURL = "https://raw.githubusercontent.com/qdm12/gluetun-servers/main/pkg/servers/manifest.json"
	var raw map[string]json.RawMessage
	err = u.fetchJSON(ctx, serversManifestURL, &raw)
	if err != nil {
		return m, err
	}

	providerNames := providers.All()
	m.providerToFilepath = make(map[string]string, len(providerNames))
	for _, name := range providerNames {
		var metadata struct {
			Filepath string `json:"filepath"`
		}
		err = json.Unmarshal(raw[name], &metadata)
		if err != nil {
			return m, fmt.Errorf("decoding manifest metadata for %s: %w", name, err)
		} else if metadata.Filepath == "" {
			return m, fmt.Errorf("manifest missing filepath for provider %s", name)
		}
		m.providerToFilepath[name] = metadata.Filepath
	}

	return m, nil
}

func (u *Updater) fetchJSON(ctx context.Context, rawURL string, dst any) (err error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}

	response, err := u.client.Do(request)
	if err != nil {
		return fmt.Errorf("doing request: %w", err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		const limit = 10 * 1024 * 1024 // 10 MiB
		body, _ := io.ReadAll(io.LimitReader(response.Body, limit))
		return fmt.Errorf("HTTP status code %d for %s: %s",
			response.StatusCode, rawURL, strings.TrimSpace(string(body)))
	}

	err = json.NewDecoder(response.Body).Decode(dst)
	if err != nil {
		return fmt.Errorf("decoding response body: %w", err)
	}

	return nil
}
