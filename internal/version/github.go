package version

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

type githubRelease struct {
	TagName     string    `json:"tag_name"`
	Name        string    `json:"name"`
	Prerelease  bool      `json:"prerelease"`
	PublishedAt time.Time `json:"published_at"`
}

type githubCommit struct {
	Sha    string `json:"sha"`
	Commit struct {
		Committer struct {
			Date time.Time `json:"date"`
		} `json:"committer"`
	} `json:"commit"`
}

func getGithubReleases(ctx context.Context, client *http.Client) (releases []githubRelease, err error) {
	// Define a timeout since the default client has a large timeout and we don't
	// want to wait too long.
	const timeout = 15 * time.Second
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	const url = "https://api.github.com/repos/passteque/gluetun/releases"
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("bad response HTTP status code: %d %s",
			response.StatusCode, response.Status)
	}

	decoder := json.NewDecoder(response.Body)
	if err := decoder.Decode(&releases); err != nil {
		return nil, err
	}
	return releases, nil
}

func getGithubCommits(ctx context.Context, client *http.Client) (commits []githubCommit, err error) {
	// Define a timeout since the default client has a large timeout and we don't
	// want to wait too long.
	const timeout = 15 * time.Second
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	const url = "https://api.github.com/repos/passteque/gluetun/commits"
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	decoder := json.NewDecoder(response.Body)
	if err := decoder.Decode(&commits); err != nil {
		return nil, err
	}
	return commits, nil
}
