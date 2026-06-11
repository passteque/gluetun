package version

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"time"

	"github.com/qdm12/gluetun/internal/format"
	"github.com/qdm12/gluetun/internal/models"
)

// GetMessage returns a message for the user describing if there is a newer version
// available. It should only be called once the tunnel is established.
func GetMessage(ctx context.Context, buildInfo models.BuildInformation,
	client *http.Client,
) (message string, err error) {
	if buildInfo.Version == "latest" {
		// Find # of commits between current commit and latest commit
		commitsSince, err := getCommitsSince(ctx, client, buildInfo.Commit)
		if err != nil {
			return "", err
		} else if commitsSince == 0 {
			return fmt.Sprintf("You are running on the bleeding edge of %s!", buildInfo.Version), nil
		}
		commits := "commits"
		if commitsSince == 1 {
			commits = "commit"
		}
		return fmt.Sprintf("You are running %d %s behind the most recent %s", commitsSince, commits, buildInfo.Version), nil
	}
	tagName, name, releaseTime, err := getLatestRelease(ctx, client)
	if err != nil {
		return "", err
	}
	if tagName == buildInfo.Version {
		return fmt.Sprintf("You are running the latest release %s", buildInfo.Version), nil
	}
	timeSinceRelease := format.FriendlyDuration(time.Since(releaseTime))
	return fmt.Sprintf("There is a new release %s (%s) created %s ago",
			tagName, name, timeSinceRelease),
		nil
}

func getLatestRelease(ctx context.Context, client *http.Client) (tagName, name string, time time.Time, err error) {
	releases, err := getGithubReleases(ctx, client)
	if err != nil {
		return "", "", time, err
	}
	// Sort releases by tag names (semver)
	sort.Slice(releases, func(i, j int) bool {
		return releases[i].TagName > releases[j].TagName
	})
	for _, release := range releases {
		if release.Prerelease {
			continue
		}
		return release.TagName, release.Name, release.PublishedAt, nil
	}
	return "", "", time, errors.New("release not found")
}

func getCommitsSince(ctx context.Context, client *http.Client, commitShort string) (n int, err error) {
	commits, err := getGithubCommits(ctx, client)
	if err != nil {
		return 0, err
	}
	for i := range commits {
		if commits[i].Sha[:7] == commitShort {
			return n, nil
		}
		n++
	}
	return 0, fmt.Errorf("commit not found: %s", commitShort)
}
