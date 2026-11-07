package api

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/qdm12/gluetun/internal/models"
	"golang.org/x/text/runes"
	"golang.org/x/text/transform"
	"golang.org/x/text/unicode/norm"
)

// ResilientFetcher is a fetcher implementation using multiple fetchers.
// If a fetcher fails, it tries the next one.
// To fetch public IP information for a specific IP address,
// it fetches from all sources to find the best result, since data
// from a single source can be wrong.
type ResilientFetcher struct {
	fetchers         []Fetcher
	logger           Warner
	fetcherToBanTime map[Fetcher]time.Time
	banMutex         sync.RWMutex
	mutex            sync.RWMutex
	timeNow          func() time.Time
}

// NewResilient creates a 'resilient' fetcher given multiple fetchers.
func NewResilient(fetchers []Fetcher, logger Warner) *ResilientFetcher {
	return &ResilientFetcher{
		fetchers:         fetchers,
		logger:           logger,
		fetcherToBanTime: make(map[Fetcher]time.Time, len(fetchers)),
		timeNow:          time.Now,
	}
}

func (r *ResilientFetcher) setBanned(fetcher Fetcher) {
	r.banMutex.Lock()
	defer r.banMutex.Unlock()
	r.fetcherToBanTime[fetcher] = r.timeNow()
}

func (r *ResilientFetcher) isBanned(fetcher Fetcher) (banned bool) {
	r.banMutex.Lock()
	defer r.banMutex.Unlock()
	banTime, banned := r.fetcherToBanTime[fetcher]
	if !banned {
		return false
	}
	const banDuration = 30 * 24 * time.Hour
	banExpiryTime := banTime.Add(banDuration)
	now := r.timeNow()
	if now.After(banExpiryTime) {
		delete(r.fetcherToBanTime, fetcher)
		return false
	}
	return true
}

func (r *ResilientFetcher) String() string {
	r.mutex.RLock()
	defer r.mutex.RUnlock()
	names := make([]string, 0, len(r.fetchers))
	for _, fetcher := range r.fetchers {
		if r.isBanned(fetcher) {
			continue
		}
		names = append(names, fetcher.String())
	}
	if len(names) == 0 {
		return "<all-banned>"
	}
	return strings.Join(names, "+")
}

func (r *ResilientFetcher) Token() string {
	panic("invalid call")
}

// CanFetchAnyIP returns true if any of the fetchers
// can fetch any IP address and is not banned.
func (r *ResilientFetcher) CanFetchAnyIP() bool {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	for _, fetcher := range r.fetchers {
		if !fetcher.CanFetchAnyIP() || r.isBanned(fetcher) {
			continue
		}
		return true
	}
	return false
}

// FetchInfo obtains information on the ip address provided.
// If the ip is the zero value, the public IP address of the machine
// is used as the IP.
// It queries all non-banned fetchers in parallel to obtain the most popular result.
// It only returns an error if all fetchers fail to return information.
func (r *ResilientFetcher) FetchInfo(ctx context.Context, ip netip.Addr) (
	result models.PublicIP, err error,
) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	type resultData struct {
		i       int
		fetcher Fetcher
		result  models.PublicIP
		err     error
	}
	resultsCh := make(chan resultData)
	fetchersStarted := 0
	for _, fetcher := range r.fetchers {
		if r.isBanned(fetcher) ||
			(ip.IsValid() && !fetcher.CanFetchAnyIP()) {
			continue
		}

		go func(i int, fetcher Fetcher) {
			result, err := fetcher.FetchInfo(ctx, ip)
			resultsCh <- resultData{
				i:       i,
				fetcher: fetcher,
				result:  result,
				err:     err,
			}
		}(fetchersStarted, fetcher)
		fetchersStarted++
	}

	if fetchersStarted == 0 {
		if ip.IsValid() {
			return models.PublicIP{}, fmt.Errorf("no fetcher available for ip address %s: "+
				"all fetchers are banned or can only fetch their own public ip address", ip)
		}
		return models.PublicIP{}, errors.New("no fetcher available: all fetchers are banned")
	}

	// Collect resultDatas from goroutines first, which takes I/O time
	// so that we don't lock the ban map mutex for too long.
	resultDatas := make([]resultData, fetchersStarted)
	for range resultDatas {
		data := <-resultsCh
		resultDatas[data.i] = data
	}

	// Mutex lock ban map and process results
	results := make([]models.PublicIP, 0, fetchersStarted)
	errs := make([]error, 0, fetchersStarted)
	for _, data := range resultDatas {
		fetcher := data.fetcher
		if data.err != nil {
			if errors.Is(data.err, ErrTooManyRequests) {
				r.setBanned(fetcher)
			}
			errs = append(errs, fmt.Errorf("%s: %w", fetcher, data.err))
			continue
		}
		results = append(results, data.result)
	}

	if len(results) == 0 { // all failed
		return models.PublicIP{}, fmt.Errorf("all fetchers failed: %w", errors.Join(errs...))
	}

	return getMostPopularResult(results), nil
}

// getMostPopularResult finds the most popular [models.PublicIP] from
// a slice of results. It does so by first checking the country, then
// region, then city fields. The other fields are ignored in this comparison.
func getMostPopularResult(results []models.PublicIP) models.PublicIP {
	if len(results) == 0 {
		panic("no results to choose from")
	}

	// 1. Filter by Country
	countries := make([]string, len(results))
	for i, r := range results {
		countries[i] = r.Country
	}
	_, countryMembers := getMostPopularString(countries)
	results = filterInPlace(results, countryMembers)

	// 2. Filter by Region
	regions := make([]string, len(results))
	for i, r := range results {
		regions[i] = r.Region
	}
	_, regionMembers := getMostPopularString(regions)
	results = filterInPlace(results, regionMembers)

	// 3. Filter by City
	cities := make([]string, len(results))
	for i, r := range results {
		cities[i] = r.City
	}
	winnerIdx, _ := getMostPopularString(cities)

	return results[winnerIdx]
}

// filterInPlace moves selected indices to the front and trims the slice.
func filterInPlace(results []models.PublicIP, indices []int) []models.PublicIP {
	for i, originalIdx := range indices {
		results[i] = results[originalIdx]
	}
	return results[:len(indices)]
}

// getMostPopularString returns the index of the representative winner
// and a slice of all indexes that belong to that winner's cluster.
func getMostPopularString(values []string) (winnerIdx int, memberIdxs []int) {
	if len(values) == 0 {
		return -1, nil
	}

	type cluster struct {
		firstIndex int
		normRep    string
		members    []int
	}

	var groups []cluster

	for i, value := range values {
		normP := normalize(value)
		found := false

		for j := range groups {
			if levenshteinDistance(normP, groups[j].normRep) <= 1 {
				groups[j].members = append(groups[j].members, i)
				found = true
				break
			}
		}

		if !found {
			groups = append(groups, cluster{
				firstIndex: i,
				normRep:    normP,
				members:    []int{i},
			})
		}
	}

	maxCount := -1
	var bestGroup cluster

	for _, g := range groups {
		if len(g.members) > maxCount {
			maxCount = len(g.members)
			bestGroup = g
		}
	}

	return bestGroup.firstIndex, bestGroup.members
}

func (r *ResilientFetcher) UpdateFetchers(fetchers []Fetcher) {
	newFetcherNameToFetcher := make(map[string]Fetcher, len(fetchers))
	for _, fetcher := range fetchers {
		newFetcherNameToFetcher[fetcher.String()] = fetcher
	}

	r.mutex.Lock()
	defer r.mutex.Unlock()

	newFetcherToBanTime := make(map[Fetcher]time.Time, len(r.fetcherToBanTime))
	for bannedFetcher, banTime := range r.fetcherToBanTime {
		if !r.isBanned(bannedFetcher) {
			// fetcher is no longer in its ban period.
			continue
		}
		bannedName := bannedFetcher.String()
		newFetcher, isNewFetcher := newFetcherNameToFetcher[bannedName]
		if isNewFetcher && newFetcher.Token() == bannedFetcher.Token() {
			newFetcherToBanTime[newFetcher] = banTime
		}
	}

	r.fetchers = fetchers
	r.fetcherToBanTime = newFetcherToBanTime
}

// normalize removes accents, trims space, and lowercases the string.
func normalize(s string) string {
	firstParentheseIndex := strings.Index(s, " (")
	if firstParentheseIndex != -1 {
		s = s[:firstParentheseIndex]
	}
	transformer := transform.Chain(norm.NFD, runes.Remove(runes.In(unicode.Mn)), norm.NFC)
	result, _, err := transform.String(transformer, s)
	if err != nil {
		panic(err)
	}
	return strings.ToLower(strings.TrimSpace(result))
}

// levenshteinDistance calculates the edit distance
// between two strings a and b.
func levenshteinDistance(a, b string) int {
	switch {
	case len(a) == 0:
		return len(b)
	case len(b) == 0:
		return len(a)
	}

	column := make([]int, len(b)+1)
	for i := 0; i <= len(b); i++ {
		column[i] = i
	}

	for i := 1; i <= len(a); i++ {
		column[0] = i
		lastValue := i - 1
		for j := 1; j <= len(b); j++ {
			oldValue := column[j]
			cost := 0
			if a[i-1] != b[j-1] {
				cost = 1
			}
			column[j] = min(column[j]+1, min(column[j-1]+1, lastValue+cost))
			lastValue = oldValue
		}
	}
	return column[len(b)]
}
