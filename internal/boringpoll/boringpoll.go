package boringpoll

import (
	"context"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"sync"
	"time"

	"github.com/qdm12/gluetun/internal/configuration/settings"
)

type BoringPoll struct {
	// Injected dependencies
	client *http.Client
	logger Logger

	// Internal state
	urlToData map[string]*urlData

	// Internal signals and channels
	cancel context.CancelFunc
	done   <-chan struct{}
	mutex  sync.Mutex
}

type urlData struct{}

func New(client *http.Client, logger Logger, settings settings.BoringPoll) *BoringPoll {
	urlToData := make(map[string]*urlData)
	if *settings.GluetunCom {
		urlToData["https://gluetun.com/wp-json"] = &urlData{}
	}
	return &BoringPoll{
		client:    client,
		logger:    logger,
		urlToData: urlToData,
	}
}

func (b *BoringPoll) Start() (runError <-chan error, err error) {
	b.mutex.Lock()
	defer b.mutex.Unlock()

	if len(b.urlToData) == 0 {
		return nil, nil //nolint:nilnil
	}

	const minPeriod = time.Minute
	const maxPeriod = 5 * time.Minute
	const logEveryBytes = 100 * 1000 * 1000 // 100 IEC MB

	var ready, done sync.WaitGroup
	ready.Add(len(b.urlToData))
	done.Add(len(b.urlToData))
	ctx, cancel := context.WithCancel(context.Background())
	b.cancel = cancel
	for url := range b.urlToData {
		go func(url string) {
			defer done.Done()

			b.logger.Infof("running against %s periodically between %s and %s "+
				"and will log every %s downloaded",
				url, minPeriod, maxPeriod, byteCountSI(logEveryBytes))
			totalDownloaded := uint64(0)
			lastDownloaded := uint64(0)
			consecutiveFails := 0
			const maxConsecutiveErrs = 3
			const coolDownTimeout = time.Hour
			timer := time.NewTimer(time.Hour)
			var err error

			ready.Done()
			for {
				timeout := minPeriod + time.Duration(rand.Int63n(int64(maxPeriod-minPeriod))) //nolint:gosec
				if consecutiveFails >= maxConsecutiveErrs {
					b.logger.Debugf("pausing poll to %s for %s due to %d consecutive errors, last error: %s",
						url, coolDownTimeout, consecutiveFails, err)
					timeout = coolDownTimeout
				}
				timer.Reset(timeout)
				select {
				case <-ctx.Done():
					timer.Stop()
					totalDownloaded += lastDownloaded
					if totalDownloaded > 0 {
						b.logger.Infof("stopping poll to %s, downloaded %s!", url, byteCountSI(totalDownloaded))
					}
					return
				case <-timer.C:
				}
				var n int64
				n, err = fetchURL(ctx, b.client, url)
				if err != nil {
					consecutiveFails++
					continue
				}
				consecutiveFails = 0
				totalDownloaded += uint64(n) //nolint:gosec
				lastDownloaded += uint64(n)  //nolint:gosec
				if lastDownloaded >= logEveryBytes {
					b.logger.Infof("thanks for helping! You have downloaded %s from %s so far!",
						byteCountSI(totalDownloaded), url)
					lastDownloaded = 0
				}
			}
		}(url)
	}
	return nil, nil //nolint:nilnil
}

func fetchURL(ctx context.Context, client *http.Client, url string) (downloaded int64, err error) {
	const requestTimeout = 10 * time.Second
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		cancel()
		return 0, err
	}
	request.Header.Set("Cache-Control", "no-cache, no-store, must-revalidate")
	request.Header.Set("Pragma", "no-cache")
	request.Header.Set("Expires", "0")
	request.Header.Set("User-Agent", getRandomUserAgent())

	response, err := client.Do(request)
	if err != nil {
		return 0, err
	}
	downloaded, err = io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()
	if err != nil {
		return 0, err
	}
	return downloaded, nil
}

func getRandomUserAgent() string {
	//nolint:lll
	userAgents := [...]string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2.1 Safari/605.1.15",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/121.0.0.0 Safari/537.36",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 17_2_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
		"Mozilla/5.0 (iPad; CPU OS 17_2_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
		"Mozilla/5.0 (Android 14; Mobile; rv:122.0) Gecko/122.0 Firefox/122.0",
		"Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Mobile Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 OPR/106.0.0.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 OPR/106.0.0.0",
		"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
		"Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
	}
	return userAgents[rand.Intn(len(userAgents))] //nolint:gosec
}

func (b *BoringPoll) Stop() error {
	b.mutex.Lock()
	defer b.mutex.Unlock()

	if b.cancel == nil {
		return nil
	}
	b.cancel()
	<-b.done
	b.cancel = nil
	b.done = nil
	return nil
}

func byteCountSI(b uint64) string {
	const unit = 1000
	if b < unit {
		return fmt.Sprintf("%dB", b)
	}

	div, exp := uint64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}

	return fmt.Sprintf("%.1f%cB", float64(b)/float64(div), "kMGTPE"[exp])
}
