package metrics

//go:generate mockgen -destination=mocks_tunstats_test.go -package=$GOPACKAGE github.com/qdm12/gluetun/internal/metrics/tunstats VPNLooper,LinkLister
