package tunstats

//go:generate mockgen -destination=mocks_test.go -package=$GOPACKAGE . VPNLooper,LinkLister,Logger
