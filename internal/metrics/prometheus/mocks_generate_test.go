package prometheus

//go:generate mockgen -destination=mocks_test.go -package=$GOPACKAGE . Gatherer
