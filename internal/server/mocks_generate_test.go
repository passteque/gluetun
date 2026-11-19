package server

//go:generate mockgen -destination=mocks_test.go -package=$GOPACKAGE . VPNLooper,DNSLoop,PortForwarding,UpdaterLooper,Logger
