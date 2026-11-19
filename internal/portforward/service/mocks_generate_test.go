package service

//go:generate mockgen -destination=mocks_test.go -package=$GOPACKAGE . Logger,PortAllower,Routing,PortForwarder
