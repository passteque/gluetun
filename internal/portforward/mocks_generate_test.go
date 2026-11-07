package portforward

//go:generate mockgen -destination=mocks_test.go -package=$GOPACKAGE . Routing,PortAllower,Logger
//go:generate mockgen -destination=mocks_service_test.go -package=$GOPACKAGE github.com/qdm12/gluetun/internal/portforward/service PortForwarder
