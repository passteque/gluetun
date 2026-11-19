package publicip

//go:generate mockgen -destination=mocks_test.go -package=$GOPACKAGE . Logger
//go:generate mockgen -destination=mocks_local_test.go -package=$GOPACKAGE -source interfaces_local.go
