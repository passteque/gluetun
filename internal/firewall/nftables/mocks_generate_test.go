//go:build linux

package nftables

//go:generate mockgen -destination=mocks_test.go -package=$GOPACKAGE . CmdRunner,Logger
//go:generate mockgen -destination=mocks_local_test.go -package=$GOPACKAGE -source=interfaces_local.go -mock_names=conn=MockConn
