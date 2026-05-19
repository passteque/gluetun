package socks5

type Settings struct {
	Enabled  bool
	Username string
	Password string
	Address  string
	Logger   Logger
}
