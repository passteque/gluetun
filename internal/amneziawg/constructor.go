package amneziawg

type Amneziawg struct {
	logger   Logger
	settings Settings
	netlink  NetLinker
}

func New(settings Settings, netlink NetLinker,
	logger Logger,
) (a *Amneziawg, err error) {
	settings.SetDefaults()
	if err := settings.Check(); err != nil {
		return nil, err
	}

	return &Amneziawg{
		logger:   logger,
		settings: settings,
		netlink:  netlink,
	}, nil
}
