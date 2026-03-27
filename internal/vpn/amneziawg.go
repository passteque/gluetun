package vpn

import (
	"context"
	"fmt"

	"github.com/qdm12/gluetun/internal/amneziawg"
	"github.com/qdm12/gluetun/internal/configuration/settings"
	"github.com/qdm12/gluetun/internal/models"
	"github.com/qdm12/gluetun/internal/provider"
	"github.com/qdm12/gluetun/internal/wireguard"
	"github.com/qdm12/gosettings"
)

// setupAmneziaWg sets AmneziaWG up using the configurators and settings given.
func setupAmneziaWg(ctx context.Context, netlinker NetLinker,
	fw Firewall, providerConf provider.Provider,
	settings settings.VPN, ipv6Supported bool, logger wireguard.Logger) (
	amneziawger *amneziawg.Amneziawg, connection models.Connection, err error,
) {
	connection, err = providerConf.GetConnection(settings.Provider.ServerSelection, ipv6Supported)
	if err != nil {
		return nil, models.Connection{}, fmt.Errorf("finding a VPN server: %w", err)
	}

	amneziaWGSettings := buildAmneziaWgSettings(connection, settings.AmneziaWg, ipv6Supported)

	logger.Debug("Amneziawg server public key: " + amneziaWGSettings.Wireguard.PublicKey)
	logger.Debug("Amneziawg client private key: " + gosettings.ObfuscateKey(amneziaWGSettings.Wireguard.PrivateKey))
	logger.Debug("Amneziawg pre-shared key: " + gosettings.ObfuscateKey(amneziaWGSettings.Wireguard.PreSharedKey))

	amneziawger, err = amneziawg.New(amneziaWGSettings, netlinker, logger)
	if err != nil {
		return nil, models.Connection{}, fmt.Errorf("creating amneziawg: %w", err)
	}

	err = fw.SetVPNConnection(ctx, connection, settings.Wireguard.Interface)
	if err != nil {
		return nil, models.Connection{}, fmt.Errorf("setting firewall: %w", err)
	}

	return amneziawger, connection, nil
}

func buildAmneziaWgSettings(connection models.Connection,
	userSettings settings.AmneziaWg, ipv6Supported bool,
) amneziawg.Settings {
	return amneziawg.Settings{
		Wireguard:       buildWireguardSettings(connection, userSettings.Wireguard, ipv6Supported),
		JunkPacketCount: *userSettings.JunkPacketCount,
		JunkPacketMin:   *userSettings.JunkPacketMin,
		JunkPacketMax:   *userSettings.JunkPacketMax,
		PaddingS1:       *userSettings.PaddingS1,
		PaddingS2:       *userSettings.PaddingS2,
		PaddingS3:       *userSettings.PaddingS3,
		PaddingS4:       *userSettings.PaddingS4,
		HeaderH1:        *userSettings.HeaderH1,
		HeaderH2:        *userSettings.HeaderH2,
		HeaderH3:        *userSettings.HeaderH3,
		HeaderH4:        *userSettings.HeaderH4,
		InitPacketI1:    *userSettings.InitPacketI1,
		InitPacketI2:    *userSettings.InitPacketI2,
		InitPacketI3:    *userSettings.InitPacketI3,
		InitPacketI4:    *userSettings.InitPacketI4,
		InitPacketI5:    *userSettings.InitPacketI5,
	}
}
