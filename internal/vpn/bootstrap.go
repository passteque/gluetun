package vpn

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"

	"github.com/qdm12/gluetun/internal/constants"
	"github.com/qdm12/gluetun/internal/models"
)

type bootstrapResolver struct {
	allowConnection func(context.Context, models.Connection) (func(context.Context) error, error)
	dialContext     func(context.Context, string, string) (net.Conn, error)
	lookupNetIP     func(context.Context, string, string,
		func(context.Context, string, string) (net.Conn, error)) ([]netip.Addr, error)
}

func newBootstrapResolver(
	mark uint32,
	allowConnection func(context.Context, models.Connection) (func(context.Context) error, error),
) *bootstrapResolver {
	return &bootstrapResolver{
		allowConnection: allowConnection,
		dialContext:     newPhysicalDialContext(mark),
		lookupNetIP: func(ctx context.Context, network, host string,
			dial func(context.Context, string, string) (net.Conn, error),
		) ([]netip.Addr, error) {
			resolver := &net.Resolver{
				PreferGo: true,
				Dial:     dial,
			}
			return resolver.LookupNetIP(ctx, network, host)
		},
	}
}

func (r *bootstrapResolver) LookupNetIP(ctx context.Context, network, host string) (
	addresses []netip.Addr, err error,
) {
	type allowedConnection struct {
		remove func(context.Context) error
	}

	allowedConnections := make([]allowedConnection, 0, 2)
	allowedConnectionsSet := make(map[models.Connection]struct{}, 2)
	var allowancesMutex sync.Mutex
	dial := func(dialCtx context.Context, dialNetwork, address string) (net.Conn, error) {
		connection, err := dnsConnection(dialNetwork, address)
		if err != nil {
			return nil, err
		}

		allowancesMutex.Lock()
		_, alreadyAllowed := allowedConnectionsSet[connection]
		if !alreadyAllowed {
			remove, err := r.allowConnection(dialCtx, connection)
			if err != nil {
				allowancesMutex.Unlock()
				return nil, fmt.Errorf("allowing bootstrap DNS connection: %w", err)
			}
			allowedConnections = append(allowedConnections, allowedConnection{
				remove: remove,
			})
			allowedConnectionsSet[connection] = struct{}{}
		}
		allowancesMutex.Unlock()

		return r.dialContext(dialCtx, dialNetwork, address)
	}

	addresses, lookupErr := r.lookupNetIP(ctx, network, host, dial)
	allowancesMutex.Lock()
	allowedConnections = append([]allowedConnection(nil), allowedConnections...)
	allowancesMutex.Unlock()
	cleanupCtx := context.WithoutCancel(ctx)
	cleanupErrs := make([]error, 0, len(allowedConnections))
	for i := len(allowedConnections) - 1; i >= 0; i-- {
		removeErr := allowedConnections[i].remove(cleanupCtx)
		if removeErr != nil {
			cleanupErrs = append(cleanupErrs,
				fmt.Errorf("removing bootstrap DNS connection: %w", removeErr))
		}
	}

	return addresses, errors.Join(lookupErr, errors.Join(cleanupErrs...))
}

func dnsConnection(network, address string) (connection models.Connection, err error) {
	switch {
	case strings.HasPrefix(network, constants.UDP):
		connection.Protocol = constants.UDP
	case strings.HasPrefix(network, constants.TCP):
		connection.Protocol = constants.TCP
	default:
		return connection, fmt.Errorf("DNS network is not supported: %s", network)
	}

	addressPort, err := netip.ParseAddrPort(address)
	if err != nil {
		return connection, fmt.Errorf("parsing DNS resolver address: %w", err)
	}
	connection.IP = addressPort.Addr().Unmap()
	if connection.IP.Is6() {
		connection.IP = connection.IP.WithZone("")
	}
	connection.Port = addressPort.Port()
	return connection, nil
}
