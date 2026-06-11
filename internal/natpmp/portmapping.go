package natpmp

import (
	"context"
	"encoding/binary"
	"fmt"
	"net/netip"
	"time"
)

// Add or delete a port mapping. To delete a mapping, set both the
// requestedExternalPort and lifetime to 0.
// See https://www.ietf.org/rfc/rfc6886.html#section-3.3
func (c *Client) AddPortMapping(ctx context.Context, gateway netip.Addr,
	protocol string, internalPort, requestedExternalPort uint16,
	lifetime time.Duration) (durationSinceStartOfEpoch time.Duration,
	assignedInternalPort, assignedExternalPort uint16, assignedLifetime time.Duration,
	err error,
) {
	lifetimeSecondsFloat := lifetime.Seconds()
	const maxLifetimeSeconds = uint64(^uint32(0))
	if uint64(lifetimeSecondsFloat) > maxLifetimeSeconds {
		return 0, 0, 0, 0, fmt.Errorf("lifetime is too long: "+
			"%d seconds must at most %d seconds",
			uint64(lifetimeSecondsFloat), maxLifetimeSeconds)
	}
	const messageSize = 12
	message := make([]byte, messageSize)
	message[0] = 0 // Version 0
	switch protocol {
	case "udp":
		message[1] = 1 // operationCode 1
	case "tcp":
		message[1] = 2 // operationCode 2
	default:
		return 0, 0, 0, 0, fmt.Errorf("network protocol is unknown: %s", protocol)
	}
	// [2:3] are reserved.
	binary.BigEndian.PutUint16(message[4:6], internalPort)
	binary.BigEndian.PutUint16(message[6:8], requestedExternalPort)
	binary.BigEndian.PutUint32(message[8:12], uint32(lifetimeSecondsFloat))

	const responseSize = 16
	response, err := c.rpc(ctx, gateway, message, responseSize)
	if err != nil {
		return 0, 0, 0, 0, fmt.Errorf("executing remote procedure call: %w", err)
	}

	secondsSinceStartOfEpoch := binary.BigEndian.Uint32(response[4:8])
	durationSinceStartOfEpoch = time.Duration(secondsSinceStartOfEpoch) * time.Second
	assignedInternalPort = binary.BigEndian.Uint16(response[8:10])
	assignedExternalPort = binary.BigEndian.Uint16(response[10:12])
	lifetimeInSeconds := binary.BigEndian.Uint32(response[12:16])
	assignedLifetime = time.Duration(lifetimeInSeconds) * time.Second
	return durationSinceStartOfEpoch, assignedInternalPort, assignedExternalPort, assignedLifetime, nil
}
