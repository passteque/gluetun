package service

import (
	"context"
	"fmt"
	"strings"
)

func runCommand(ctx context.Context, cmder Cmder, logger Logger,
	commandTemplate string, ports []uint16, vpnInterface string,
) (err error) {
	portStrings := make([]string, len(ports))
	for i, port := range ports {
		portStrings[i] = fmt.Sprint(int(port))
	}
	portsString := strings.Join(portStrings, ",")
	commandString := strings.ReplaceAll(commandTemplate, "{{PORTS}}", portsString)
	commandString = strings.ReplaceAll(commandString, "{{PORT}}", portStrings[0])
	commandString = strings.ReplaceAll(commandString, "{{VPN_INTERFACE}}", vpnInterface)
	return cmder.RunAndLog(ctx, commandString, logger)
}
