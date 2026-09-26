package settings

import (
	"errors"
	"fmt"
	"net/netip"
	"os/exec"
	"regexp"

	"github.com/qdm12/gluetun/internal/command"
	"github.com/qdm12/gluetun/internal/constants"
	"github.com/qdm12/gosettings"
	"github.com/qdm12/gosettings/reader"
	"github.com/qdm12/gosettings/validate"
	"github.com/qdm12/gotree"
)

// CustomVPN contains settings to run a custom VPN client binary.
// Gluetun only executes the binary and does no network setup for it,
// so the binary must create its tunnel network interface and install
// the default route through it within the container.
type CustomVPN struct {
	// Binary is the path to the VPN client binary to execute.
	// It cannot be the empty string when the VPN type is 'custom'.
	Binary string `json:"binary"`
	// Args is the arguments string for the binary, which is split
	// following shell word splitting rules. It can be the empty
	// string for no argument, and it cannot be nil in the
	// internal state.
	Args *string `json:"args"`
	// Interface is the name of the tunnel network interface the
	// binary creates. It defaults to tun0 and cannot be the empty
	// string in the internal state.
	Interface string `json:"interface"`
	// ReadyLine is a regular expression matched against each line
	// the binary writes to its standard output or standard error.
	// The tunnel is considered ready on the first matching line.
	// If it is empty, the tunnel is considered ready when the
	// tunnel network interface exists, carries at least one address
	// and has a route through it, checked periodically. It cannot
	// be nil in the internal state.
	ReadyLine *string `json:"ready_line"`
	// EndpointIP is the VPN server IP address, used to allow the
	// VPN connection through the firewall. It cannot be the zero
	// value when the VPN type is 'custom'.
	EndpointIP netip.Addr `json:"endpoint_ip"`
	// EndpointPort is the VPN server port, used to allow the VPN
	// connection through the firewall. It cannot be zero when the
	// VPN type is 'custom'.
	EndpointPort uint16 `json:"endpoint_port"`
	// EndpointProtocol is the network protocol used to reach the
	// VPN server, and can be 'udp' or 'tcp'. It defaults to 'udp'
	// and cannot be the empty string in the internal state.
	EndpointProtocol string `json:"endpoint_protocol"`
}

// validate validates the custom VPN settings.
// It should only be ran if the VPN type chosen is custom.
func (c CustomVPN) validate() (err error) {
	if c.Binary == "" {
		return errors.New("binary path is not set")
	}
	_, err = exec.LookPath(c.Binary)
	if err != nil {
		return fmt.Errorf("finding binary: %w", err)
	}

	if *c.Args != "" {
		_, err = command.Split(*c.Args)
		if err != nil {
			return fmt.Errorf("splitting arguments: %w", err)
		}
	}

	if !regexpInterfaceName.MatchString(c.Interface) {
		return fmt.Errorf("interface name is not valid: '%s' does not match regex '%s'",
			c.Interface, regexpInterfaceName)
	}

	if *c.ReadyLine != "" {
		_, err = regexp.Compile(*c.ReadyLine)
		if err != nil {
			return fmt.Errorf("compiling ready line regular expression: %w", err)
		}
	}

	if !c.EndpointIP.IsValid() {
		return errors.New("endpoint IP address is not set")
	}

	if c.EndpointPort == 0 {
		return errors.New("endpoint port is not set")
	}

	err = validate.IsOneOf(c.EndpointProtocol, constants.UDP, constants.TCP)
	if err != nil {
		return fmt.Errorf("endpoint protocol is not valid: %w", err)
	}

	return nil
}

func (c CustomVPN) copy() (copied CustomVPN) {
	return CustomVPN{
		Binary:           c.Binary,
		Args:             gosettings.CopyPointer(c.Args),
		Interface:        c.Interface,
		ReadyLine:        gosettings.CopyPointer(c.ReadyLine),
		EndpointIP:       c.EndpointIP,
		EndpointPort:     c.EndpointPort,
		EndpointProtocol: c.EndpointProtocol,
	}
}

func (c *CustomVPN) overrideWith(other CustomVPN) {
	c.Binary = gosettings.OverrideWithComparable(c.Binary, other.Binary)
	c.Args = gosettings.OverrideWithPointer(c.Args, other.Args)
	c.Interface = gosettings.OverrideWithComparable(c.Interface, other.Interface)
	c.ReadyLine = gosettings.OverrideWithPointer(c.ReadyLine, other.ReadyLine)
	c.EndpointIP = gosettings.OverrideWithValidator(c.EndpointIP, other.EndpointIP)
	c.EndpointPort = gosettings.OverrideWithComparable(c.EndpointPort, other.EndpointPort)
	c.EndpointProtocol = gosettings.OverrideWithComparable(c.EndpointProtocol, other.EndpointProtocol)
}

func (c *CustomVPN) setDefaults() {
	c.Args = gosettings.DefaultPointer(c.Args, "")
	c.Interface = gosettings.DefaultComparable(c.Interface, "tun0")
	c.ReadyLine = gosettings.DefaultPointer(c.ReadyLine, "")
	c.EndpointProtocol = gosettings.DefaultComparable(c.EndpointProtocol, constants.UDP)
}

func (c CustomVPN) String() string {
	return c.toLinesNode().String()
}

func (c CustomVPN) toLinesNode() (node *gotree.Node) {
	node = gotree.New("Custom VPN settings:")
	node.Appendf("Binary: %s", c.Binary)
	if *c.Args != "" {
		node.Appendf("Arguments: %s", *c.Args)
	}
	node.Appendf("Network interface: %s", c.Interface)
	if *c.ReadyLine != "" {
		node.Appendf("Ready line regular expression: %s", *c.ReadyLine)
	}
	node.Appendf("Endpoint: %s:%d (%s)", c.EndpointIP, c.EndpointPort, c.EndpointProtocol)
	return node
}

func (c *CustomVPN) read(r *reader.Reader) (err error) {
	c.Binary = r.String("CUSTOM_VPN_BINARY", reader.ForceLowercase(false))
	c.Args = r.Get("CUSTOM_VPN_ARGS", reader.ForceLowercase(false))
	c.Interface = r.String("CUSTOM_VPN_INTERFACE", reader.ForceLowercase(false))
	c.ReadyLine = r.Get("CUSTOM_VPN_READY_LINE", reader.ForceLowercase(false))

	c.EndpointIP, err = r.NetipAddr("CUSTOM_VPN_ENDPOINT_IP")
	if err != nil {
		return err
	}

	c.EndpointPort, err = r.Uint16("CUSTOM_VPN_ENDPOINT_PORT")
	if err != nil {
		return err
	}

	c.EndpointProtocol = r.String("CUSTOM_VPN_ENDPOINT_PROTOCOL")

	return nil
}
