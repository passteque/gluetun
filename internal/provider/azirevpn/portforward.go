package azirevpn

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/qdm12/gluetun/internal/provider/utils"
)

var (
	ErrPortForwardingNotFound = errors.New("port forwarding not found")
)

func (p *Provider) PortForward(ctx context.Context,
	objects utils.PortForwardObjects,
) (internalToExternalPorts map[uint16]uint16, err error) {
	persisted, err := readPersistedData(p.dataPath)
	if err != nil {
		return nil, fmt.Errorf("reading persisted azirevpn state: %w", err)
	}

	internalIPv4, err := determineInternalIPv4(persisted, objects.InternalIP)
	if err != nil {
		return nil, err
	}
	persisted.InternalIPv4 = internalIPv4

	portForwardingData, err := p.listPortForwardings(ctx, objects.Client, internalIPv4)
	if err != nil {
		statusCode, hasStatusCode := statusCodeOf(err)
		if !(hasStatusCode && statusCode == http.StatusNotFound) {
			return nil, fmt.Errorf("listing port forwardings: %w", err)
		}
		objects.Logger.Info("fetching existing port forwards, got []")
		objects.Logger.Debug("no existing azirevpn port forwarding found, creating one")
	} else {
		objects.Logger.Info("fetching existing port forwards, got " + formatPortsForLog(portForwardingData.Ports))
	}

	nowUnix := time.Now().Unix()
	persistedPortIsActive := persisted.Port != 0 && persisted.PortExpiresAt > nowUnix
	if persistedPortIsActive {
		for _, apiPort := range portForwardingData.Ports {
			if apiPort.Port == persisted.Port && apiPort.ExpiresAt > nowUnix {
				persisted.PortExpiresAt = apiPort.ExpiresAt
				err = writePersistedData(p.dataPath, persisted)
				if err != nil {
					return nil, fmt.Errorf("persisting azirevpn state: %w", err)
				}
				objects.Logger.Info(fmt.Sprintf("reusing existing forwarded port: %d", persisted.Port))
				return map[uint16]uint16{persisted.Port: persisted.Port}, nil
			}
		}
	}

	for _, apiPort := range portForwardingData.Ports {
		if apiPort.ExpiresAt > nowUnix {
			persisted.Port = apiPort.Port
			persisted.PortExpiresAt = apiPort.ExpiresAt
			err = writePersistedData(p.dataPath, persisted)
			if err != nil {
				return nil, fmt.Errorf("persisting azirevpn state: %w", err)
			}
			objects.Logger.Info(fmt.Sprintf("reusing existing forwarded port: %d", persisted.Port))
			return map[uint16]uint16{persisted.Port: persisted.Port}, nil
		}
	}

	const maxAttempts = 5
	const retryDelay = 3 * time.Minute
	var created portForwardData
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		created, err = p.createPortForwarding(ctx, objects.Client, internalIPv4)
		if err == nil {
			break
		}

		if isCreatePortForwardingDailyLimitReachedError(err) {
			persisted.Port = 0
			persisted.PortExpiresAt = 0
			persistErr := writePersistedData(p.dataPath, persisted)
			if persistErr != nil {
				return nil, fmt.Errorf("persisting azirevpn state: %w", persistErr)
			}
			objects.Logger.Warn("azirevpn API daily creation limit reached, continuing without port forwarding for now")
			return nil, nil //nolint:nilnil
		}

		statusCode, hasStatusCode := statusCodeOf(err)
		if !(hasStatusCode && statusCode == http.StatusTooManyRequests) {
			return nil, fmt.Errorf("creating port forwarding: %w", err)
		}

		if attempt == maxAttempts {
			return nil, fmt.Errorf("azirevpn API rate limit reached while creating port forwarding after %d attempts: %w",
				maxAttempts, err)
		}

		objects.Logger.Warn(fmt.Sprintf("azirevpn API rate limit reached while creating port forwarding (attempt %d/%d), retrying in %s",
			attempt, maxAttempts, retryDelay))

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(retryDelay):
		}
	}

	if created.Port == nil {
		return nil, errors.New("port forwarding API did not return assigned port")
	}

	persisted.Port = *created.Port
	persisted.PortExpiresAt = created.ExpiresAt
	err = writePersistedData(p.dataPath, persisted)
	if err != nil {
		return nil, fmt.Errorf("persisting azirevpn state: %w", err)
	}

	return []uint16{persisted.Port}, nil
}

func determineInternalIPv4(persisted persistedData,
	assignedIP netip.Addr,
) (internalIPv4 string, err error) {
	if persisted.InternalIPv4 != "" {
		return persisted.InternalIPv4, nil
	}

	if !assignedIP.IsValid() {
		return "", errors.New("internal VPN IP address is not valid")
	}
	if assignedIP.Is6() {
		return "", errors.New("internal VPN IPv4 address is required for azirevpn port forwarding")
	}

	return assignedIP.String(), nil
}

func (p *Provider) KeepPortForward(ctx context.Context,
	objects utils.PortForwardObjects,
) (err error) {
	persisted, err := readPersistedData(p.dataPath)
	if err != nil {
		return fmt.Errorf("reading persisted azirevpn state: %w", err)
	}

	if persisted.Port == 0 {
		objects.Logger.Info("no azirevpn forwarded port to maintain")
		<-ctx.Done()
		return ctx.Err()
	}

	internalIPv4, err := determineInternalIPv4(persisted, objects.InternalIP)
	if err != nil {
		return err
	}

	const checkPeriod = 15 * time.Minute
	checkTicker := time.NewTicker(checkPeriod)
	defer checkTicker.Stop()

	const renewPeriod = 30 * 24 * time.Hour
	renewTicker := time.NewTicker(renewPeriod)
	defer renewTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			cleanupErr := p.cleanupOnStop(objects.Client, internalIPv4, persisted.Port, objects.Logger)
			if cleanupErr != nil {
				objects.Logger.Warn("cleanup on stop failed: " + cleanupErr.Error())
			}
			return ctx.Err()
		case <-checkTicker.C:
			err = p.checkPortForwarding(ctx, objects.Client, internalIPv4, persisted.Port)
			if err != nil {
				statusCode, hasStatusCode := statusCodeOf(err)
				if hasStatusCode && statusCode >= http.StatusBadRequest &&
					statusCode < http.StatusInternalServerError && statusCode != http.StatusTooManyRequests {
					return fmt.Errorf("checking port forwarding: %w", err)
				}
				if hasStatusCode && statusCode == http.StatusTooManyRequests {
					objects.Logger.Warn("azirevpn API rate limit reached while checking port forwarding, retrying on next interval")
					continue
				}
				objects.Logger.Warn("transient error while checking port forwarding: " + err.Error())
				continue
			}
			objects.Logger.Debug(fmt.Sprintf("port %d still active", persisted.Port))
		case <-renewTicker.C:
			data, renewErr := p.renewPortForwarding(ctx, objects.Client, internalIPv4, persisted.Port)
			if renewErr != nil {
				objects.Logger.Warn("failed renewing port forwarding, continuing with existing lease: " + renewErr.Error())
				continue
			}
			if data.ExpiresAt != 0 {
				persisted.PortExpiresAt = data.ExpiresAt
				persistErr := writePersistedData(p.dataPath, persisted)
				if persistErr != nil {
					objects.Logger.Warn("failed persisting renewed port forwarding expiry: " + persistErr.Error())
				}
			}
			objects.Logger.Debug(fmt.Sprintf("renewed port %d for 365 days", persisted.Port))
		}
	}
}

func (p *Provider) checkPortForwarding(ctx context.Context,
	client *http.Client, internalIPv4 string, expectedPort uint16,
) (err error) {
	data, err := p.listPortForwardings(ctx, client, internalIPv4)
	if err != nil {
		return err
	}

	nowUnix := time.Now().Unix()
	for _, apiPort := range data.Ports {
		if apiPort.Port == expectedPort && apiPort.ExpiresAt > nowUnix {
			return nil
		}
	}

	return fmt.Errorf("%w: expected %d", ErrPortForwardingNotFound, expectedPort)
}

func (p *Provider) cleanupOnStop(client *http.Client,
	internalIPv4 string, port uint16,
	logger utils.Logger,
) (err error) {
	cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err = p.deletePortForwarding(cleanupCtx, client, internalIPv4, port)
	if err != nil {
		logger.Warn("failed to delete azirevpn port forwarding: " + err.Error())
	}

	persistErr := writePersistedData(p.dataPath, persistedData{})
	if persistErr != nil {
		logger.Warn("failed to clear azirevpn persisted state: " + persistErr.Error())
	}

	return nil
}

func formatPortsForLog(apiPorts []portForward) (s string) {
	if len(apiPorts) == 0 {
		return "[]"
	}

	ports := make([]string, len(apiPorts))
	for i, apiPort := range apiPorts {
		ports[i] = strconv.FormatUint(uint64(apiPort.Port), 10)
	}

	return "[" + strings.Join(ports, ", ") + "]"
}

func isCreatePortForwardingDailyLimitReachedError(err error) bool {
	var statusErr *apiHTTPStatusError
	if !errors.As(err, &statusErr) {
		return false
	}

	if statusErr.StatusCode() != http.StatusNotAcceptable {
		return false
	}

	body := strings.ToLower(statusErr.Body())
	return strings.Contains(body, "todays limit reached")
}
