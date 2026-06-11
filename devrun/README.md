# devrun

`devrun` is a small development helper for starting a local `qmcgaw/gluetun` Docker container with provider credentials stored in an encrypted file.

It solves two practical problems for local development:

- keeping VPN credentials out of the shell history and out of a plaintext file once setup is complete;
- quickly starting a Gluetun container for a specific provider and VPN type with a small set of extra Docker runtime options.

The tool has four commands:

- `add-cred`: add or replace credentials for one provider and one VPN type in the encrypted store `credentials`;
- `delete-cred`: remove credentials for one provider and one VPN type from the encrypted store `credentials`;
- `dump-cred`: print credentials for one provider and one VPN type from the encrypted store `credentials`;
- `run`: decrypt credentials on demand, build the required Gluetun environment variables, and run a `qmcgaw/gluetun` container.

## Prerequisites

- Go installed locally
- Docker installed and a daemon available to the Docker client
- an interactive terminal, since the tool prompts for passwords without echoing them

The Docker client is created from the standard Docker environment, so settings such as `DOCKER_HOST` are honored.

## Quick start

### Add credentials

Add one credential entry to the encrypted store:

```sh
go run ./cmd/main.go add-cred protonvpn openvpn
go run ./cmd/main.go add-cred mullvad wireguard
```

Behavior:

- if `credentials` does not exist yet, `add-cred` asks for a new credentials password and creates the encrypted store;
- if `credentials` already exists, `add-cred` asks for the existing password first, decrypts the store, updates it, and writes it back encrypted;
- sensitive fields are read from stdin without echo.

Prompted values depend on the VPN type:

- `openvpn`: username and password
- `wireguard`: private key, optional address, optional preshared key

Running `add-cred` again for the same provider and VPN type replaces the existing values for that entry.

### Delete credentials

Remove one credential entry from the encrypted store:

```sh
go run ./cmd/main.go delete-cred protonvpn openvpn
```

This asks for the credentials password first, decrypts the store, removes the requested provider and VPN type, and writes the store back encrypted.

### Dump credentials

Print one credential entry from the encrypted store:

```sh
go run ./cmd/main.go dump-cred protonvpn openvpn
```

This asks for the credentials password first and then prints the selected provider and VPN type values.

### Container run

Run a container using the image `qmcgaw/gluetun` and the encrypted credentials with the `run` command.
For example:

```sh
go run ./cmd/main.go run mullvad wireguard
go run ./cmd/main.go run protonvpn wireguard -e PORT_FORWARDING=on -p 8000:8000/tcp
```

You will be prompted for the credentials password, the file `credentials` will be decrypted in memory, and the container will be started.

The following environment variables are always added by the tool:

- `VPN_SERVICE_PROVIDER=<provider>`
- `VPN_TYPE=<vpn-type>`
- `LOG_LEVEL=debug`

The tool also adds `NET_ADMIN` to the container capabilities by default.

## Credential model

Internally, the encrypted file stores a binary-encoded map keyed by provider name. Each provider can define `openvpn`, `wireguard`, or both.

Conceptually, the stored data looks like this:

- provider `mullvad`: contains `wireguard`
- provider `protonvpn`: contains `wireguard`
- provider `protonvpn`: contains `openvpn`

You do not edit this directly. It is stored as encrypted binary data in `credentials`.

### OpenVPN fields

- `username` is required;
- `password` is required;

At runtime these map to:

- `OPENVPN_USER`
- `OPENVPN_PASSWORD`

### WireGuard fields

- `private_key` is required and must be a valid WireGuard private key;
- `address` is optional and must be a valid network prefix if set;
- `preshared_key` is optional and must be a valid WireGuard key if set.

At runtime these map to:

- `WIREGUARD_PRIVATE_KEY`
- `WIREGUARD_ADDRESSES` when `address` is set
- `WIREGUARD_PRESHARED_KEY` when `preshared_key` is set

## Supported extra Docker flags

The `run` command only accepts a focused subset of Docker-style runtime flags. Unsupported flags return an error.

Supported flags:

- `-e`, `--env KEY=VALUE`
- `-v`, `--volume SOURCE:TARGET[:mode]`
- `-p`, `--publish HOSTPORT:CONTAINERPORT[/proto]`
- `--dns IP`
- `--device SPEC`
- `--label KEY=VALUE`
- `--cap-add CAPABILITY`

## Signals and shutdown

While the container is running:

- the first `Ctrl+C` requests a graceful stop with a 5 second timeout;
- the second `Ctrl+C` sends a kill signal to the container;
- a further interrupt exits the tool immediately.

## Notes and limitations

- The container image is fixed to `qmcgaw/gluetun`.
- The container name is fixed to `gluetun`.
- Credentials are decrypted in memory only during execution.
- If the requested provider or VPN type is not present in the encrypted credentials file, the command fails with an explicit error.
- The encrypted credential store file is named `credentials`.
- This tool is intended for local development convenience, not as a general replacement for `docker run`.
