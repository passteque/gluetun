# Development container

Development container that can be used with VSCode.

It works on Linux, Windows (WSL2) and OSX.

## Requirements

- [VS code](https://code.visualstudio.com/download) installed
- [VS code dev containers extension](https://marketplace.visualstudio.com/items?itemName=ms-vscode-remote.remote-containers) installed
- [Docker](https://www.docker.com) **or** [Podman](https://podman.io) installed and running

## Setup

1. This dev container expects to bind mount several files directly, so they must exist on the host, even if empty:

    ```sh
    touch ~/.gitconfig # git configuration
    touch ~/.zsh_history # ZSH shell commands history
    touch ~/AGENTS.md # AI agent context file
    touch ~/.config/containers/auth.json # Container registry credentials for container engine
    ```

    On top of these files, note by default this container bind mounts:

    - Some public files from `~/.ssh` (no private key), see the [SSH agent section below](#ssh-agent)
    - The Docker daemon socket `/var/run/docker.sock` (for [./docker](./docker)) or the Podman socket `${XDG_RUNTIME_DIR}/podman/podman.sock` (for [./podman](./podman))

    You can alternatively modify the mounts in `devcontainer.json` to suit your needs.
1. The container runs as an unprivileged user with uid `1000` and gid `1000` by default. Any bind mounts from the host should therefore be writable and/or readable by that group id and/or user id, including your workspace. A quick way to do so is with the following shell commands on the host, from the workspace:

    ```sh
    # Workspace - group read/write
    chown -R :1000 .
    chmod g+rw -R .
    # Config files - group read/write
    chown :1000 ~/.gitconfig ~/.zsh_history ~/AGENTS.md ~/.config/containers/auth.json ~/.ssh/known_hosts
    chmod g+rw ~/.gitconfig ~/.zsh_history ~/AGENTS.md ~/.config/containers/auth.json ~/.ssh/known_hosts
    # SSH public files - group read
    chown :1000 ~/.ssh/*.pub ~/.ssh/allowed_signers
    chmod g+r ~/.ssh/*.pub ~/.ssh/allowed_signers
    ```

1. **For OSX hosts**: ensure the project directory and your home directory `~` are accessible by the container engine.
1. Whether you want to use SSH or not, see the [SSH keys section below](#ssh-keys)
1. Open the command palette in Visual Studio Code (CTRL+SHIFT+P).
1. Select `Dev-Containers: Open Folder in Container...` and choose the project directory.

### SSH keys

Three options as subsections below: ssh agent, ssh bind mount, or no ssh.

#### SSH agent

This is the default, preferred and more secure method.
You need to have the agent running on your host and have the environment variable `SSH_AUTH_SOCK` set to the path to the agent socket.

Just make sure you have the `~/.ssh/known_hosts` file on your host.

For example, if your SSH private key is `~/.ssh/id_ed25519` you can have a systemd unit `~/.config/systemd/user/ssh-agent.service` like this:

```ini
[Unit]
Description=OpenSSH key agent
Documentation=man:ssh-agent(1)
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
Environment=SSH_AUTH_SOCK=%t/ssh-agent.sock
ExecStart=/usr/bin/ssh-agent -D -a %t/ssh-agent.sock
# Leading - so a missing/unreadable key never fails the unit.
# Loops because the socket is created shortly after ssh-agent starts.
ExecStartPost=-/bin/sh -c 'for i in $(seq 1 50); do ssh-add %h/.ssh/id_ed25519 2>/dev/null && exit 0; sleep 0.1; done; exit 1'
Restart=on-failure
RestartSec=1s
UMask=0077

[Install]
WantedBy=default.target
```

💁 this also works on WSL2 with Ubuntu

By default, the devcontainer mounts files to be able to use GPG SSH git commit signing with an `id_ed25519`-named key:

- `~/.ssh/allowed_signers` <-> `/home/user/.ssh/allowed_signers`
- `~/.ssh/id_ed25519.pub` <-> `/home/user/.ssh/id_ed25519.pub` - `id_ed25519.pub` may need to be adapted to match your key filename

If you do not want to use GPG SSH git commit signing, comment out the mounts in `devcontainer.json`:

```jsonc
{
    "source": "${localEnv:HOME}/.ssh/id_ed25519.pub",
    "target": "/home/user/.ssh/id_ed25519.pub",
    "type": "bind,readonly"
},
{
    "source": "${localEnv:HOME}/.ssh/allowed_signers",
    "target": "/home/user/.ssh/allowed_signers",
    "type": "bind,readonly"
},
```

#### SSH bind mount

You bind mount `~/.ssh` to `/mnt/ssh` in the container, and the [ssh script](https://github.com/qdm12/basedevcontainer/blob/master/.ssh.sh) takes care of mapping those to `~/.ssh` in the container depending on the host platform.

This is **not the default** so `devcontainer.json` needs the following changes:

1. Comment out with `//`

    ```jsonc
    "SSH_AUTH_SOCK": "/tmp/ssh-agent.sock"
    ```

    ```jsonc
    {
        "source": "${localEnv:SSH_AUTH_SOCK}",
        "target": "/tmp/ssh-agent.sock",
        "type": "bind"
    },
    {
        "source": "${localEnv:HOME}/.ssh/id_ed25519.pub",
        "target": "/home/user/.ssh/id_ed25519.pub",
        "type": "bind,readonly"
    },
    {
        "source": "${localEnv:HOME}/.ssh/allowed_signers",
        "target": "/home/user/.ssh/allowed_signers",
        "type": "bind,readonly"
    },
    ```

1. Uncomment by removing `//`:

    ```jsonc
    // {
    //     "source": "${localEnv:HOME}/.ssh",
    //     "target": "/mnt/ssh",
    //     "type": "bind"
    // },
    ```

#### No SSH

If you do not want to use SSH at all, comment out

```jsonc
"SSH_AUTH_SOCK": "/tmp/ssh-agent.sock"
```

and all the ssh mounts in `devcontainer.json`:

```jsonc
{
    "source": "${localEnv:SSH_AUTH_SOCK}",
    "target": "/tmp/ssh-agent.sock",
    "type": "bind"
},
{
    "source": "${localEnv:HOME}/.ssh/known_hosts",
    "target": "/etc/ssh/ssh_known_hosts",
    "type": "bind"
},
{
    "source": "${localEnv:HOME}/.ssh/id_ed25519.pub",
    "target": "/home/user/.ssh/id_ed25519.pub",
    "type": "bind,readonly"
},
{
    "source": "${localEnv:HOME}/.ssh/allowed_signers",
    "target": "/home/user/.ssh/allowed_signers",
    "type": "bind,readonly"
},
```

## Github cli `gh`

1. [Create fine grained personal access token](https://github.com/settings/personal-access-tokens)
2. Set it on your host environment variable as `GH_TOKEN`:

    ```sh
    export GH_TOKEN=ghp_XXXXXXXXXXXXXXXX
    ```

3. The devcontainer will pick it up and inject it as `GH_TOKEN`, which is then used by `gh` within the devcontainer.

If needed, you can modify this in the `devcontainer.json` file the `containerEnv` key, for example if you prefer to read another variable name.

## Customization

For customizations to take effect, you should "rebuild and reopen":

1. Open the command palette in Visual Studio Code (CTRL+SHIFT+P)
2. Select `Dev-Containers: Rebuild Container`

Customizations available are notably:

- Changes to the container image in [Dockerfile](Dockerfile)
- Changes to VSCode **settings** and **extensions** in `devcontainer.json` (in the `podman/` or `docker/` directory, whichever you use).
- Change the entrypoint script by adding a bind mount in `devcontainer.json` of a shell script to `/home/user/.welcome.sh` to replace the [current welcome script](https://github.com/qdm12/godevcontainer/blob/master/shell/.welcome.sh). For example:

    ```jsonc
    // Welcome script
    {
        "source": "/yourpath/.welcome.sh",
        "target": "/home/user/.welcome.sh",
        "type": "bind"
    }
    ```

- Change the container configuration in `devcontainer.json`
- Add other services in a `docker-compose.yml`, see [this README section](https://github.com/qdm12/godevcontainer/blob/master/README.md#docker-composeyml)
- More customizations available are documented in the [devcontainer.json reference](https://containers.dev/implementors/json_reference/).

## Container engine

This container does not run an engine of its own, it mounts the **host's** container engine API socket at the canonical path `/var/run/docker.sock`.
That way `docker`, `docker compose` and `podman-remote` (symlinked as `podman`) drive the host engine (run, build, cross-architecture build) and share its images etc.
Nothing needs to be installed beyond the client CLIs already in the image, and there are no privileges involved.

Because the host socket path differs per engine, there are two configurations, one per engine: `podman` and `docker`.

To ease using the host engine, because volume paths resolve on the host, the checkout is mounted at the same absolute path inside and outside the container (`workspaceFolder`), so `docker run -v $PWD/data:/data` refers to the same files on both sides. Note this is still limited to the bind mounted volumes, mounting a container path that the host does not have will fail.

### Docker engine

See [docker/devcontainer.json](docker/devcontainer.json) for the Docker Desktop or dockerd engine. It mounts the host's `/var/run/docker.sock` at the canonical path inside the container.

It builds and cross-builds using the docker plugin buildx.

A rootful dockerd socket belongs to `root:docker`, so the unprivileged user needs that group to open it. You have two options:

- Uncomment `// --group-add=$(stat -c %g /var/run/docker.sock)` in the `runArgs` key in [.devcontainer/docker/devcontainer.json](docker/devcontainer.json)
- Set your host environment variable `export DOCKER_GID=$(stat -c %g /var/run/docker.sock)` and rebuild the container image. The [.devcontainer/docker/devcontainer.json](docker/devcontainer.json) already uses the host `DOCKER_GID` variable as its `DOCKER_GID` build argument.

**Docker Desktop / OrbStack / Colima**: their socket is world-writable, nothing to do.

### Podman engine

See [podman/devcontainer.json](podman/devcontainer.json) for the Podman engine.

#### Setup the devcontainer

To create the devcontainer, the extension shells out to the CLI named by VSCode's setting `dev.containers.dockerPath`. Point it at the **`podman` CLI**, as an **absolute path**.

```jsonc
"dev.containers.dockerPath": "/usr/bin/podman",
```

Nothing else needs to point at the engine: `podman` carries its own connection configuration (the rootless socket at `${XDG_RUNTIME_DIR}/podman/podman.sock` by default, or a `podman system connection`), so no socket path or Docker host setting is involved.

⚠️ Podman must log events to a **file**, set once on the host in `~/.config/containers/containers.conf`:

```toml
[engine]
events_logger = "file"
```

Right after `podman run`, the Dev Containers CLI waits for the container `start` event on a `podman events --filter event=start` stream it started a millisecond earlier. The `podman` CLI has to initialize its database before it subscribes, so the event lands first - and the journald logger, rootless Podman's default, keeps no replayable log to recover it from, so the window hangs forever at `Container started`. A file-backed log is replayable, so the event is never lost. References: [devcontainers/cli#1236](https://github.com/devcontainers/cli/issues/1236), [microsoft/vscode-remote-release#7980](https://github.com/microsoft/vscode-remote-release/issues/7980).

💁 Why the `podman` CLI and not a Docker CLI against Podman's API: `--userns=keep-id` in [devcontainer.json](podman/devcontainer.json) `runArgs` is a Podman user namespace mode. A Docker CLI has `--userns` too, but validates its value client-side and rejects everything but `host` (`docker: --userns: invalid USER mode`), so `keep-id` never reaches Podman - and Podman's Docker-compatible API ignores `UsernsMode` altogether, so even `--userns=host` through that API is a no-op. Without the user namespace mapping, the container's uid 1000 is the host's `subuid+999`: files written in the bind-mounted workspace land outside your uid, and the bind-mounted Podman socket (mode `0660`, your user only) is unreachable from inside.

#### Host engine access

It mounts the host's `${XDG_RUNTIME_DIR}/podman/podman.sock` at the canonical `/var/run/docker.sock` inside the container. If your editor server does not export the environment variable `XDG_RUNTIME_DIR`, hardcode it in the [devcontainer.json](podman/devcontainer.json) mounts to the value given by running `echo "/run/user/$(id -u)"`. That way all `docker`, `docker compose` (default docker socket path) and `podman` (using `CONTAINER_HOST`) all work using the same socket path.

The Docker buildx plugin is not supported by a Podman host, so `DOCKER_BUILDKIT=0` is set. Cross building is still possible.

## TUN device and raw sockets

The test suite is pure user space, bar two packages that talk to the kernel networking stack:

| Package | What it does | Needs |
| --- | --- | --- |
| [internal/wireguard](../internal/wireguard) | brings up a userspace TUN interface (`Test_Wireguard_Run_teardown/userspace`) | `NET_ADMIN`, and the `/dev/net/tun` device |
| [internal/pmtud/tcp](../internal/pmtud/tcp) | sends raw TCP probes to discover the PMTU/MSS | `NET_RAW`, for `AF_INET` and `AF_INET6` alike |

All configurations grant them: `NET_ADMIN`, `NET_RAW` and `SYS_PTRACE` under `capAdd` (the last for `dlv`), and `--device=/dev/net/tun:/dev/net/tun` under `runArgs`.

⚠️ The device node comes from the machine running the engine, so the `tun` module has to be loaded ther with `modprobe tun`.

⚠️ On rootless Podman, `NET_RAW` gets you the socket, not the packets. Podman's networking stack **pasta** is a userspace stack that carries TCP and UDP for ordinary sockets and nothing for raw ones: in one of those, `ping 1.1.1.1` loses every packet. The tests of [internal/pmtud/tcp](../internal/pmtud/tcp) notice, and skip themselves rather than time out, in case the pasta stack is in se.
