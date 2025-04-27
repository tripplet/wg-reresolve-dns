# wg-reresolve-dns

[![CI](https://github.com/tripplet/wg-reresolve-dns/actions/workflows/ci.yml/badge.svg)](https://github.com/tripplet/wg-reresolve-dns/actions/workflows/ci.yml)

Small systemd service that periodically re-resolves all peer endpoints for a WireGuard interface.

## Installation (Arch Linux)

```sh
makepkg -si
```

## Usage

Enable and start the service for the desired WireGuard interface:

```sh
sudo systemctl enable --now wg-reresolve-dns@wg0.service
````
