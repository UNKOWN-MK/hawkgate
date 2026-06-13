# Testlab

Linux network namespace-based test environment for HawkGate development.

## Quick start

```bash
sudo bash setup.sh
```

This script creates isolated network namespaces simulating LAN clients, a bridge
interface, and a WAN — no physical hardware required.

## Files

- `setup.sh` — automated namespace + veth setup
- `scapy_client.py` — simulates unauthenticated / authenticated client traffic
- `scapy_server.py` — simulates a remote server responding to client requests
