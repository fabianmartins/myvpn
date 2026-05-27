# MyVPN

Personal AWS-backed VPN using a [GL-MT300N-V2 (Mango)](https://www.gl-inet.com/products/gl-mt300n-v2/) router.

Deploys OpenVPN servers on AWS and configures the router automatically via its API.

## Architecture
```
Devices → GL-MT300N-V2 → Home WiFi → Internet (via VPN)
          (192.168.8.1)
```

## Prerequisites

- **Router**: Must be in Repeater mode, connected to your home WiFi
- **AWS CLI**: Configured with valid credentials
- **Connected to router**: Via WiFi or ethernet (to reach 192.168.8.1)

## Usage

### Step 1: Check what you have

```bash
./glinet.sh login --password <password>
./glinet.sh list-vpn-clients
```

This shows the state of each region across three layers:

```json
{
  "232189948602-sa-east-1": {
    "router": true,
    "ovpn-client": true,
    "aws-server": true,
    "ip-match": true,
    "status": "CONSISTENT"
  }
}
```

### Step 2: Connect

Based on the output above, follow the matching case:

#### Case A: Status is `CONSISTENT` — just start it

The client is configured, the server is running, and the IP matches.

```bash
./glinet.sh start-vpn-client --region <region>
```

#### Case B: Status is `STALE_IP` — reconfigure the router

The server's IP changed (e.g. after a stop/start). You need to delete the old config, retrieve the new one, and reconfigure.

```bash
./glinet.sh delete-vpn-client --region <region>
./glinet.sh retrieve-aws-openvpn --region <region>
./glinet.sh configure-vpn-client --file vpn-configs/aws-vpn-<account-id>-<region>.ovpn
./glinet.sh start-vpn-client --region <region>
```

#### Case C: Router shows `false` but aws-server is `true` — configure the router

The server exists but the router was never configured (or config was deleted).

```bash
# If the server is stopped, start it first:
./glinet.sh start-aws-openvpn --region <region>

# Retrieve the .ovpn file (or skip if ovpn-client is already true):
./glinet.sh retrieve-aws-openvpn --region <region>

# Configure the router:
./glinet.sh configure-vpn-client --file vpn-configs/aws-vpn-<account-id>-<region>.ovpn

# Start:
./glinet.sh start-vpn-client --region <region>
```

#### Case D: No server exists — create one from scratch

```bash
./glinet.sh create-aws-openvpn --region <region>
./glinet.sh configure-vpn-client --file vpn-configs/aws-vpn-<account-id>-<region>.ovpn
./glinet.sh start-vpn-client --region <region>
```

### Disconnect and save costs

```bash
./glinet.sh stop-vpn-client
./glinet.sh stop-aws-openvpn --region <region>
```

### Switch regions

```bash
./glinet.sh stop-vpn-client
./glinet.sh start-vpn-client --region <other-region>
```

### Destroy a server permanently

```bash
./glinet.sh destroy-aws-openvpn --region <region>
```

## Verify

```bash
curl https://api.ipify.org
```

Should show the AWS region IP when VPN is active.

## Cost

- Running t3.micro: ~$7.50/month
- Stopped instance: ~$0.80/month (EBS only)

## Troubleshooting

- **Session expired**: `./glinet.sh login --password <password>` (sessions last ~1 hour)
- **Client already exists**: You don't need to reconfigure — just `start-vpn-client`
- **VPN won't connect**: Security group is auto-managed; check AWS console if issues persist
- **No internet through VPN**: NAT rules may be missing; the server uses `iptables-persistent` to prevent this
- **IP changed after restart**: `start-aws-openvpn` automatically retrieves the updated config

## Files

- `glinet.sh` — All VPN operations
- `openvpn-stack.yaml` — CloudFormation template
- `vpn-configs/` — .ovpn configuration files
- `COMMANDS.md` — Detailed command reference
- `API_METHODS.md` — Router API documentation
