# MyVPN

This project is a personal AWS-backed VPN architecture based on [Mango (GL-MT300N-V2)](https://www.gl-inet.com/products/gl-mt300n-v2/).

This project deploys and manages multi-account, multi-region (not in a DR sense) VPN architecture on AWS, and provides scripts for automatic configuration of the router using the OpenVPN configuration files (.ovpn).

The router's configuration is made through the router's APIs.

## Architecture
```
Devices → GL-MT300N-V2 → Home WiFi → Internet (via VPN)
          (192.168.8.1)
```

## Prerequisites

- **Router Setup**: Router must be in Repeater mode, connected to your home WiFi
  1. Connect to router WiFi or ethernet
  2. Access admin panel: http://192.168.8.1
  3. Go to **Internet** → Select **Repeater** mode
  4. Connect to your home WiFi network
- **AWS Credentials**: Configure AWS CLI with your credentials
- **Router Login**: Most commands require login: `./glinet.sh login --password <password>`

## Common Scenarios

### Scenario 1: Create a New VPN Server

**Goal:** Set up a new VPN server on AWS and configure your router to use it.

```bash
# 1. Create AWS OpenVPN server (takes 3-5 minutes)
./glinet.sh create-aws-openvpn --region us-east-1

# 2. Login to router
./glinet.sh login --password <password>

# 3. Configure router with the VPN
./glinet.sh configure-vpn-client --file vpn-configs/aws-vpn-<account-id>-us-east-1.ovpn

# 4. Start the VPN
./glinet.sh start-vpn-client --region us-east-1
```

### Scenario 2: Connect to an Existing Running VPN Server

**Goal:** Configure your router to use a VPN server that's already running on AWS.

```bash
# 1. Retrieve the configuration from AWS
./glinet.sh retrieve-aws-openvpn --region us-east-1

# 2. Login to router
./glinet.sh login --password <password>

# 3. Configure router with the VPN
./glinet.sh configure-vpn-client --file vpn-configs/aws-vpn-<account-id>-us-east-1.ovpn

# 4. Start the VPN
./glinet.sh start-vpn-client --region us-east-1
```

### Scenario 3: Stop VPN on Router and AWS

**Goal:** Stop using the VPN and shut down the AWS server to save costs.

```bash
# 1. Login to router (if needed)
./glinet.sh login --password <password>

# 2. Stop VPN on router
./glinet.sh stop-vpn-client

# 3. Stop AWS server
./glinet.sh stop-aws-openvpn --region us-east-1
```

### Scenario 4: Restart a Stopped VPN Server

**Goal:** Start using a VPN server that exists on AWS but is currently stopped.

```bash
# 1. Start the AWS server (retrieves new config with updated IP)
./glinet.sh start-aws-openvpn --region us-east-1

# 2. Login to router (if needed)
./glinet.sh login --password <password>

# 3. Check if router already has this client configured
./glinet.sh list-vpn-clients

# 4. If router shows "false", reconfigure it (IP changed when server restarted)
./glinet.sh configure-vpn-client --file vpn-configs/aws-vpn-<account-id>-us-east-1.ovpn

# 5. Start the VPN
./glinet.sh start-vpn-client --region us-east-1
```

**Note:** When an AWS server stops and restarts, its public IP changes. The `start-aws-openvpn` command automatically retrieves the updated configuration.

### Scenario 5: Destroy a VPN Server

**Goal:** Permanently delete the VPN server from AWS.

```bash
# 1. Login to router (if needed)
./glinet.sh login --password <password>

# 2. Destroy everything (removes from router, deletes local files, deletes AWS stack)
./glinet.sh destroy-aws-openvpn --region us-east-1
```

## Quick Reference Commands

### Check Status
```bash
# Check if VPN is active on router
./glinet.sh get-vpn-status

# List all VPN configurations (router, local, AWS)
./glinet.sh list-vpn-clients
```

### Switch Between Regions
```bash
# Stop current VPN
./glinet.sh stop-vpn-client

# Start different region
./glinet.sh start-vpn-client --region sa-east-1
```

### Router Session Management
```bash
# Login (session lasts ~1 hour)
./glinet.sh login --password <password>

# If you get "Session expired" error, just login again
```

## Files in This Directory

- `glinet.sh` - Main unified script for all VPN operations
- `openvpn-stack.yaml` - CloudFormation template for AWS OpenVPN server
- `COMMANDS.md` - **Detailed command reference and explanations**
- `API_METHODS.md` - Router API documentation
- `vpn-configs/` - Directory for .ovpn files
- `.glinet-session` - Session file (auto-generated, stores router authentication)

For detailed explanations about each command, see [COMMANDS.md](COMMANDS.md).

## Technical Notes

### Security Group Management
- The script automatically detects your current public IP
- Before connecting, it removes old IPs and adds your current IP to the security group
- This ensures the VPN works even when your ISP changes your IP address

### IP Address Changes
- When an AWS instance stops and restarts, its public IP changes
- The script never trusts CloudFormation outputs for IPs or security groups
- Always queries the instance directly for current state

### Session Management
- Router sessions expire after ~1 hour
- If you get "Session expired" error, just login again

### Timing
- VPN start/stop operations: 30-35 seconds
- CloudFormation stack creation: 3-5 minutes

## Verification

Check your public IP to verify VPN is working:

```bash
# Without VPN - shows your home IP
curl https://api.ipify.org

# With VPN active - shows AWS region IP
curl https://api.ipify.org
```

## Cost Optimization
- Stop instance when not in use: `./glinet.sh stop-aws-openvpn --region <region>`
- Stopped instances: ~$0.80/month (EBS storage only)
- Running t3.micro: ~$7.50/month

## Troubleshooting
- **Can't access router**: Ensure you're connected to router network (WiFi or ethernet)
- **Session expired**: Run `./glinet.sh login --password <password>`
- **VPN won't connect**: Security group is automatically managed - if issues persist, check AWS console
- **VPN connects but no internet**: NAT rules may be missing on server. The script uses `iptables-persistent` to prevent this
- **Slow speeds**: Try different AWS region closer to you
- **IP changed**: Run `./glinet.sh start-vpn-client --region <region>` to update security group automatically
