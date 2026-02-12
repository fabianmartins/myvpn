# MyVPN

This project is a personal AWS-backed VPN architecture based on [Mango (GL-MT300N-V2)](https://www.gl-inet.com/products/gl-mt300n-v2/).

This project deploys and manages multi-account, multi-region (not in a DR sense) VPN architecture on AWS, and provides scripts for automatic configuration of the router using the OpenVPN configuration files (.ovpn).

The router's configuration is made through the router's APIs.

## Architecture
```
Devices → GL-MT300N-V2 → Home WiFi → Internet (via VPN)
          (192.168.8.1)
```

## Workflow

Important:
- **The router must be configured in Repeater mode** to connect to your home WiFi and route traffic through the VPN
- Every command that goes to the router, requires previous login
- Every command that goes to AWS requires AWS credentials configured in the AWS CLI (not managed by this script)
- The `configure-vpn-client` and `start-vpn-client` commands automatically update the AWS security group to allow your current public IP. Old IPs are removed to keep the security group clean.

### 1. create the AWS OpenVPN back-end environment

You need to have access to the AWS account.

```bash
./glinet.sh create-aws-openvpn --region us-east-1
```

After running this, the client configuration file (ovpn) will be dowloaded to the vpn-configs folder.

### 2. Login and get the credentials

You need to be connected to the router to make this work

```bash
glinet.sh login --password <password> --router-ip <router-ip>
```
The access token and router-ip (if not standard) will be stored in the local directory and in  environment variables so they can be used by the other commands,

### 3. Configure the client

Requires a previous login in the router.

```bash
glinet.sh configure-vpn-client --file <ovpn-file>
```
This command:
1. Updates the security group to allow your current IP
2. Uploads the OpenVPN configuration to the router
3. Creates a client with name format: `aws-vpn-<account-id>-<region>`

### 4. Deactivate the VPN

Requires a previous login in the router. Requires AWS authentication.

```bash
glinet.sh stop-vpn-client
```


### 5. Activate a client previously configured

Requires a previous login in the router.

```bash
glinet.sh start-vpn-client --region <region>
```

This command:
1. Updates the security group to allow your current IP
2. Activates the VPN client associated with the region

### 6. Delete a client

Requires a previous login in the router.

```bash
glinet.sh delete-vpn-client --region <region>
```
This command does this:

1. Finds the client in the router's OpenVPN Client llist.
2. IF found
    2a. deletes the OpenVPN Client configuration in the router
    2b. deletes the OpenVPN "ovpn" local file

### 7. Retrieve client configuration

Requires AWS credentials.

```bash
glinet.sh retrieve-aws-openvpn --region <region>
```
Retrieves the configuration - the ovpn file - from the OpenVPN server in that region. Stores it locally so it can be used.

### 7. Stop back-end OpenVPN server

Requires AWS credentials.

```bash
glinet.sh stop-aws-openvpn --region <region>
```
This command stops the back-end server for this region, if it is running.


### 8. Start back-end OpenVPN server

Requires AWS credentials.

```bash
glinet.sh start-aws-openvpn --region <region>
```

This command starts the back-end server for this region, if it is stopped.

### 9. Update OpenVPN configuration after server restart

When you stop and restart the AWS OpenVPN server, the public IP changes. This command automatically updates the router configuration with the new IP.

The computer should be connected to the router.
Requires a previous login in the router. 
Requires AWS authentication.

```bash
glinet.sh update-aws-openvpn-ip --region <region>
```

This command:
    1. Checks if VPN is active and stops it if needed
    2. Removes old configuration from router
    3. Downloads new configuration from AWS (with updated IP)
    4. Reconfigures the router with new IP
    5. Restarts VPN if it was active before

### 10. destroy the back-end OpenVPN server

The computer should be connected to the router.
Requires a previous login in the router. 
Requires AWS authentication.

```bash
glinet.sh destroy-aws-openvpn --region <region>
```

This command:
    1. Calls glinet.sh delete-vpn-client --region <region>
    2. Deletes the stack that has created the instance.


### 10. List OpenVPN configurations

The computer should be connected to the router.
Requires a previous login in the router. 
Requires AWS authentication.

```bash
glinet.sh list-vpn-clients
```

This command:
    1. Will reach to the router, and obtain the registered clients.
    2. Will check the local vpn-configs, and identify the existing configurations.
    3. If either the router client or the local vpn-config exists, then it should check the AWS configuration.

The response will be in this format:

```json
{
    "sa-east-1" : {
        "router" : true,
        "ovpn-client" : true,
        "aws-server" : true,
        "status" : "CONSISTENT"
    },
    "us-east-1" : {
        "router" : false,
        "ovpn-client" : true,
        "aws-server" : true,
        "status" : "INCONSISTENT"
    },
    "us-west-1" : {
        "router" : false,
        "ovpn-client" : true,
        "aws-server" : false,
        "status" : "INCONSISTENT"
    },
    ...
}
```

### 11. Get OpenVPN status

The computer should be connected to the router.
Requires a previous login in the router. 

```bash
glinet.sh get-vpn-status
```
This command will reach out to the router, and identify:
1. Is the VPN active?
2. What's the client?

Responses:

- If none is active
    NO VPN ACTIVE

- If VPN is active
    VPN ACTIVE: sa-east-1


## Quick Start

### Part 1: Initial Setup (One-time)

#### 1. Initial Router Configuration
1. Connect to router WiFi or plug ethernet cable
2. Access admin panel: http://192.168.8.1
3. Complete initial setup wizard
4. Go to **Internet** → Select **Repeater** mode
5. Connect to your home WiFi network
6. Verify internet connectivity

#### 2. Login to Router
```bash
./glinet.sh login --password <your-password>
```

#### 3. Create and Configure VPN
```bash
# Create AWS OpenVPN server
./glinet.sh create-aws-openvpn --region us-east-1

# Configure router with the VPN
./glinet.sh configure-vpn-client --file vpn-configs/aws-vpn-us-east-1.ovpn
```

### Part 2: Daily Usage

#### Check VPN Status
```bash
./glinet.sh get-vpn-status
```

#### Start VPN
```bash
./glinet.sh start-vpn-client --region us-east-1
```

#### Stop VPN
```bash
./glinet.sh stop-vpn-client
```

#### Update IP After Server Restart
If you stopped and restarted the AWS server, the IP changed. Update the router configuration:
```bash
./glinet.sh update-aws-openvpn-ip --region us-east-1
```

**Note:** If you get a "Session expired" error, login again:
```bash
./glinet.sh login --password <your-password>
```

## Files in This Directory

- `glinet.sh` - Main unified script for all VPN operations
- `openvpn-stack.yaml` - CloudFormation template for AWS OpenVPN server
- `API_METHODS.md` - Router API documentation
- `vpn-configs/` - Directory for .ovpn files
- `.glinet-session` - Session file (auto-generated, stores router authentication)

## Technical Notes

### Router API Authentication
- Uses MD5 crypt for password hashing
- Session stored in `.glinet-session` file
- Session timeout: ~1 hour (requires re-login)
- Automatic session expiration detection: commands will fail with clear error message when session expires

### VPN Configuration Upload
The router's upload endpoint requires specific parameters:
- Cookie: `Admin-Token` (not `sysauth`)
- File upload must include explicit filename: `-F "file=@path;filename=name.ovpn"`
- Workflow requires delays between steps (5 seconds recommended)
- Order: create group → upload file → check_config → confirm_config → set_group

### Security Group Management
- The script automatically detects your current public IP
- Before connecting, it removes old IPs and adds your current IP to the security group
- Only UDP port 1194 is managed automatically
- This ensures the VPN works even when your ISP changes your IP address

### NAT Persistence on OpenVPN Server
- The CloudFormation template installs `iptables-persistent` package
- NAT masquerade rules are automatically saved to `/etc/iptables/rules.v4`
- Rules are restored on every reboot via `netfilter-persistent` service
- This ensures VPN traffic routing works after instance restarts

### Timing Considerations
- VPN start/stop operations take 30-35 seconds
- File upload processing needs 5-second delays between API calls
- CloudFormation stack creation takes 3-5 minutes

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
- Stopped instances only incur EBS storage costs (~$0.80/month)
- Running t3.micro costs ~$7.50/month

## Troubleshooting
- **Can't access router**: Ensure you're connected to router network
- **Session expired**: Run `./glinet.sh login --password <password>` again
- **VPN won't connect**: Check AWS security group allows UDP 1194 from your IP (automatically managed by script)
- **VPN connects but no internet**: NAT rules may be missing on server. The script now uses `iptables-persistent` to prevent this
- **Slow speeds**: Try different AWS region closer to you
- **Router loses connection**: Disable VPN, reconnect to home WiFi, re-enable VPN
- **IP changed after server restart**: Run `./glinet.sh update-aws-openvpn-ip --region <region>` to automatically update configuration
- **Configuration validation failed**: Wait a few seconds and try again. The router needs time to process uploaded files
