# Command Reference

This document provides detailed explanations of all available commands in `glinet.sh`.

## Table of Contents

- [Router Commands](#router-commands)
- [AWS Commands](#aws-commands)
- [Status Commands](#status-commands)

---

## Router Commands

### `login`

Authenticate with the GL-iNET router and create a session.

**Syntax:**
```bash
./glinet.sh login --password <password> [--router-ip <ip>]
```

**Parameters:**
- `--password` (required): Router admin password
- `--router-ip` (optional): Router IP address (default: auto-detect 192.168.8.1 or 192.168.9.1)

**What it does:**
1. Attempts to ping router at common IP addresses
2. Performs challenge-response authentication using MD5 hashing
3. Saves session ID to `.glinet-session` file
4. Session expires after ~1 hour

**Example:**
```bash
./glinet.sh login --password mypassword
```

---

### `configure-vpn-client`

Upload and configure an OpenVPN client on the router.

**Syntax:**
```bash
./glinet.sh configure-vpn-client --file <ovpn-file>
```

**Parameters:**
- `--file` (required): Path to .ovpn configuration file

**Requirements:**
- Router login session
- AWS credentials (for security group update)

**What it does:**
1. Checks if client already exists on router
2. Updates AWS security group to allow your current public IP
3. Creates a group on router with name format: `aws-vpn-<account-id>-<region>`
4. Uploads the .ovpn file to router
5. Validates and imports the configuration

**Example:**
```bash
./glinet.sh configure-vpn-client --file vpn-configs/aws-vpn-123456789012-us-east-1.ovpn
```

**Note:** If the client already exists, you must delete it first with `delete-vpn-client`.

---

### `start-vpn-client`

Start the VPN connection on the router.

**Syntax:**
```bash
./glinet.sh start-vpn-client --region <region>
```

**Parameters:**
- `--region` (required): AWS region identifier (e.g., us-east-1, sa-east-1)

**Requirements:**
- Router login session
- AWS credentials (for security group update)
- VPN client must be configured on router

**What it does:**
1. Updates AWS security group to allow your current public IP
2. Finds the VPN client configuration by region
3. Activates the VPN connection
4. Waits up to 30 seconds for connection to establish
5. Verifies connection is active

**Example:**
```bash
./glinet.sh start-vpn-client --region us-east-1
```

**Timing:** Takes 30-35 seconds to complete.

---

### `stop-vpn-client`

Stop the active VPN connection on the router.

**Syntax:**
```bash
./glinet.sh stop-vpn-client
```

**Requirements:**
- Router login session

**What it does:**
1. Checks if VPN is currently active
2. Sends stop command to router
3. Waits up to 30 seconds for VPN to stop
4. Verifies VPN is stopped

**Example:**
```bash
./glinet.sh stop-vpn-client
```

**Timing:** Takes 30-35 seconds to complete.

---

### `delete-vpn-client`

Remove VPN client configuration from router and delete local .ovpn file.

**Syntax:**
```bash
./glinet.sh delete-vpn-client --region <region>
```

**Parameters:**
- `--region` (required): AWS region identifier

**Requirements:**
- Router login session

**What it does:**
1. Finds the VPN client on router by region
2. Removes the client configuration from router
3. Removes the group from router
4. Deletes the local .ovpn file from `vpn-configs/` directory

**Example:**
```bash
./glinet.sh delete-vpn-client --region us-east-1
```

**Note:** This does NOT affect the AWS server. Use `destroy-aws-openvpn` to delete the AWS infrastructure.

---

## AWS Commands

### `create-aws-openvpn`

Create a new OpenVPN server on AWS using CloudFormation.

**Syntax:**
```bash
./glinet.sh create-aws-openvpn --region <region>
```

**Parameters:**
- `--region` (required): AWS region where server will be created

**Requirements:**
- AWS credentials configured

**What it does:**
1. Creates CloudFormation stack named `glinet-openvpn`
2. Deploys Ubuntu 22.04 t3.micro EC2 instance
3. Installs and configures OpenVPN server
4. Sets up security group allowing UDP port 1194
5. Configures NAT masquerading for internet routing
6. Waits for stack creation to complete (3-5 minutes)
7. Automatically retrieves the .ovpn configuration file

**Example:**
```bash
./glinet.sh create-aws-openvpn --region us-east-1
```

**Timing:** Takes 3-5 minutes to complete.

**Cost:** Running t3.micro costs ~$7.50/month.

---

### `retrieve-aws-openvpn`

Download the OpenVPN configuration file from an existing AWS server.

**Syntax:**
```bash
./glinet.sh retrieve-aws-openvpn --region <region>
```

**Parameters:**
- `--region` (required): AWS region of the server

**Requirements:**
- AWS credentials configured
- OpenVPN server must be running

**What it does:**
1. Gets instance ID from CloudFormation stack
2. Verifies instance is in "running" state
3. Uses AWS Systems Manager (SSM) to retrieve `/root/client.ovpn` from server
4. Gets current public IP from instance (not CloudFormation)
5. Updates the `remote` line in .ovpn file with current IP
6. Saves file to `vpn-configs/aws-vpn-<account-id>-<region>.ovpn`

**Example:**
```bash
./glinet.sh retrieve-aws-openvpn --region us-east-1
```

**Important:** This command always gets the current public IP from the instance, which is critical because IPs change when instances stop/start.

---

### `start-aws-openvpn`

Start a stopped OpenVPN server on AWS.

**Syntax:**
```bash
./glinet.sh start-aws-openvpn --region <region>
```

**Parameters:**
- `--region` (required): AWS region of the server

**Requirements:**
- AWS credentials configured
- OpenVPN server must exist (stopped state)

**What it does:**
1. Gets instance ID from CloudFormation stack
2. Starts the EC2 instance
3. Waits for instance to reach "running" state
4. Automatically retrieves new .ovpn configuration with updated public IP

**Example:**
```bash
./glinet.sh start-aws-openvpn --region us-east-1
```

**Important:** When an instance restarts, AWS assigns a new public IP. This command automatically retrieves the updated configuration.

---

### `stop-aws-openvpn`

Stop a running OpenVPN server on AWS to save costs.

**Syntax:**
```bash
./glinet.sh stop-aws-openvpn --region <region>
```

**Parameters:**
- `--region` (required): AWS region of the server

**Requirements:**
- AWS credentials configured

**What it does:**
1. Gets instance ID from CloudFormation stack
2. Stops the EC2 instance

**Example:**
```bash
./glinet.sh stop-aws-openvpn --region us-east-1
```

**Cost savings:** Stopped instances only cost ~$0.80/month (EBS storage) vs ~$7.50/month running.

---

### `destroy-aws-openvpn`

Permanently delete the OpenVPN server and all AWS resources.

**Syntax:**
```bash
./glinet.sh destroy-aws-openvpn --region <region>
```

**Parameters:**
- `--region` (required): AWS region of the server

**Requirements:**
- Router login session
- AWS credentials configured

**What it does:**
1. Calls `delete-vpn-client` to remove configuration from router
2. Deletes local .ovpn file
3. Deletes the CloudFormation stack
4. Removes all AWS resources (EC2 instance, security group, IAM role)

**Example:**
```bash
./glinet.sh destroy-aws-openvpn --region us-east-1
```

**Warning:** This is permanent and cannot be undone. All data on the server will be lost.

---

## Status Commands

### `get-vpn-status`

Check if VPN is active on the router and which client is connected.

**Syntax:**
```bash
./glinet.sh get-vpn-status
```

**Requirements:**
- Router login session

**What it does:**
1. Queries router for current VPN status
2. If active, extracts the region from client name

**Output:**
- `NO VPN ACTIVE` - No VPN connection
- `VPN ACTIVE: <region>` - VPN is connected to specified region

**Example:**
```bash
./glinet.sh get-vpn-status
# Output: VPN ACTIVE: us-east-1
```

---

### `list-vpn-clients`

List all VPN configurations across router, local files, and AWS.

**Syntax:**
```bash
./glinet.sh list-vpn-clients
```

**Requirements:**
- Router login session
- AWS credentials configured

**What it does:**
1. Queries router for configured clients
2. Scans `vpn-configs/` directory for .ovpn files
3. Checks AWS for CloudFormation stacks
4. Compares all three sources and reports consistency

**Output format:**
```json
{
  "232189948602-us-east-1": {
    "router": true,
    "ovpn-client": true,
    "aws-server": true,
    "status": "CONSISTENT"
  },
  "232189948602-sa-east-1": {
    "router": false,
    "ovpn-client": true,
    "aws-server": true,
    "status": "INCONSISTENT"
  }
}
```

**Status meanings:**
- `CONSISTENT`: Configuration exists in all three places
- `INCONSISTENT`: Configuration missing from one or more places

**Example:**
```bash
./glinet.sh list-vpn-clients
```

---

## Session Management

### Session File

The `.glinet-session` file stores:
- `SID`: Session ID for router authentication
- `ROUTER_IP`: Router IP address
- `TIMESTAMP`: When session was created

**Location:** Project root directory

**Lifetime:** ~1 hour

**Security:** Contains authentication token - do not commit to version control (already in `.gitignore`)

---

## Security Group Management

Commands that interact with AWS security groups (`configure-vpn-client`, `start-vpn-client`) automatically:

1. Detect your current public IP using `https://api.ipify.org`
2. Query the EC2 instance for its actual security group ID (never trusts CloudFormation outputs)
3. Remove old IP addresses from UDP port 1194 rules
4. Add your current IP address

This ensures the VPN works even when your ISP changes your IP address.

---

## Error Handling

### Common Errors

**"Session expired"**
- Solution: Run `./glinet.sh login --password <password>`

**"Client already exists"**
- Solution: Run `./glinet.sh delete-vpn-client --region <region>` first

**"Instance is stopped"**
- Solution: Run `./glinet.sh start-aws-openvpn --region <region>`

**"Stack not found"**
- Solution: Create the stack with `./glinet.sh create-aws-openvpn --region <region>`

**"Not logged in to router"**
- Solution: Run `./glinet.sh login --password <password>`

**"AWS authentication failed"**
- Solution: Configure AWS credentials with `aws configure`
