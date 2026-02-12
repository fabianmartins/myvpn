#!/bin/bash
set -e

SESSION_FILE=".glinet-session"
VPN_DIR="./vpn-configs"

# Helper: Get AWS Account ID
get_aws_account_id() {
  aws sts get-caller-identity --query Account --output text 2>/dev/null || echo "unknown"
}

# Helper: Ensure security group allows current IP
ensure_security_group_access() {
  local REGION="$1"
  local STACK_NAME="glinet-openvpn"
  
  MY_IP=$(curl -s https://api.ipify.org)
  if [ -z "$MY_IP" ]; then
    echo "WARNING: Could not detect public IP, skipping security group check"
    return
  fi
  
  SG_ID=$(aws cloudformation describe-stacks \
    --stack-name "$STACK_NAME" \
    --region "$REGION" \
    --query 'Stacks[0].Outputs[?OutputKey==`SecurityGroupId`].OutputValue' \
    --output text 2>/dev/null)
  
  if [ -z "$SG_ID" ]; then
    echo "WARNING: Could not find security group, skipping check"
    return
  fi
  
  # Check if current IP already has access
  HAS_ACCESS=$(aws ec2 describe-security-groups \
    --group-ids "$SG_ID" \
    --region "$REGION" \
    --query "SecurityGroups[0].IpPermissions[?FromPort==\`1194\`].IpRanges[?CidrIp==\`$MY_IP/32\`]" \
    --output text 2>/dev/null || echo "")
  
  if [ -n "$HAS_ACCESS" ]; then
    return
  fi
  
  echo "Updating security group with current IP ($MY_IP)..."
  
  # Remove old IPs for port 1194
  OLD_IPS=$(aws ec2 describe-security-groups \
    --group-ids "$SG_ID" \
    --region "$REGION" \
    --query "SecurityGroups[0].IpPermissions[?FromPort==\`1194\` && ToPort==\`1194\` && IpProtocol==\`udp\`].IpRanges[].CidrIp" \
    --output text 2>/dev/null || echo "")
  
  for OLD_IP in $OLD_IPS; do
    if [ "$OLD_IP" != "$MY_IP/32" ]; then
      echo "  Removing old IP: $OLD_IP"
      aws ec2 revoke-security-group-ingress \
        --group-id "$SG_ID" \
        --region "$REGION" \
        --protocol udp \
        --port 1194 \
        --cidr "$OLD_IP" >/dev/null 2>&1 || true
    fi
  done
  
  # Add current IP
  echo "  Adding current IP: $MY_IP"
  aws ec2 authorize-security-group-ingress \
    --group-id "$SG_ID" \
    --region "$REGION" \
    --protocol udp \
    --port 1194 \
    --cidr "$MY_IP/32" >/dev/null 2>&1 || echo "  Note: IP may already exist"
}

# Helper: Format JSON for router API call
format_router_json() {
  local SID="$1"
  local SERVICE="$2"
  local METHOD="$3"
  local PARAMS="$4"
  
  echo '{"jsonrpc":"2.0","id":1,"method":"call","params":["'"$SID"'","'"$SERVICE"'","'"$METHOD"'",'"$PARAMS"']}'
}

# Helper: Router API call
router_api_call() {
  local SERVICE="$1"
  local METHOD="$2"
  local PARAMS="${3:-{}}"
  
  if [ ! -f "$SESSION_FILE" ]; then
    echo "ERROR: Not logged in. Run: $0 login --password <password>" >&2
    exit 1
  fi
  
  source "$SESSION_FILE"
  
  JSON=$(format_router_json "$SID" "$SERVICE" "$METHOD" "$PARAMS")
  
  RESPONSE=$(curl -s "http://$ROUTER_IP/rpc" \
    -H "Content-Type: application/json" \
    -H "Cookie: sysauth=$SID" \
    -d "$JSON")
  
  # Check for session expiration
  ERROR_CODE=$(echo "$RESPONSE" | jq -r '.error.code // empty' 2>/dev/null)
  if [ "$ERROR_CODE" = "-32000" ]; then
    echo "ERROR: Session expired. Please login again: $0 login --password <password>" >&2
    exit 1
  fi
  
  echo "$RESPONSE"
}


# Command: login
cmd_login() {
  local PASSWORD=""
  local ROUTER_IP=""
  
  while [[ $# -gt 0 ]]; do
    case $1 in
      --password) PASSWORD="$2"; shift 2 ;;
      --router-ip) ROUTER_IP="$2"; shift 2 ;;
      *) echo "Unknown option: $1"; exit 1 ;;
    esac
  done
  
  if [ -z "$PASSWORD" ]; then
    echo "ERROR: --password required"
    exit 1
  fi
  
  # Auto-detect router IP if not provided
  if [ -z "$ROUTER_IP" ]; then
    for IP in 192.168.8.1 192.168.9.1; do
      if ping -c 1 -W 1 "$IP" > /dev/null 2>&1; then
        ROUTER_IP="$IP"
        break
      fi
    done
    ROUTER_IP="${ROUTER_IP:-192.168.8.1}"
  fi
  
  echo "Authenticating with router at $ROUTER_IP..."
  
  # Get challenge
  CHALLENGE=$(curl -s "http://$ROUTER_IP/rpc" \
    -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","id":1,"method":"challenge","params":{"username":"root"}}')
  
  SALT=$(echo "$CHALLENGE" | jq -r '.result.salt')
  NONCE=$(echo "$CHALLENGE" | jq -r '.result.nonce')
  
  if [ "$SALT" = "null" ] || [ "$NONCE" = "null" ]; then
    echo "ERROR: Failed to get challenge from router"
    exit 1
  fi
  
  # Compute hash
  CIPHER=$(openssl passwd -1 -salt "$SALT" "$PASSWORD")
  HASH=$(echo -n "root:${CIPHER}:${NONCE}" | openssl dgst -md5 | awk '{print $2}')
  
  # Login
  LOGIN=$(curl -s "http://$ROUTER_IP/rpc" \
    -H "Content-Type: application/json" \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"login\",\"params\":{\"username\":\"root\",\"hash\":\"$HASH\"}}")
  
  SID=$(echo "$LOGIN" | jq -r '.result.sid')
  
  if [ "$SID" = "null" ] || [ -z "$SID" ]; then
    echo "ERROR: Login failed"
    exit 1
  fi
  
  # Save session
  cat > "$SESSION_FILE" <<EOF
SID=$SID
ROUTER_IP=$ROUTER_IP
TIMESTAMP=$(date +%s)
EOF
  
  echo "✓ Logged in successfully"
  echo "Session saved to $SESSION_FILE"
}

# Command: configure-vpn-client
cmd_configure_vpn_client() {
  local OVPN_FILE=""
  
  while [[ $# -gt 0 ]]; do
    case $1 in
      --file) OVPN_FILE="$2"; shift 2 ;;
      *) echo "Unknown option: $1"; exit 1 ;;
    esac
  done
  
  if [ -z "$OVPN_FILE" ] || [ ! -f "$OVPN_FILE" ]; then
    echo "ERROR: --file required and must exist"
    exit 1
  fi
  
  FILENAME=$(basename "$OVPN_FILE")
  # Extract account-id and region from filename: aws-vpn-<account-id>-<region>.ovpn
  ACCOUNT_ID=$(echo "$FILENAME" | sed 's/aws-vpn-\([0-9]\{12\}\)-.*\.ovpn/\1/')
  REGION=$(echo "$FILENAME" | sed 's/aws-vpn-[0-9]\{12\}-\(.*\)\.ovpn/\1/')
  CLIENT_NAME="aws-vpn-$ACCOUNT_ID-$REGION"
  
  # Ensure security group allows current IP
  ensure_security_group_access "$REGION"
  
  echo "Configuring VPN client: $CLIENT_NAME"
  
  source "$SESSION_FILE"
  
  # Check if client already exists
  CONFIGS=$(router_api_call "ovpn-client" "get_all_config_list")
  CLIENT_EXISTS=$(echo "$CONFIGS" | jq -r ".result.config_list[].clients[]? | select(.name == \"$CLIENT_NAME\") | .name" 2>/dev/null || echo "")
  if [ -n "$CLIENT_EXISTS" ]; then
    echo "ERROR: Client $CLIENT_NAME already exists. Delete it first."
    exit 1
  fi
  
  # Find or create group
  GROUP_LIST=$(curl -s "http://$ROUTER_IP/rpc" \
    -H "Content-Type: application/json" \
    -H "Cookie: sysauth=$SID" \
    -d '{"jsonrpc":"2.0","id":1,"method":"call","params":["'$SID'","ovpn-client","get_group_list",{}]}')
  
  GROUP_ID=$(echo "$GROUP_LIST" | jq -r ".result.groups[] | select(.group_name == \"$CLIENT_NAME\") | .group_id")
  
  if [ -z "$GROUP_ID" ]; then
    echo "Creating group..."
    curl -s "http://$ROUTER_IP/rpc" \
      -H "Content-Type: application/json" \
      -H "Cookie: sysauth=$SID" \
      -d '{"jsonrpc":"2.0","id":1,"method":"call","params":["'$SID'","ovpn-client","add_group",{"group_name":"'$CLIENT_NAME'"}]}' > /dev/null
    
    sleep 5
    
    GROUP_LIST=$(curl -s "http://$ROUTER_IP/rpc" \
      -H "Content-Type: application/json" \
      -H "Cookie: sysauth=$SID" \
      -d '{"jsonrpc":"2.0","id":1,"method":"call","params":["'$SID'","ovpn-client","get_group_list",{}]}')
    GROUP_ID=$(echo "$GROUP_LIST" | jq -r ".result.groups[] | select(.group_name == \"$CLIENT_NAME\") | .group_id")
    
    if [ -z "$GROUP_ID" ]; then
      echo "ERROR: Failed to create group"
      exit 1
    fi
  fi
  
  # Upload file
  echo "Uploading configuration..."
  SIZE=$(wc -c < "$OVPN_FILE" | tr -d ' ')
  curl -s "http://$ROUTER_IP/upload" \
    -H "Cookie: Admin-Token=$SID" \
    -F "sid=$SID" \
    -F "size=$SIZE" \
    -F "path=/tmp/ovpn_upload/$FILENAME" \
    -F "file=@$OVPN_FILE;filename=$FILENAME" > /dev/null
  
  echo "Waiting for file processing..."
  sleep 10
  
  if [ -z "$GROUP_ID" ]; then
    echo "Creating group..."
    curl -s "http://$ROUTER_IP/rpc" \
      -H "Content-Type: application/json" \
      -H "Cookie: sysauth=$SID" \
      -d '{"jsonrpc":"2.0","id":1,"method":"call","params":["'$SID'","ovpn-client","add_group",{"group_name":"'$CLIENT_NAME'"}]}' > /dev/null
    
    sleep 5
    GROUP_LIST=$(curl -s "http://$ROUTER_IP/rpc" \
      -H "Content-Type: application/json" \
      -H "Cookie: sysauth=$SID" \
      -d '{"jsonrpc":"2.0","id":1,"method":"call","params":["'$SID'","ovpn-client","get_group_list",{}]}')
    GROUP_ID=$(echo "$GROUP_LIST" | jq -r ".result.groups[] | select(.group_name == \"$CLIENT_NAME\") | .group_id")
    
    if [ -z "$GROUP_ID" ]; then
      echo "ERROR: Failed to create group"
      exit 1
    fi
  fi
  
  # Check config
  echo "Validating configuration..."
  CHECK_RESULT=$(curl -s "http://$ROUTER_IP/rpc" \
    -H "Content-Type: application/json" \
    -H "Cookie: sysauth=$SID" \
    -d '{"jsonrpc":"2.0","id":1,"method":"call","params":["'$SID'","ovpn-client","check_config",{"filename":"'$FILENAME'","group_id":'$GROUP_ID'}]}')
  
  VALIDATION_OK=$(echo "$CHECK_RESULT" | jq -r ".result.passed[]? | select(. == \"$FILENAME\")" 2>/dev/null || echo "")
  if [ -z "$VALIDATION_OK" ]; then
    echo "ERROR: Configuration validation failed"
    echo "$CHECK_RESULT" | jq '.result'
    exit 1
  fi
  
  sleep 5
  
  # Confirm config (this imports the file)
  echo "Importing configuration..."
  curl -s "http://$ROUTER_IP/rpc" \
    -H "Content-Type: application/json" \
    -H "Cookie: sysauth=$SID" \
    -d '{"jsonrpc":"2.0","id":1,"method":"call","params":["'$SID'","ovpn-client","confirm_config",{"group_id":'$GROUP_ID'}]}' > /dev/null
  
  sleep 5
  
  # Set group
  curl -s "http://$ROUTER_IP/rpc" \
    -H "Content-Type: application/json" \
    -H "Cookie: sysauth=$SID" \
    -d '{"jsonrpc":"2.0","id":1,"method":"call","params":["'$SID'","ovpn-client","set_group",{"group_id":'$GROUP_ID',"group_name":"'$CLIENT_NAME'","username":"","password":"","askpass":""}]}' > /dev/null
  
  echo "✓ VPN client configured successfully"
  echo ""
  echo "To start: $0 start-vpn-client --region $REGION"
}

# Command: list-vpn-clients
cmd_list_vpn_clients() {
  # Check router authentication
  if [ ! -f "$SESSION_FILE" ]; then
    echo "ERROR: Not logged in to router. Run: $0 login --password <password>"
    exit 1
  fi
  
  # Check AWS authentication
  if ! aws sts get-caller-identity &>/dev/null; then
    echo "ERROR: AWS authentication failed. Configure AWS credentials first."
    exit 1
  fi
  
  REGIONS_LIST=""
  
  # 1. Get router clients
  CONFIGS=$(router_api_call "ovpn-client" "get_all_config_list")
  
  if [ "$(echo "$CONFIGS" | jq -r '.result.config_list')" != "null" ]; then
    ROUTER_REGIONS=$(echo "$CONFIGS" | jq -r '.result.config_list[].clients[]?.name // empty' | grep "^aws-vpn-" | sed 's/aws-vpn-//')
    REGIONS_LIST="$ROUTER_REGIONS"
  fi
  
  # 2. Check local vpn-configs
  for ovpn_file in "$VPN_DIR"/aws-vpn-*.ovpn; do
    if [ -f "$ovpn_file" ]; then
      REGION=$(basename "$ovpn_file" | sed 's/aws-vpn-.*-\(.*\)\.ovpn/\1/')
      ACCOUNT_REGION=$(basename "$ovpn_file" | sed 's/aws-vpn-\(.*\)\.ovpn/\1/')
      if ! echo "$REGIONS_LIST" | grep -q "^${ACCOUNT_REGION}$"; then
        REGIONS_LIST="$REGIONS_LIST"$'\n'"$ACCOUNT_REGION"
      fi
    fi
  done
  
  # 3. Output JSON
  echo "{"
  FIRST=true
  
  while IFS= read -r ACCOUNT_REGION; do
    [ -z "$ACCOUNT_REGION" ] && continue
    
    [ "$FIRST" = false ] && echo ","
    FIRST=false
    
    # Extract actual region for AWS check (account-id is always 12 digits)
    REGION=$(echo "$ACCOUNT_REGION" | sed 's/^[0-9]\{12\}-//')
    
    # Check router
    ROUTER_EXISTS="false"
    ROUTER_CHECK=$(echo "$CONFIGS" | jq -r ".result.config_list[].clients[]? | select(.name == \"aws-vpn-$ACCOUNT_REGION\") | .name" 2>/dev/null || echo "")
    if [ -n "$ROUTER_CHECK" ]; then
      ROUTER_EXISTS="true"
    fi
    
    # Check local ovpn file
    OVPN_EXISTS="false"
    if [ -f "$VPN_DIR/aws-vpn-${ACCOUNT_REGION}.ovpn" ]; then
      OVPN_EXISTS="true"
    fi
    
    # Check AWS
    AWS_EXISTS="false"
    if aws cloudformation describe-stacks --stack-name glinet-openvpn --region "$REGION" &>/dev/null; then
      AWS_EXISTS="true"
    fi
    
    # Determine status
    if [ "$ROUTER_EXISTS" = "true" ] && [ "$OVPN_EXISTS" = "true" ] && [ "$AWS_EXISTS" = "true" ]; then
      STATUS="CONSISTENT"
    else
      STATUS="INCONSISTENT"
    fi
    
    echo -n "  \"$ACCOUNT_REGION\": {"
    echo -n "\"router\": $ROUTER_EXISTS, "
    echo -n "\"ovpn-client\": $OVPN_EXISTS, "
    echo -n "\"aws-server\": $AWS_EXISTS, "
    echo -n "\"status\": \"$STATUS\""
    echo -n "}"
  done <<< "$REGIONS_LIST"
  
  echo ""
  echo "}"
}

# Command: get-vpn-status
cmd_get_vpn_status() {
  STATUS=$(router_api_call "ovpn-client" "get_status")
  VPN_STATUS=$(echo "$STATUS" | jq -r '.result.status')
  
  if [ "$VPN_STATUS" = "0" ]; then
    echo "NO VPN ACTIVE"
    exit 0
  fi
  
  # Get the client name and extract region (e.g., aws-vpn-sa-east-1 -> sa-east-1)
  CLIENT_NAME=$(echo "$STATUS" | jq -r '.result.name')
  
  if [ -z "$CLIENT_NAME" ] || [ "$CLIENT_NAME" = "null" ]; then
    echo "VPN ACTIVE: (unknown)"
  else
    REGION=$(echo "$CLIENT_NAME" | sed 's/aws-vpn-\(.*\)/\1/')
    echo "VPN ACTIVE: $REGION"
  fi
}


# Command: stop-vpn-client
cmd_stop_vpn_client() {
  STATUS=$(router_api_call "ovpn-client" "get_status")
  VPN_STATUS=$(echo "$STATUS" | jq -r '.result.status')
  
  if [ "$VPN_STATUS" = "0" ]; then
    echo "NO VPN ACTIVE"
    exit 0
  fi
  
  echo "Stopping VPN..."
  
  source "$SESSION_FILE"
  curl -s "http://$ROUTER_IP/rpc" \
    -H "Content-Type: application/json" \
    -H "Cookie: sysauth=$SID" \
    -d '{"jsonrpc":"2.0","id":1,"method":"call","params":["'$SID'","ovpn-client","stop",{}]}' > /dev/null
  
  echo -n "Verifying"
  for i in {1..30}; do
    sleep 1
    echo -n "."
    STATUS=$(router_api_call "ovpn-client" "get_status")
    if [ "$(echo "$STATUS" | jq -r '.result.status')" = "0" ]; then
      echo ""
      echo "✓ VPN stopped successfully"
      exit 0
    fi
  done
  
  echo ""
  echo "WARNING: VPN may not have stopped"
  exit 1
}

# Command: start-vpn-client
cmd_start_vpn_client() {
  local REGION=""
  
  while [[ $# -gt 0 ]]; do
    case $1 in
      --region) REGION="$2"; shift 2 ;;
      *) echo "Unknown option: $1"; exit 1 ;;
    esac
  done
  
  if [ -z "$REGION" ]; then
    echo "ERROR: --region required"
    exit 1
  fi
  
  # Ensure security group allows current IP
  ensure_security_group_access "$REGION"
  
  echo "Starting VPN client for region: $REGION"
  
  # Get all configs to find the client
  CONFIGS=$(router_api_call "ovpn-client" "get_all_config_list")
  
  # Find group and client by name
  ACCOUNT_ID=$(get_aws_account_id)
  CLIENT_NAME="aws-vpn-$ACCOUNT_ID-$REGION"
  GROUP_DATA=$(echo "$CONFIGS" | jq -r ".result.config_list[] | select(.clients[]?.name == \"$CLIENT_NAME\")")
  
  if [ -z "$GROUP_DATA" ]; then
    echo "ERROR: VPN client not found for region: $REGION"
    echo "Run 'glinet.sh list-vpn-clients' to see available clients"
    exit 1
  fi
  
  GROUP_ID=$(echo "$GROUP_DATA" | jq -r '.group_id')
  CLIENT_ID=$(echo "$GROUP_DATA" | jq -r ".clients[] | select(.name == \"$CLIENT_NAME\") | .client_id")
  
  echo "Starting: $CLIENT_NAME (group: $GROUP_ID, client: $CLIENT_ID)"
  
  source "$SESSION_FILE"
  RESULT=$(curl -s "http://$ROUTER_IP/rpc" \
    -H "Content-Type: application/json" \
    -H "Cookie: sysauth=$SID" \
    -d '{"jsonrpc":"2.0","id":1,"method":"call","params":["'"$SID"'","ovpn-client","start",{"group_id":'"$GROUP_ID"',"client_id":'"$CLIENT_ID"'}]}')
  
  # Check for errors
  ERR_CODE=$(echo "$RESULT" | jq -r '.result.err_code // empty' 2>/dev/null)
  if [ -n "$ERR_CODE" ] && [ "$ERR_CODE" != "0" ] && [ "$ERR_CODE" != "null" ]; then
    ERR_MSG=$(echo "$RESULT" | jq -r '.result.err_msg // empty')
    echo "ERROR: Failed to start VPN (code: $ERR_CODE, message: $ERR_MSG)"
    exit 1
  fi
  
  # Verify it started (wait up to 30 seconds)
  echo -n "Verifying connection"
  for i in {1..30}; do
    sleep 1
    echo -n "."
    STATUS=$(router_api_call "ovpn-client" "get_status")
    VPN_STATUS=$(echo "$STATUS" | jq -r '.result.status')
    
    if [ "$VPN_STATUS" = "1" ]; then
      ACTIVE_NAME=$(echo "$STATUS" | jq -r '.result.name')
      if [ "$ACTIVE_NAME" = "$CLIENT_NAME" ]; then
        echo ""
        echo "✓ VPN started successfully"
        echo "IP: $(echo "$STATUS" | jq -r '.result.ipv4')"
        exit 0
      fi
    fi
  done
  
  echo ""
  # Final check
  STATUS=$(router_api_call "ovpn-client" "get_status")
  VPN_STATUS=$(echo "$STATUS" | jq -r '.result.status')
  if [ "$VPN_STATUS" = "1" ]; then
    ACTIVE_NAME=$(echo "$STATUS" | jq -r '.result.name')
    if [ "$ACTIVE_NAME" = "$CLIENT_NAME" ]; then
      echo "✓ VPN started successfully"
      echo "IP: $(echo "$STATUS" | jq -r '.result.ipv4')"
      exit 0
    fi
  fi
  
  echo "WARNING: VPN may not have started (status: $VPN_STATUS)"
  exit 1
}

# Command: retrieve-aws-openvpn
cmd_retrieve_aws_openvpn() {
  local REGION=""
  
  while [[ $# -gt 0 ]]; do
    case $1 in
      --region) REGION="$2"; shift 2 ;;
      *) echo "Unknown option: $1"; exit 1 ;;
    esac
  done
  
  if [ -z "$REGION" ]; then
    echo "ERROR: --region required"
    exit 1
  fi
  
  if ! aws sts get-caller-identity &>/dev/null; then
    echo "ERROR: AWS credentials not configured. Run 'aws configure' first."
    exit 1
  fi
  
  STACK_NAME="glinet-openvpn"
  
  echo "Retrieving OpenVPN config from $REGION..."
  
  INSTANCE_ID=$(aws cloudformation describe-stacks \
    --stack-name "$STACK_NAME" \
    --region "$REGION" \
    --query 'Stacks[0].Outputs[?OutputKey==`InstanceId`].OutputValue' \
    --output text 2>/dev/null)
  
  if [ -z "$INSTANCE_ID" ]; then
    echo "ERROR: Stack not found in region $REGION"
    exit 1
  fi
  
  STATE=$(aws ec2 describe-instances \
    --instance-ids "$INSTANCE_ID" \
    --region "$REGION" \
    --query 'Reservations[0].Instances[0].State.Name' \
    --output text)
  
  if [ "$STATE" != "running" ]; then
    echo "ERROR: Instance is $STATE. Start it first with: $0 start-aws-openvpn --region $REGION"
    exit 1
  fi
  
  echo "Downloading configuration..."
  
  COMMAND_ID=$(aws ssm send-command \
    --instance-ids "$INSTANCE_ID" \
    --region "$REGION" \
    --document-name "AWS-RunShellScript" \
    --parameters 'commands=["cat /root/client.ovpn"]' \
    --query 'Command.CommandId' \
    --output text)
  
  sleep 5
  
  ACCOUNT_ID=$(get_aws_account_id)
  
  aws ssm get-command-invocation \
    --command-id "$COMMAND_ID" \
    --instance-id "$INSTANCE_ID" \
    --region "$REGION" \
    --query 'StandardOutputContent' \
    --output text > "$VPN_DIR/aws-vpn-$ACCOUNT_ID-${REGION}.ovpn"
  
  PUBLIC_IP=$(aws ec2 describe-instances \
    --instance-ids "$INSTANCE_ID" \
    --region "$REGION" \
    --query 'Reservations[0].Instances[0].PublicIpAddress' \
    --output text)
  
  sed -i '' "s/^remote .* 1194/remote $PUBLIC_IP 1194/" "$VPN_DIR/aws-vpn-$ACCOUNT_ID-${REGION}.ovpn"
  
  echo "✓ Config saved to: $VPN_DIR/aws-vpn-$ACCOUNT_ID-${REGION}.ovpn"
}

# Command: delete-vpn-client
cmd_delete_vpn_client() {
  local REGION=""
  
  while [[ $# -gt 0 ]]; do
    case $1 in
      --region) REGION="$2"; shift 2 ;;
      *) echo "Unknown option: $1"; exit 1 ;;
    esac
  done
  
  if [ -z "$REGION" ]; then
    echo "ERROR: --region required"
    exit 1
  fi
  
  echo "Deleting VPN client: $CLIENT_NAME"
  
  source "$SESSION_FILE"
  
  ACCOUNT_ID=$(get_aws_account_id)
  CLIENT_NAME="aws-vpn-$ACCOUNT_ID-$REGION"
  FILENAME="aws-vpn-$ACCOUNT_ID-${REGION}.ovpn"
  
  # Find client (name in router doesn't have .ovpn extension)
  CONFIGS=$(router_api_call "ovpn-client" "get_all_config_list")
  GROUP_DATA=$(echo "$CONFIGS" | jq -r ".result.config_list[] | select(.clients[]?.name == \"$CLIENT_NAME\")")
  
  if [ -n "$GROUP_DATA" ]; then
    GROUP_ID=$(echo "$GROUP_DATA" | jq -r '.group_id')
    CLIENT_ID=$(echo "$GROUP_DATA" | jq -r ".clients[] | select(.name == \"$CLIENT_NAME\") | .client_id")
    
    echo "Removing client from router..."
    curl -s "http://$ROUTER_IP/rpc" \
      -H "Content-Type: application/json" \
      -H "Cookie: sysauth=$SID" \
      -d '{"jsonrpc":"2.0","id":1,"method":"call","params":["'$SID'","ovpn-client","remove_config",{"group_id":'$GROUP_ID',"client_id":'$CLIENT_ID'}]}' > /dev/null
    
    echo "Removing group from router..."
    curl -s "http://$ROUTER_IP/rpc" \
      -H "Content-Type: application/json" \
      -H "Cookie: sysauth=$SID" \
      -d '{"jsonrpc":"2.0","id":1,"method":"call","params":["'$SID'","ovpn-client","remove_group",{"group_id":'$GROUP_ID'}]}' > /dev/null
  else
    echo "Client not found on router"
  fi
  
  # Delete local file
  if [ -f "$VPN_DIR/$FILENAME" ]; then
    echo "Deleting local file..."
    rm "$VPN_DIR/$FILENAME"
  fi
  
  echo "✓ VPN client deleted"
}

# AWS wrapper commands
cmd_create_aws_openvpn() {
  local REGION=""
  
  while [[ $# -gt 0 ]]; do
    case $1 in
      --region) REGION="$2"; shift 2 ;;
      *) echo "Unknown option: $1"; exit 1 ;;
    esac
  done
  
  [[ -z "$REGION" ]] && { echo "Error: --region required"; exit 1; }
  
  local STACK_NAME="glinet-openvpn"
  
  echo "Creating OpenVPN stack in $REGION..."
  aws cloudformation create-stack \
    --region "$REGION" \
    --stack-name "$STACK_NAME" \
    --template-body file://openvpn-stack.yaml \
    --capabilities CAPABILITY_IAM >/dev/null
  
  echo "Waiting for stack creation..."
  aws cloudformation wait stack-create-complete \
    --region "$REGION" \
    --stack-name "$STACK_NAME"
  
  echo "Stack created. Retrieving configuration..."
  cmd_retrieve_aws_openvpn --region "$REGION"
}

cmd_start_aws_openvpn() {
  local REGION=""
  
  while [[ $# -gt 0 ]]; do
    case $1 in
      --region) REGION="$2"; shift 2 ;;
      *) echo "Unknown option: $1"; exit 1 ;;
    esac
  done
  
  [[ -z "$REGION" ]] && { echo "Error: --region required"; exit 1; }
  
  local STACK_NAME="glinet-openvpn"
  local INSTANCE_ID=$(aws cloudformation describe-stacks \
    --region "$REGION" \
    --stack-name "$STACK_NAME" \
    --query 'Stacks[0].Outputs[?OutputKey==`InstanceId`].OutputValue' \
    --output text 2>/dev/null)
  
  [[ -z "$INSTANCE_ID" ]] && { echo "Error: Stack $STACK_NAME not found in $REGION"; exit 1; }
  
  echo "Starting instance $INSTANCE_ID..."
  aws ec2 start-instances --region "$REGION" --instance-ids "$INSTANCE_ID" >/dev/null
  
  echo "Waiting for instance to be running..."
  aws ec2 wait instance-running --region "$REGION" --instance-ids "$INSTANCE_ID"
  
  echo "Instance started. Retrieving new configuration..."
  cmd_retrieve_aws_openvpn --region "$REGION"
}

cmd_stop_aws_openvpn() {
  local REGION=""
  
  while [[ $# -gt 0 ]]; do
    case $1 in
      --region) REGION="$2"; shift 2 ;;
      *) echo "Unknown option: $1"; exit 1 ;;
    esac
  done
  
  [[ -z "$REGION" ]] && { echo "Error: --region required"; exit 1; }
  
  local STACK_NAME="glinet-openvpn"
  local INSTANCE_ID=$(aws cloudformation describe-stacks \
    --region "$REGION" \
    --stack-name "$STACK_NAME" \
    --query 'Stacks[0].Outputs[?OutputKey==`InstanceId`].OutputValue' \
    --output text 2>/dev/null)
  
  [[ -z "$INSTANCE_ID" ]] && { echo "Error: Stack $STACK_NAME not found in $REGION"; exit 1; }
  
  echo "Stopping instance $INSTANCE_ID..."
  aws ec2 stop-instances --region "$REGION" --instance-ids "$INSTANCE_ID" >/dev/null
  echo "Instance stopped"
}

cmd_destroy_aws_openvpn() {
  local REGION=""
  
  while [[ $# -gt 0 ]]; do
    case $1 in
      --region) REGION="$2"; shift 2 ;;
      *) break ;;
    esac
  done
  
  if [ -n "$REGION" ]; then
    cmd_delete_vpn_client --region "$REGION" 2>/dev/null || true
  fi
  
  ./destroy-aws-openvpn.sh "$@"
}

# Command: update-aws-openvpn-ip
cmd_update_aws_openvpn_ip() {
  local REGION=""
  
  while [[ $# -gt 0 ]]; do
    case $1 in
      --region) REGION="$2"; shift 2 ;;
      *) echo "Unknown option: $1"; exit 1 ;;
    esac
  done
  
  if [ -z "$REGION" ]; then
    echo "ERROR: --region required"
    exit 1
  fi
  
  echo "Updating OpenVPN configuration for region: $REGION"
  
  # Check if VPN is active for this region
  STATUS=$(router_api_call "ovpn-client" "get_status")
  VPN_STATUS=$(echo "$STATUS" | jq -r '.result.status')
  ACCOUNT_ID=$(get_aws_account_id)
  CLIENT_NAME="aws-vpn-$ACCOUNT_ID-$REGION"
  
  WAS_ACTIVE=false
  if [ "$VPN_STATUS" = "1" ]; then
    ACTIVE_NAME=$(echo "$STATUS" | jq -r '.result.name')
    if [ "$ACTIVE_NAME" = "$CLIENT_NAME" ]; then
      WAS_ACTIVE=true
      echo "VPN is active, stopping..."
      cmd_stop_vpn_client
    fi
  fi
  
  # Delete existing client configuration
  echo "Removing old configuration..."
  cmd_delete_vpn_client --region "$REGION" 2>/dev/null || true
  
  # Retrieve new configuration from AWS
  echo "Downloading new configuration from AWS..."
  cmd_retrieve_aws_openvpn --region "$REGION"
  
  # Configure the client with new config
  OVPN_FILE="$VPN_DIR/aws-vpn-$ACCOUNT_ID-${REGION}.ovpn"
  echo "Configuring router with new IP..."
  cmd_configure_vpn_client --file "$OVPN_FILE"
  
  # Restart VPN if it was active
  if [ "$WAS_ACTIVE" = true ]; then
    echo "Restarting VPN..."
    cmd_start_vpn_client --region "$REGION"
  fi
  
  echo "✓ OpenVPN configuration updated successfully"
}

# Main
COMMAND="${1:-}"
shift || true

case "$COMMAND" in
  login) cmd_login "$@" ;;
  list-vpn-clients) cmd_list_vpn_clients "$@" ;;
  get-vpn-status) cmd_get_vpn_status "$@" ;;
  configure-vpn-client) cmd_configure_vpn_client "$@" ;;
  stop-vpn-client) cmd_stop_vpn_client "$@" ;;
  start-vpn-client) cmd_start_vpn_client "$@" ;;
  delete-vpn-client) cmd_delete_vpn_client "$@" ;;
  retrieve-aws-openvpn) cmd_retrieve_aws_openvpn "$@" ;;
  create-aws-openvpn) cmd_create_aws_openvpn "$@" ;;
  start-aws-openvpn) cmd_start_aws_openvpn "$@" ;;
  stop-aws-openvpn) cmd_stop_aws_openvpn "$@" ;;
  destroy-aws-openvpn) cmd_destroy_aws_openvpn "$@" ;;
  update-aws-openvpn-ip) cmd_update_aws_openvpn_ip "$@" ;;
  *)
    echo "Usage: $0 <command> [options]"
    echo ""
    echo "Commands:"
    echo "  login --password <pass> [--router-ip <ip>]"
    echo "  list-vpn-clients"
    echo "  get-vpn-status"
    echo "  configure-vpn-client --file <ovpn-file>"
    echo "  start-vpn-client --region <region>"
    echo "  stop-vpn-client"
    echo "  delete-vpn-client --region <region>"
    echo "  retrieve-aws-openvpn --region <region>"
    echo "  create-aws-openvpn --region <region>"
    echo "  start-aws-openvpn --region <region>"
    echo "  stop-aws-openvpn --region <region>"
    echo "  destroy-aws-openvpn --region <region>"
    echo "  update-aws-openvpn-ip --region <region>"
    exit 1
    ;;
esac
