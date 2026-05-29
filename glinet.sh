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
  
  if ! aws sts get-caller-identity &>/dev/null; then
    echo "ERROR: AWS credentials not configured. Run 'aws configure' first."
    exit 1
  fi
  
  MY_IP=$(curl -s https://api.ipify.org)
  if [ -z "$MY_IP" ]; then
    echo "WARNING: Could not detect public IP, skipping security group check"
    return
  fi
  
  # Get instance ID from CloudFormation
  INSTANCE_ID=$(aws cloudformation describe-stacks \
    --stack-name "$STACK_NAME" \
    --region "$REGION" \
    --query 'Stacks[0].Outputs[?OutputKey==`InstanceId`].OutputValue' \
    --output text 2>/dev/null)
  
  if [ -z "$INSTANCE_ID" ]; then
    echo "WARNING: Could not find instance, skipping security group check"
    return
  fi
  
  # Get actual security group ID from the instance
  SG_ID=$(aws ec2 describe-instances \
    --instance-ids "$INSTANCE_ID" \
    --region "$REGION" \
    --query 'Reservations[0].Instances[0].SecurityGroups[0].GroupId' \
    --output text 2>/dev/null)
  
  if [ -z "$SG_ID" ] || [ "$SG_ID" = "None" ]; then
    echo "WARNING: Could not find security group, skipping check"
    return
  fi
  
  # Check if current IP already has access
  HAS_ACCESS=$(aws ec2 describe-security-groups \
    --group-ids "$SG_ID" \
    --region "$REGION" \
    --query "SecurityGroups[0].IpPermissions[?FromPort==\`1194\`].IpRanges[?CidrIp==\`$MY_IP/32\`]" \
    --output text 2>/dev/null)
  
  if [ -n "$HAS_ACCESS" ]; then
    return
  fi
  
  echo "Updating security group with current IP ($MY_IP)..."
  
  # Remove old IPs for port 1194
  OLD_IPS=$(aws ec2 describe-security-groups \
    --group-ids "$SG_ID" \
    --region "$REGION" \
    --query "SecurityGroups[0].IpPermissions[?FromPort==\`1194\` && ToPort==\`1194\` && IpProtocol==\`udp\`].IpRanges[].CidrIp" \
    --output text 2>/dev/null)
  
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
  
  if [ ! -f "$SESSION_FILE" ]; then
    echo "ERROR: Not logged in to router. Run: $0 login --password <password>"
    exit 1
  fi
  
  REGION=$(basename "$OVPN_FILE" | sed 's/aws-vpn-[0-9]*-\(.*\)\.ovpn/\1/')
  ACCOUNT_ID=$(basename "$OVPN_FILE" | sed 's/aws-vpn-\([0-9]*\)-.*\.ovpn/\1/')
  CLIENT_NAME="aws-vpn-$ACCOUNT_ID-$REGION"
  FILENAME=$(basename "$OVPN_FILE")
  
  echo "Configuring VPN client: $CLIENT_NAME"
  
  # Check if client already exists (this will also validate session)
  CONFIGS=$(router_api_call "ovpn-client" "get_all_config_list")
  
  if echo "$CONFIGS" | jq -e ".result.config_list[].clients[]? | select(.name == \"$CLIENT_NAME\")" > /dev/null 2>&1; then
    echo "✓ Client $CLIENT_NAME already configured on router. Skipping."
    exit 0
  fi
  
  source "$SESSION_FILE"
  
  # Ensure security group allows current IP
  ensure_security_group_access "$REGION"
  
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
  
  sleep 5
  
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
  
  if ! echo "$CHECK_RESULT" | jq -e ".result.passed[]? | select(. == \"$FILENAME\")" > /dev/null 2>&1; then
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
      REGION=$(basename "$ovpn_file" | sed 's/aws-vpn-[0-9]*-\(.*\)\.ovpn/\1/')
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
    if echo "$CONFIGS" | jq -e ".result.config_list[].clients[]? | select(.name == \"aws-vpn-$ACCOUNT_REGION\")" > /dev/null 2>&1; then
      ROUTER_EXISTS="true"
    fi
    
    # Check local ovpn file
    OVPN_EXISTS="false"
    if [ -f "$VPN_DIR/aws-vpn-${ACCOUNT_REGION}.ovpn" ]; then
      OVPN_EXISTS="true"
    fi
    
    # Check AWS
    AWS_EXISTS="false"
    AWS_IP=""
    STACK_OUTPUT=$(aws cloudformation describe-stacks --stack-name glinet-openvpn --region "$REGION" 2>/dev/null)
    if [ $? -eq 0 ]; then
      AWS_EXISTS="true"
      INSTANCE_ID=$(echo "$STACK_OUTPUT" | jq -r '.Stacks[0].Outputs[] | select(.OutputKey=="InstanceId") | .OutputValue')
      if [ -n "$INSTANCE_ID" ]; then
        AWS_IP=$(aws ec2 describe-instances --instance-ids "$INSTANCE_ID" --region "$REGION" \
          --query 'Reservations[0].Instances[0].PublicIpAddress' --output text 2>/dev/null)
        [ "$AWS_IP" = "None" ] && AWS_IP=""
      fi
    fi
    
    # Check IP match
    IP_MATCH="false"
    if [ "$OVPN_EXISTS" = "true" ] && [ -n "$AWS_IP" ]; then
      OVPN_IP=$(grep -oP '^remote \K[^ ]+' "$VPN_DIR/aws-vpn-${ACCOUNT_REGION}.ovpn" 2>/dev/null)
      [ "$OVPN_IP" = "$AWS_IP" ] && IP_MATCH="true"
    fi
    
    # Determine status
    if [ "$ROUTER_EXISTS" = "true" ] && [ "$OVPN_EXISTS" = "true" ] && [ "$AWS_EXISTS" = "true" ] && [ "$IP_MATCH" = "true" ]; then
      STATUS="CONSISTENT"
    elif [ "$ROUTER_EXISTS" = "true" ] && [ "$AWS_EXISTS" = "true" ] && [ "$IP_MATCH" = "false" ]; then
      STATUS="STALE_IP"
    else
      STATUS="INCONSISTENT"
    fi
    
    echo -n "  \"$ACCOUNT_REGION\": {"
    echo -n "\"router\": $ROUTER_EXISTS, "
    echo -n "\"ovpn-client\": $OVPN_EXISTS, "
    echo -n "\"aws-server\": $AWS_EXISTS, "
    echo -n "\"ip-match\": $IP_MATCH, "
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
  if echo "$RESULT" | jq -e '.result.err_code' > /dev/null 2>&1; then
    ERR_CODE=$(echo "$RESULT" | jq -r '.result.err_code')
    ERR_MSG=$(echo "$RESULT" | jq -r '.result.err_msg')
    if [ "$ERR_CODE" != "0" ] && [ "$ERR_CODE" != "null" ]; then
      echo "ERROR: Failed to start VPN (code: $ERR_CODE, message: $ERR_MSG)"
      exit 1
    fi
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
  
  sed -i "s/^remote .* 1194/remote $PUBLIC_IP 1194/" "$VPN_DIR/aws-vpn-$ACCOUNT_ID-${REGION}.ovpn"
  
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
  
  if ! aws sts get-caller-identity &>/dev/null; then
    echo "ERROR: AWS credentials not configured. Run 'aws configure' first."
    exit 1
  fi
  
  local STACK_NAME="glinet-openvpn"
  
  # Check if stack already exists
  if aws cloudformation describe-stacks --stack-name "$STACK_NAME" --region "$REGION" &>/dev/null; then
    echo "✓ Stack $STACK_NAME already exists in $REGION. Skipping creation."
    cmd_retrieve_aws_openvpn --region "$REGION"
    return
  fi
  
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
  
  if ! aws sts get-caller-identity &>/dev/null; then
    echo "ERROR: AWS credentials not configured. Run 'aws configure' first."
    exit 1
  fi
  
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
  
  if ! aws sts get-caller-identity &>/dev/null; then
    echo "ERROR: AWS credentials not configured. Run 'aws configure' first."
    exit 1
  fi
  
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
  
  if ! aws sts get-caller-identity &>/dev/null; then
    echo "ERROR: AWS credentials not configured. Run 'aws configure' first."
    exit 1
  fi
  
  if [ -n "$REGION" ]; then
    cmd_delete_vpn_client --region "$REGION" 2>/dev/null || true
  fi
  
  ./destroy-aws-openvpn.sh "$@"
}

# Command: start-vpn (orchestrated)
cmd_start_vpn() {
  local REGION="" PASSWORD="" PROFILE="" ROUTER_IP_OPT=""

  while [[ $# -gt 0 ]]; do
    case $1 in
      --region) REGION="$2"; shift 2 ;;
      --router-pwd) PASSWORD="$2"; shift 2 ;;
      --profile) PROFILE="$2"; shift 2 ;;
      --router-ip) ROUTER_IP_OPT="$2"; shift 2 ;;
      *) echo "Unknown option: $1"; exit 1 ;;
    esac
  done

  [[ -z "$REGION" ]] && { echo "ERROR: --region required"; exit 1; }
  [[ -z "$PASSWORD" ]] && { echo "ERROR: --router-pwd required"; exit 1; }
  [[ -n "$PROFILE" ]] && export AWS_PROFILE="$PROFILE"

  # 1. Check AWS credentials
  echo "① Checking AWS credentials..."
  if ! aws sts get-caller-identity &>/dev/null; then
    echo "FAILURE: AWS credentials not valid."
    exit 1
  fi
  ACCOUNT_ID=$(get_aws_account_id)
  echo "  ✓ Account: $ACCOUNT_ID"

  # 2. Login to router
  echo "② Logging into router..."
  local LOGIN_ARGS=(--password "$PASSWORD")
  [[ -n "$ROUTER_IP_OPT" ]] && LOGIN_ARGS+=(--router-ip "$ROUTER_IP_OPT")
  cmd_login "${LOGIN_ARGS[@]}" | tail -1

  # 3. Check stack exists
  echo "③ Checking CloudFormation stack..."
  local STACK_NAME="glinet-openvpn"
  local STACK_OUTPUT
  STACK_OUTPUT=$(aws cloudformation describe-stacks --stack-name "$STACK_NAME" --region "$REGION" 2>&1) || {
    echo "FAILURE: Stack $STACK_NAME not found in $REGION. Create it first with: $0 create-aws-openvpn --region $REGION"
    exit 1
  }
  local INSTANCE_ID
  INSTANCE_ID=$(echo "$STACK_OUTPUT" | jq -r '.Stacks[0].Outputs[] | select(.OutputKey=="InstanceId") | .OutputValue')
  echo "  ✓ Stack exists, instance: $INSTANCE_ID"

  # 4. Start instance if necessary
  echo "④ Checking instance state..."
  local STATE
  STATE=$(aws ec2 describe-instances --instance-ids "$INSTANCE_ID" --region "$REGION" \
    --query 'Reservations[0].Instances[0].State.Name' --output text)

  if [ "$STATE" = "running" ]; then
    echo "  ✓ Already running"
  elif [ "$STATE" = "stopped" ]; then
    echo "  Starting instance..."
    aws ec2 start-instances --region "$REGION" --instance-ids "$INSTANCE_ID" >/dev/null
    aws ec2 wait instance-running --region "$REGION" --instance-ids "$INSTANCE_ID"
    echo "  ✓ Instance started"
  else
    echo "FAILURE: Instance is in state '$STATE', cannot proceed."
    exit 1
  fi

  # 5. Ensure security group allows current IP
  echo "⑤ Checking security group..."
  ensure_security_group_access "$REGION"
  echo "  ✓ Security group OK"

  # 6. Get current public IP of instance
  local AWS_IP
  AWS_IP=$(aws ec2 describe-instances --instance-ids "$INSTANCE_ID" --region "$REGION" \
    --query 'Reservations[0].Instances[0].PublicIpAddress' --output text)

  # 7. Download new client config if necessary
  local CLIENT_NAME="aws-vpn-$ACCOUNT_ID-$REGION"
  local OVPN_FILE="$VPN_DIR/aws-vpn-$ACCOUNT_ID-${REGION}.ovpn"
  local NEED_NEW_CONFIG="false"

  if [ ! -f "$OVPN_FILE" ]; then
    NEED_NEW_CONFIG="true"
  else
    local OVPN_IP
    OVPN_IP=$(grep -oP '^remote \K[^ ]+' "$OVPN_FILE" 2>/dev/null)
    if [ "$OVPN_IP" != "$AWS_IP" ]; then
      NEED_NEW_CONFIG="true"
    fi
  fi

  if [ "$NEED_NEW_CONFIG" = "true" ]; then
    echo "⑥ Retrieving new VPN config (IP: $AWS_IP)..."
    # Wait for SSM agent to be ready
    echo "  Waiting for SSM agent..."
    for i in {1..30}; do
      if aws ssm describe-instance-information --region "$REGION" \
        --filters "Key=InstanceIds,Values=$INSTANCE_ID" \
        --query 'InstanceInformationList[0].PingStatus' --output text 2>/dev/null | grep -q "Online"; then
        break
      fi
      sleep 2
    done
    cmd_retrieve_aws_openvpn --region "$REGION" | grep -v "^Retrieving\|^Downloading"
  else
    echo "⑥ Config already up-to-date (IP: $AWS_IP)"
  fi

  # 8. Update router client if necessary
  echo "⑦ Checking router VPN client..."
  local CONFIGS
  CONFIGS=$(router_api_call "ovpn-client" "get_all_config_list")
  local ROUTER_HAS_CLIENT="false"
  local ROUTER_IP_MATCH="false"

  if echo "$CONFIGS" | jq -e ".result.config_list[].clients[]? | select(.name == \"$CLIENT_NAME\")" > /dev/null 2>&1; then
    ROUTER_HAS_CLIENT="true"
    # Check if the router's configured remote matches current AWS IP
    local ROUTER_DOMAIN
    ROUTER_DOMAIN=$(echo "$CONFIGS" | jq -r ".result.config_list[] | select(.clients[]?.name == \"$CLIENT_NAME\") | .clients[] | select(.name == \"$CLIENT_NAME\") | .remote[0]? // empty")
    # The router status shows domain field - check via get_status or just compare with what we know
    # Safest: if we needed a new config, we need to reconfigure the router
    if [ "$NEED_NEW_CONFIG" = "false" ]; then
      ROUTER_IP_MATCH="true"
    fi
  fi

  if [ "$ROUTER_HAS_CLIENT" = "true" ] && [ "$ROUTER_IP_MATCH" = "false" ]; then
    echo "  Stale client on router, replacing..."
    # Remove from router only (not local file)
    source "$SESSION_FILE"
    local GROUP_DATA_DEL GROUP_ID_DEL CLIENT_ID_DEL
    GROUP_DATA_DEL=$(echo "$CONFIGS" | jq -r ".result.config_list[] | select(.clients[]?.name == \"$CLIENT_NAME\")")
    GROUP_ID_DEL=$(echo "$GROUP_DATA_DEL" | jq -r '.group_id')
    CLIENT_ID_DEL=$(echo "$GROUP_DATA_DEL" | jq -r ".clients[] | select(.name == \"$CLIENT_NAME\") | .client_id")
    curl -s "http://$ROUTER_IP/rpc" -H "Content-Type: application/json" -H "Cookie: sysauth=$SID" \
      -d '{"jsonrpc":"2.0","id":1,"method":"call","params":["'$SID'","ovpn-client","remove_config",{"group_id":'$GROUP_ID_DEL',"client_id":'$CLIENT_ID_DEL'}]}' > /dev/null
    curl -s "http://$ROUTER_IP/rpc" -H "Content-Type: application/json" -H "Cookie: sysauth=$SID" \
      -d '{"jsonrpc":"2.0","id":1,"method":"call","params":["'$SID'","ovpn-client","remove_group",{"group_id":'$GROUP_ID_DEL'}]}' > /dev/null
    echo "  ✓ Old client removed"
    (cmd_configure_vpn_client --file "$OVPN_FILE") 2>&1 | sed 's/^/  /'
  elif [ "$ROUTER_HAS_CLIENT" = "false" ]; then
    echo "  Configuring new client on router..."
    (cmd_configure_vpn_client --file "$OVPN_FILE") 2>&1 | sed 's/^/  /'
  else
    echo "  ✓ Router client is current"
  fi

  # 9. Start VPN
  echo "⑧ Starting VPN..."
  (cmd_start_vpn_client --region "$REGION") 2>&1 | sed 's/^/  /'

  # 10. Verify and report
  echo ""
  echo "Verifying public IP..."
  local CURRENT_IP=""
  for i in {1..5}; do
    CURRENT_IP=$(curl -s --max-time 10 https://api.ipify.org 2>/dev/null) || true
    [ -n "$CURRENT_IP" ] && break
    sleep 2
  done

  if [ -n "$CURRENT_IP" ] && [ "$CURRENT_IP" = "$AWS_IP" ]; then
    echo "SUCCESS ✓ VPN active via $REGION"
    echo "Public IP: $CURRENT_IP"
  elif [ -n "$CURRENT_IP" ]; then
    echo "FAILURE ✗ VPN may not be routing traffic correctly"
    echo "Expected IP: $AWS_IP"
    echo "Actual IP: $CURRENT_IP"
    exit 1
  else
    echo "WARNING: VPN started but could not verify public IP"
  fi
}

# Command: stop-vpn (orchestrated)
cmd_stop_vpn() {
  local REGION="" PASSWORD="" PROFILE="" ROUTER_IP_OPT=""

  while [[ $# -gt 0 ]]; do
    case $1 in
      --region) REGION="$2"; shift 2 ;;
      --router-pwd) PASSWORD="$2"; shift 2 ;;
      --profile) PROFILE="$2"; shift 2 ;;
      --router-ip) ROUTER_IP_OPT="$2"; shift 2 ;;
      *) echo "Unknown option: $1"; exit 1 ;;
    esac
  done

  [[ -z "$REGION" ]] && { echo "ERROR: --region required"; exit 1; }
  [[ -z "$PASSWORD" ]] && { echo "ERROR: --router-pwd required"; exit 1; }
  [[ -n "$PROFILE" ]] && export AWS_PROFILE="$PROFILE"

  # 1. Check AWS credentials
  echo "① Checking AWS credentials..."
  if ! aws sts get-caller-identity &>/dev/null; then
    echo "FAILURE: AWS credentials not valid."
    exit 1
  fi
  echo "  ✓ OK"

  # 2. Login to router
  echo "② Logging into router..."
  local LOGIN_ARGS=(--password "$PASSWORD")
  [[ -n "$ROUTER_IP_OPT" ]] && LOGIN_ARGS+=(--router-ip "$ROUTER_IP_OPT")
  cmd_login "${LOGIN_ARGS[@]}" | tail -1

  # 3. Stop VPN on router
  echo "③ Stopping VPN on router..."
  (cmd_stop_vpn_client) 2>&1 | sed 's/^/  /'

  # Wait for network to recover after VPN disconnect
  echo "  Waiting for network..."
  for i in {1..15}; do
    if curl -s --max-time 3 https://api.ipify.org &>/dev/null; then
      break
    fi
    sleep 1
  done

  # 4. Stop EC2 instance
  echo "④ Stopping EC2 instance..."
  local STOP_OUTPUT
  STOP_OUTPUT=$( (cmd_stop_aws_openvpn --region "$REGION") 2>&1) || true
  echo "$STOP_OUTPUT" | sed 's/^/  /'
  if echo "$STOP_OUTPUT" | grep -q "ERROR"; then
    echo ""
    echo "FAILURE ✗ Could not stop EC2 instance"
    exit 1
  fi

  # 5. Verify and report
  echo ""
  local CURRENT_IP=""
  CURRENT_IP=$(curl -s --max-time 10 https://api.ipify.org 2>/dev/null) || true

  if [ -n "$CURRENT_IP" ]; then
    echo "SUCCESS ✓ VPN stopped, instance stopped"
    echo "Public IP: $CURRENT_IP"
  else
    echo "WARNING: VPN stopped but could not verify public IP"
  fi
}

# Main
COMMAND="${1:-}"
shift || true

case "$COMMAND" in
  start-vpn) cmd_start_vpn "$@" ;;
  stop-vpn) cmd_stop_vpn "$@" ;;
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
  *)
    echo "Usage: $0 <command> [options]"
    echo ""
    echo "High-level commands:"
    echo "  start-vpn --region <region> --router-pwd <password> [--profile <aws-profile>] [--router-ip <ip>]"
    echo "  stop-vpn --region <region> --router-pwd <password> [--profile <aws-profile>] [--router-ip <ip>]"
    echo ""
    echo "Low-level commands:"
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
    exit 1
    ;;
esac
