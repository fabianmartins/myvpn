# GL-iNET Router API Methods Reference

## Authentication
All API calls require authentication using the `call` method format:
```json
{
  "jsonrpc": "2.0",
  "method": "call",
  "params": [sid, service, method, params]
}
```

## Methods Required for Project Workflow

### OpenVPN Client Management
| Service | Method | Params | Description |
|---------|--------|--------|-------------|
| `ovpn-client` | `get_status` | `{}` | Get current VPN status (status, group_id, client_id, rx/tx bytes, ipv4) |
| `ovpn-client` | `get_all_config_list` | `{}` | List all VPN configurations (groups and clients) |
| `ovpn-client` | `start` | `{group_id, client_id}` | Start VPN connection |
| `ovpn-client` | `stop` | `{group_id, client_id}` | Stop VPN connection |
| `ovpn-client` | `add_config` | `{group_id, name, config}` | Add new VPN config to group |
| `ovpn-client` | `remove_config` | `{group_id, client_id}` | Remove VPN config |
| `ovpn-client` | `add_group` | `{name}` | Create new VPN group |

### System Information
| Service | Method | Params | Description |
|---------|--------|--------|-------------|
| `system` | `get_status` | `{}` | Get system status (network, wifi, services, clients, system info) |
| `system` | `get_info` | `{}` | Get system information |
| `system` | `get_load` | `{}` | Get CPU load and memory |
| `system` | `get_unixtime` | `{}` | Get Unix timestamp |
| `system` | `disk_info` | `{}` | Get disk information |
| `system` | `reboot` | `{}` | Reboot the router |

## Additional Available Methods (for future use)

### WireGuard Client
| Service | Method | Params | Description |
|---------|--------|--------|-------------|
| `wg-client` | `get_status` | `{}` | Get WireGuard VPN status |
| `wg-client` | `get_all_config_list` | `{}` | List all WireGuard configs |
| `wg-client` | `start` | `{group_id, peer_id}` | Start WireGuard connection |
| `wg-client` | `stop` | `{group_id, peer_id}` | Stop WireGuard connection |

### WireGuard Server
| Service | Method | Params | Description |
|---------|--------|--------|-------------|
| `wg-server` | `get_status` | `{}` | Get WireGuard server status |
| `wg-server` | `get_config` | `{}` | Get server configuration |
| `wg-server` | `set_config` | `{config}` | Set server configuration |
| `wg-server` | `start` | `{}` | Start WireGuard server |
| `wg-server` | `stop` | `{}` | Stop WireGuard server |
| `wg-server` | `set_peer` | `{peer_config}` | Modify peer configuration |

### OpenVPN Server
| Service | Method | Params | Description |
|---------|--------|--------|-------------|
| `ovpn-server` | `get_status` | `{}` | Get OpenVPN server status |
| `ovpn-server` | `start` | `{}` | Start OpenVPN server |
| `ovpn-server` | `stop` | `{}` | Stop OpenVPN server |

### WiFi Management
| Service | Method | Params | Description |
|---------|--------|--------|-------------|
| `wifi` | `get_status` | `{}` | Get WiFi device status |
| `wifi` | `get_config` | `{}` | Get WiFi configuration |
| `wifi` | `set_config` | `{config}` | Set WiFi configuration |

### Client Management
| Service | Method | Params | Description |
|---------|--------|--------|-------------|
| `clients` | `get_list` | `{}` | Get all connected clients |

### Firewall
| Service | Method | Params | Description |
|---------|--------|--------|-------------|
| `firewall` | `get_rule_list` | `{}` | Get firewall rules |
| `firewall` | `add_rule` | `{rule_params}` | Add firewall rule |
| `firewall` | `remove_rule` | `{id}` or `{all: true}` | Remove firewall rule |
| `firewall` | `set_rule` | `{id, rule_params}` | Modify firewall rule |
| `firewall` | `get_dmz` | `{}` | Get DMZ configuration |
| `firewall` | `set_dmz` | `{enabled, dest_ip}` | Set DMZ configuration |
| `firewall` | `get_port_forward_list` | `{}` | Get port forward rules |
| `firewall` | `add_port_forward` | `{forward_params}` | Add port forward rule |
| `firewall` | `set_port_forward` | `{id, forward_params}` | Modify port forward rule |
| `firewall` | `remove_port_forward` | `{id}` or `{all: true}` | Remove port forward rule |
| `firewall` | `get_wan_access` | `{}` | Get WAN access config |
| `firewall` | `set_wan_access` | `{config}` | Set WAN access config |
| `firewall` | `get_zone_list` | `{}` | Get firewall zones |

## Example Usage

### Bash
```bash
./router-api-call.sh --service ovpn-client --method get_status
./router-api-call.sh --service ovpn-client --method start --params '{"group_id":1,"client_id":1}'
```

### Node.js
```bash
node router-cli.js --service ovpn-client --method get_status
node router-cli.js --service ovpn-client --method start --params '{"group_id":1,"client_id":1}'
```

## Notes
- VPN configs are organized in groups (group_id)
- Each config within a group has a client_id
- To add a config, you may need to create a group first with `add_group`
- The `config` parameter for `add_config` likely expects the .ovpn file content
- "Global proxy" mode setting needs further investigation
