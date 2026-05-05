# Check Point 15600 Data Limitations

## Device Status: OFFLINE

**Device**: MUM-FW-01 (Check Point 15600 Security Gateway)
**Serial**: CP-15600-001  
**Location**: Mumbai, India
**IP Address**: 192.168.202.1
**Last Seen**: 2025-08-03 11:15:22

## Mock Data Requirements
- **CPU Usage**: 0% (offline)
- **Memory Usage**: 0% (offline) 
- **Temperature**: 0°C (offline)
- **Interfaces**: 24
- **Uptime**: "0m"
- **Status**: offline

## Data Availability

### Available via SNMP (when online)
- System description (1.3.6.1.2.1.1.1.0)
- System object ID (1.3.6.1.2.1.1.2.0) 
- System uptime (1.3.6.1.2.1.1.3.0) - Returns 0 when offline
- System contact (1.3.6.1.2.1.1.4.0)
- System name (1.3.6.1.2.1.1.5.0)
- System location (1.3.6.1.2.1.1.6.0)
- Interface count (1.3.6.1.2.1.2.1.0)
- Serial number (1.3.6.1.4.1.2620.1.1.21.0)

### Available via SSH (when online)
Check Point uses proprietary commands:
- `cpstat os -f all` - System statistics including CPU/memory
- `ifconfig -a` - Network interface information  
- `netstat -rn` - Routing table
- `cpconfig` - System configuration info
- `fw stat` - Firewall statistics

### Limitations When Offline

1. **SNMP Access**: All SNMP queries timeout or return connection refused
2. **SSH Access**: Connection attempts fail with "Connection refused" or timeout
3. **Performance Metrics**: No real-time CPU, memory, or temperature data available
4. **Interface Status**: Cannot determine current interface states
5. **Configuration**: Cannot access current running configuration

### Offline Simulation Behavior

When simulating this offline device:

**SNMP Responses**:
- Connection timeout after 5-10 seconds
- Or return error code indicating device unreachable

**SSH Responses**:  
- Connection refused errors
- Or timeout messages: "ssh: connect to host 192.168.202.1 port 22: Connection timed out"

**Mock Data Source**: 
All metrics (CPU: 0%, Memory: 0%, Temperature: 0°C) represent the device's offline state from the mock data, not actual hardware readings.

### Recovery Scenarios

When the device comes back online, it should report:
- Normal boot sequence in system logs
- Interface initialization messages  
- Firewall policy compilation status
- Service startup confirmations
- Hardware diagnostics results

### Monitoring Implications

1. **Network Management Systems** should mark device as unreachable
2. **Alert Generation** for device offline condition
3. **Dependency Impact** on connected network segments
4. **Service Availability** impact for protected network zones

### Geographic Data Availability

The device location (Mumbai, India) and coordinates (19.0760, 72.8777) are from network management configuration, not device-reported data. Check Point devices do not typically expose geographic coordinates via SNMP or SSH.