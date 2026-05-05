# Server Devices Data Limitations

This document outlines data availability limitations for server-class devices in the mock data.

## Affected Devices

### Dell PowerEdge R750 (AMS-SRV-01)
- **IP**: 192.168.103.1
- **Serial**: PE-R750-001
- **Location**: Amsterdam, Netherlands
- **CPU**: 18%, **Memory**: 35%, **Temperature**: 32°C

### HPE ProLiant DL380 Gen10 (SEO-SRV-01) 
- **IP**: 192.168.203.1
- **Serial**: HP-DL380-001  
- **Location**: Seoul, South Korea
- **CPU**: 78%, **Memory**: 91%, **Temperature**: 51°C
- **Status**: WARNING (High resource usage)

### IBM Power System S922 (CPT-SRV-01)
- **IP**: 192.168.501.1
- **Serial**: IBM-S922-001
- **Location**: Cape Town, South Africa  
- **CPU**: 26%, **Memory**: 43%, **Temperature**: 38°C

## Data Availability via Standard Protocols

### Available via SNMP
Servers typically expose limited data via SNMP compared to network devices:

**Standard MIB-2 Data**:
- System description (1.3.6.1.2.1.1.1.0)
- System uptime (1.3.6.1.2.1.1.3.0)
- System contact/name/location (1.3.6.1.2.1.1.4.0-6.0)
- Network interface count (1.3.6.1.2.1.2.1.0)
- Interface statistics (1.3.6.1.2.1.2.2.1.x)

**Vendor-Specific Performance Data**:
- **Dell**: iDRAC SNMP OIDs for CPU, memory, temperature
- **HPE**: iLO SNMP OIDs for hardware monitoring  
- **IBM**: AIX/PowerVM SNMP extensions

### Available via SSH/Console

**Linux/Unix Servers (Dell, HPE)**:
- `top`, `htop` - Real-time CPU/memory usage
- `free -h` - Memory utilization details
- `df -h` - Disk space usage
- `sensors` - Temperature readings from hardware sensors
- `uptime` - System uptime and load average
- `dmidecode` - Hardware inventory details
- `ip addr show` - Network interface configuration

**IBM AIX Servers**:
- `topas`, `vmstat` - Performance monitoring
- `svmon` - Virtual memory statistics  
- `prtconf` - System configuration
- `lsattr -El sys0` - System attributes
- `errpt` - Error report analysis
- `lscfg` - Hardware configuration

## Data Not Available via Network Protocols

### Geographic Coordinates
- **Issue**: Servers don't expose latitude/longitude via SNMP/SSH
- **Source**: Geographic coordinates come from data center management systems
- **Mock Data**: Coordinates (latitude/longitude) are management system data, not device-reported

### Network Management Timestamps  
- **Issue**: "Last Seen" timestamps are monitoring system generated
- **Source**: Network monitoring tools track device connectivity
- **Mock Data**: lastSeen values represent monitoring system records

### Interface Count Discrepancies
- **Physical vs Logical**: Servers may report physical NICs vs all network interfaces
- **Virtual Interfaces**: VLANs, bonds, bridges create additional logical interfaces
- **Mock Data**: Interface counts represent total network interfaces available

## Vendor-Specific Limitations

### Dell PowerEdge (iDRAC)
- **Temperature**: Multiple sensors (CPU, ambient, memory, PCIe)
- **Power**: Detailed power consumption and PSU status
- **Storage**: RAID controller and drive health
- **Available**: Most hardware data via iDRAC SNMP/HTTPS APIs

### HPE ProLiant (iLO)  
- **Hardware Health**: Comprehensive monitoring via iLO
- **Performance**: Real-time metrics available
- **Remote Management**: Full out-of-band access
- **Available**: Extensive hardware monitoring capabilities

### IBM Power (PowerVM/HMC)
- **LPAR**: Logical partition resource allocation
- **Performance**: PowerVM performance monitoring
- **Hardware**: Service processor data
- **Limited**: Some data only via Hardware Management Console (HMC)

## High Resource Usage Scenarios

### HPE Server Warning Status (78% CPU, 91% Memory)
**Typical Causes**:
- Database workloads with high memory requirements
- Virtual machine hosting with over-commitment
- Application memory leaks
- Insufficient cooling causing thermal throttling

**Monitoring Commands**:
```bash
# Memory analysis
free -h
cat /proc/meminfo
ps aux --sort=-%mem | head -10

# CPU analysis  
top -p 1 -n 1
vmstat 5 5
sar -u 5 5

# Temperature monitoring
sensors
ipmitool sensor reading "Inlet Temp"
```

**Alerts Generated**:
- Memory utilization above 90% (critical)
- CPU sustained above 75% (warning)
- Temperature sensors above normal range
- Performance degradation detected

## Simulation Recommendations

### Realistic Response Times
- **Network Devices**: Sub-second SNMP responses
- **Servers**: 1-3 second SSH command execution
- **High Load**: Slower response times under resource pressure

### Error Conditions
- **Resource Exhaustion**: Commands may timeout or return errors
- **Hardware Failures**: Sensors may return invalid readings
- **Network Issues**: Intermittent connectivity problems

### Monitoring Integration
- **SNMP Traps**: Automatic alert generation for threshold breaches
- **Log Analysis**: System log entries for performance issues
- **Trend Analysis**: Historical performance data patterns