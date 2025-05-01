
## Introduction

This comprehensive guide walks you through creating a powerful, enterprise-grade home network security and monitoring solution using only free and open-source software. The entire setup runs on your Windows desktop computer using virtual machines, providing professional-level network management without additional hardware costs.

### What This Guide Will Build

**A Complete Home Network Security System** featuring:

- **pfSense Firewall**: Enterprise-class routing, firewall, and network services
- **ELK Stack**: Elasticsearch, Logstash, and Kibana for advanced log analysis and visualization
- **Network Monitoring**: Real-time traffic analysis and bandwidth monitoring
- **Security Systems**: Dual IDS (Suricata and Snort) with automatic threat blocking
- **VLAN Segmentation**: Separate virtual networks for different device categories
- **Guest Network**: Isolated WiFi with captive portal
- **Remote Access**: VPN for worldwide access to your network and RDP to your desktop
- **Mobile Dashboards**: Secure access to monitoring dashboards from your phone

### Key Features

1. **Network Visibility**:
    - Track every device on your network, even with dynamic IPs
    - Monitor bandwidth usage by device and application
    - Visualize network traffic patterns and trends
2. **Advanced Security**:
    - Intrusion Detection Systems (Suricata & Snort)
    - Automatic threat blocking with pfBlockerNG
    - Firewall rules with granular device control
    - VLAN isolation for enhanced security
3. **Remote Access**:
    - Free VPN solution for secure remote access
    - Access your desktop via RDP from anywhere
    - View network dashboards from mobile devices
    - Dynamic DNS support for non-static IP addresses
4. **Comprehensive Logging**:
    - All network traffic logged and analyzed
    - System logs from your Windows host
    - Security events and alerts
    - Custom dashboards for visualization
5. **Device Management**:
    - DHCP with hostname resolution
    - MAC address management and grouping
    - Traffic shaping by device type
    - Captive portal for guest access

### Why This Setup?

- **Free & Open Source**: No licensing costs for any component
- **VM-Based**: Runs entirely on your existing Windows desktop
- **Enterprise-Grade**: Professional features typically found in corporate networks
- **Scalable**: Can grow with your needs
- **Educational**: Learn network administration and security concepts
- **Privacy-Focused**: Keep your data within your control

### Who This Guide Is For

- Homelab enthusiasts
- Privacy-conscious individuals
- Those wanting to learn network security
- Anyone needing professional-grade network monitoring at home
- Users with dynamic IP addresses from their ISP

### Timeline and Complexity

- **Setup Time**: 1-2 days for basic functionality
- **Full Implementation**: 3-5 days including all features
- **Skill Level**: Intermediate (some networking knowledge helpful)
- **Maintenance**: 1-2 hours per week for updates and monitoring

This guide provides step-by-step instructions for creating a comprehensive network monitoring solution that rivals commercial offerings, all while using free software and minimal hardware investment.

## System Architecture Overview

```
Your Desktop Computer
├── Windows Host OS
├── VirtualBox
│   ├── pfSense VM (192.168.1.1)
│   │   ├── Firewall/Router
│   │   ├── DHCP Server (Multiple VLANs)
│   │   ├── Suricata IDS
│   │   ├── Snort IDS
│   │   ├── pfBlockerNG
│   │   ├── ntopng Bandwidth Monitor
│   │   └── Captive Portal
│   └── ELK Stack VM (192.168.1.20)
│       ├── Elasticsearch
│       ├── Logstash
│       └── Kibana (with additional dashboards)
└── Network Traffic Flow
```

## Prerequisites

### Hardware Requirements

- Windows desktop computer (Host OS)
- Minimum 16GB RAM (8GB for VMs, 8GB for host)
- At least 80GB free disk space (8GB pfSense + 60GB ELK + overhead)
- 2 network interfaces (1 built-in + 1 USB-to-Ethernet adapter)
- CPU with virtualization support (Intel VT-x or AMD-V)

### Software Downloads

1. [VirtualBox](https://www.virtualbox.org/wiki/Downloads) - For running VMs
2. [VirtualBox Extension Pack](https://www.virtualbox.org/wiki/Downloads) - For enhanced features
3. [pfSense ISO](https://www.pfsense.org/download/) - For the firewall VM
4. [Ubuntu Server ISO](https://ubuntu.com/download/server) - For the ELK VM
5. USB-to-Ethernet driver (if using USB adapter)

## Step 1: Prepare Host System

_Purpose: Enable virtualization and set up VirtualBox for running both VMs_

### 1.1 Enable Virtualization in BIOS

_Purpose: Allow VirtualBox to run efficiently and support multiple VMs_

1. Restart computer and enter BIOS (usually F2, F10, or Del)
2. Look for "Intel VT-x" or "AMD-V" or "Virtualization Technology"
3. Enable the feature
4. Save and exit BIOS

### 1.2 Install VirtualBox

_Purpose: Creates the virtualization environment for both VMs_

1. Download and install VirtualBox
2. Install VirtualBox Extension Pack
3. Restart computer after installation

### 1.3 Configure Host Network Interfaces

_Purpose: Establish physical network connections for pfSense_

1. **Built-in Ethernet**: Will connect to modem (WAN)
2. **USB-to-Ethernet**: Will connect to local network (LAN)

### 1.4 Set Up Host-Only Network

_Purpose: Create internal networking for VM communication_

```
VirtualBox → File → Host Network Manager
- Create new host-only network
- Configure IPv4 Address: 192.168.56.1
- Configure DHCP (disable it)
```

## Step 2: Create pfSense Virtual Machine

_Purpose: Set up the primary firewall, router, and DHCP server_

### 2.1 Create VM

_Purpose: Allocate resources for pfSense_

1. Open VirtualBox
2. Click "New"
3. Name: pfSense
4. Type: BSD
5. Version: FreeBSD (64-bit)
6. Memory: 4096 MB (4GB RAM - needed for multiple security packages)
7. Create virtual hard disk: 8 GB (VDI, dynamically allocated)

### 2.2 Configure VM Settings

_Purpose: Set up network interfaces and hardware acceleration_

```
1. System:
   - Processor: 2 cores (for routing performance)
   - Enable PAE/NX (for stability)
   - Enable Nested Paging (for performance)

2. Network:
   - Adapter 1 (WAN):
     - Enable Network Adapter
     - Attached to: NAT
     - Advanced → Promiscuous Mode: Allow All
   
   - Adapter 2 (LAN):
     - Enable Network Adapter
     - Attached to: Bridged Adapter
     - Name: Your USB-to-Ethernet or second physical adapter

3. Storage:
   - Controller: IDE
   - Attach pfSense ISO
```

## Step 3: Install pfSense

_Purpose: Install the operating system and configure basic settings_

### 3.1 Start VM and Install

_Purpose: Get pfSense running as your firewall_

1. Start the pfSense VM
2. Select Install
3. Choose defaults for most options
4. Set password for admin user
5. Reboot after installation
6. Remove ISO from virtual drive

### 3.2 Initial Configuration

_Purpose: Set up basic networking parameters_

1. VM boots to pfSense
2. Assign interfaces:
    - WAN: em0 (Adapter 1 - connects to modem)
    - LAN: em1 (Adapter 2 - connects to local network)
3. Set LAN IP: 192.168.1.1 (will be the default gateway)
4. Enable DHCP server (will manage IP addresses for all devices)

## Step 4: Configure Windows Host Networking

### 4.1 Windows Network Configuration

```
1. Network Connections:
   - Right-click USB Ethernet adapter
   - Properties → TCP/IPv4 → Properties
   - Set IP: 192.168.1.10
   - Subnet: 255.255.255.0
   - Gateway: 192.168.1.1
   - DNS: 192.168.1.1

2. Built-in Ethernet:
   - Remain connected to modem
   - DHCP from ISP
```

### 4.2 Configure Windows Default Route

```bash
# Open Command Prompt as Administrator
route delete 0.0.0.0
route add 0.0.0.0 mask 0.0.0.0 192.168.1.1
```

## Step 5: Configure pfSense Web Interface

### 5.1 Access pfSense

1. From host OS, open browser
2. Navigate to https://192.168.1.1
3. Login: admin / pfsense
4. Complete setup wizard

### 5.2 Basic Configuration

```
1. General Information:
   - Hostname: pfSense
   - Domain: localdomain
   - DNS Servers: 8.8.8.8, 8.8.4.4

2. Time Server:
   - Use default NTP servers

3. Configure WAN Interface:
   - Type: DHCP
   - Block RFC1918 Networks: Unchecked
   - Block bogon networks: Checked

4. Set admin password:
   - Choose strong password

5. Reload pfSense configuration
```

## Step 6: Advanced DHCP Configuration for Device Tracking

### 6.1 Configure DHCP Server

```
Services → DHCP Server → LAN
- Range: 192.168.1.100-192.168.1.250
- DNS Servers: 192.168.1.1
- Domain name: home.local
- Gateway: 192.168.1.1
- Enable DDNS: Check (for hostname resolution)
- DHCP Registration: Register leases in DNS resolver
```

### 6.2 Set Up Static Mappings for Important Devices

```
Services → DHCP Server → LAN → DHCP Static Mappings for this Interface
- Click "+Add" for each device:
  - MAC Address: (device MAC)
  - IP Address: (static IP you want)
  - Hostname: Descriptive name (e.g., "Johns-iPhone", "Living-Room-TV")
  - Description: Device details
```

### 6.3 Configure DNS Resolver

```
Services → DNS Resolver → General Settings
- Enable DNS Resolver: Check
- Network Interfaces: LAN
- Enable DNSSEC Support: Check
- Register DHCP leases in DNS Resolver: Check
- Register DHCP static mappings in DNS Resolver: Check
```

## Step 7: Install and Configure Suricata

### 7.1 Install Package

```
1. System → Package Manager → Available Packages
2. Search for "suricata"
3. Click "Install"
```

### 7.2 Configure Suricata with Enhanced Monitoring

```
1. Services → Suricata → Global Settings:
   - Enable: Check
   - Remove Blocked Hosts Interval: 3600
   - Live Rule Swap: Check
   - Log to System Log: Check

2. Services → Suricata → Interfaces:
   - Add interface
   - Interface: LAN
   - Enable: Check
   - IPS Mode: Check
   - Block Offenders: Check
   - Interface Description: "Primary Network Monitoring"
   
   - Protocol Logging:
     - HTTP Log: Check
     - TLS Log: Check
     - DNS Log: Check
     
   - EVE Output Settings:
     - EVE JSON Log: Check
     - EVE Output Type: FILE
     - EVE Log Alerts: Check
     - EVE Log HTTP: Check
     - EVE Log DNS: Check
     - EVE Log TLS: Check
     - EVE Log Files: Check
     - EVE Log Tracked Files: Check
     - EVE Log STATS: Check

3. Services → Suricata → Updates:
   - Enable rule updates
   - Update Interval: 12 hours
   - Click "Update" to download rules

4. Services → Suricata → Categories:
   - Enable rule categories:
     - emerging-attack_response
     - emerging-malware
     - emerging-scan
     - emerging-trojan
     - emerging-mobile_malware
     - emerging-phishing
```

## Step 8: Install Additional Security Packages

### 8.1 Install Snort IDS (Alternative to Suricata)

```
1. System → Package Manager → Available Packages
2. Search for "snort"
3. Click "Install"
4. Configure similar to Suricata
```

### 8.2 Install pfBlockerNG

```
1. System → Package Manager → Available Packages
2. Search for "pfBlockerNG"
3. Click "Install"

Configuration:
1. Firewall → pfBlockerNG → General
   - Enable pfBlockerNG: Check
   - Keep Settings: 7 days
   - CRON Settings: Daily
   
2. Firewall → pfBlockerNG → IP → IPv4
   - Add List: 
     - Name: "Spamhaus Drop"
     - Description: "Malicious IPs"
     - Format: Auto
     - State: Deny Both
     - List Action: Deny Both
     - URL: https://www.spamhaus.org/drop/drop.txt
     
3. Firewall → pfBlockerNG → DNSBL → DNSBL Groups
   - Add Group:
     - Name: "Advertisement Blocking"
     - List Action: Unbound
     - Sources: Steven Black, Easyprivacy
     
4. Force Update after configuration
```

### 8.3 Install ntopng for Bandwidth Monitoring

```
1. System → Package Manager → Available Packages
2. Search for "ntopng"
3. Click "Install"

Configuration:
Diagnostics → ntopng Settings
- Enable ntopng: Check
- Interface Selection: All relevant interfaces
- Admin Password: Set strong password
- DNS Mode: Local resolution
- Local Networks: 192.168.0.0/16
```

## Step 9: Configure VLANs for Network Segmentation

### 9.1 Create VLANs

```
Interfaces → VLANs → Add for each:
1. Default LAN (No VLAN): Primary devices - Laptops, Desktops, Phones
2. VLAN 10: Servers and Network Infrastructure
3. VLAN 20: Workstations and Business Devices  
4. VLAN 30: IoT Devices
5. VLAN 40: Smart Home and Media
6. VLAN 50: Kids/Teen Devices
7. VLAN 100: Guest Network
8. VLAN 200: Camera/Security Devices
9. VLAN 250: VoIP Devices
```

### 9.2 Assign and Configure VLAN Interfaces

```
For each VLAN:
1. Interfaces → Assignments → Add
2. Interfaces → [New Interface]
   - Enable: Check
   - IPv4 Configuration Type: Static IPv4
   - Address: 192.168.[VLAN].1/24
3. Save and Apply
```

### 9.3 Configure DHCP per VLAN

```
Services → DHCP Server → [VLAN Interface]
- Enable DHCP server: Check
- Range: .100 to .200
- DNS: Interface IP address
- Domain names based on VLAN:
  - servers.local (VLAN 10)
  - work.local (VLAN 20)
  - iot.local (VLAN 30)
  - smart.local (VLAN 40)
  - kids.local (VLAN 50)
  - guest.local (VLAN 100)
  - cameras.local (VLAN 200)
  - voip.local (VLAN 250)
```

### 9.4 Configure Firewall Rules per VLAN

```
Create rules for each VLAN:
1. Allow DNS/DHCP to interface
2. Allow internet access (specific ports only)
3. Deny inter-VLAN communication (unless needed)
4. Log all denied traffic
```

## Step 10: Set Up ELK Stack for Advanced Monitoring

### 10.1 Create ELK VM

```
1. Create new VM in VirtualBox:
   - Name: ELK
   - Type: Linux
   - Version: Ubuntu 64-bit
   - Memory: 8096 MB (8GB RAM for better performance)
   - Disk: 60 GB
   - Network: Bridged to LAN interface

2. Install Ubuntu Server
3. Set static IP: 192.168.1.20
```

### 10.2 Install ELK Components

```bash
# Add Elastic repository
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add -
echo "deb https://artifacts.elastic.co/packages/7.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-7.x.list

# Update and install
sudo apt update
sudo apt install elasticsearch logstash kibana

# Configure Elasticsearch
sudo nano /etc/elasticsearch/elasticsearch.yml
# Set: network.host: 0.0.0.0

# Configure Kibana
sudo nano /etc/kibana/kibana.yml
# Set: server.host: "0.0.0.0"

# Start services
sudo systemctl enable elasticsearch logstash kibana
sudo systemctl start elasticsearch logstash kibana
```

### 10.3 Configure Logstash with Enhanced Parsing

```bash
sudo nano /etc/logstash/conf.d/pfsense-with-device-tracking.conf
```

Add:

```
input {
  tcp {
    port => 5140
    type => syslog
  }
  udp {
    port => 5140
    type => syslog
  }
}

filter {
  if [type] == "syslog" {
    grok {
      match => { "message" => "%{SYSLOGTIMESTAMP:timestamp} %{SYSLOGHOST:hostname} %{DATA:program}(?:\[%{POSINT:pid}\])?: %{GREEDYDATA:message}" }
      overwrite => [ "message" ]
    }
    date {
      match => [ "timestamp", "MMM  d HH:mm:ss", "MMM dd HH:mm:ss" ]
    }
    
    # Extract DHCP device information
    if [program] == "dhcpd" {
      grok {
        match => { "message" => "DHCPACK on %{IP:client_ip} to %{MAC:client_mac} (?:\(%{HOSTNAME:client_hostname}\))?" }
        add_tag => [ "dhcp_lease" ]
      }
    }
    
    # Extract firewall rule hits
    if [program] == "filterlog" {
      grok {
        match => { "message" => "%{INT:rule_number},%{NOTSPACE:sub_rule},%{NOTSPACE:anchor},%{INT:tracker},%{NOTSPACE:interface},%{NOTSPACE:reason},%{NOTSPACE:action},%{NOTSPACE:direction},%{IP:ip_version},%{NOTSPACE:tos},%{NOTSPACE:ecn},%{NOTSPACE:ttl},%{NOTSPACE:id},%{NOTSPACE:offset},%{NOTSPACE:flags},%{INT:protocol_id},%{NOTSPACE:protocol},%{INT:length},%{IP:src_ip},%{IP:dest_ip}" }
        add_tag => [ "pfsense_filterlog" ]
      }
    }
    
    # Extract Suricata alerts with more device context
    if [program] == "suricata" {
      grok {
        match => { "message" => "\[%{NUMBER:gid}:%{NUMBER:sid}:%{NUMBER:rev}\] %{GREEDYDATA:signature} \[Classification: %{GREEDYDATA:classification}\] \[Priority: %{NUMBER:priority}\] (?:\{%{NOTSPACE:protocol}\} )?%{IP:src_ip}:%{NUMBER:src_port} -> %{IP:dest_ip}:%{NUMBER:dest_port}" }
        add_tag => [ "suricata_alert" ]
      }
    }
    
    # Add GeoIP data
    if [src_ip] {
      geoip {
        source => "src_ip"
        target => "src_geo"
      }
    }
    if [dest_ip] {
      geoip {
        source => "dest_ip"
        target => "dest_geo"
      }
    }
    
    # Resolve MAC address vendors
    if [client_mac] {
      mutate {
        add_field => { "vendor_prefix" => "%{client_mac}" }
        convert => { "vendor_prefix" => "string" }
      }
      mutate {
        gsub => [ "vendor_prefix", ":.*", "" ]
      }
    }
  }
}

output {
  elasticsearch {
    hosts => ["localhost:9200"]
    index => "pfsense-%{+YYYY.MM.dd}"
  }
}
```

### 10.4 Configure Log Retention

```
Create /etc/elasticsearch/templates/retention-policy.json:
{
  "template": "*",
  "settings": {
    "index.lifecycle.name": "retention-policy",
    "index.lifecycle.rollover_alias": "logs"
  }
}

Configure ILM policies:
1. Hot phase: 0-7 days (no compression)
2. Warm phase: 7-30 days (partial compression)
3. Cold phase: 30+ days (full compression)
4. Delete phase: Based on log type
```

### 10.5 Install Additional Logstash Plugins

```bash
sudo /usr/share/logstash/bin/logstash-plugin install logstash-filter-translate
```

## Step 11: Configure pfSense Logging

### 11.1 Enable Remote Logging

```
1. Status → System Logs → Settings
2. Enable Remote Logging: Check
3. Remote Log Servers: 192.168.1.20:5140
4. Remote Syslog Contents: Everything
5. Log Message Format: RFC 5424 (slightly better structured logs)
6. Log firewall default blocks: Check
7. Save
```

### 11.2 Configure DHCP Logging

```
Status → System Logs → DHCP
- Number of DHCP log entries to show: 500
- Log packets handled by dhcpd: Check
```

### 11.3 Configure DNS Logging

```
Services → DNS Resolver → Advanced Settings
- Log Level: Default (Log DNS queries)
```

## Step 12: Connect ASUS Router as Access Point

### 12.1 Configure ASUS Router

```
1. Connect to ASUS router (before connection to pfSense)
2. Administration → Operation Mode
3. Select Access Point (AP) mode
4. Set static IP: 192.168.1.2
5. Enable VLAN support
6. Connect ASUS WAN port to pfSense LAN port
```

### 12.2 Maintain Wireless Settings

```
1. Keep same SSID and password
2. Enable band steering
3. Set to AP mode
4. Disable DHCP server
5. Configure VLANs for wireless networks
```

## Step 13: Create Device Tracking Dashboards in Kibana

_Purpose: Visualize and monitor all network activity and devices_

### 13.1 Access Kibana

_Purpose: Access the web interface for data visualization_

1. Access Kibana: http://192.168.1.20:5601
2. Management → Index Patterns
3. Create pattern: pfsense-* (captures all pfSense logs)
4. Time field: @timestamp

### 13.2 Create Device Tracking Visualizations

_Purpose: Build comprehensive views of network activity_

```
1. DHCP Lease Dashboard:
   - Purpose: Track all connected devices
   - Table showing active devices (IP, MAC, Hostname)
   - Device join/leave timeline
   - Device type distribution (based on MAC vendor)

2. Per-Device Activity Dashboard:
   - Purpose: Monitor individual device behavior
   - Traffic volume by device
   - Top websites visited by device
   - Security alerts by device
   - Connection timeline

3. Network Overview Dashboard:
   - Purpose: Get high-level network status
   - Active devices count
   - Traffic patterns by device type
   - Geographic map of external connections
   - Top talkers (highest bandwidth users)

4. Security Dashboard:
   - Purpose: Monitor network security
   - Suricata alerts by device
   - Blocked connections by device
   - Suspicious DNS queries
   - Unusual traffic patterns
```

### 13.3 Additional Dashboards

```
1. Network Performance Dashboard:
   - Network throughput by interface
   - Connection states over time
   - Latency trends by service
   - Packet loss metrics

2. VLAN Activity Dashboard:
   - Traffic by VLAN
   - Top talkers per VLAN
   - Inter-VLAN communication map
   - VLAN-specific alerts

3. Device Type Analysis Dashboard:
   - Activity by device type
   - Protocol usage per device type
   - DNS query analysis by device
   - Application usage patterns
```

### 13.4 Configure Alerts

_Purpose: Get notified of important events_

```
Stack Management → Alerts and Actions
1. New Device Alert:
   - Purpose: Detect unauthorized devices
   - Trigger: New MAC address in DHCP logs
   - Action: Email notification
   
2. High Traffic Alert:
   - Purpose: Prevent bandwidth abuse
   - Trigger: Device exceeds bandwidth threshold
   - Action: Email notification
   
3. Security Event Alert:
   - Purpose: Respond to threats quickly
   - Trigger: Suricata high-priority alert
   - Action: Email + Slack notification
   
4. VLAN Breach Alert:
   - Purpose: Detect unauthorized VLAN access
   - Trigger: Unexpected inter-VLAN traffic
   - Action: Email notification
```

## Step 14: Advanced Device Tracking Features

_Purpose: Implement granular device management and monitoring_

### 14.1 MAC Address Management

_Purpose: Group and control devices by type_

```
1. Firewall → Aliases → MAC
   - Create groups for different device types:
     - "Corporate Devices"
     - "Guest Devices"
     - "IoT Devices"
     - "Mobile Devices"

2. Firewall → Rules
   - Create rules based on MAC groups
   - Apply different policies to device types
```

### 14.2 Enhanced Device Identification

_Purpose: Better identify and categorize devices_

```
1. Services → Captive Portal
   - Set up for guest network
   - Collect device information on first connect
   
2. Services → FreeRADIUS
   - Enable 802.1X authentication (optional)
   - Track authenticated devices
```

### 14.3 Traffic Shaping by Device

_Purpose: Manage bandwidth allocation_

```
Firewall → Traffic Shaper
1. Create queues for device types:
   - Priority queue: Critical devices
   - Standard queue: Regular traffic
   - Limited queue: Guest devices

2. Apply queues based on MAC addresses or IP ranges
```

## Step 15: Set Up Guest Network with Captive Portal

_Purpose: Provide secure guest access with isolation_

### 15.1 Create Guest VLAN

_Purpose: Isolate guest traffic from main network_

```
Interfaces → VLANs
- Click "+Add"
- VLAN Tag: 100
- Description: Guest Network
- Parent Interface: Select your LAN interface
- Save
```

### 15.2 Configure Guest Network Interface

_Purpose: Set up guest network parameters_

```
Interfaces → Assignments
- Add VLAN100 as new interface
- Click "+Add" to assign
- Name it "OPT1" and save

Interfaces → OPT1
- Enable: Check
- Description: Guest Network
- IPv4 Configuration Type: Static IPv4
- IPv4 Address: 192.168.100.1/24 (separate subnet)
- Save
```

### 15.3 Configure Guest DHCP

_Purpose: Manage guest IP addresses separately_

```
Services → DHCP Server → OPT1 (Guest)
- Enable DHCP server: Check
- Range: 192.168.100.100 to 192.168.100.200
- DNS Servers: 8.8.8.8, 8.8.4.4 (public DNS)
- Gateway: Leave blank (will use interface IP)
- Domain name: guest.local
- Save
```

### 15.4 Configure ASUS Router for Guest WiFi

_Purpose: Create separate WiFi for guests_

```
1. Access ASUS router configuration
2. Create Guest Network:
   - SSID: YourName-Guest
   - Password: GuestPass123 (or your choice)
   - Configure to use VLAN 100
   - Enable Guest Network isolation
   - Save settings
```

### 15.5 Configure Captive Portal

_Purpose: Control guest access and display terms_

```
Services → Captive Portal
- Enable: Check
- Interface: OPT1 (Guest Network)
- Maximum concurrent connections: 0 (unlimited)
- Idle timeout: 60 minutes
- Hard timeout: 480 minutes (8 hours)
- Authentication method: No Authentication
- MAC filtering: Unchecked
- Pass-through MAC Auto Entry: Unchecked
- Logout popup window: Check
- Enable MAC filtering: Unchecked
- Form authentication: No Authentication
- Redirection URL: Leave blank
- Concurrent user logins: Unchecked
- Save
```

### 15.6 Create Custom Captive Portal Page

_Purpose: Present terms and welcome message to guests_

```
Services → Captive Portal → Guest → Portal Page Contents → HTML Tab
- Replace content with:
```

```html
<!DOCTYPE html>
<html>
<head>
    <title>Guest WiFi Access</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; text-align: center; }
        .container { max-width: 600px; margin: 0 auto; }
        h1 { color: #333; }
        .welcome { font-size: 18px; margin: 20px 0; }
        .button { 
            background: #007bff; 
            color: white; 
            padding: 10px 20px; 
            border: none; 
            border-radius: 4px; 
            cursor: pointer; 
            font-size: 16px;
        }
        .terms { font-size: 12px; margin-top: 20px; color: #666; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Welcome to Guest WiFi</h1>
        <p class="welcome">To access the internet, please accept our terms of use.</p>
        <form method="post" action="$PORTAL_ACTION$">
            <input name="accept" type="submit" value="Connect to Internet" class="button">
            <input name="redirurl" type="hidden" value="$PORTAL_REDIRURL$">
        </form>
        <p class="terms">
            By clicking "Connect to Internet" you agree to:
            <br>- Use this network responsibly
            <br>- Not access illegal content
            <br>- Not attempt to access local network resources
        </p>
    </div>
</body>
</html>
```

### 15.7 Configure Guest Firewall Rules

_Purpose: Secure guest network while allowing internet access_

```
Firewall → Rules → OPT1 (Guest)
1. Allow Guest DNS Requests:
   - Purpose: Let guests resolve domain names
   - Action: Pass
   - Interface: Guest
   - Address Family: IPv4
   - Protocol: TCP/UDP
   - Source: Guest net
   - Destination: any
   - Destination Port Range: DNS (53)
   - Description: Allow guest DNS

2. Allow Guest Web Access for Captive Portal:
   - Purpose: Enable captive portal login
   - Action: Pass
   - Interface: Guest
   - Address Family: IPv4
   - Protocol: TCP
   - Source: Guest net
   - Destination: Guest address
   - Destination Port Range: 8000-8001
   - Description: Allow captive portal login

3. Allow Guest Internet Access (after authentication):
   - Purpose: Provide internet access to authenticated guests
   - Action: Pass
   - Interface: Guest
   - Address Family: IPv4
   - Protocol: any
   - Source: Guest net
   - Destination: !LAN net (inverted to exclude main network)
   - Description: Allow internet, block LAN access

4. Block Guest to LAN Access:
   - Purpose: Prevent guests from accessing main network
   - Action: Block
   - Interface: Guest
   - Address Family: IPv4
   - Protocol: any
   - Source: Guest net
   - Destination: LAN net
   - Description: Block guest access to main network
```

### 15.8 Configure NAT for Guest Network

_Purpose: Enable guest internet access_

```
Firewall → NAT → Outbound
1. Set mode to "Hybrid outbound NAT"
2. Add NAT rule for guest network:
   - Interface: WAN
   - Source: Guest net
   - Translation: Interface address
   - Description: NAT for guest network
   - Save
```

### 15.9 Configure Guest Network Monitoring

_Purpose: Track guest activity and security_

```
Services → Suricata → Interfaces
- Add guest interface (OPT1) to monitoring
- Enable: Check
- Interface Description: Guest Network
- Enable IPS Mode: Check
- Block Offenders: Check (to protect your network)
- Save
```

### 15.10 Set Up Guest Dashboards in Kibana

_Purpose: Monitor guest network specifically_

```
Create visualizations for guest network:
1. Guest Active Connections:
   - Visualization type: Metric
   - Field: client_ip
   - Filter: interface:OPT1 AND program:suricata

2. Guest Traffic Volume:
   - Visualization type: Area chart
   - X-axis: @timestamp
   - Y-axis: bytes count
   - Filter: interface:OPT1

3. Top Guest Destinations:
   - Visualization type: Pie chart
   - Field: dest_ip
   - Filter: interface:OPT1
   - Size: 10

4. Guest Security Alerts:
   - Visualization type: Table
   - Columns: @timestamp, src_ip, dest_ip, signature
   - Filter: interface:OPT1
```

## Step 16: Configure Remote Access VPN

### 16.1 Install OpenVPN Package

_Purpose: Enable secure remote access_

```
1. System → Package Manager → Available Packages
2. Search for "openvpn-client-export"
3. Click "Install"
4. Wait for installation to complete
```

### 16.2 Create Certificate Authority (CA)

```
1. System → Cert Manager → CAs
2. Click "+Add"
3. Fill in:
   - Descriptive name: "HomeLab-CA"
   - Method: Create an internal Certificate Authority
   - Key length: 2048-bit
   - Digest Algorithm: SHA256
   - Lifetime: 3650 days
   - Common Name: HomeLab CA
   - Country Code: US (or your country)
   - State: YourState
   - City: YourCity
   - Organization: HomeLab
4. Save
```

### 16.3 Create Server Certificate

```
1. System → Cert Manager → Certificates
2. Click "+Add/Sign"
3. Fill in:
   - Method: Create an internal Certificate
   - Descriptive name: "VPN-Server"
   - Certificate authority: HomeLab-CA
   - Key length: 2048-bit
   - Certificate Type: Server Certificate
   - Common Name: vpn.yourdomain.com
   - Country Code: US
   - State: YourState
   - City: YourCity
   - Organization: HomeLab
4. Save
```

### 16.4 Create User Certificates

```
1. System → Cert Manager → Certificates
2. Click "+Add/Sign"
3. Fill in:
   - Method: Create an internal Certificate
   - Descriptive name: "RDP-User"
   - Certificate authority: HomeLab-CA
   - Key length: 2048-bit
   - Certificate Type: User Certificate
   - Common Name: YourName
4. Save
```

### 16.5 Set Up OpenVPN Server

```
1. VPN → OpenVPN → Servers
2. Click "+Add"
3. Configure:
   - Server mode: Remote Access (SSL/TLS)
   - Protocol: UDP
   - Device mode: tun
   - Interface: WAN
   - Local port: 1194
   - TLS Authentication: Enabled
   - Peer Certificate Authority: HomeLab-CA
   - Server certificate: VPN-Server
   - DH Parameter Length: 2048-bit
   - Encryption Algorithm: AES-256-CBC
   - Auth digest algorithm: SHA256
   - Hardware Crypto: No hardware crypto acceleration
   - Certificate Depth: One (Client+Server)
   - IPv4 Tunnel Network: 10.0.8.0/24
   - IPv4 Local network(s): 192.168.1.0/24
   - IPv4 Remote network(s): (leave blank)
   - Concurrent connections: 10
   - Compression: Disabled
   - Push Comp: None
   - Type-of-Service: Disabled
   - Inter-client communication: Checked
   - Duplicate Connections: Unchecked
   - DNS Default Domain: Unchecked
   - DNS Servers: 192.168.1.1
   - Block Outside DNS: Unchecked
   - Force DNS cache update: Unchecked
   - NTP Servers: (leave blank)
   - NetBIOS Options: Disable NetBIOS
   - Custom options: 
     ```
     push "route 192.168.1.0 255.255.255.0"
     push "dhcp-option DNS 192.168.1.1"
     push "redirect-gateway def1"
     ```
4. Save
```

### 16.6 Configure VPN Client Export

```
1. VPN → OpenVPN → Client Export
2. Remote Access Server: Your VPN server
3. Host Name Resolution: Interface IP Address
4. Verify Server CN: Automatic
5. Use Microsoft Certificate Storage: Unchecked
6. Advanced → Additional configuration options:
```

persist-key persist-tun

```
7. Save
```

### 16.7 Create Firewall Rules for VPN

```
1. Firewall → Rules → WAN
2. Add rule for OpenVPN:
   - Action: Pass
   - Interface: WAN
   - Address Family: IPv4
   - Protocol: UDP
   - Source: any
   - Destination: WAN address
   - Destination Port Range: 1194
   - Description: Allow OpenVPN access
   
3. Firewall → Rules → OpenVPN (tab will appear after creating server)
4. Add rule for VPN clients:
   - Action: Pass
   - Interface: OpenVPN
   - Address Family: IPv4
   - Protocol: any
   - Source: OpenVPN clients
   - Destination: LAN net
   - Description: Allow VPN to LAN access
```

### 16.8 Export VPN Client Configuration

```
1. VPN → OpenVPN → Client Export
2. Download configuration for your user:
   - Client: YourName
   - Configuration Type: Most Clients (Inline)
   - Click "Download"
3. Save the .ovpn file for import into OpenVPN client
```

## Step 17: Set Up Remote Desktop Access

### 17.1 Configure Windows Desktop for RDP

```
1. On your desktop host:
   - System Properties → Remote
   - Enable "Allow remote connections to this computer"
   - Add specific users:
     - Click "Select Users"
     - Add your VPN username
   - Configure network level authentication

2. Add firewall rule for RDP on pfSense:
   - Firewall → Rules → OpenVPN
   - Add rule:
     - Action: Pass
     - Interface: OpenVPN
     - Protocol: TCP
     - Source: OpenVPN net
     - Destination: 192.168.1.10 (your desktop IP)
     - Destination Port: 3389
     - Description: Allow RDP to desktop
```

### 17.2 Install OpenVPN Client on Remote Devices

```
For Windows:
1. Download OpenVPN GUI client
2. Install OpenVPN
3. Copy .ovpn file to C:\Program Files\OpenVPN\config\
4. Right-click OpenVPN icon → Connect

For Android:
1. Install OpenVPN Connect from Play Store
2. Import .ovpn file
3. Connect to VPN

For iOS:
1. Install OpenVPN Connect from App Store
2. Import .ovpn file
3. Connect to VPN
```

## Step 18: Configure Mobile Dashboard Access

### 18.1 Secure Kibana Access (Multiple Options)

#### Option 1: VPN-Only Access (Most Secure)

```
1. Connect to VPN first
2. Access Kibana at https://192.168.1.20:5601 (internal)
3. This requires VPN connection for access
```

#### Option 2: Direct Access with Dynamic DNS

```
1. Set up Dynamic DNS (Free Option):
   - Use No-IP or DuckDNS for free dynamic DNS
   - Create account at www.noip.com
   - Get dynamic hostname (e.g., yourhome.ddns.net)
   
2. Configure dynamic DNS client:
   - Services → Dynamic DNS
   - Service Type: No-IP
   - Interface: WAN
   - Username: your-no-ip-username
   - Password: your-no-ip-password
   - Hostname: yourhome.ddns.net
   - Check "Enable"
```

### 18.2 Set Up Reverse Proxy with Nginx

```
1. Install Nginx on ELK VM:
   sudo apt update
   sudo apt install nginx
```

2. Create Nginx configuration:
    
    ```bash
    sudo nano /etc/nginx/sites-available/kibana
    ```
    
    Add:
    
    ```nginx
    server {
        listen 80;
        server_name kibana.yourdomain.com;
        
        location / {
            proxy_pass http://localhost:5601;
            proxy_http_version 1.1;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection 'upgrade';
            proxy_set_header Host $host;
            proxy_cache_bypass $http_upgrade;
        }
    }
    ```
    
3. Enable the site:
    
    ```bash
    sudo ln -s /etc/nginx/sites-available/kibana /etc/nginx/sites-enabled/
    sudo nginx -t
    sudo systemctl restart nginx
    ```
    
### 18.3 Enable HTTPS with Let's Encrypt


1. Install Certbot for SSL:
    
    ```bash
    sudo apt install certbot python3-certbot-nginx
    ```
    
2. Obtain certificate:
    
    ```bash
    sudo certbot --nginx -d yourhome.ddns.net
    ```
    
3. Certbot will automatically configure Nginx for HTTPS
    

## Step 19: Windows Host Logging

### 19.1 Configure Windows Host System Logging
*Purpose: Comprehensive logging from your desktop that hosts all VMs*

#### A. Install NXLog for Windows Syslog Forwarding


1. Download NXLog Community Edition:
    - Go to nxlog.co/products/nxlog-community-edition
    - Download Windows installer
    
2. Install NXLog:
    - Run installer as administrator
    - Choose default installation location
    
3. Configure NXLog for ELK forwarding:
    - Edit C:\Program Files (x86)\nxlog\conf\nxlog.conf



#### B. NXLog Configuration for Desktop Host


```
define ROOT C:\Program Files (x86)\nxlog

Moduledir %ROOT%\modules CacheDir %ROOT%\data Pidfile %ROOT%\data\nxlog.pid SpoolDir %ROOT%\data LogFile %ROOT%\data\nxlog.log

<Extension json> Module xm_json </Extension> <Extension syslog> Module xm_syslog </Extension> <Input eventlog> Module im_msvistalog Query <QueryList> <Query Id="0"> <Select Path="Application">*</Select> <Select Path="System">*</Select> <Select Path="Security">*</Select> <Select Path="Windows PowerShell">*</Select> <Select Path="Microsoft-Windows-Windows Defender/Operational">*</Select> <Select Path="Microsoft-Windows-Windows Firewall With Advanced Security/Firewall">*</Select> <Select Path="Microsoft-Windows-NetworkProfile/Operational">*</Select> <Select Path="Microsoft-Windows-VirtualPC/Admin">*</Select> <Select Path="VirtualBox">*</Select> </Query> </QueryList> </Input> <Output to_elk> Module om_tcp Host 192.168.1.20 Port 5145 OutputType Syslog_TLS Exec $Message = to_json(); </Output>

<Route 1> Path eventlog => to_elk </Route>

````

### 19.2 Configure Logstash for Windows Host Logs
```bash
# Create Windows-specific Logstash pipeline
sudo nano /etc/logstash/conf.d/windows-host.conf
````

Add:

```
input {
  tcp {
    port => 5145
    codec => json
    tags => ["windows", "host"]
  }
}

filter {
  if "windows" in [tags] {
    # Parse Windows Event Log
    if [EventID] {
      mutate {
        add_field => { "event_id" => "%{EventID}" }
      }
      
      # Categorize critical events
      if [EventID] == "4624" {
        mutate { add_tag => "login_success" }
      }
      if [EventID] == "4625" {
        mutate { add_tag => "login_failure" }
      }
      if [EventID] == "104" {
        mutate { add_tag => "log_cleared" }
      }
    }
    
    # Parse VirtualBox events
    if [SourceName] == "VirtualBox" {
      grok {
        match => { "message" => "VM %{WORD:vm_name} %{WORD:vm_state}" }
      }
      mutate { add_tag => "virtualbox_event" }
    }
    
    # Parse network events
    if [EventLog] == "Microsoft-Windows-NetworkProfile/Operational" {
      mutate { add_tag => "network_event" }
    }
  }
}

output {
  if "windows" in [tags] {
    elasticsearch {
      hosts => ["localhost:9200"]
      index => "windows-host-%{+YYYY.MM.dd}"
    }
  }
}
```

### 19.3 Create Host System Dashboard in Kibana

```
Create dashboard for host monitoring:
1. VM Resource Usage:
   - CPU utilization by VM
   - Memory allocation per VM
   - Disk I/O statistics
   - Network throughput

2. Host System Events:
   - Login attempts
   - Service status changes
   - Security events
   - VirtualBox events

3. Network Activity:
   - Network adapter status
   - Firewall events
   - Network connection states
   - DHCP requests from host

4. Performance Metrics:
   - Overall system performance
   - Resource warnings
   - Disk space utilization
   - Critical errors
```

## Step 20: Regular Maintenance and Security

### 20.1 Regular Tasks

```
1. Update pfSense: System → Update (weekly)
2. Update Suricata rules: Services → Suricata → Updates (daily)
3. Review device inventory: Kibana dashboards (daily)
4. Clean up stale DHCP leases: Services → DHCP Server (weekly)
5. Monitor ELK storage: Kibana → Index Management (weekly)
```

### 20.2 Backup Strategy

```
1. pfSense configuration:
   - Diagnostics → Backup & Restore (weekly)
   - Automate with cron if possible

2. VM snapshots:
   - Create before major changes
   - Keep 2-3 snapshots maximum

3. ELK data:
   - Set up index lifecycle management
   - Configure retention policies
   - Export important dashboards
```

### 20.3 Security Best Practices

```
1. Regular rule reviews:
   - Disable unused Suricata rules
   - Update firewall rules based on usage
   
2. Access control:
   - Limit pfSense admin access to specific IPs
   - Use complex passwords
   - Enable 2FA if available

3. Network segmentation:
   - Consider VLANs for different device types
   - Implement guest network isolation
```

## Troubleshooting Guide

### Common Issues and Solutions

#### Device Not Getting IP

```
- Check DHCP server status: Status → Services
- Verify interface is enabled
- Check firewall rules allow DHCP
```

#### Device Not Resolving Hostnames

```
- Verify DNS Resolver is enabled
- Check DHCP options include DNS server
- Ensure device accepts DNS settings
```

#### Logs Not Appearing in ELK

```
- Check Logstash status: systemctl status logstash
- Verify firewall allows port 5140
- Test with: nc -zv 192.168.1.20 5140
```

#### Suricata Not Capturing Traffic

```
- Verify interface is in IPS mode
- Check interface is enabled
- Review Suricata logs for errors
```

### VM-Related Issues

```
1. Check VirtualBox logs
2. Verify host virtualization enabled
3. Monitor host resource usage
4. Check network adapter assignments
```

### Performance Problems

```
1. Monitor VM CPU/Memory
2. Check disk I/O performance
3. Review ELK retention settings
4. Optimize firewall rules
```

## Conclusion

You now have a comprehensive home network security monitoring system with:

- Complete visibility of all network devices
- Dynamic device tracking despite DHCP
- Advanced logging and analysis capabilities
- Per-device traffic monitoring and security alerts
- Beautiful dashboards for network insights
- VLAN segmentation for enhanced security
- Guest network with captive portal
- Bandwidth monitoring with ntopng
- Dual IDS systems for comprehensive protection
- Automatic threat blocking with pfBlockerNG
- Remote access via VPN to your entire network
- Mobile dashboard access for monitoring from anywhere

