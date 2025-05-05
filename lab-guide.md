# Complete pfSense-ELK Homelab Setup Guide (With Specific Adapters)

> **Network Adapter Information**
> - **WAN Connection**: Using the built-in Killer Gigabit adapter on motherboard
> - **LAN Connection**: Using the TP-Link adapter

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

### Who This Guide Is For

- Homelab enthusiasts
- Privacy-conscious individuals
- Those wanting to learn network security
- Anyone needing professional-grade network monitoring at home
- Users with dynamic IP addresses from their ISP

## System Architecture Overview

```
Your Desktop Computer
├── Windows Host OS
├── VirtualBox/VMware/Hyper-V
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
    ├── Internet ⟷ Modem ⟷ PC (Killer Gigabit NIC) ⟷ pfSense VM WAN
    └── pfSense VM LAN ⟷ PC (TP-Link NIC) ⟷ Wireless Router ⟷ Home Devices
```

## Prerequisites

### Hardware Requirements

- Windows desktop computer (Host OS)
- Minimum 16GB RAM (8GB for VMs, 8GB for host)
- At least 80GB free disk space (8GB pfSense + 60GB ELK + overhead)
- 2 network interfaces (1 built-in + 1 USB-to-Ethernet adapter)
- CPU with virtualization support (Intel VT-x or AMD-V)

### Physical Network Setup

1. **Killer Gigabit Adapter (built-in)**: Connected to your modem (will be pfSense WAN)
2. **TP-Link Adapter**: Connected to your wireless router (will be pfSense LAN)

### Software Downloads

1. [VirtualBox](https://www.virtualbox.org/wiki/Downloads), [VMware Workstation/Player](https://www.vmware.com/products/workstation-player.html), or [Hyper-V](https://docs.microsoft.com/en-us/virtualization/hyper-v-on-windows/quick-start/enable-hyper-v)
2. [VirtualBox Extension Pack](https://www.virtualbox.org/wiki/Downloads) (if using VirtualBox)
3. [pfSense ISO](https://www.pfsense.org/download/) - For the firewall VM
4. [Ubuntu Server ISO](https://ubuntu.com/download/server) - For the ELK VM
5. USB-to-Ethernet driver (if using USB adapter)

## Step 1: Prepare Host System

### 1.1 Enable Virtualization in BIOS

1. Restart computer and enter BIOS (usually F2, F10, or Del)
2. Look for "Intel VT-x" or "AMD-V" or "Virtualization Technology"
3. Enable the feature
4. Save and exit BIOS

### 1.2 Install Virtualization Software

1. Download and install your preferred virtualization software
2. Install Extension Pack (for VirtualBox)
3. Restart computer after installation

### 1.3 Configure Host Network Interfaces

Make sure both network interfaces are properly connected:
- **Killer Gigabit Adapter (built-in)**: Connected to your modem
- **TP-Link Adapter**: Will be connected to your wireless router (but don't connect it yet)

## Step 2: Create pfSense Virtual Machine

### 2.1 Create VM (VirtualBox Instructions)

1. Open VirtualBox
2. Click "New"
3. Name: pfSense
4. Type: BSD
5. Version: FreeBSD (64-bit)
6. Memory: 4096 MB (4GB RAM)
7. Create virtual hard disk: 20 GB (VDI, dynamically allocated)

### 2.2 Configure VM Settings

**System Settings:**
- Processor: 2 cores minimum
- Enable PAE/NX
- Enable Nested Paging

**Network Settings (Critical Configuration):**

- **Adapter 1 (WAN)**:
  - Enable Network Adapter
  - Attached to: **Bridged Adapter**
  - Select the **Killer Gigabit Adapter** (built-in motherboard NIC)
  - **Advanced → Promiscuous Mode: Allow All**
   
- **Adapter 2 (LAN)**:
  - Enable Network Adapter
  - Attached to: **Bridged Adapter**
  - Select the **TP-Link Adapter**
  - **Advanced → Promiscuous Mode: Allow All**

**Storage Settings:**
- Controller: IDE/SATA
- Attach pfSense ISO to virtual optical drive

## Step 3: Install pfSense

### 3.1 Start VM and Install

1. Start the pfSense VM
2. Select Install option at boot menu
3. Accept copyright notice
4. Choose defaults for most options
5. Select Auto (ZFS) for partitioning
6. Set password for admin user
7. Reboot after installation
8. Remove ISO from virtual drive after reboot

### 3.2 Initial Configuration

1. When prompted for VLAN setup, select "n" (no)
2. Assign interfaces:
   - WAN: Select the interface connected to your modem (usually em0/vtnet0)
   - LAN: Select the interface connected to your wireless router (usually em1/vtnet1)
3. Confirm the assignments
4. Configure LAN IP: 192.168.1.1 (default is fine)
5. Enable DHCP server on LAN when prompted

## Step 4: Configure Windows Host Networking

### 4.1 Windows Network Configuration

**For the TP-Link Adapter (that will connect to your wireless router):**
1. Right-click the TP-Link adapter in Network Connections
2. Properties → TCP/IPv4 → Properties
3. Set IP: 192.168.1.10
4. Subnet: 255.255.255.0
5. Gateway: 192.168.1.1
6. DNS: 192.168.1.1

**For the Killer Gigabit Adapter (connected to your modem):**
- Leave as configured to receive DHCP from your ISP

### 4.2 Configure Windows Default Route

Open Command Prompt as Administrator and run:
```
route delete 0.0.0.0
route add 0.0.0.0 mask 0.0.0.0 192.168.1.1
```

## Step 5: Configure pfSense Web Interface

### 5.1 Access pfSense

1. From your Windows host, open a browser
2. Navigate to https://192.168.1.1
3. Login with admin/pfsense (default credentials)
4. Accept security certificate warning

### 5.2 Basic Configuration

Run through the setup wizard:

1. **General Information:**
   - Hostname: pfSense
   - Domain: localdomain
   - DNS Servers: Use your ISP's DNS or public DNS (8.8.8.8, 8.8.4.4)

2. **Time Server:**
   - Use default NTP servers

3. **WAN Interface Configuration:**
   - Type: DHCP (or static IP if provided by ISP)
   - **Important:** Uncheck "Block private networks" and "Block bogon networks"

4. **LAN Interface Configuration:**
   - IP Address: 192.168.1.1
   - Subnet Mask: 24

5. **Set Admin Password:**
   - Choose a strong password

6. **Reload pfSense**

### 5.3 Critical Performance Settings

1. Navigate to System → Advanced → Networking
2. **Check "Disable hardware checksum offload"**
3. **Check "Disable hardware TCP segmentation offload"**
4. Save changes

These settings are crucial for virtual environments to prevent networking issues.

## Step 6: Configure Wireless Router as Access Point

### 6.1 Access Router Configuration

1. Connect to your wireless router (default IP usually 192.168.0.1 or 192.168.1.1)
2. Login with default credentials

### 6.2 Configure Access Point Mode

1. Find "Operation Mode" or "Wireless Mode" in settings
2. Change from "Router Mode" to "Access Point Mode"
3. Set a static IP for the router: 192.168.1.2
4. **Disable DHCP server** on the router (pfSense will handle this)
5. Configure your wireless settings (SSID, password)
6. Save changes and reboot

### 6.3 Connect Router to pfSense

Important: Connect the router to your computer's second NIC using one of the router's **LAN ports**, not the WAN port.

## Step 7: Advanced DHCP Configuration

### 7.1 Configure DHCP Server

1. In pfSense, navigate to Services → DHCP Server → LAN
2. Configure:
   - Range: 192.168.1.100 - 192.168.1.250
   - DNS Servers: 192.168.1.1
   - Domain name: home.local
   - Gateway: 192.168.1.1
   - Enable DDNS: Check
   - DHCP Registration: Register leases in DNS resolver

### 7.2 Set Up Static Mappings for Important Devices

For devices you want to have fixed IPs:
1. Services → DHCP Server → LAN → DHCP Static Mappings
2. Click "+Add" for each device
3. Enter MAC Address, desired IP, and hostname
4. Save

## Step 8: Install and Configure Suricata IDS

### 8.1 Install Package

1. System → Package Manager → Available Packages
2. Search for "suricata"
3. Click "Install"
4. Confirm installation

### 8.2 Configure Suricata

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
   
3. Enable Protocol Logging:
   - HTTP Log: Check
   - TLS Log: Check
   - DNS Log: Check
   
4. Configure EVE Output Settings:
   - EVE JSON Log: Check
   - EVE Output Type: FILE
   - Enable various EVE log types (Alerts, HTTP, DNS, TLS, Files)

5. Update rules:
   - Services → Suricata → Updates
   - Enable rule updates
   - Update Interval: 12 hours
   - Click "Update" to download rules

## Step 9: Install Additional Security Packages

### 9.1 Install pfBlockerNG

1. System → Package Manager → Available Packages
2. Search for "pfBlockerNG"
3. Click "Install"

Configuration:
1. Firewall → pfBlockerNG → General
   - Enable pfBlockerNG: Check
   - Keep Settings: 7 days
   - CRON Settings: Daily
   
2. Configure IP blocking lists and DNS blocking as desired

### 9.2 Install ntopng for Bandwidth Monitoring

1. System → Package Manager → Available Packages
2. Search for "ntopng"
3. Click "Install"

Configuration:
1. Diagnostics → ntopng Settings
   - Enable ntopng: Check
   - Interface Selection: LAN
   - Admin Password: Set strong password
   - DNS Mode: Local resolution
   - Local Networks: 192.168.0.0/16

## Step 10: Create ELK Stack VM

### 10.1 Create VM

1. Create new VM in VirtualBox:
   - Name: ELK
   - Type: Linux
   - Version: Ubuntu 64-bit
   - Memory: 8096 MB (8GB RAM)
   - Disk: 60 GB
   - Network: Bridged to LAN interface

2. Install Ubuntu Server:
   - Select minimal installation
   - Set static IP: 192.168.1.20
   - Create user account

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
# Set: discovery.type: single-node

# Configure Kibana
sudo nano /etc/kibana/kibana.yml
# Set: server.host: "0.0.0.0"

# Start services
sudo systemctl enable elasticsearch logstash kibana
sudo systemctl start elasticsearch logstash kibana
```

### 10.3 Configure Logstash for pfSense Logs

```bash
sudo nano /etc/logstash/conf.d/pfsense.conf
```

Add the following configuration:

```
input {
  udp {
    port => 5140
    type => syslog
  }
}

filter {
  if [type] == "syslog" {
    # Parse syslog messages
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
        match => { "message" => "%{INT:rule_number},%{NOTSPACE:sub_rule},%{NOTSPACE:anchor},%{INT:tracker},%{NOTSPACE:interface},%{NOTSPACE:reason},%{NOTSPACE:action},%{NOTSPACE:direction},%{IP:ip_version}" }
        add_tag => [ "pfsense_filterlog" ]
      }
    }
    
    # Extract Suricata alerts
    if [program] == "suricata" {
      grok {
        match => { "message" => "\[%{NUMBER:gid}:%{NUMBER:sid}:%{NUMBER:rev}\] %{GREEDYDATA:signature}" }
        add_tag => [ "suricata_alert" ]
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

## Step 11: Configure pfSense Logging to ELK

### 11.1 Enable Remote Logging

1. In pfSense, navigate to Status → System Logs → Settings
2. Under Remote Logging Options:
   - Enable Remote Logging: Check
   - Server 1: 192.168.1.20
   - Port: 5140
   - Protocol: UDP
   - Remote Syslog Contents: Everything
3. Save

### 11.2 Configure Additional Logging

1. Enable DHCP Logging:
   - Status → System Logs → DHCP
   - Log packets handled by dhcpd: Check

2. Enable DNS Logging:
   - Services → DNS Resolver → Advanced Settings
   - Log Level: set appropriate level

## Step 12: Create Kibana Dashboards

### 12.1 Access Kibana

1. Open browser on your Windows host
2. Navigate to http://192.168.1.20:5601
3. Kibana interface will load

### 12.2 Create Index Pattern

1. Management → Stack Management → Index Patterns
2. Create pattern: pfsense-*
3. Time field: @timestamp
4. Create index pattern

### 12.3 Build Basic Dashboards

Create visualizations for:

1. Network Activity:
   - Traffic volume over time
   - Top source/destination IPs
   - Protocol distribution
   
2. Security Events:
   - Suricata alerts timeline
   - Blocked connections
   - Top attack signatures
   
3. Device Tracking:
   - Active devices list
   - Device connection timeline
   - Device bandwidth usage

## Step 13: Testing Your Setup

### 13.1 Verify Internet Connectivity

1. Connect a device to your wireless router
2. Verify you can access the internet
3. Check pfSense dashboard to confirm traffic is flowing

### 13.2 Verify Logging and Monitoring

1. Access Kibana dashboard
2. Confirm logs are being received from pfSense
3. Generate some traffic and verify it appears in the dashboards

## Step 14: Optional Remote Access Configuration

### 14.1 Set Up OpenVPN for Remote Access

1. System → Package Manager → Available Packages
2. Install "openvpn-client-export" package
3. Follow the pfSense OpenVPN wizard to set up the server
4. Configure firewall rules to allow VPN traffic
5. Export client configurations for your devices

### 14.2 Configure Remote Kibana Access

Option 1: VPN-only access (most secure)
Option 2: Set up HTTPS with reverse proxy and authentication

## Step 15: Regular Maintenance

### 15.1 Update Schedule

1. pfSense: System → Update (weekly)
2. Suricata rules: Services → Suricata → Updates (daily)
3. ELK Stack: Regular apt updates

### 15.2 Backup Procedure

1. pfSense configuration: Diagnostics → Backup & Restore
2. ELK Stack: Configure regular snapshots and backups
3. Dashboard exports: Save Kibana dashboard configurations

## Troubleshooting Guide

### Common Issues and Solutions

#### No Internet Connection

- Check physical connections
- Verify VM network adapter settings
- Confirm promiscuous mode is enabled on both interfaces
- Check firewall rules

#### pfSense LAN Interface Not Working

- Verify bridged adapter is correctly assigned 
- Check promiscuous mode settings
- Test with different USB ports if using USB adapter

#### Device Not Getting IP Address

- Check DHCP server status in pfSense
- Verify wireless router is in AP mode with DHCP disabled
- Check for IP conflicts

#### ELK Not Receiving Logs

- Verify remote logging is enabled in pfSense
- Check Logstash configuration
- Confirm firewall allows traffic on port 5140

### Performance Optimization

1. **Virtual Machine Resources:**
   - Allocate sufficient RAM and CPU
   - Use hardware virtualization extensions
   
2. **Network Performance:**
   - Disable hardware offloading in pfSense
   - Use quality NICs and cables
   
3. **Logging Volume:**
   - Configure appropriate log levels
   - Set up log rotation and retention policies

## Conclusion

You've now set up a complete home network security and monitoring solution that:

- Routes all traffic through pfSense for inspection
- Captures and analyzes network activity
- Provides real-time monitoring dashboards
- Enhances network security with IDS and blocking
- Allows for detailed logging and historical analysis

This homelab setup offers enterprise-grade features while running entirely on your Windows desktop, without specialized hardware. As you gain familiarity with the system, you can explore advanced features like VLANs, captive portals, and additional security tools.
