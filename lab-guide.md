# Updated pfSense-ELK Homelab Setup Guide (Host-Only Monitoring)

> **Network Adapter Information**
> - **External Connection**: Host PC connects to internet via Killer Gigabit adapter (built-in) through existing ASUS Router
> - **Internal Monitoring**: Using VirtualBox virtual adapters for VM traffic monitoring

## Introduction

This simplified guide walks you through creating a virtual network monitoring solution that focuses on monitoring your host PC and all VMs running on it. By using pfSense in a virtual environment, you can gain enterprise-grade security and monitoring capabilities without disrupting your existing home network setup.

### What This Guide Will Build

**A VM-Focused Network Monitoring System** featuring:

- **pfSense Firewall VM**: Security and routing for your virtual machines
- **ELK Stack VM**: Elasticsearch, Logstash, and Kibana for log analysis and visualization
- **Network Monitoring**: Real-time traffic analysis of VM communications
- **Security Systems**: IDS (Suricata) with threat blocking for VMs
- **Virtual Network Isolation**: Separate your VM traffic from your physical network
- **Comprehensive Logging**: Track traffic between VMs and internet access
- **Security Dashboard**: Monitor all VM network activity in real-time

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
External Network
├── Internet ⟷ Modem ⟷ ASUS Router ⟷ Host PC (Killer Gigabit NIC)

Your Desktop Computer
├── Windows Host OS
│   ├── VirtualBox Host-Only Network (vboxnet0, 192.168.56.1)
│   │   └── Internet Connection Sharing enabled
├── VirtualBox
│   ├── pfSense VM
│   │   ├── WAN Interface (192.168.56.2) ⟷ VirtualBox Host-Only Network
│   │   ├── LAN Interface (192.168.1.1) ⟷ VirtualBox Internal Network
│   │   ├── DHCP Server (192.168.1.100-200)
│   │   ├── Suricata IDS
│   │   ├── pfBlockerNG
│   │   └── ntopng Bandwidth Monitor
│   └── ELK Stack VM (192.168.1.20)
│       ├── Connected to VirtualBox Internal Network
│       ├── Elasticsearch
│       ├── Logstash
│       └── Kibana (with monitoring dashboards)
└── Network Traffic Flow
    ├── Internet ⟷ ASUS Router ⟷ Host PC ⟷ VirtualBox Host-Only ⟷ pfSense WAN
    └── pfSense LAN ⟷ VirtualBox Internal Network ⟷ Other VMs
```

## Prerequisites

### Hardware Requirements

- Windows desktop computer (Host OS)
- Minimum 16GB RAM (8GB for VMs, 8GB for host)
- At least 80GB free disk space (8GB pfSense + 60GB ELK + overhead)
- Single network connection (Killer Gigabit Adapter) to your existing ASUS Router
- CPU with virtualization support (Intel VT-x or AMD-V)

### Network Setup

1. **External Connection**: Killer Gigabit Adapter (built-in) → ASUS Router → Modem → Internet
2. **Internal Connection**: Virtual network adapters in VirtualBox for VM monitoring

### Software Downloads

1. [VirtualBox](https://www.virtualbox.org/wiki/Downloads) (recommended for this setup)
2. [VirtualBox Extension Pack](https://www.virtualbox.org/wiki/Downloads)
3. [pfSense ISO](https://www.pfsense.org/download/) - For the firewall VM
4. [Ubuntu Server ISO](https://ubuntu.com/download/server) - For the ELK VM

## Step 1: Prepare Host System

### 1.1 Enable Virtualization in BIOS

1. Restart computer and enter BIOS (usually F2, F10, or Del)
2. Look for "Intel VT-x" or "AMD-V" or "Virtualization Technology"
3. Enable the feature
4. Save and exit BIOS

### 1.2 Install VirtualBox and Extension Pack

1. Download and install VirtualBox
2. Install the VirtualBox Extension Pack
3. Restart computer after installation

### 1.3 Configure VirtualBox Host-Only Network

1. Open VirtualBox
2. Go to File → Host Network Manager
3. Click "Create" to create a new host-only network
4. Configure the network:
   - IPv4 Address: 192.168.56.1
   - IPv4 Network Mask: 255.255.255.0
   - Disable DHCP Server
5. Click Apply and close the Host Network Manager

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
  - Attached to: **Host-only Adapter**
  - Select the **VirtualBox Host-Only Ethernet Adapter** (vboxnet0)
  - **Advanced → Promiscuous Mode: Allow All**
   
- **Adapter 2 (LAN)**:
  - Enable Network Adapter
  - Attached to: **Internal Network**
  - Name: "pfSense-LAN"
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
   - WAN: Select the interface connected to vboxnet0 (usually em0/vtnet0)
   - LAN: Select the interface connected to the Internal Network (usually em1/vtnet1)
3. Confirm the assignments
4. Configure LAN IP: 192.168.1.1 (default is fine)
5. Enable DHCP server on LAN when prompted
6. Set DHCP range: 192.168.1.100 to 192.168.1.200

### 3.3 Verify Network Configuration

**Connectivity Test #1:**
1. Check if pfSense shows successful boot with both interfaces UP
2. From the pfSense console, test internet connectivity:
   ```
   ping 8.8.8.8
   ```
   - If successful, pfSense can reach the internet
   - If failed, check the WAN configuration and Host-Only network settings

3. Verify services are running:
   ```
   ps ax | grep dhcpd
   ```
   - Should show the DHCP service is active

4. Record interface names and MAC addresses for reference:
   ```
   ifconfig
   ```

## Step 4: Configure Windows Host Networking

### 4.1 Configure Host-Only Network Adapter

1. Open Network Connections (Win+R, type "ncpa.cpl")
2. Find the VirtualBox Host-Only Network adapter (named "VirtualBox Host-Only Ethernet Adapter")
3. Right-click → Properties → TCP/IPv4 → Properties
4. Confirm these settings:
   - IP: 192.168.56.1
   - Subnet: 255.255.255.0
   - Gateway: Leave blank
   - DNS: Leave blank
5. Click OK to save

### 4.2 Enable Internet Connection Sharing

1. In Network Connections, right-click your Killer Gigabit adapter (connected to ASUS Router)
2. Select Properties
3. Go to the Sharing tab
4. Check "Allow other network users to connect through this computer's Internet connection"
5. From the dropdown, select the VirtualBox Host-Only Ethernet Adapter
6. Click OK to save

### 4.3 Verify Host Network Configuration

**Connectivity Test #2:**
1. Open Command Prompt as Administrator
2. Check your network adapters and IP assignments:
   ```
   ipconfig /all
   ```
   - Verify Killer Gigabit adapter has internet connection
   - Verify VirtualBox Host-Only adapter shows 192.168.56.1

3. Test connectivity to pfSense WAN:
   ```
   ping 192.168.56.2
   ```
   - If successful, your host can communicate with pfSense
   - If failed, check VirtualBox and network adapter settings

4. Verify Internet Connection Sharing is working:
   ```
   netsh interface ipv4 show interfaces
   ```
   - Look for shared connection status

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
   - DNS Servers: Use public DNS (8.8.8.8, 8.8.4.4)

2. **Time Server:**
   - Use default NTP servers

3. **WAN Interface Configuration:**
   - Type: Static IP
   - IP Address: 192.168.56.2
   - Subnet Mask: 24
   - Gateway: 192.168.56.1 (your host-only adapter IP)
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

### 5.4 Configure Basic Firewall Rules

1. Navigate to Firewall → Rules → LAN
2. Verify the default "Allow all from LAN to any" rule exists
3. Add a more restrictive rule (above the default):
   - Action: Pass
   - Interface: LAN
   - Address Family: IPv4
   - Protocol: Any
   - Source: LAN net
   - Destination: Any
   - Description: "Allow LAN to Any"
4. Save and Apply Changes

5. Navigate to Firewall → Rules → WAN
6. Add a rule to allow established connections:
   - Action: Pass
   - Interface: WAN
   - Address Family: IPv4
   - Protocol: Any
   - Source: Any
   - Destination: Any
   - Advanced Options: Check "This firewall" 
   - Description: "Allow established connections"
7. Save and Apply Changes

### 5.5 Verify Web Configuration

**Connectivity Test #3:**
1. From your Windows host, open a Command Prompt
2. Test connection to Google DNS:
   ```
   ping 8.8.8.8
   ```
   - Should be successful

3. Test DNS resolution:
   ```
   nslookup google.com
   ```
   - Should resolve correctly

4. In pfSense web interface, go to Status → System Logs → System
5. Verify no critical errors are present

## Step 6: Create ELK Stack VM

### 6.1 Create Ubuntu VM for ELK Stack

1. In VirtualBox, click "New"
2. Name: ELK-Stack
3. Type: Linux
4. Version: Ubuntu (64-bit)
5. Memory: 8192 MB (8GB RAM)
6. Create virtual hard disk: 60 GB (VDI, dynamically allocated)

### 6.2 Configure VM Network Settings

1. Select the ELK-Stack VM
2. Go to Settings → Network
3. **Adapter 1**:
   - Enable Network Adapter
   - Attached to: **Internal Network**
   - Name: "pfSense-LAN" (same as pfSense's LAN interface)
4. Click OK to save

### 6.3 Install Ubuntu Server

1. Attach the Ubuntu Server ISO to the virtual optical drive
2. Start the VM and follow the Ubuntu installation wizard
3. When configuring network, use DHCP (it will get an IP from pfSense)
4. Complete the installation and reboot

### 6.4 Verify ELK VM Connectivity

**Connectivity Test #4:**
1. After Ubuntu boots, login to the system
2. Check the IP address assigned by pfSense:
   ```bash
   ip addr show
   ```
   - Should show an IP in the 192.168.1.x range

3. Test connectivity to pfSense:
   ```bash
   ping 192.168.1.1
   ```
   - Should be successful

4. Test internet connectivity:
   ```bash
   ping 8.8.8.8
   ping google.com
   ```
   - Both should be successful

## Step 7: Install and Configure ELK Stack

### 7.1 Set Static IP for ELK VM

1. After Ubuntu boots, login to the system
2. Configure a static IP:
   ```bash
   sudo nano /etc/netplan/00-installer-config.yaml
   ```
3. Add the following configuration:
   ```yaml
   network:
     ethernets:
       enp0s3:
         dhcp4: no
         addresses: [192.168.1.20/24]
         gateway4: 192.168.1.1
         nameservers:
           addresses: [192.168.1.1, 8.8.8.8]
     version: 2
   ```
4. Apply the configuration:
   ```bash
   sudo netplan apply
   ```

### 7.2 Install ELK Components

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

## Step 8: Install and Configure Security Packages in pfSense

### 8.1 Install Suricata IDS/IPS Package

1. In pfSense, go to System → Package Manager → Available Packages
2. Search for "suricata"
3. Click "Install"
4. Confirm installation

### 8.2 Configure Suricata with IPS

1. Services → Suricata → Global Settings:
   - Enable: Check
   - Remove Blocked Hosts Interval: 3600
   - Live Rule Swap: Check
   - Log to System Log: Check

2. Services → Suricata → Interfaces:
   - Add interface
   - Interface: LAN
   - Enable: Check
   - **IPS Mode: Check** (enables intrusion prevention)
   - Block Offenders: Check
   - Promiscuous Mode: Check
   
3. Enable Protocol Logging:
   - HTTP Log: Check
   - TLS Log: Check
   - DNS Log: Check
   - File Extraction: Check (enables malware detection)
   
4. Configure EVE Output Settings:
   - EVE JSON Log: Check
   - EVE Output Type: FILE
   - Enable all relevant EVE log types (Alerts, HTTP, DNS, TLS, Files)

5. Update rules:
   - Services → Suricata → Updates
   - Enable rule updates
   - Update Interval: 12 hours
   - Click "Update" to download rules
   - Select relevant rule categories (emerging threats, malware, etc.)

### 8.3 Verify Suricata Installation

**Connectivity Test #5:**
1. In pfSense, go to Services → Suricata → Interfaces
2. Verify the status is "Running"
3. Check Status → System Logs → Suricata
4. Confirm log entries are being generated
5. Test a known benign detection rule:
   - From a VM on the internal network, visit testmyids.com
   - Check Suricata logs for the expected alert

 Enable ntopng: Check
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

## Step 12: Create Additional Virtual Machines

### 12.1 Create Test VMs for Monitoring

Creating additional VMs on the "pfSense-LAN" internal network will allow you to test your monitoring setup.

1. In VirtualBox, create a new VM (e.g., "TestVM"):
   - Type: Linux/Windows (your preference)
   - Memory: 2048 MB (2GB RAM)
   - Disk: 20 GB (dynamically allocated)

2. Configure Network:
   - Adapter 1: Internal Network
   - Name: "pfSense-LAN" (same as pfSense's LAN interface)
   - Promiscuous Mode: Allow All

3. Install the operating system of your choice

4. Verify Network Connectivity:
   - VM should receive an IP from pfSense (192.168.1.x)
   - VM should be able to access the internet via pfSense
   - VM traffic should be logged and monitored

### 12.2 Configure Monitoring for Host PC Traffic

To monitor traffic from your host PC:

1. Create a Virtual Machine specifically for testing host traffic:
   - Adapter 1: Internal Network ("pfSense-LAN")
   - Install lightweight OS

2. On this VM, install tools like Wireshark or tcpdump:
   ```bash
   sudo apt install wireshark
   ```

3. Generate test traffic from your host PC to verify monitoring

### 12.3 Verify Test VM Configuration

**Connectivity Test #9:**
1. From the test VM, check its IP configuration:
   - Windows: `ipconfig /all`
   - Linux: `ip addr show`
   
2. Verify connectivity to pfSense:
   - Ping 192.168.1.1
   
3. Test internet connectivity:
   - Ping 8.8.8.8
   - Browse a website
   
4. Check pfSense and ELK dashboards:
   - Verify traffic from the test VM appears in logs
   - Check ntopng to see the VM in the hosts list
   - Verify Suricata is monitoring the VM's traffic

## Step 13: Testing Your Complete Setup

### 13.1 Comprehensive Connectivity Testing

1. **External to Internal Testing**:
   - Generate traffic from internet to VMs (if allowed by firewall)
   - Verify pfSense firewall blocks unauthorized access
   - Check logs for blocked connection attempts

2. **Internal to External Testing**:
   - Browse websites from test VMs
   - Download various file types
   - Run speed tests to verify throughput
   - Confirm all traffic is logged in ELK

3. **VM-to-VM Communication Testing**:
   - Set up file sharing between VMs
   - Transfer files between VMs
   - Check network flow visualization
   - Verify traffic is properly monitored

### 13.2 Security Testing

1. **IPS Testing**:
   - Visit a test site like testmyids.com
   - Generate known patterns that trigger Suricata
   - Verify alerts appear in Kibana
   - Confirm block actions work if configured

2. **DNS Blocking Testing**:
   - Attempt to visit known malicious domains
   - Check pfBlockerNG logs for blocked requests
   - Verify the events appear in ELK dashboards

3. **Log Collection Testing**:
   - Generate various types of events
   - Search for them in Kibana
   - Verify all expected fields are parsed correctly
   - Check log retention policy is working

### 13.3 Performance Testing

1. **Network Throughput**:
   - Run iperf between VMs
   - Measure bandwidth with ntopng
   - Verify performance impact of security features

2. **Resource Utilization**:
   - Monitor CPU/RAM usage on pfSense
   - Check ELK stack performance
   - Ensure host system remains responsive

**Final Connectivity Test #10:**
1. Verify all components are working together:
   - pfSense is routing and protecting
   - Suricata is detecting threats
   - pfBlockerNG is blocking malicious content
   - ntopng is visualizing traffic
   - ELK is collecting and analyzing logs
   - Kibana dashboards display meaningful data

2. Run a manual packet capture on pfSense:
   - Diagnostics → Packet Capture
   - Capture some traffic
   - Analyze for expected behavior

## Step 14: Advanced Configuration

### 14.1 Configure Advanced Firewall Rules

1. **Layer 7 Application Control**:
   - Navigate to Firewall → Rules → LAN
   - Add rule to block specific applications:
     - Action: Block
     - Protocol: TCP/UDP
     - Destination: Any
     - Advanced Features: Layer 7 (select applications to block)
     - Description: "Block unauthorized applications"

2. **Time-Based Access Rules**:
   - Create schedule:
     - Firewall → Schedules → Add
     - Name: "WorkHours" 
     - Define time periods
   - Add rule with schedule:
     - Action: Pass/Block
     - Schedule: "WorkHours"
     - Description: "Time-based access control"

3. **Rate Limiting**:
   - Create limiter:
     - Firewall → Traffic Shaper → Limiters → New Limiter
     - Name: "BandwidthLimit"
     - Bandwidth: Set appropriate limit (e.g., 10Mbit/s)
   - Apply to firewall rule:
     - Edit rule → Advanced Features → In/Out Pipe: "BandwidthLimit"

### 14.2 Enhanced Logging and Alerting

1. **Configure Email Notifications**:
   - System → Advanced → Notifications
   - Enable SMTP notifications
   - Enter SMTP server details
   - Test notification

2. **Create Suricata Alert Rules**:
   - Services → Suricata → Rules → Add
   - SID: 9000001 (custom rule)
   - Rule: `alert tcp any any -> $HOME_NET any (msg:"Custom Alert Rule"; content:"suspicious"; classtype:bad-unknown; sid:9000001; rev:1;)`
   - Save and update

3. **Configure pfBlockerNG Alerts**:
   - Firewall → pfBlockerNG → Alerts
   - Enable Alert settings
   - Configure notification preferences

### 14.3 Network Flow Analysis Tuning

1. **Configure ntopng Flow Collection**:
   - Enable NetFlow/sFlow:
     - Diagnostics → ntopng Settings
     - Enable Flow Collection: Check
     - Flow Sampling Rate: 1

2. **Customize ntopng Categories**:
   - Create application categories:
     - Access ntopng web interface
     - Configure → Category Configuration
     - Add categories for different types of VMs or applications

3. **Flow Visualization Enhancements**:
   - Enable historical data:
     - Configure → Preferences
     - Historical Interface: Enable
     - Retention: Set appropriate period (e.g., 30 days)

## Step 15: Maintenance and Disaster Recovery

### 15.1 Regular Updates

1. **pfSense Updates**:
   - System → Update (check weekly)
   - Update all installed packages
   - Create a backup before updates
   - Schedule updates during low-traffic periods
   - Verify functionality after updates

2. **ELK Stack Updates**:
   ```bash
   sudo apt update
   sudo apt upgrade
   ```
   - Test after major version upgrades
   - Backup configurations before upgrading

3. **Security Rule Updates**:
   - Services → Suricata → Updates
   - Set automatic update schedule
   - Review rule changes regularly
   - Monitor for false positives after updates

### 15.2 Performance Monitoring and Tuning

1. **pfSense Resource Monitoring**:
   - Status → Monitoring
   - Track CPU, memory, and disk usage
   - Set up SNMP monitoring if needed
   - Configure email alerts for resource thresholds

2. **ELK Performance Tuning**:
   - Monitor Elasticsearch heap usage
   - Adjust JVM settings as needed:
     ```bash
     sudo nano /etc/elasticsearch/jvm.options
     # Set -Xms and -Xmx to appropriate values (50% of RAM)
     ```
   - Optimize index settings for performance

3. **Network Performance**:
   - Use ntopng to identify bandwidth issues
   - Implement traffic shaping for critical services
   - Optimize firewall rules (order by most used)

### 15.3 Comprehensive Backup Strategy

1. **pfSense Configuration Backup**:
   - Diagnostics → Backup & Restore
   - Check "Backup area" → All
   - Enable encryption option
   - Schedule regular automated backups:
     - System → Cron
     - Add job to run config backup script

2. **ELK Stack Backups**:
   - Elasticsearch snapshots:
     ```bash
     # Create repository
     curl -X PUT "localhost:9200/_snapshot/backup_repo" -H 'Content-Type: application/json' -d'
     {
       "type": "fs",
       "settings": {
         "location": "/path/to/backup"
       }
     }'
     
     # Create snapshot
     curl -X PUT "localhost:9200/_snapshot/backup_repo/snapshot_1"
     ```
   - Kibana saved objects export:
     - Management → Saved Objects → Export
   - Logstash configuration backup

3. **Recovery Testing**:
   - Periodically test restore procedures
   - Document recovery steps
   - Estimate recovery time for planning
   - Create VM snapshots before major changes

## Conclusion

You've now set up a comprehensive virtual network monitoring and protection solution focused on your host PC and VMs. This setup provides enterprise-grade security capabilities while maintaining your existing home network setup.

### Key Accomplishments

1. **Complete Network Security**: Your virtual environment is now protected by pfSense's advanced firewall, Suricata IDS/IPS, and pfBlockerNG threat intelligence.

2. **In-Depth Traffic Analysis**: With ntopng flow visualization and ELK Stack analytics, you have complete visibility into all VM network communications.

3. **Active Threat Prevention**: The IPS capabilities actively block detected threats, protecting your VMs from malicious activity.

4. **Comprehensive Logging**: All network activity is logged, analyzed, and visualized in Kibana dashboards, providing real-time security insights.

5. **Skill Development**: This homelab provides an excellent platform for developing network security and monitoring skills.

### Key Benefits

- **Isolated Security Environment**: Test security configurations without impacting your main network
- **Real-Time Network Visibility**: See all traffic flowing through your virtual environment
- **Professional Security Tools**: Learn enterprise-grade security applications
- **Customizable Protection**: Configure security settings based on your specific needs
- **Non-Disruptive Implementation**: Maintain your existing internet connection while adding security

### Next Steps

As you become more familiar with this setup, consider:

1. **Extending Monitoring**: Add more advanced Kibana visualizations and machine learning for anomaly detection
2. **Custom Security Rules**: Develop your own Suricata rules for specific threats
3. **Advanced Network Scenarios**: Experiment with more complex network topologies using VLANs
4. **Automation**: Add scripted responses to security events
5. **Integration with Other Tools**: Connect to third-party threat intelligence feeds

This virtual monitoring and protection system provides an excellent foundation for network security experimentation, learning, and protection for your virtual machines while allowing you to maintain your existing network infrastructure.

Happy monitoring and securing!
