# Intrusion Detection System (IDS) using Snort

Welcome to the **Intrusion Detection System (IDS)** powered by Snort! This project leverages 30 custom Snort rules to detect various forms of network reconnaissance, attacks, and suspicious activities, providing a robust layer of security against potential threats. The rules are meticulously designed to recognize and respond to malicious network behavior across multiple attack vectors.

## Table of Contents
- [Project Overview](#project-overview)
- [Key Features](#key-features)
- [Snort Rules Overview](#snort-rules-overview)
- [Setup and Usage](#setup-and-usage)
- [Rule Categories](#rule-categories)
- [Contributors](#contributors)

## Project Overview
This IDS project is tailored to detect multiple cyber attack vectors, reconnaissance attempts, and unauthorized access attempts. By using Snort, an open-source network intrusion prevention system (NIPS) and network intrusion detection system (NIDS), this system actively monitors network traffic for suspicious behavior and alerts the security team of potential threats.

## Contributors

- **Anmol**
- **Chaman Rathore** 
- **Daksh**

## Key Features
- **Reconnaissance Detection**: Identifies port scanning, ping sweeps, and protocol fingerprinting
- **Injection Attack Detection**: SQL Injection (SQLi), Cross-Site Scripting (XSS), and Local File Inclusion (LFI) detection
- **Brute Force Attack Detection**: SSH, FTP, and HTTP brute-force detection
- **Vulnerability Exploitation Detection**: Monitors attempts to exploit web vulnerabilities such as RFI, LFI, RCE, and SSRF
- **Evasion and Bypass Tactics**: Detects stealthy scans like NULL, FIN, Xmas tree, and window scans
- **Access Violation Alerts**: Triggers alerts on attempts to access restricted files or directories
- **Advanced Threat Detection**: Covers 30 different attack patterns with unique SIDs

## Snort Rules Overview

The project includes **30 custom Snort rules** organized into the following categories:

### 1. **Website Reconnaissance & Information Gathering**
- **HTTP OPTIONS Method Scan** (SID: 100001): Detects HTTP OPTIONS method scans used in reconnaissance
- **Endpoint Discovery** (SID: 100028): Identifies multiple connection attempts from the same IP
- **Telnet Banner Grabbing** (SID: 100010): Detects attempts to gather system information via Telnet

### 2. **SQL Injection Attacks**
- **Basic SQL Keywords** (SID: 100002-100003): Detects 'select' and 'from' keywords in HTTP requests
- **SQL Comments** (SID: 100004): Identifies SQL comment patterns (`--`, `#`, `%23`)
- **Boolean-Based SQLi** (SID: 100023): Detects boolean-based SQL injection patterns
- **Time-Based SQLi** (SID: 100024): Identifies time-based SQL injection using sleep/wait/delay functions

### 3. **Cross-Site Scripting (XSS)**
- **Script Tag Detection** (SID: 100020): Detects `<script>` tags in HTTP requests
- **URL Encoded Scripts** (SID: 100019): Identifies URL-encoded script tags (`%3Cscript`)

### 4. **File Inclusion Attacks**
- **Local File Inclusion (LFI)** (SID: 100015, 100029-100032): Detects attempts to access sensitive files like `/etc/passwd`, config files, and backup files
- **Remote File Inclusion (RFI)** (SID: 100016): Identifies attempts to include remote files via PHP parameters
- **Directory Traversal** (SID: 100033-100035): Detects path traversal attempts using `../`, `..%2F`, and `..%2e/`

### 5. **Remote Code Execution (RCE)**
- **Command Execution** (SID: 100017-100018): Detects attempts to execute commands via `/bin/bash` and `exec` functions

### 6. **Server-Side Request Forgery (SSRF)**
- **Internal IP Detection** (SID: 100021-100022): Identifies attempts to access internal resources via `127.0.0.1` and `localhost`

### 7. **Brute Force Attacks**
- **SSH Brute Force** (SID: 100006): Detects multiple SSH connection attempts
- **FTP Brute Force** (SID: 100010): Identifies repeated FTP login attempts
- **HTTP Login Brute Force** (SID: 100014): Detects repeated login attempts on web applications
- **FTP Anonymous Login** (SID: 100009): Alerts on anonymous FTP access attempts

### 8. **Network Scanning & Reconnaissance**
- **Ping Sweep** (SID: 100005): Monitors ICMP Echo Requests for ping sweeps
- **ICMP Time Exceeded** (SID: 100012): Detects potential traceroute activities
- **Suspicious ICMP Size** (SID: 100025): Flags ICMP packets exceeding normal size

### 9. **Stealth Scan Detection**
- **NULL Scan** (SID: 100036): Detects TCP packets with no flags set
- **FIN Scan** (SID: 100038): Identifies FIN flag scans
- **Xmas Tree Scan** (SID: 100039): Detects packets with FIN, PSH, and URG flags
- **SYN Scan** (SID: 100040): Monitors SYN scan patterns
- **Window Scan** (SID: 100037): Detects unusual TCP window sizes
- **SYN-ACK Scan** (SID: 100041): Identifies SYN-ACK without ACK patterns

### 10. **Miscellaneous Threats**
- **DNS Malicious Queries** (SID: 100026): Detects DNS requests to known malicious domains
- **Internal IP in External Traffic** (SID: 100027): Flags internal IP addresses in external traffic
- **Web Application Failed Logins** (SID: 100011): Monitors failed authentication attempts

## Rule Examples

Here are some key rule examples from the collection:

### SQL Injection Detection
```snort
alert tcp any any -> any 80 (msg:"SQL Injection Attempt - 'select' keyword detected"; flow:to_server,established; content:"select"; nocase; sid:100002; rev:1;)
```

### XSS Attack Detection
```snort
alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"Cross-Site Scripting (XSS) Attack Detected"; flow:to_server,established; content:"<script>"; nocase; sid:100020; rev:1;)
```

### Port Scan Detection
```snort
alert tcp $EXTERNAL_NET any -> $HOME_NET any (flags:0; msg:"Potential NULL Scan - TCP Packet with No Flags"; threshold:type limit, track by_src, count 5, seconds 60; sid:100036; rev:1;)
```

### Brute Force Detection
```snort
alert tcp $EXTERNAL_NET any -> $HOME_NET 22 (msg:"SSH Brute Force Attack Detected"; flow:to_server,established; content:"SSH-"; pcre:"/SSH-\d+\.\d+/"; detection_filter:track by_src, count 5, seconds 1; sid:100006; rev:1;)
```

## Setup and Usage

### Prerequisites
- Snort 2.9.x or 3.x installed on your system
- Proper network configuration with defined `$HOME_NET` and `$EXTERNAL_NET` variables

### Installation Steps

1. **Install Snort**: 
   - **Ubuntu/Debian**: `sudo apt-get install snort`
   - **CentOS/RHEL**: `sudo yum install snort`
   - **Windows**: Download from [Snort.org](https://www.snort.org/downloads)

2. **Configure Network Variables**:
   Edit your `snort.conf` file to define:
   ```bash
   var HOME_NET [your_network_cidr]
   var EXTERNAL_NET any
   var HTTP_SERVERS $HOME_NET
   var HTTP_PORTS 80
   var DNS_SERVERS $HOME_NET
   ```

3. **Deploy Custom Rules**:
   ```bash
   # Copy rules to Snort rules directory
   sudo cp localrules /etc/snort/rules/
   
   # Include in snort.conf
   include $RULE_PATH/localrules
   ```

4. **Start Snort**:
   ```bash
   # Test configuration
   snort -T -c /etc/snort/snort.conf
   
   # Run in IDS mode
   snort -c /etc/snort/snort.conf -l /var/log/snort
   
   # Run in packet logging mode
   snort -c /etc/snort/snort.conf -l /var/log/snort -K pcap
   ```

### Configuration Options

- **Alert Mode**: Configure alert output (console, log file, syslog, etc.)
- **Thresholds**: Adjust detection thresholds based on your network environment
- **Logging**: Configure log rotation and storage
- **Performance**: Tune rule processing for your network bandwidth

## Rule Categories

| Category | Rule Count | SID Range | Description |
|----------|------------|-----------|-------------|
| **Reconnaissance** | 4 | 100001, 100005, 100012, 100028 | Port scans, ping sweeps, endpoint discovery |
| **SQL Injection** | 4 | 100002-100004, 100023-100024 | Various SQL injection patterns |
| **XSS Attacks** | 2 | 100019-100020 | Cross-site scripting detection |
| **File Inclusion** | 6 | 100015-100016, 100029-100035 | LFI, RFI, and directory traversal |
| **RCE Detection** | 2 | 100017-100018 | Remote code execution attempts |
| **SSRF Detection** | 2 | 100021-100022 | Server-side request forgery |
| **Brute Force** | 4 | 100006, 100009-100010, 100014 | SSH, FTP, and HTTP brute force |
| **Stealth Scans** | 6 | 100036-100041 | NULL, FIN, Xmas tree, SYN scans |
| **Access Control** | 4 | 100007-100008, 100011, 100013 | Login attempts and access violations |
| **Network Anomalies** | 2 | 100025, 100027 | Suspicious packet sizes and IP patterns |

## Best Practices

1. **Regular Updates**: Keep Snort rules updated with the latest threat intelligence
2. **Threshold Tuning**: Adjust detection thresholds based on your network baseline
3. **False Positive Management**: Monitor and tune rules to reduce false positives
4. **Log Analysis**: Implement proper log analysis and alerting mechanisms
5. **Network Segmentation**: Use proper network segmentation to limit attack surface

## Troubleshooting

- **Rule Syntax Errors**: Use `snort -T` to test configuration
- **Performance Issues**: Adjust rule processing order and thresholds
- **False Positives**: Tune specific rules or add suppressions
- **Log Issues**: Check file permissions and disk space

## Contributing

To contribute to this project:
1. Fork the repository
2. Create a feature branch
3. Add new rules following the existing SID numbering scheme
4. Test rules thoroughly
5. Submit a pull request with detailed descriptions
