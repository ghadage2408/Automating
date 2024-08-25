#!/bin/bash

# Configuration file path
CONFIG_FILE="/etc/security_audit/config.conf"

# Function to check for root privileges
check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        echo "This script must be run as root." >&2
        exit 1
    fi
}

# Function to load configuration file
load_config() {
    if [ -f "$CONFIG_FILE" ]; then
        source "$CONFIG_FILE"
    else
        echo "Configuration file not found: $CONFIG_FILE"
        exit 1
    fi
}

# Function to perform user and group audits
user_group_audit() {
    echo "### User and Group Audits ###"
    echo "List of users and groups:"
    cut -d: -f1 /etc/passwd
    echo "Users with UID 0:"
    awk -F: '$3 == 0 {print $1}' /etc/passwd
    echo "Users without passwords:"
    awk -F: '($2 == "" || $2 == "*") {print $1}' /etc/shadow
    echo "Files with SUID/SGID bits set:"
    find / -perm /6000 -type f 2>/dev/null
}

# Function to perform file and directory permissions checks
file_directory_permissions() {
    echo "### File and Directory Permissions ###"
    echo "World-writable files and directories:"
    find / -xdev \( -type f -o -type d \) -perm -022 -exec ls -ld {} \; 2>/dev/null
    echo "Checking .ssh directories:"
    find / -type d -name ".ssh" -exec ls -ld {} \; 2>/dev/null
}

# Function to perform service audits
service_audit() {
    echo "### Service Audits ###"
    echo "Running services:"
    systemctl list-units --type=service --state=running
    echo "Critical services status:"
    systemctl status sshd
    systemctl status iptables
}

# Function to perform firewall and network security checks
firewall_network_security() {
    echo "### Firewall and Network Security ###"
    echo "Firewall status:"
    if command -v ufw > /dev/null; then
        ufw status
    elif command -v iptables > /dev/null; then
        iptables -L -n
    else
        echo "No firewall detected."
    fi
    echo "Open ports and associated services:"
    netstat -tuln
    echo "IP forwarding status:"
    sysctl net.ipv4.ip_forward
}

# Function to perform IP and network configuration checks
ip_network_configuration() {
    echo "### IP and Network Configuration ###"
    echo "IP address summary:"
    ip -br addr show
    echo "Public vs Private IPs:"
    # This part can be extended with a more sophisticated public/private IP check
}

# Function to check for security updates
security_updates() {
    echo "### Security Updates and Patching ###"
    if command -v apt-get > /dev/null; then
        apt-get update
        apt-get -s upgrade | grep ^Inst
    elif command -v yum > /dev/null; then
        yum check-update
    else
        echo "Package manager not found."
    fi
}

# Function to perform log monitoring
log_monitoring() {
    echo "### Log Monitoring ###"
    grep -i "sshd" /var/log/auth.log
}

# Function to perform server hardening steps
server_hardening() {
    echo "### Server Hardening Steps ###"
    echo "Configuring SSH:"
    sed -i 's/^PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
    systemctl restart sshd
    echo "Disabling IPv6 (if configured):"
    # Add IPv6 disablement commands based on your guidelines
    echo "Securing GRUB bootloader:"
    # Implement GRUB password setup
    echo "Configuring firewall:"
    # Implement iptables rules
    echo "Configuring automatic updates:"
    apt-get install unattended-upgrades
    dpkg-reconfigure --priority=low unattended-upgrades
}

# Function to generate report
generate_report() {
    echo "### Generating Report ###"
    echo "Security Audit Report" > /var/log/security_audit_report.txt
    # Append results of each function to the report
    user_group_audit >> /var/log/security_audit_report.txt
    file_directory_permissions >> /var/log/security_audit_report.txt
    service_audit >> /var/log/security_audit_report.txt
    firewall_network_security >> /var/log/security_audit_report.txt
    ip_network_configuration >> /var/log/security_audit_report.txt
    security_updates >> /var/log/security_audit_report.txt
    log_monitoring >> /var/log/security_audit_report.txt
    server_hardening >> /var/log/security_audit_report.txt
}

# Function to send alerts (optional)
send_alert() {
    echo "### Sending Alerts ###"
    # Add email or other alerting mechanism here
}

# Main script execution
check_root
load_config
user_group_audit
file_directory_permissions
service_audit
firewall_network_security
ip_network_configuration
security_updates
log_monitoring
server_hardening
generate_report
send_alert

echo "Security audit and hardening process completed."
