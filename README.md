# Security Audit and Hardening Script
Introduction
This script automates the security audit and hardening process for Linux servers. It performs a series of checks to ensure that the server meets stringent security standards, identifying vulnerabilities, securing configurations, and implementing best practices. The script is modular and reusable, designed to be easily deployed across multiple servers.

Usage
Prepare the Script
Download the script to your server:
wget https://github.com/ghadage2408/Automating/raw/main/Automating Security.sh

Make the script executable
chmod +x Automating Security.sh

Run the Script
Execute the script with root privileges:
sudo ./Automating Security.sh


•Example
1. User and Group Audits
Purpose: Identify potential issues with user and group configurations that could pose security risks.
Checks Performed:
List all users and groups on the server.
Identify users with UID 0 (root privileges).
Detect users without passwords or with weak passwords.
Report files with SUID/SGID bits set, which could be exploited.
2. File and Directory Permissions
Purpose: Ensure that files and directories have appropriate permissions to prevent unauthorized access.
Checks Performed:
Find files and directories with world-writable permissions.
Check .ssh directories for secure permissions.
Report files with SUID/SGID bits set.
3. Service Audits
Purpose: Verify that only necessary and secure services are running on the server.
Checks Performed:
List all running services.
Ensure critical services (e.g., sshd, iptables) are running and properly configured.
Check that no services are listening on non-standard or insecure ports.
4. Firewall and Network Security
Purpose: Ensure that the firewall is active and properly configured to block unauthorized access.
Checks Performed:
Verify the status and configuration of the firewall (iptables or ufw).
Report open ports and their associated services.
Check for IP forwarding and other insecure network configurations.
5. IP and Network Configuration Checks
Purpose: Confirm that IP addresses are properly classified and sensitive services are not exposed unnecessarily.
Checks Performed:
Provide a summary of all IP addresses and classify them as public or private.
Ensure sensitive services (e.g., SSH) are not exposed on public IPs unless required.
6. Security Updates and Patching
Purpose: Check for available security updates and ensure that the server is up-to-date with patches.
Checks Performed:
Check for and report any available security updates.
Ensure the server is configured to receive and install updates regularly.
7. Log Monitoring
Purpose: Detect any suspicious log entries that may indicate security breaches.
Checks Performed:
Monitor logs for signs of suspicious activities, such as multiple failed SSH login attempts.
8. Server Hardening Steps
Purpose: Apply hardening measures to improve server security.
Steps Implemented:
Configure SSH to use key-based authentication and disable password-based root login.
Disable IPv6 if not in use.
Secure the GRUB bootloader with a password.
Configure firewall rules (iptables).
Set up automatic updates using unattended-upgrades.
9. Custom Security Checks
Purpose: Allow for additional, organization-specific security checks.
Implementation:
Extend the script using the config.conf file for custom checks.
10. Reporting and Alerting
Purpose: Summarize the audit results and provide notifications for critical issues.
Implementation:
Generate a detailed report of the security audit.
Optionally configure email alerts for critical vulnerabilities or misconfigurations.
