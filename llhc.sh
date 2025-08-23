#!/bin/bash

# Linux Security Hardening Check (LSHC)
# Comprehensive security audit script for Linux systems
# Equivalent to the Windows LWHC PowerShell script

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
GRAY='\033[0;37m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color

# Global arrays to track security issues
declare -a SECURITY_ISSUES
declare -a ISSUE_SEVERITIES
declare -a ISSUE_CATEGORIES

# Function to add security issues
add_security_issue() {
    local category="$1"
    local issue="$2"
    local severity="${3:-Medium}"
    
    SECURITY_ISSUES+=("$issue")
    ISSUE_SEVERITIES+=("$severity")
    ISSUE_CATEGORIES+=("$category")
}

# Color output function
print_color() {
    local message="$1"
    local color="${2:-$WHITE}"
    echo -e "${color}${message}${NC}"
}

# Section header function
print_section_header() {
    local title="$1"
    echo ""
    print_color "================================================================" "$CYAN"
    print_color "${title^^}" "$CYAN"
    print_color "================================================================" "$CYAN"
}

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_color "This script requires root privileges. Please run with sudo." "$RED"
        exit 1
    fi
}

# Function to detect Linux distribution
detect_distro() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        DISTRO="$ID"
        DISTRO_VERSION="$VERSION_ID"
        DISTRO_NAME="$NAME"
    elif [[ -f /etc/redhat-release ]]; then
        DISTRO="rhel"
        DISTRO_NAME=$(cat /etc/redhat-release)
    elif [[ -f /etc/debian_version ]]; then
        DISTRO="debian"
        DISTRO_NAME="Debian $(cat /etc/debian_version)"
    else
        DISTRO="unknown"
        DISTRO_NAME="Unknown"
    fi
}

# Disk encryption status (equivalent to BitLocker)
check_disk_encryption() {
    print_section_header "DISK ENCRYPTION STATUS"
    
    local encrypted_found=false
    
    # Check for LUKS encrypted partitions
    if command_exists lsblk; then
        print_color "Checking for LUKS encrypted partitions..." "$YELLOW"
        
        while IFS= read -r line; do
            if [[ $line == *"crypt"* ]]; then
                encrypted_found=true
                local device=$(echo "$line" | awk '{print $1}')
                local mountpoint=$(echo "$line" | awk '{print $7}')
                print_color "Encrypted partition found: $device mounted at $mountpoint" "$GREEN"
            fi
        done < <(lsblk -f 2>/dev/null | grep -v "^NAME")
        
        # Check cryptsetup status for detailed info
        if command_exists cryptsetup; then
            for mapper in /dev/mapper/*; do
                if [[ -b "$mapper" && "$mapper" != "/dev/mapper/control" ]]; then
                    local mapper_name=$(basename "$mapper")
                    local status=$(cryptsetup status "$mapper_name" 2>/dev/null)
                    if [[ -n "$status" ]]; then
                        encrypted_found=true
                        print_color "Encrypted device: $mapper_name" "$GREEN"
                        echo "$status" | while read -r line; do
                            print_color "  $line" "$GRAY"
                        done
                    fi
                fi
            done
        fi
    fi
    
    # Check for eCryptfs (home directory encryption)
    if command_exists ecryptfs-stat; then
        if ecryptfs-stat "$HOME" >/dev/null 2>&1; then
            encrypted_found=true
            print_color "eCryptfs home directory encryption detected" "$GREEN"
        fi
    fi
    
    # Check for ZFS encryption
    if command_exists zfs; then
        local zfs_encrypted=$(zfs get -H encryption | grep -v "off" | grep -v "PROPERTY")
        if [[ -n "$zfs_encrypted" ]]; then
            encrypted_found=true
            print_color "ZFS encrypted datasets found:" "$GREEN"
            echo "$zfs_encrypted" | while read -r line; do
                print_color "  $line" "$GRAY"
            done
        fi
    fi
    
    if [[ "$encrypted_found" == false ]]; then
        print_color "No disk encryption detected" "$RED"
        add_security_issue "Disk Encryption" "No disk encryption found on system" "High"
    fi
}

# Boot security status (equivalent to Secure Boot/TPM)
check_boot_security() {
    print_section_header "BOOT SECURITY STATUS"
    
    # Check Secure Boot status
    if [[ -d /sys/firmware/efi ]]; then
        print_color "UEFI Boot Mode: Detected" "$GREEN"
        
        if [[ -f /sys/firmware/efi/efivars/SecureBoot-* ]]; then
            local secureboot_status=$(mokutil --sb-state 2>/dev/null || echo "Cannot determine")
            print_color "Secure Boot Status: $secureboot_status" "$YELLOW"
            
            if [[ "$secureboot_status" == *"disabled"* ]]; then
                add_security_issue "Boot Security" "Secure Boot is disabled" "High"
            fi
        else
            print_color "Secure Boot Status: Not available" "$YELLOW"
            add_security_issue "Boot Security" "Secure Boot status cannot be determined" "Medium"
        fi
    else
        print_color "Boot Mode: Legacy BIOS" "$YELLOW"
        add_security_issue "Boot Security" "System is using Legacy BIOS instead of UEFI" "Medium"
    fi
    
    # Check TPM status
    if [[ -d /sys/class/tpm ]]; then
        print_color "TPM Device: Present" "$GREEN"
        
        for tpm_dev in /sys/class/tpm/tpm*; do
            if [[ -d "$tpm_dev" ]]; then
                local tpm_name=$(basename "$tpm_dev")
                print_color "TPM Device: $tpm_name" "$GREEN"
                
                # Check TPM version
                if [[ -f "$tpm_dev/tpm_version_major" ]]; then
                    local tpm_version=$(cat "$tpm_dev/tpm_version_major" 2>/dev/null)
                    print_color "  TPM Version: $tpm_version.x" "$WHITE"
                    
                    if [[ "$tpm_version" -lt 2 ]]; then
                        add_security_issue "Boot Security" "TPM version is below 2.0" "Medium"
                    fi
                fi
                
                # Check if TPM is enabled
                if [[ -f "$tpm_dev/enabled" ]]; then
                    local tpm_enabled=$(cat "$tpm_dev/enabled" 2>/dev/null)
                    print_color "  TPM Enabled: $tpm_enabled" "$([ "$tpm_enabled" == "1" ] && echo "$GREEN" || echo "$RED")"
                    
                    if [[ "$tpm_enabled" != "1" ]]; then
                        add_security_issue "Boot Security" "TPM is present but not enabled" "High"
                    fi
                fi
            fi
        done
    else
        print_color "TPM Device: Not found" "$RED"
        add_security_issue "Boot Security" "No TPM device found" "High"
    fi
    
    # Check kernel module signing
    if [[ -f /proc/sys/kernel/modules_disabled ]]; then
        local modules_disabled=$(cat /proc/sys/kernel/modules_disabled)
        print_color "Kernel Module Loading: $([ "$modules_disabled" == "1" ] && echo "Disabled" || echo "Enabled")" "$([ "$modules_disabled" == "1" ] && echo "$GREEN" || echo "$YELLOW")"
    fi
    
    # Check for kernel lockdown mode
    if [[ -f /sys/kernel/security/lockdown ]]; then
        local lockdown_mode=$(cat /sys/kernel/security/lockdown)
        print_color "Kernel Lockdown Mode: $lockdown_mode" "$WHITE"
        
        if [[ "$lockdown_mode" == *"none"* ]]; then
            add_security_issue "Boot Security" "Kernel lockdown mode is disabled" "Medium"
        fi
    fi
}

# USB and external media policies
check_usb_policies() {
    print_section_header "USB/EXTERNAL MEDIA POLICIES"
    
    # Check USB storage module status
    local usb_storage_status="Loaded"
    if ! lsmod | grep -q usb_storage; then
        usb_storage_status="Not Loaded"
    fi
    print_color "USB Storage Module: $usb_storage_status" "$([ "$usb_storage_status" == "Not Loaded" ] && echo "$GREEN" || echo "$YELLOW")"
    
    # Check if USB storage is blacklisted
    local usb_blacklisted=false
    for blacklist_file in /etc/modprobe.d/*.conf; do
        if [[ -f "$blacklist_file" ]] && grep -q "blacklist usb.storage\|install usb.storage /bin/true" "$blacklist_file"; then
            usb_blacklisted=true
            print_color "USB Storage Blacklisted: Yes (in $(basename "$blacklist_file"))" "$GREEN"
            break
        fi
    done
    
    if [[ "$usb_blacklisted" == false ]]; then
        print_color "USB Storage Blacklisted: No" "$YELLOW"
        add_security_issue "USB/External Media" "USB storage is not blacklisted" "Medium"
    fi
    
    # Check udev rules for USB restrictions
    if [[ -d /etc/udev/rules.d ]]; then
        local usb_rules_found=false
        for rule_file in /etc/udev/rules.d/*.rules; do
            if [[ -f "$rule_file" ]] && grep -q "SUBSYSTEM.*usb" "$rule_file"; then
                usb_rules_found=true
                print_color "USB udev rules found in: $(basename "$rule_file")" "$GREEN"
            fi
        done
        
        if [[ "$usb_rules_found" == false ]]; then
            add_security_issue "USB/External Media" "No USB restriction udev rules found" "Medium"
        fi
    fi
    
    # Check for USBGuard if available
    if command_exists usbguard; then
        local usbguard_status=$(systemctl is-active usbguard 2>/dev/null || echo "inactive")
        print_color "USBGuard Service: $usbguard_status" "$([ "$usbguard_status" == "active" ] && echo "$GREEN" || echo "$RED")"
        
        if [[ "$usbguard_status" != "active" ]]; then
            add_security_issue "USB/External Media" "USBGuard service is not active" "Medium"
        else
            local usbguard_rules=$(usbguard list-rules 2>/dev/null | wc -l)
            print_color "USBGuard Rules Count: $usbguard_rules" "$([ "$usbguard_rules" -gt 0 ] && echo "$GREEN" || echo "$YELLOW")"
        fi
    else
        print_color "USBGuard: Not installed" "$YELLOW"
        add_security_issue "USB/External Media" "USBGuard is not installed" "Low"
    fi
    
    # Check mount options for removable media
    if command_exists findmnt; then
        print_color "Checking mount options for removable media..." "$WHITE"
        while IFS= read -r line; do
            if [[ $line == *"noexec"* ]]; then
                print_color "  Found noexec mount option: $line" "$GREEN"
            elif [[ $line == *"/media"* || $line == *"/mnt"* ]]; then
                print_color "  Removable media mount without noexec: $line" "$YELLOW"
                add_security_issue "USB/External Media" "Removable media mounted without noexec option" "Medium"
            fi
        done < <(findmnt -D 2>/dev/null)
    fi
}

# Screen lock and session policies
check_screen_lock_policies() {
    print_section_header "SCREEN LOCK POLICIES"
    
    # Check screen lock timeout (depends on desktop environment)
    local screen_lock_found=false
    
    # GNOME settings
    if command_exists gsettings; then
        local lock_enabled=$(gsettings get org.gnome.desktop.screensaver lock-enabled 2>/dev/null || echo "unknown")
        local lock_delay=$(gsettings get org.gnome.desktop.screensaver lock-delay 2>/dev/null || echo "unknown")
        local idle_delay=$(gsettings get org.gnome.desktop.session idle-delay 2>/dev/null || echo "unknown")
        
        if [[ "$lock_enabled" != "unknown" ]]; then
            screen_lock_found=true
            print_color "GNOME Screen Lock Enabled: $lock_enabled" "$([ "$lock_enabled" == "true" ] && echo "$GREEN" || echo "$RED")"
            print_color "GNOME Lock Delay: $lock_delay seconds" "$WHITE"
            print_color "GNOME Idle Delay: $idle_delay seconds" "$WHITE"
            
            if [[ "$lock_enabled" != "true" ]]; then
                add_security_issue "Screen Lock" "GNOME screen lock is disabled" "High"
            fi
        fi
    fi
    
    # KDE settings
    if command_exists kreadconfig5; then
        local kde_lock=$(kreadconfig5 --file kscreenlockerrc --group Daemon --key Autolock 2>/dev/null || echo "unknown")
        local kde_timeout=$(kreadconfig5 --file kscreenlockerrc --group Daemon --key Timeout 2>/dev/null || echo "unknown")
        
        if [[ "$kde_lock" != "unknown" ]]; then
            screen_lock_found=true
            print_color "KDE Screen Lock Enabled: $kde_lock" "$([ "$kde_lock" == "true" ] && echo "$GREEN" || echo "$RED")"
            print_color "KDE Lock Timeout: $kde_timeout minutes" "$WHITE"
            
            if [[ "$kde_lock" != "true" ]]; then
                add_security_issue "Screen Lock" "KDE screen lock is disabled" "High"
            fi
        fi
    fi
    
    # Check for xautolock
    if command_exists xautolock; then
        if pgrep -x xautolock >/dev/null; then
            screen_lock_found=true
            print_color "xautolock: Running" "$GREEN"
        else
            print_color "xautolock: Not running" "$YELLOW"
        fi
    fi
    
    # Check for light-locker
    if command_exists light-locker; then
        if pgrep -x light-locker >/dev/null; then
            screen_lock_found=true
            print_color "light-locker: Running" "$GREEN"
        else
            print_color "light-locker: Not running" "$YELLOW"
        fi
    fi
    
    if [[ "$screen_lock_found" == false ]]; then
        add_security_issue "Screen Lock" "No screen lock mechanism detected" "High"
    fi
    
    # Check session timeout settings
    if [[ -f /etc/profile.d/autologout.sh ]]; then
        local timeout_value=$(grep TMOUT /etc/profile.d/autologout.sh | cut -d'=' -f2 2>/dev/null || echo "0")
        print_color "Session Timeout (TMOUT): $timeout_value seconds" "$([ "$timeout_value" -gt 0 ] && [ "$timeout_value" -le 1800 ] && echo "$GREEN" || echo "$YELLOW")"
        
        if [[ "$timeout_value" -eq 0 ]]; then
            add_security_issue "Screen Lock" "Session timeout is disabled" "Medium"
        elif [[ "$timeout_value" -gt 1800 ]]; then
            add_security_issue "Screen Lock" "Session timeout is too long (>30 minutes)" "Medium"
        fi
    else
        add_security_issue "Screen Lock" "No session timeout configured" "Medium"
    fi
    
    # Check account lockout policies via PAM
    if [[ -f /etc/pam.d/common-auth ]] || [[ -f /etc/pam.d/system-auth ]]; then
        local pam_file="/etc/pam.d/common-auth"
        [[ -f /etc/pam.d/system-auth ]] && pam_file="/etc/pam.d/system-auth"
        
        if grep -q "pam_faillock\|pam_tally" "$pam_file"; then
            print_color "Account Lockout (PAM): Configured" "$GREEN"
            local lockout_config=$(grep "pam_faillock\|pam_tally" "$pam_file")
            print_color "  Configuration: $lockout_config" "$GRAY"
        else
            print_color "Account Lockout (PAM): Not configured" "$YELLOW"
            add_security_issue "Screen Lock" "Account lockout policy is not configured" "Medium"
        fi
    fi
}

# Antivirus status (Linux equivalents)
check_antivirus_status() {
    print_section_header "ANTIVIRUS STATUS"
    
    local av_found=false
    
    # Check ClamAV
    if command_exists clamscan; then
        av_found=true
        print_color "ClamAV: Installed" "$GREEN"
        
        local clamd_status=$(systemctl is-active clamav-daemon 2>/dev/null || systemctl is-active clamd 2>/dev/null || echo "inactive")
        print_color "ClamAV Daemon: $clamd_status" "$([ "$clamd_status" == "active" ] && echo "$GREEN" || echo "$RED")"
        
        if [[ "$clamd_status" != "active" ]]; then
            add_security_issue "Antivirus" "ClamAV daemon is not running" "High"
        fi
        
        # Check freshclam (signature updates)
        local freshclam_status=$(systemctl is-active clamav-freshclam 2>/dev/null || echo "inactive")
        print_color "ClamAV Freshclam: $freshclam_status" "$([ "$freshclam_status" == "active" ] && echo "$GREEN" || echo "$RED")"
        
        if [[ "$freshclam_status" != "active" ]]; then
            add_security_issue "Antivirus" "ClamAV signature updates (freshclam) not running" "Medium"
        fi
        
        # Check signature age
        local db_path="/var/lib/clamav"
        if [[ -f "$db_path/main.cvd" ]] || [[ -f "$db_path/main.cld" ]]; then
            local main_db=$(find "$db_path" -name "main.c?d" -type f 2>/dev/null | head -1)
            if [[ -n "$main_db" ]]; then
                local days_old=$(( ($(date +%s) - $(stat -c %Y "$main_db")) / 86400 ))
                print_color "ClamAV Signatures Age: $days_old days" "$([ "$days_old" -le 7 ] && echo "$GREEN" || echo "$RED")"
                
                if [[ "$days_old" -gt 7 ]]; then
                    add_security_issue "Antivirus" "ClamAV signatures are outdated ($days_old days old)" "High"
                fi
            fi
        fi
    fi
    
    # Check rkhunter
    if command_exists rkhunter; then
        av_found=true
        print_color "RKHunter: Installed" "$GREEN"
        
        local rkhunter_config="/etc/rkhunter.conf"
        if [[ -f "$rkhunter_config" ]]; then
            local auto_update=$(grep "^UPDATE_MIRRORS" "$rkhunter_config" | cut -d'=' -f2 2>/dev/null || echo "0")
            print_color "RKHunter Auto Update: $auto_update" "$([ "$auto_update" == "1" ] && echo "$GREEN" || echo "$YELLOW")"
        fi
    fi
    
    # Check chkrootkit
    if command_exists chkrootkit; then
        av_found=true
        print_color "Chkrootkit: Installed" "$GREEN"
    fi
    
    # Check ESET (if installed)
    if [[ -d /opt/eset ]]; then
        av_found=true
        print_color "ESET NOD32: Installed" "$GREEN"
        
        if command_exists /opt/eset/esets/sbin/esets_daemon; then
            if pgrep -f esets_daemon >/dev/null; then
                print_color "ESET Daemon: Running" "$GREEN"
            else
                print_color "ESET Daemon: Not running" "$RED"
                add_security_issue "Antivirus" "ESET daemon is not running" "High"
            fi
        fi
    fi
    
    # Check Sophos (if installed)
    if [[ -d /opt/sophos-av ]]; then
        av_found=true
        print_color "Sophos: Installed" "$GREEN"
        
        if command_exists /opt/sophos-av/bin/savdstatus; then
            local sophos_status=$(/opt/sophos-av/bin/savdstatus 2>/dev/null | grep "running")
            if [[ -n "$sophos_status" ]]; then
                print_color "Sophos Status: Running" "$GREEN"
            else
                print_color "Sophos Status: Not running" "$RED"
                add_security_issue "Antivirus" "Sophos antivirus is not running" "High"
            fi
        fi
    fi
    
    if [[ "$av_found" == false ]]; then
        print_color "No antivirus software detected" "$RED"
        add_security_issue "Antivirus" "No antivirus software found" "High"
    fi
}

# Firewall status
check_firewall_status() {
    print_section_header "FIREWALL STATUS"
    
    local firewall_found=false
    
    # Check iptables
    if command_exists iptables; then
        firewall_found=true
        print_color "iptables: Available" "$GREEN"
        
        local iptables_rules=$(iptables -L 2>/dev/null | wc -l)
        print_color "iptables Rules Count: $iptables_rules" "$([ "$iptables_rules" -gt 10 ] && echo "$GREEN" || echo "$YELLOW")"
        
        # Check default policies
        local input_policy=$(iptables -L INPUT 2>/dev/null | head -1 | grep -o "(policy [A-Z]*)" | cut -d' ' -f2 | tr -d ')')
        local forward_policy=$(iptables -L FORWARD 2>/dev/null | head -1 | grep -o "(policy [A-Z]*)" | cut -d' ' -f2 | tr -d ')')
        local output_policy=$(iptables -L OUTPUT 2>/dev/null | head -1 | grep -o "(policy [A-Z]*)" | cut -d' ' -f2 | tr -d ')')
        
        print_color "INPUT Policy: $input_policy" "$([ "$input_policy" == "DROP" ] && echo "$GREEN" || echo "$YELLOW")"
        print_color "FORWARD Policy: $forward_policy" "$([ "$forward_policy" == "DROP" ] && echo "$GREEN" || echo "$YELLOW")"
        print_color "OUTPUT Policy: $output_policy" "$WHITE"
        
        if [[ "$input_policy" != "DROP" ]]; then
            add_security_issue "Firewall" "iptables INPUT policy is not DROP" "Medium"
        fi
        if [[ "$forward_policy" != "DROP" ]]; then
            add_security_issue "Firewall" "iptables FORWARD policy is not DROP" "Medium"
        fi
    fi
    
    # Check UFW (Uncomplicated Firewall)
    if command_exists ufw; then
        firewall_found=true
        local ufw_status=$(ufw status 2>/dev/null | head -1)
        print_color "UFW Status: $ufw_status" "$(echo "$ufw_status" | grep -q "active" && echo "$GREEN" || echo "$RED")"
        
        if ! echo "$ufw_status" | grep -q "active"; then
            add_security_issue "Firewall" "UFW firewall is not active" "High"
        fi
        
        # Show UFW rules count
        local ufw_rules=$(ufw status numbered 2>/dev/null | grep -c "^\[")
        print_color "UFW Rules Count: $ufw_rules" "$([ "$ufw_rules" -gt 0 ] && echo "$GREEN" || echo "$YELLOW")"
    fi
    
    # Check firewalld
    if command_exists firewall-cmd; then
        firewall_found=true
        local firewalld_status=$(systemctl is-active firewalld 2>/dev/null || echo "inactive")
        print_color "firewalld Status: $firewalld_status" "$([ "$firewalld_status" == "active" ] && echo "$GREEN" || echo "$RED")"
        
        if [[ "$firewalld_status" != "active" ]]; then
            add_security_issue "Firewall" "firewalld service is not active" "High"
        else
            local default_zone=$(firewall-cmd --get-default-zone 2>/dev/null)
            print_color "Default Zone: $default_zone" "$WHITE"
            
            local active_zones=$(firewall-cmd --get-active-zones 2>/dev/null | grep -v "interfaces\|sources")
            print_color "Active Zones: $active_zones" "$WHITE"
        fi
    fi
    
    # Check nftables
    if command_exists nft; then
        firewall_found=true
        local nft_rules=$(nft list tables 2>/dev/null | wc -l)
        print_color "nftables Tables: $nft_rules" "$([ "$nft_rules" -gt 0 ] && echo "$GREEN" || echo "$YELLOW")"
        
        if [[ "$nft_rules" -eq 0 ]]; then
            add_security_issue "Firewall" "No nftables rules configured" "Medium"
        fi
    fi
    
    if [[ "$firewall_found" == false ]]; then
        print_color "No firewall detected" "$RED"
        add_security_issue "Firewall" "No firewall software found" "Critical"
    fi
}

# Application security and mandatory access controls
check_application_security() {
    print_section_header "APPLICATION SECURITY CONTROLS"
    
    # Check SELinux
    if command_exists getenforce; then
        local selinux_status=$(getenforce 2>/dev/null)
        print_color "SELinux Status: $selinux_status" "$([ "$selinux_status" == "Enforcing" ] && echo "$GREEN" || echo "$YELLOW")"
        
        if [[ "$selinux_status" == "Disabled" ]]; then
            add_security_issue "Application Security" "SELinux is disabled" "High"
        elif [[ "$selinux_status" == "Permissive" ]]; then
            add_security_issue "Application Security" "SELinux is in permissive mode" "Medium"
        fi
        
        if [[ "$selinux_status" != "Disabled" ]]; then
            local selinux_policy=$(sestatus 2>/dev/null | grep "Current mode" | cut -d: -f2 | xargs)
            local selinux_type=$(sestatus 2>/dev/null | grep "Policy name" | cut -d: -f2 | xargs)
            print_color "SELinux Policy: $selinux_type" "$WHITE"
        fi
    fi
    
    # Check AppArmor
    if command_exists aa-status; then
        local apparmor_status=$(systemctl is-active apparmor 2>/dev/null || echo "inactive")
        print_color "AppArmor Status: $apparmor_status" "$([ "$apparmor_status" == "active" ] && echo "$GREEN" || echo "$RED")"
        
        if [[ "$apparmor_status" != "active" ]]; then
            add_security_issue "Application Security" "AppArmor is not active" "High"
        else
            local profiles_loaded=$(aa-status 2>/dev/null | grep "profiles are loaded" | cut -d' ' -f1)
            local profiles_enforcing=$(aa-status 2>/dev/null | grep "profiles are in enforce mode" | cut -d' ' -f1)
            local profiles_complain=$(aa-status 2>/dev/null | grep "profiles are in complain mode" | cut -d' ' -f1)
            
            print_color "AppArmor Profiles Loaded: $profiles_loaded" "$WHITE"
            print_color "AppArmor Profiles Enforcing: $profiles_enforcing" "$([ "$profiles_enforcing" -gt 0 ] && echo "$GREEN" || echo "$YELLOW")"
            print_color "AppArmor Profiles Complaining: $profiles_complain" "$WHITE"
            
            if [[ "$profiles_enforcing" -eq 0 ]]; then
                add_security_issue "Application Security" "No AppArmor profiles in enforce mode" "Medium"
            fi
        fi
    fi
    
    # Check grsecurity/PaX (if available)
    if [[ -f /proc/sys/kernel/grsecurity/grsec_lock ]]; then
        local grsec_status=$(cat /proc/sys/kernel/grsecurity/grsec_lock 2>/dev/null)
        print_color "Grsecurity Lock: $grsec_status" "$([ "$grsec_status" == "1" ] && echo "$GREEN" || echo "$YELLOW")"
    fi
    
    # Check ASLR (Address Space Layout Randomization)
    if [[ -f /proc/sys/kernel/randomize_va_space ]]; then
        local aslr_status=$(cat /proc/sys/kernel/randomize_va_space 2>/dev/null)
        local aslr_text="Disabled"
        [[ "$aslr_status" == "1" ]] && aslr_text="Conservative"
        [[ "$aslr_status" == "2" ]] && aslr_text="Full"
        
        print_color "ASLR Status: $aslr_text ($aslr_status)" "$([ "$aslr_status" == "2" ] && echo "$GREEN" || echo "$YELLOW")"
        
        if [[ "$aslr_status" == "0" ]]; then
            add_security_issue "Application Security" "ASLR is disabled" "High"
        elif [[ "$aslr_status" == "1" ]]; then
            add_security_issue "Application Security" "ASLR is only in conservative mode" "Medium"
        fi
    fi
    
    # Check DEP/NX bit
    if grep -q " nx " /proc/cpuinfo; then
        print_color "NX Bit (DEP): Supported" "$GREEN"
    else
        print_color "NX Bit (DEP): Not supported" "$RED"
        add_security_issue "Application Security" "NX bit (DEP) is not supported by CPU" "High"
    fi
    
    # Check kernel.exec-shield (if available)
    if [[ -f /proc/sys/kernel/exec-shield ]]; then
        local exec_shield=$(cat /proc/sys/kernel/exec-shield 2>/dev/null)
        print_color "Exec Shield: $exec_shield" "$([ "$exec_shield" == "1" ] && echo "$GREEN" || echo "$YELLOW")"
        
        if [[ "$exec_shield" != "1" ]]; then
            add_security_issue "Application Security" "Exec Shield is disabled" "Medium"
        fi
    fi
    
    # Check for PIE (Position Independent Executable) support
    if command_exists hardening-check; then
        print_color "PIE/Hardening Analysis Available: Yes (hardening-check)" "$GREEN"
    else
        print_color "PIE/Hardening Analysis: hardening-check not installed" "$YELLOW"
        add_security_issue "Application Security" "hardening-check tool not available for binary analysis" "Low"
    fi
    
    # Check sysctl security settings
    local security_sysctls=(
        "kernel.dmesg_restrict:1"
        "kernel.kptr_restrict:2"
        "kernel.yama.ptrace_scope:1"
        "net.ipv4.conf.all.send_redirects:0"
        "net.ipv4.conf.default.send_redirects:0"
        "net.ipv4.conf.all.accept_redirects:0"
        "net.ipv4.conf.default.accept_redirects:0"
        "net.ipv4.conf.all.accept_source_route:0"
        "net.ipv4.conf.default.accept_source_route:0"
        "net.ipv4.icmp_echo_ignore_broadcasts:1"
        "net.ipv4.ip_forward:0"
    )
    
    print_color "\nKernel Security Parameters:" "$WHITE"
    for sysctl_setting in "${security_sysctls[@]}"; do
        local param=$(echo "$sysctl_setting" | cut -d: -f1)
        local expected=$(echo "$sysctl_setting" | cut -d: -f2)
        local current=$(sysctl -n "$param" 2>/dev/null || echo "unknown")
        
        local color="$RED"
        [[ "$current" == "$expected" ]] && color="$GREEN"
        [[ "$current" == "unknown" ]] && color="$YELLOW"
        
        print_color "  $param: $current (expected: $expected)" "$color"
        
        if [[ "$current" != "$expected" && "$current" != "unknown" ]]; then
            add_security_issue "Application Security" "Kernel parameter $param is not securely configured" "Medium"
        fi
    done
}

# Additional security checks
check_additional_security() {
    print_section_header "ADDITIONAL SECURITY CHECKS"
    
    # Check for fail2ban
    if command_exists fail2ban-client; then
        local fail2ban_status=$(systemctl is-active fail2ban 2>/dev/null || echo "inactive")
        print_color "Fail2ban Status: $fail2ban_status" "$([ "$fail2ban_status" == "active" ] && echo "$GREEN" || echo "$RED")"
        
        if [[ "$fail2ban_status" == "active" ]]; then
            local jail_count=$(fail2ban-client status 2>/dev/null | grep "Jail list" | cut -d: -f2 | wc -w)
            print_color "Fail2ban Active Jails: $jail_count" "$([ "$jail_count" -gt 0 ] && echo "$GREEN" || echo "$YELLOW")"
        else
            add_security_issue "Additional Security" "Fail2ban is not running" "Medium"
        fi
    else
        print_color "Fail2ban: Not installed" "$YELLOW"
        add_security_issue "Additional Security" "Fail2ban is not installed" "Low"
    fi
    
    # Check SSH configuration
    if [[ -f /etc/ssh/sshd_config ]]; then
        print_color "SSH Configuration Analysis:" "$WHITE"
        
        local ssh_settings=(
            "PermitRootLogin:no"
            "PasswordAuthentication:no"
            "PermitEmptyPasswords:no"
            "X11Forwarding:no"
            "Protocol:2"
        )
        
        for setting in "${ssh_settings[@]}"; do
            local param=$(echo "$setting" | cut -d: -f1)
            local expected=$(echo "$setting" | cut -d: -f2)
            local current=$(grep "^$param" /etc/ssh/sshd_config | awk '{print tolower($2)}' | head -1)
            
            if [[ -n "$current" ]]; then
                local color="$RED"
                [[ "$current" == "$expected" ]] && color="$GREEN"
                
                print_color "  $param: $current" "$color"
                
                if [[ "$current" != "$expected" ]]; then
                    add_security_issue "SSH Security" "SSH $param is not securely configured" "High"
                fi
            else
                print_color "  $param: not configured (default may apply)" "$YELLOW"
                add_security_issue "SSH Security" "SSH $param is not explicitly configured" "Medium"
            fi
        done
        
        # Check SSH key algorithms
        local ssh_algos=$(grep "^KexAlgorithms\|^Ciphers\|^MACs" /etc/ssh/sshd_config 2>/dev/null)
        if [[ -n "$ssh_algos" ]]; then
            print_color "  Cryptographic algorithms explicitly configured" "$GREEN"
        else
            print_color "  Using default cryptographic algorithms" "$YELLOW"
            add_security_issue "SSH Security" "SSH cryptographic algorithms not explicitly configured" "Low"
        fi
    fi
    
    # Check for rootkits with basic commands
    print_color "Basic Rootkit Checks:" "$WHITE"
    
    # Check for suspicious processes
    local suspicious_procs=$(ps aux | grep -E "\[.*\]$|^$" | grep -v grep | wc -l)
    print_color "  Suspicious process names: $suspicious_procs" "$([ "$suspicious_procs" -eq 0 ] && echo "$GREEN" || echo "$YELLOW")"
    
    # Check for hidden files in common locations
    local hidden_files=$(find /tmp /var/tmp -name ".*" -type f 2>/dev/null | wc -l)
    print_color "  Hidden files in temp directories: $hidden_files" "$([ "$hidden_files" -lt 10 ] && echo "$GREEN" || echo "$YELLOW")"
    
    # Check file permissions on critical files
    print_color "Critical File Permissions:" "$WHITE"
    
    local critical_files=(
        "/etc/passwd:644"
        "/etc/shadow:640"
        "/etc/sudoers:440"
        "/etc/ssh/ssh_host_rsa_key:600"
    )
    
    for file_perm in "${critical_files[@]}"; do
        local file_path=$(echo "$file_perm" | cut -d: -f1)
        local expected_perm=$(echo "$file_perm" | cut -d: -f2)
        
        if [[ -f "$file_path" ]]; then
            local current_perm=$(stat -c "%a" "$file_path" 2>/dev/null)
            local color="$RED"
            [[ "$current_perm" == "$expected_perm" ]] && color="$GREEN"
            
            print_color "  $file_path: $current_perm (expected: $expected_perm)" "$color"
            
            if [[ "$current_perm" != "$expected_perm" ]]; then
                add_security_issue "File Permissions" "$file_path has incorrect permissions ($current_perm)" "High"
            fi
        fi
    done
    
    # Check for SUID/SGID files
    print_color "SUID/SGID Analysis:" "$WHITE"
    local suid_count=$(find / -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null | wc -l)
    print_color "  Total SUID/SGID files: $suid_count" "$WHITE"
    
    # Check for world-writable files
    local world_writable=$(find / -type f -perm -002 2>/dev/null | grep -v "/proc\|/sys\|/dev" | wc -l)
    print_color "  World-writable files: $world_writable" "$([ "$world_writable" -eq 0 ] && echo "$GREEN" || echo "$YELLOW")"
    
    if [[ "$world_writable" -gt 0 ]]; then
        add_security_issue "File Permissions" "$world_writable world-writable files found" "Medium"
    fi
}

# System information and updates
check_system_updates() {
    print_section_header "SYSTEM UPDATES AND INFORMATION"
    
    print_color "System Information:" "$WHITE"
    print_color "  Hostname: $(hostname)" "$GRAY"
    print_color "  Kernel: $(uname -r)" "$GRAY"
    print_color "  Distribution: $DISTRO_NAME" "$GRAY"
    print_color "  Architecture: $(uname -m)" "$GRAY"
    print_color "  Uptime: $(uptime -p 2>/dev/null || uptime)" "$GRAY"
    
    # Check for available updates based on distribution
    case "$DISTRO" in
        "ubuntu"|"debian")
            if command_exists apt; then
                print_color "Checking APT updates..." "$WHITE"
                apt update >/dev/null 2>&1
                local upgradable=$(apt list --upgradable 2>/dev/null | wc -l)
                local security_updates=$(apt list --upgradable 2>/dev/null | grep -c security || echo "0")
                
                print_color "  Available updates: $upgradable" "$([ "$upgradable" -eq 1 ] && echo "$GREEN" || echo "$YELLOW")"
                print_color "  Security updates: $security_updates" "$([ "$security_updates" -eq 0 ] && echo "$GREEN" || echo "$RED")"
                
                if [[ "$security_updates" -gt 0 ]]; then
                    add_security_issue "System Updates" "$security_updates security updates available" "High"
                fi
                if [[ "$upgradable" -gt 20 ]]; then
                    add_security_issue "System Updates" "Many updates available ($upgradable packages)" "Medium"
                fi
            fi
            ;;
        "centos"|"rhel"|"fedora")
            if command_exists yum; then
                print_color "Checking YUM updates..." "$WHITE"
                local updates=$(yum check-update 2>/dev/null | grep -v "^$" | wc -l)
                local security_updates=$(yum --security check-update 2>/dev/null | grep -v "^$" | wc -l)
                
                print_color "  Available updates: $updates" "$([ "$updates" -eq 0 ] && echo "$GREEN" || echo "$YELLOW")"
                print_color "  Security updates: $security_updates" "$([ "$security_updates" -eq 0 ] && echo "$GREEN" || echo "$RED")"
                
                if [[ "$security_updates" -gt 0 ]]; then
                    add_security_issue "System Updates" "$security_updates security updates available" "High"
                fi
            elif command_exists dnf; then
                print_color "Checking DNF updates..." "$WHITE"
                local updates=$(dnf check-update 2>/dev/null | grep -v "^$" | wc -l)
                
                print_color "  Available updates: $updates" "$([ "$updates" -eq 0 ] && echo "$GREEN" || echo "$YELLOW")"
                
                if [[ "$updates" -gt 20 ]]; then
                    add_security_issue "System Updates" "Many updates available ($updates packages)" "Medium"
                fi
            fi
            ;;
        "arch")
            if command_exists pacman; then
                print_color "Checking Pacman updates..." "$WHITE"
                local updates=$(pacman -Qu 2>/dev/null | wc -l)
                
                print_color "  Available updates: $updates" "$([ "$updates" -eq 0 ] && echo "$GREEN" || echo "$YELLOW")"
                
                if [[ "$updates" -gt 20 ]]; then
                    add_security_issue "System Updates" "Many updates available ($updates packages)" "Medium"
                fi
            fi
            ;;
    esac
    
    # Check automatic updates configuration
    if [[ -f /etc/apt/apt.conf.d/20auto-upgrades ]]; then
        local auto_updates=$(grep "APT::Periodic::Unattended-Upgrade" /etc/apt/apt.conf.d/20auto-upgrades | cut -d'"' -f4)
        print_color "Automatic Security Updates: $([ "$auto_updates" == "1" ] && echo "Enabled" || echo "Disabled")" "$([ "$auto_updates" == "1" ] && echo "$GREEN" || echo "$YELLOW")"
        
        if [[ "$auto_updates" != "1" ]]; then
            add_security_issue "System Updates" "Automatic security updates are disabled" "Medium"
        fi
    fi
}

# Security summary function
write_security_summary() {
    print_section_header "SECURITY ISSUES SUMMARY"
    
    if [[ ${#SECURITY_ISSUES[@]} -eq 0 ]]; then
        print_color "No critical security issues detected!" "$GREEN"
        print_color "Your system appears to be well-configured." "$GREEN"
        return
    fi
    
    print_color "Found ${#SECURITY_ISSUES[@]} security issues that need attention:\n" "$YELLOW"
    
    # Count issues by severity
    local critical_count=0
    local high_count=0
    local medium_count=0
    local low_count=0
    
    for i in "${!SECURITY_ISSUES[@]}"; do
        case "${ISSUE_SEVERITIES[$i]}" in
            "Critical") ((critical_count++)) ;;
            "High") ((high_count++)) ;;
            "Medium") ((medium_count++)) ;;
            "Low") ((low_count++)) ;;
        esac
    done
    
    # Display issues by severity
    if [[ $critical_count -gt 0 ]]; then
        print_color "CRITICAL ISSUES:" "$RED"
        for i in "${!SECURITY_ISSUES[@]}"; do
            if [[ "${ISSUE_SEVERITIES[$i]}" == "Critical" ]]; then
                print_color "   [${ISSUE_CATEGORIES[$i]}] ${SECURITY_ISSUES[$i]}" "$RED"
            fi
        done
        echo ""
    fi
    
    if [[ $high_count -gt 0 ]]; then
        print_color "HIGH PRIORITY ISSUES:" "$RED"
        for i in "${!SECURITY_ISSUES[@]}"; do
            if [[ "${ISSUE_SEVERITIES[$i]}" == "High" ]]; then
                print_color "   [${ISSUE_CATEGORIES[$i]}] ${SECURITY_ISSUES[$i]}" "$RED"
            fi
        done
        echo ""
    fi
    
    if [[ $medium_count -gt 0 ]]; then
        print_color "MEDIUM PRIORITY ISSUES:" "$YELLOW"
        for i in "${!SECURITY_ISSUES[@]}"; do
            if [[ "${ISSUE_SEVERITIES[$i]}" == "Medium" ]]; then
                print_color "   [${ISSUE_CATEGORIES[$i]}] ${SECURITY_ISSUES[$i]}" "$YELLOW"
            fi
        done
        echo ""
    fi
    
    if [[ $low_count -gt 0 ]]; then
        print_color "LOW PRIORITY ISSUES:" "$GRAY"
        for i in "${!SECURITY_ISSUES[@]}"; do
            if [[ "${ISSUE_SEVERITIES[$i]}" == "Low" ]]; then
                print_color "   [${ISSUE_CATEGORIES[$i]}] ${SECURITY_ISSUES[$i]}" "$GRAY"
            fi
        done
        echo ""
    fi
    
    print_color "Summary:" "$WHITE"
    print_color "  Critical: $critical_count" "$([ $critical_count -eq 0 ] && echo "$GREEN" || echo "$RED")"
    print_color "  High: $high_count" "$([ $high_count -eq 0 ] && echo "$GREEN" || echo "$RED")"
    print_color "  Medium: $medium_count" "$([ $medium_count -eq 0 ] && echo "$GREEN" || echo "$YELLOW")"
    print_color "  Low: $low_count" "$([ $low_count -eq 0 ] && echo "$GREEN" || echo "$GRAY")"
}

# Export results function
export_results() {
    local output_path="$1"
    
    if [[ -n "$output_path" ]]; then
        print_section_header "EXPORTING RESULTS"
        
        local timestamp=$(date +"%Y-%m-%d_%H-%M-%S")
        local filename="SecurityAudit_$(hostname)_$timestamp.txt"
        local full_path="$output_path/$filename"
        
        # Create output directory if it doesn't exist
        mkdir -p "$output_path"
        
        {
            echo "Linux Security Audit Report"
            echo "Generated: $(date)"
            echo "Hostname: $(hostname)"
            echo "User: $(whoami)"
            echo "Distribution: $DISTRO_NAME"
            echo "Kernel: $(uname -r)"
            echo "================================================================"
            echo ""
            
            # Re-run all checks and capture output (this is a simplified approach)
            echo "=== DISK ENCRYPTION STATUS ==="
            check_disk_encryption 2>&1 | sed 's/\x1b\[[0-9;]*m//g'
            echo ""
            
            echo "=== BOOT SECURITY STATUS ==="
            check_boot_security 2>&1 | sed 's/\x1b\[[0-9;]*m//g'
            echo ""
            
            echo "=== USB/EXTERNAL MEDIA POLICIES ==="
            check_usb_policies 2>&1 | sed 's/\x1b\[[0-9;]*m//g'
            echo ""
            
            echo "=== SCREEN LOCK POLICIES ==="
            check_screen_lock_policies 2>&1 | sed 's/\x1b\[[0-9;]*m//g'
            echo ""
            
            echo "=== ANTIVIRUS STATUS ==="
            check_antivirus_status 2>&1 | sed 's/\x1b\[[0-9;]*m//g'
            echo ""
            
            echo "=== FIREWALL STATUS ==="
            check_firewall_status 2>&1 | sed 's/\x1b\[[0-9;]*m//g'
            echo ""
            
            echo "=== APPLICATION SECURITY CONTROLS ==="
            check_application_security 2>&1 | sed 's/\x1b\[[0-9;]*m//g'
            echo ""
            
            echo "=== ADDITIONAL SECURITY CHECKS ==="
            check_additional_security 2>&1 | sed 's/\x1b\[[0-9;]*m//g'
            echo ""
            
            echo "=== SYSTEM UPDATES AND INFORMATION ==="
            check_system_updates 2>&1 | sed 's/\x1b\[[0-9;]*m//g'
            echo ""
            
            echo "=== SECURITY ISSUES SUMMARY ==="
            for i in "${!SECURITY_ISSUES[@]}"; do
                echo "[${ISSUE_SEVERITIES[$i]}] [${ISSUE_CATEGORIES[$i]}] ${SECURITY_ISSUES[$i]}"
            done
            
        } > "$full_path"
        
        print_color "Results exported to: $full_path" "$GREEN"
    fi
}

# Main function
main() {
    local export_path=""
    
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -e|--export)
                export_path="$2"
                shift 2
                ;;
            -h|--help)
                echo "Usage: $0 [OPTIONS]"
                echo "Options:"
                echo "  -e, --export PATH    Export results to specified directory"
                echo "  -h, --help          Show this help message"
                exit 0
                ;;
            *)
                echo "Unknown option: $1"
                echo "Use -h or --help for usage information"
                exit 1
                ;;
        esac
    done
    
    # ASCII Art Header
    print_color "" "$CYAN"
    print_color "██      ██      ██   ██  ██████ " "$CYAN"
    print_color "██      ██      ██   ██ ██      " "$CYAN"
    print_color "██      ██      ███████ ██      " "$CYAN"
    print_color "██      ██      ██   ██ ██      " "$CYAN"
    print_color "███████ ███████ ██   ██  ██████ " "$CYAN"
    print_color "" "$CYAN"
    print_color "Local Linux Hardening Check" "$CYAN"
    print_color "" "$WHITE"
    
    print_color "Starting comprehensive security audit..." "$WHITE"
    print_color "Hostname: $(hostname)" "$GRAY"
    print_color "Date: $(date)" "$GRAY"
    print_color "User: $(whoami)" "$GRAY"
    
    # Detect distribution
    detect_distro
    print_color "Distribution: $DISTRO_NAME" "$GRAY"
    
    # Run all security checks
    check_disk_encryption
    check_boot_security
    check_usb_policies
    check_screen_lock_policies
    check_antivirus_status
    check_firewall_status
    check_application_security
    check_additional_security
    check_system_updates
    
    # Display summary
    write_security_summary
    
    # Export results if requested
    if [[ -n "$export_path" ]]; then
        export_results "$export_path"
    fi
    
    print_section_header "AUDIT COMPLETED"
    print_color "Security audit completed successfully!" "$GREEN"
    print_color "Review the findings above and address any security issues identified." "$WHITE"
}

# Check if running as root
check_root

# Run main function with all arguments
main "$@"