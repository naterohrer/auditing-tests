#sp00ky script to give you a rough idea of your win system hardening
#some code below was written/rewritten by Claude AI /fulldisclosure

# Parameter handling
param(
    [Parameter(Mandatory=$false)]
    [string]$ExportPath
)

# Global variable to track security issues
$script:SecurityIssues = @()

# Color coding for output
function Write-ColorOutput {
    param(
        [string]$Message,
        [string]$Color = "White"
    )
    
    # Validate color parameter
    $validColors = @("Black", "DarkBlue", "DarkGreen", "DarkCyan", "DarkRed", "DarkMagenta", "DarkYellow", "Gray", "DarkGray", "Blue", "Green", "Cyan", "Red", "Magenta", "Yellow", "White")
    
    if ($Color -in $validColors) {
        Write-Host $Message -ForegroundColor $Color
    } else {
        Write-Host $Message -ForegroundColor White
    }
}

function Write-SectionHeader {
    param([string]$Title)
    Write-Host "`n================================================================" -ForegroundColor Cyan
    Write-Host $Title.ToUpper() -ForegroundColor Cyan
    Write-Host "================================================================" -ForegroundColor Cyan
}

function Add-SecurityIssue {
    param(
        [string]$Category,
        [string]$Issue,
        [string]$Severity = "Medium"
    )
    $script:SecurityIssues += [PSCustomObject]@{
        Category = $Category
        Issue = $Issue
        Severity = $Severity
    }
}

function Write-SecuritySummary {
    Write-SectionHeader "SECURITY ISSUES SUMMARY"
    
    if ($script:SecurityIssues.Count -eq 0) {
        Write-ColorOutput "No critical security issues detected!" "Green"
        Write-ColorOutput "Your system appears to be well-configured." "Green"
        return
    }
    
    Write-ColorOutput "Found $($script:SecurityIssues.Count) security issues that need attention:`n" "Yellow"
    
    # Group by severity
    $critical = $script:SecurityIssues | Where-Object { $_.Severity -eq "Critical" }
    $high = $script:SecurityIssues | Where-Object { $_.Severity -eq "High" }
    $medium = $script:SecurityIssues | Where-Object { $_.Severity -eq "Medium" }
    $low = $script:SecurityIssues | Where-Object { $_.Severity -eq "Low" }
    
    if ($critical) {
        Write-ColorOutput "CRITICAL ISSUES:" "Red"
        foreach ($issue in $critical) {
            Write-ColorOutput "   [$($issue.Category)] $($issue.Issue)" "Red"
        }
        Write-Host ""
    }
    
    if ($high) {
        Write-ColorOutput "HIGH PRIORITY ISSUES:" "Red"
        foreach ($issue in $high) {
            Write-ColorOutput "   [$($issue.Category)] $($issue.Issue)" "Red"
        }
        Write-Host ""
    }
    
    if ($medium) {
        Write-ColorOutput "MEDIUM PRIORITY ISSUES:" "Yellow"
        foreach ($issue in $medium) {
            Write-ColorOutput "   [$($issue.Category)] $($issue.Issue)" "Yellow"
        }
        Write-Host ""
    }
    
    if ($low) {
        Write-ColorOutput "LOW PRIORITY ISSUES:" "Gray"
        foreach ($issue in $low) {
            Write-ColorOutput "   [$($issue.Category)] $($issue.Issue)" "Gray"
        }
        Write-Host ""
    }
    
    Write-ColorOutput "Summary:" "White"
    Write-ColorOutput "  Critical: $($critical.Count)" $(if($critical.Count -gt 0) {"Red"} else {"Green"})
    Write-ColorOutput "  High: $($high.Count)" $(if($high.Count -gt 0) {"Red"} else {"Green"})
    Write-ColorOutput "  Medium: $($medium.Count)" $(if($medium.Count -gt 0) {"Yellow"} else {"Green"})
    Write-ColorOutput "  Low: $($low.Count)" $(if($low.Count -gt 0) {"Gray"} else {"Green"})
}

function Get-BitLockerStatus {
    Write-SectionHeader "BITLOCKER ENCRYPTION STATUS"
    
    try {
        $bitlockerVolumes = Get-BitLockerVolume -ErrorAction SilentlyContinue
        
        if ($bitlockerVolumes) {
            foreach ($volume in $bitlockerVolumes) {
                Write-ColorOutput "Drive: $($volume.MountPoint)" "Yellow"
                Write-ColorOutput "  Protection Status: $($volume.ProtectionStatus)" $(if($volume.ProtectionStatus -eq "On") {"Green"} else {"Red"})
                Write-ColorOutput "  Lock Status: $($volume.LockStatus)" $(if($volume.LockStatus -eq "Unlocked") {"Green"} else {"Yellow"})
                Write-ColorOutput "  Encryption Percentage: $($volume.EncryptionPercentage)%" $(if($volume.EncryptionPercentage -eq 100) {"Green"} else {"Yellow"})
                Write-ColorOutput "  Volume Status: $($volume.VolumeStatus)" $(if($volume.VolumeStatus -eq "FullyEncrypted") {"Green"} else {"Yellow"})
                Write-ColorOutput "  Encryption Method: $($volume.EncryptionMethod)" "White"
                
                if ($volume.ProtectionStatus -ne "On") {
                    Add-SecurityIssue -Category "BitLocker" -Issue "Drive $($volume.MountPoint) is not protected by BitLocker" -Severity "High"
                }
                if ($volume.EncryptionPercentage -lt 100) {
                    Add-SecurityIssue -Category "BitLocker" -Issue "Drive $($volume.MountPoint) encryption is incomplete ($($volume.EncryptionPercentage)%)" -Severity "Medium"
                }
                
                if ($volume.KeyProtector) {
                    Write-ColorOutput "  Key Protectors:" "White"
                    foreach ($kp in $volume.KeyProtector) {
                        Write-ColorOutput "    - $($kp.KeyProtectorType)" "Gray"
                    }
                } else {
                    Add-SecurityIssue -Category "BitLocker" -Issue "Drive $($volume.MountPoint) has no key protectors configured" -Severity "Critical"
                }
                Write-Host ""
            }
        } else {
            Write-ColorOutput "BitLocker is not available or no encrypted volumes found" "Red"
            Add-SecurityIssue -Category "BitLocker" -Issue "No BitLocker encrypted volumes found" -Severity "High"
        }
    }
    catch {
        Write-ColorOutput "Error checking BitLocker status: $($_.Exception.Message)" "Red"
        Add-SecurityIssue -Category "BitLocker" -Issue "Unable to check BitLocker status" -Severity "Medium"
    }
}

function Get-BootSecurity {
    Write-SectionHeader "BOOT SECURITY STATUS"
    
    # Check Secure Boot
    try {
        $secureBootState = Confirm-SecureBootUEFI -ErrorAction SilentlyContinue
        Write-ColorOutput "Secure Boot Status: $(if($secureBootState) {'Enabled'} else {'Disabled'})" $(if($secureBootState) {"Green"} else {"Red"})
        
        if (-not $secureBootState) {
            Add-SecurityIssue -Category "Boot Security" -Issue "Secure Boot is disabled" -Severity "High"
        }
    }
    catch {
        Write-ColorOutput "Secure Boot Status: Unable to determine (Legacy BIOS or unsupported)" "Yellow"
        Add-SecurityIssue -Category "Boot Security" -Issue "Secure Boot status cannot be determined - may be Legacy BIOS" -Severity "Medium"
    }
    
    # Check TPM Status
    try {
        $tpm = Get-Tpm -ErrorAction SilentlyContinue
        if ($tpm) {
            Write-ColorOutput "TPM Present: $($tpm.TpmPresent)" $(if($tpm.TmpPresent) {"Green"} else {"Red"})
            Write-ColorOutput "TPM Ready: $($tpm.TmpReady)" $(if($tpm.TmpReady) {"Green"} else {"Red"})
            Write-ColorOutput "TPM Enabled: $($tpm.TmpEnabled)" $(if($tpm.TmpEnabled) {"Green"} else {"Red"})
            Write-ColorOutput "TPM Activated: $($tpm.TmpActivated)" $(if($tpm.TmpActivated) {"Green"} else {"Red"})
            Write-ColorOutput "TPM Owned: $($tpm.TmpOwned)" $(if($tpm.TmpOwned) {"Green"} else {"Yellow"})
            
            # Track TPM issues
            if (-not $tpm.TmpPresent) {
                Add-SecurityIssue -Category "Boot Security" -Issue "TPM chip is not present" -Severity "High"
            }
            if ($tpm.TmpPresent -and -not $tpm.TmpReady) {
                Add-SecurityIssue -Category "Boot Security" -Issue "TPM chip is present but not ready" -Severity "Medium"
            }
            if ($tpm.TmpPresent -and -not $tpm.TmpEnabled) {
                Add-SecurityIssue -Category "Boot Security" -Issue "TPM chip is present but not enabled" -Severity "High"
            }
            if ($tpm.TmpPresent -and -not $tpm.TmpActivated) {
                Add-SecurityIssue -Category "Boot Security" -Issue "TPM chip is present but not activated" -Severity "Medium"
            }
            
            # Get TPM version
            $tmpVersion = Get-WmiObject -Class Win32_Tpm -Namespace "ROOT\CIMV2\Security\MicrosoftTpm" -ErrorAction SilentlyContinue
            if ($tmpVersion) {
                Write-ColorOutput "TPM Version: $($tmpVersion.SpecVersion)" "White"
                if ($tmpVersion.SpecVersion -lt "2.0") {
                    Add-SecurityIssue -Category "Boot Security" -Issue "TPM version is below 2.0" -Severity "Medium"
                }
            }
        } else {
            Write-ColorOutput "TPM: Not found or not accessible" "Red"
            Add-SecurityIssue -Category "Boot Security" -Issue "TPM not found or not accessible" -Severity "High"
        }
    }
    catch {
        Write-ColorOutput "Error checking TPM status: $($_.Exception.Message)" "Red"
        Add-SecurityIssue -Category "Boot Security" -Issue "Unable to check TPM status" -Severity "Medium"
    }
    
    # Check UEFI vs Legacy Boot
    try {
        $bootMode = (Get-ComputerInfo).BiosFirmwareType
        Write-ColorOutput "Boot Mode: $bootMode" $(if($bootMode -eq "Uefi") {"Green"} else {"Yellow"})
        
        if ($bootMode -ne "Uefi") {
            Add-SecurityIssue -Category "Boot Security" -Issue "System is using Legacy BIOS instead of UEFI" -Severity "Medium"
        }
    }
    catch {
        Write-ColorOutput "Boot Mode: Unable to determine" "Yellow"
        Add-SecurityIssue -Category "Boot Security" -Issue "Unable to determine boot mode" -Severity "Low"
    }
}

function Get-USBPolicies {
    Write-SectionHeader "USB/EXTERNAL MEDIA POLICIES"
    
# removable media
    $usbPolicies = @(
        @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\USBSTOR"; Name="Start"; Description="USB Storage Service"},
        @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices"; Name="Deny_All"; Description="Deny All Removable Storage"},
        @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices\{53f56307-b6bf-11d0-94f2-00a0c91efb8b}"; Name="Deny_Write"; Description="Deny Write to Removable Disks"},
        @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices\{53f56307-b6bf-11d0-94f2-00a0c91efb8b}"; Name="Deny_Read"; Description="Deny Read from Removable Disks"}
    )
    
    foreach ($policy in $usbPolicies) {
        try {
            $value = Get-ItemProperty -Path $policy.Path -Name $policy.Name -ErrorAction SilentlyContinue
            if ($value) {
                $status = $value.($policy.Name)
                Write-ColorOutput "$($policy.Description): $status" $(if($status -eq 4 -or $status -eq 1) {"Red"} elseif($status -eq 3) {"Green"} else {"Yellow"})
            } else {
                Write-ColorOutput "$($policy.Description): Not configured" "Yellow"
                Add-SecurityIssue -Category "USB/External Media" -Issue "$($policy.Description) is not configured" -Severity "Medium"
            }
        }
        catch {
            Write-ColorOutput "$($policy.Description): Not configured" "Yellow"
            Add-SecurityIssue -Category "USB/External Media" -Issue "$($policy.Description) is not configured" -Severity "Medium"
        }
    }
    
# mobile bitlocker policies
    try {
        $btgPolicy = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -ErrorAction SilentlyContinue
        if ($btgPolicy) {
            Write-ColorOutput "`nBitLocker To Go Policies:" "White"
            if ($btgPolicy.RDVRequireEncryption) {
                Write-ColorOutput "  Require encryption for removable drives: $($btgPolicy.RDVRequireEncryption)" "Green"
            }
            if ($btgPolicy.RDVDenyWriteAccess) {
                Write-ColorOutput "  Deny write access to unencrypted drives: $($btgPolicy.RDVDenyWriteAccess)" "Green"
            }
        } else {
            Write-ColorOutput "BitLocker To Go policies: Not configured" "Yellow"
            Add-SecurityIssue -Category "USB/External Media" -Issue "BitLocker To Go policies are not configured" -Severity "Medium"
        }
    }
    catch {
        Write-ColorOutput "BitLocker To Go policies: Not configured" "Yellow"
        Add-SecurityIssue -Category "USB/External Media" -Issue "BitLocker To Go policies are not configured" -Severity "Medium"
    }
}

function Get-ScreenLockPolicies {
    Write-SectionHeader "SCREEN LOCK POLICIES"
    
# screen saver info
    try {
        $screenSaverTimeout = Get-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "ScreenSaveTimeOut" -ErrorAction SilentlyContinue
        if ($screenSaverTimeout) {
            $timeoutMinutes = [int]$screenSaverTimeout.ScreenSaveTimeOut / 60
            Write-ColorOutput "Screen Saver Timeout: $timeoutMinutes minutes" $(if($timeoutMinutes -le 15 -and $timeoutMinutes -gt 0) {"Green"} elseif($timeoutMinutes -eq 0) {"Red"} else {"Yellow"})
            
            if ($timeoutMinutes -eq 0) {
                Add-SecurityIssue -Category "Screen Lock" -Issue "Screen saver timeout is disabled" -Severity "Medium"
            } elseif ($timeoutMinutes -gt 15) {
                Add-SecurityIssue -Category "Screen Lock" -Issue "Screen saver timeout is too long ($timeoutMinutes minutes)" -Severity "Medium"
            }
        } else {
            Write-ColorOutput "Screen Saver Timeout: Not configured" "Yellow"
            Add-SecurityIssue -Category "Screen Lock" -Issue "Screen saver timeout is not configured" -Severity "Medium"
        }
        
        $screenSaverActive = Get-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "ScreenSaveActive" -ErrorAction SilentlyContinue
        if ($screenSaverActive) {
            Write-ColorOutput "Screen Saver Active: $($screenSaverActive.ScreenSaveActive)" $(if($screenSaverActive.ScreenSaveActive -eq "1") {"Green"} else {"Red"})
            
            if ($screenSaverActive.ScreenSaveActive -ne "1") {
                Add-SecurityIssue -Category "Screen Lock" -Issue "Screen saver is not active" -Severity "Medium"
            }
        } else {
            Write-ColorOutput "Screen Saver Active: Not configured" "Yellow"
            Add-SecurityIssue -Category "Screen Lock" -Issue "Screen saver activation is not configured" -Severity "Medium"
        }
        
        $screenSaverSecure = Get-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "ScreenSaverIsSecure" -ErrorAction SilentlyContinue
        if ($screenSaverSecure) {
            Write-ColorOutput "Screen Saver Password Protected: $($screenSaverSecure.ScreenSaverIsSecure)" $(if($screenSaverSecure.ScreenSaverIsSecure -eq "1") {"Green"} else {"Red"})
            
            if ($screenSaverSecure.ScreenSaverIsSecure -ne "1") {
                Add-SecurityIssue -Category "Screen Lock" -Issue "Screen saver is not password protected" -Severity "High"
            }
        } else {
            Write-ColorOutput "Screen Saver Password Protected: Not configured" "Yellow"
            Add-SecurityIssue -Category "Screen Lock" -Issue "Screen saver password protection is not configured" -Severity "Medium"
        }
    }
    catch {
        Write-ColorOutput "Error checking screen saver settings: $($_.Exception.Message)" "Red"
    }
    
# Check power settings
	#need for screen locks etc
    try {
        $powerSettings = powercfg /query SCHEME_CURRENT SUB_VIDEO VIDEOIDLE 2>$null
        if ($powerSettings) {
            $timeout = ($powerSettings | Select-String "Current AC Power Setting Index:" | ForEach-Object { $_.Line.Split(':')[1].Trim() })
            if ($timeout) {
                $timeoutMinutes = [int]("0x" + $timeout) / 60
                Write-ColorOutput "Display timeout (AC): $timeoutMinutes minutes" $(if($timeoutMinutes -le 15 -and $timeoutMinutes -gt 0) {"Green"} else {"Yellow"})
                
                if ($timeoutMinutes -eq 0) {
                    Add-SecurityIssue -Category "Screen Lock" -Issue "Display timeout is disabled" -Severity "Medium"
                } elseif ($timeoutMinutes -gt 15) {
                    Add-SecurityIssue -Category "Screen Lock" -Issue "Display timeout is too long ($timeoutMinutes minutes)" -Severity "Low"
                }
            }
        }
    }
    catch {
        Write-ColorOutput "Error checking power settings" "Yellow"
    }
    
# account lockout policies
    try {
        $lockoutPolicy = net accounts 2>$null | Select-String "Lockout threshold:"
        if ($lockoutPolicy) {
            $threshold = ($lockoutPolicy.Line -split ":")[1].Trim()
            Write-ColorOutput "Account Lockout Threshold: $threshold" $(if($threshold -ne "Never" -and [int]$threshold -le 10) {"Green"} else {"Yellow"})
            
            if ($threshold -eq "Never") {
                Add-SecurityIssue -Category "Screen Lock" -Issue "Account lockout threshold is disabled" -Severity "Medium"
            } elseif ([int]$threshold -gt 10) {
                Add-SecurityIssue -Category "Screen Lock" -Issue "Account lockout threshold is too high ($threshold attempts)" -Severity "Low"
            }
        } else {
            Write-ColorOutput "Account Lockout Threshold: Not configured" "Yellow"
            Add-SecurityIssue -Category "Screen Lock" -Issue "Account lockout threshold is not configured" -Severity "Medium"
        }
    }
    catch {
        Write-ColorOutput "Error checking account lockout policy" "Yellow"
    }
}

function Get-AntivirusStatus {
    Write-SectionHeader "ANTIVIRUS STATUS"
    
    try {
# Get Defender info
        $defenderStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue
        if ($defenderStatus) {
            Write-ColorOutput "Windows Defender:" "White"
            Write-ColorOutput "  Antimalware Enabled: $($defenderStatus.AntivirusEnabled)" $(if($defenderStatus.AntivirusEnabled) {"Green"} else {"Red"})
            Write-ColorOutput "  Real-time Protection: $($defenderStatus.RealTimeProtectionEnabled)" $(if($defenderStatus.RealTimeProtectionEnabled) {"Green"} else {"Red"})
            Write-ColorOutput "  Behavior Monitor: $($defenderStatus.BehaviorMonitorEnabled)" $(if($defenderStatus.BehaviorMonitorEnabled) {"Green"} else {"Red"})
            Write-ColorOutput "  IOAV Protection: $($defenderStatus.IoavProtectionEnabled)" $(if($defenderStatus.IoavProtectionEnabled) {"Green"} else {"Red"})
            Write-ColorOutput "  On Access Protection: $($defenderStatus.OnAccessProtectionEnabled)" $(if($defenderStatus.OnAccessProtectionEnabled) {"Green"} else {"Red"})
            Write-ColorOutput "  Antivirus Signature Age: $($defenderStatus.AntivirusSignatureAge) days" $(if($defenderStatus.AntivirusSignatureAge -le 7) {"Green"} else {"Red"})
            Write-ColorOutput "  Last Quick Scan: $($defenderStatus.QuickScanAge) days ago" $(if($defenderStatus.QuickScanAge -le 7) {"Green"} else {"Yellow"})
            Write-ColorOutput "  Last Full Scan: $($defenderStatus.FullScanAge) days ago" $(if($defenderStatus.FullScanAge -le 30) {"Green"} else {"Yellow"})
            
            # Track AV issues
            if (-not $defenderStatus.AntivirusEnabled) {
                Add-SecurityIssue -Category "Antivirus" -Issue "Windows Defender antivirus is disabled" -Severity "Critical"
            }
            if (-not $defenderStatus.RealTimeProtectionEnabled) {
                Add-SecurityIssue -Category "Antivirus" -Issue "Real-time protection is disabled" -Severity "Critical"
            }
            if (-not $defenderStatus.BehaviorMonitorEnabled) {
                Add-SecurityIssue -Category "Antivirus" -Issue "Behavior monitoring is disabled" -Severity "High"
            }
            if ($defenderStatus.AntivirusSignatureAge -gt 7) {
                Add-SecurityIssue -Category "Antivirus" -Issue "Antivirus signatures are outdated ($($defenderStatus.AntivirusSignatureAge) days old)" -Severity "High"
            }
            if ($defenderStatus.QuickScanAge -gt 14) {
                Add-SecurityIssue -Category "Antivirus" -Issue "Last quick scan was over 2 weeks ago" -Severity "Medium"
            }
            if ($defenderStatus.FullScanAge -gt 60) {
                Add-SecurityIssue -Category "Antivirus" -Issue "Last full scan was over 2 months ago" -Severity "Medium"
            }
        }
        
        # Check for other antivirus products via WMI
        $antivirusProducts = Get-WmiObject -Namespace "root\SecurityCenter2" -Class AntiVirusProduct -ErrorAction SilentlyContinue
        if ($antivirusProducts) {
            Write-ColorOutput "`nInstalled Antivirus Products:" "White"
            $activeAV = $false
            foreach ($av in $antivirusProducts) {
                $state = $av.productState
                $enabled = ($state -band 0x1000) -ne 0
                $updated = ($state -band 0x10) -eq 0
                
                Write-ColorOutput "  Product: $($av.displayName)" "White"
                Write-ColorOutput "    Enabled: $enabled" $(if($enabled) {"Green"} else {"Red"})
                Write-ColorOutput "    Up to Date: $updated" $(if($updated) {"Green"} else {"Red"})
                
                if ($enabled) { $activeAV = $true }
                
                if (-not $enabled) {
                    Add-SecurityIssue -Category "Antivirus" -Issue "$($av.displayName) is installed but disabled" -Severity "High"
                }
                if (-not $updated) {
                    Add-SecurityIssue -Category "Antivirus" -Issue "$($av.displayName) definitions are out of date" -Severity "High"
                }
            }
            
            if (-not $activeAV) {
                Add-SecurityIssue -Category "Antivirus" -Issue "No active antivirus protection detected" -Severity "Critical"
            }
        } else {
            Add-SecurityIssue -Category "Antivirus" -Issue "No antivirus products detected" -Severity "Critical"
        }
    }
    catch {
        Write-ColorOutput "Error checking antivirus status: $($_.Exception.Message)" "Red"
        Add-SecurityIssue -Category "Antivirus" -Issue "Unable to check antivirus status" -Severity "Medium"
    }
}

function Get-FirewallStatus {
    Write-SectionHeader "WINDOWS FIREWALL STATUS"
    
    try {
# Get fw profiles
        $firewallProfiles = Get-NetFirewallProfile -ErrorAction SilentlyContinue
        
        if ($firewallProfiles) {
            foreach ($profile in $firewallProfiles) {
                Write-ColorOutput "`n$($profile.Name) Profile:" "Yellow"
                Write-ColorOutput "  Enabled: $($profile.Enabled)" $(if($profile.Enabled) {"Green"} else {"Red"})
                Write-ColorOutput "  Default Inbound Action: $($profile.DefaultInboundAction)" $(if($profile.DefaultInboundAction -eq "Block") {"Green"} else {"Red"})
                Write-ColorOutput "  Default Outbound Action: $($profile.DefaultOutboundAction)" $(if($profile.DefaultOutboundAction -eq "Allow") {"Green"} else {"Yellow"})
                Write-ColorOutput "  Notifications: $($profile.NotifyOnListen)" $(if($profile.NotifyOnListen) {"Green"} else {"Yellow"})
                Write-ColorOutput "  Log Allowed: $($profile.LogAllowed)" $(if($profile.LogAllowed) {"Green"} else {"Yellow"})
                Write-ColorOutput "  Log Blocked: $($profile.LogBlocked)" $(if($profile.LogBlocked) {"Green"} else {"Yellow"})
                
                if (-not $profile.Enabled) {
                    Add-SecurityIssue -Category "Firewall" -Issue "$($profile.Name) firewall profile is disabled" -Severity "Critical"
                }
                if ($profile.DefaultInboundAction -ne "Block") {
                    Add-SecurityIssue -Category "Firewall" -Issue "$($profile.Name) profile allows inbound connections by default" -Severity "High"
                }
                if (-not $profile.LogBlocked) {
                    Add-SecurityIssue -Category "Firewall" -Issue "$($profile.Name) profile is not logging blocked connections" -Severity "Medium"
                }
                
                if ($profile.LogFileName) {
                    Write-ColorOutput "  Log File: $($profile.LogFileName)" "White"
                    
                    # Check if log file exists and get size
                    if (Test-Path $profile.LogFileName) {
                        $logSize = (Get-Item $profile.LogFileName).Length / 1KB
                        Write-ColorOutput "  Log File Size: $([math]::Round($logSize, 2)) KB" "Gray"
                    }
                }
            }
        }
        
# Get fw status
        $firewallService = Get-Service -Name "MpsSvc" -ErrorAction SilentlyContinue
        if ($firewallService) {
            Write-ColorOutput "`nWindows Firewall Service (MpsSvc):" "Yellow"
            Write-ColorOutput "  Status: $($firewallService.Status)" $(if($firewallService.Status -eq "Running") {"Green"} else {"Red"})
            Write-ColorOutput "  Start Type: $($firewallService.StartType)" $(if($firewallService.StartType -eq "Automatic") {"Green"} else {"Red"})
            
            if ($firewallService.Status -ne "Running") {
                Add-SecurityIssue -Category "Firewall" -Issue "Windows Firewall service is not running" -Severity "Critical"
            }
            if ($firewallService.StartType -ne "Automatic") {
                Add-SecurityIssue -Category "Firewall" -Issue "Windows Firewall service is not set to start automatically" -Severity "High"
            }
        }
        
    }
    catch {
        Write-ColorOutput "Error checking firewall status: $($_.Exception.Message)" "Red"
        Add-SecurityIssue -Category "Firewall" -Issue "Unable to check firewall status" -Severity "Medium"
    }
}

function Get-WindowsASMSettings {
    Write-SectionHeader "WINDOWS APPLICATION SECURITY MANAGER (ASM) SETTINGS"
    
# Device Guard
    try {
        $deviceGuardStatus = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction SilentlyContinue
        if ($deviceGuardStatus) {
            Write-ColorOutput "Device Guard Available: $($deviceGuardStatus.AvailableSecurityProperties -contains 1)" $(if($deviceGuardStatus.AvailableSecurityProperties -contains 1) {"Green"} else {"Yellow"})
            Write-ColorOutput "Virtualization Based Security: $($deviceGuardStatus.VirtualizationBasedSecurityStatus)" $(if($deviceGuardStatus.VirtualizationBasedSecurityStatus -eq 2) {"Green"} else {"Yellow"})
            Write-ColorOutput "HVCI Status: $($deviceGuardStatus.CodeIntegrityPolicyEnforcementStatus)" $(if($deviceGuardStatus.CodeIntegrityPolicyEnforcementStatus -eq 2) {"Green"} else {"Yellow"})
        } else {
            Write-ColorOutput "Device Guard information not available" "Yellow"
            Add-SecurityIssue -Category "Application Security" -Issue "Device Guard information is not available" -Severity "Medium"
        }
    }
    catch {
        Write-ColorOutput "Error checking Device Guard status: $($_.Exception.Message)" "Red"
        Add-SecurityIssue -Category "Application Security" -Issue "Unable to check Device Guard status" -Severity "Medium"
    }
    
# Applocker checks
    try {
        $appLockerPolicies = Get-AppLockerPolicy -Effective -ErrorAction SilentlyContinue
        if ($appLockerPolicies -and $appLockerPolicies.RuleCollections) {
            Write-ColorOutput "`nAppLocker Policies:" "White"
            foreach ($collection in $appLockerPolicies.RuleCollections) {
                $ruleCount = $collection.Rules.Count
                Write-ColorOutput "  $($collection.RuleCollectionType): $ruleCount rules" $(if($ruleCount -gt 0) {"Green"} else {"Yellow"})
                
                if ($ruleCount -eq 0) {
                    Add-SecurityIssue -Category "Application Security" -Issue "AppLocker $($collection.RuleCollectionType) has no rules configured" -Severity "Medium"
                }
            }
        } else {
            Write-ColorOutput "AppLocker: No policies configured" "Yellow"
            Add-SecurityIssue -Category "Application Security" -Issue "AppLocker policies are not configured" -Severity "Medium"
        }
    }
    catch {
        Write-ColorOutput "Error checking AppLocker policies: $($_.Exception.Message)" "Red"
        Add-SecurityIssue -Category "Application Security" -Issue "Unable to check AppLocker policies" -Severity "Medium"
    }
    
    # Check Windows Defender SmartScreen
    try {
        $smartScreenPolicy = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableSmartScreen" -ErrorAction SilentlyContinue
        if ($smartScreenPolicy) {
            Write-ColorOutput "SmartScreen (Policy): $($smartScreenPolicy.EnableSmartScreen)" $(if($smartScreenPolicy.EnableSmartScreen -eq 1) {"Green"} else {"Red"})
            
            if ($smartScreenPolicy.EnableSmartScreen -ne 1) {
                Add-SecurityIssue -Category "Application Security" -Issue "SmartScreen is disabled by policy" -Severity "High"
            }
        } else {
            # Check user setting
            $smartScreenUser = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "SmartScreenEnabled" -ErrorAction SilentlyContinue
            if ($smartScreenUser) {
                Write-ColorOutput "SmartScreen (User): $($smartScreenUser.SmartScreenEnabled)" $(if($smartScreenUser.SmartScreenEnabled -eq "RequireAdmin") {"Green"} else {"Yellow"})
                
                if ($smartScreenUser.SmartScreenEnabled -ne "RequireAdmin") {
                    Add-SecurityIssue -Category "Application Security" -Issue "SmartScreen is not set to require admin approval" -Severity "Medium"
                }
            } else {
                Write-ColorOutput "SmartScreen: Not configured" "Yellow"
                Add-SecurityIssue -Category "Application Security" -Issue "SmartScreen is not configured" -Severity "Medium"
            }
        }
    }
    catch {
        Write-ColorOutput "Error checking SmartScreen status: $($_.Exception.Message)" "Red"
        Add-SecurityIssue -Category "Application Security" -Issue "Unable to check SmartScreen status" -Severity "Medium"
    }
    
# ASR
    try {
        $exploitProtection = Get-ProcessMitigation -System -ErrorAction SilentlyContinue
        if ($exploitProtection) {
            Write-ColorOutput "`nExploit Protection (System-wide):" "White"
            $mitigations = @("DEP", "ASLR", "HighEntropy", "StrictHandle", "SystemCall", "ExtensionPoint")
            foreach ($mitigation in $mitigations) {
                if ($exploitProtection.$mitigation) {
                    $status = $exploitProtection.$mitigation.Enable
                    Write-ColorOutput "  $mitigation`: $status" $(if($status -eq "ON") {"Green"} elseif($status -eq "NOTSET") {"Yellow"} else {"Red"})
                    
                    if ($status -eq "NOTSET") {
                        Add-SecurityIssue -Category "Exploit Protection" -Issue "$mitigation exploit protection is not set" -Severity "Medium"
                    } elseif ($status -eq "OFF") {
                        Add-SecurityIssue -Category "Exploit Protection" -Issue "$mitigation exploit protection is disabled" -Severity "High"
                    }
                } else {
                    Write-ColorOutput "  $mitigation`: Not available" "Gray"
                }
            }
        } else {
            Write-ColorOutput "Exploit Protection: Not configured" "Yellow"
            Add-SecurityIssue -Category "Exploit Protection" -Issue "Exploit Protection settings are not configured" -Severity "Medium"
        }
    }
    catch {
        Write-ColorOutput "Error checking Exploit Protection: $($_.Exception.Message)" "Red"
        Add-SecurityIssue -Category "Exploit Protection" -Issue "Unable to check Exploit Protection settings" -Severity "Medium"
    }
}

# Main execution
function Main {
    param([string]$ExportPath)
    
    Write-ColorOutput "`n" + @"
██      ██     ██ ██   ██  ██████ 
██      ██     ██ ██   ██ ██      
██      ██  █  ██ ███████ ██      
██      ██ ███ ██ ██   ██ ██      
███████  ███ ███  ██   ██  ██████ 
                                  
Local Windows Hardening Check
"@ "Cyan"
    
    Write-ColorOutput "Starting comprehensive security audit..." "White"
    Write-ColorOutput "Computer: $env:COMPUTERNAME" "Gray"
    Write-ColorOutput "Date: $(Get-Date)" "Gray"
    
# Run em all
    Get-BitLockerStatus
    Get-BootSecurity
    Get-USBPolicies
    Get-ScreenLockPolicies
    Get-AntivirusStatus
    Get-FirewallStatus
    Get-WindowsASMSettings

    Write-SecuritySummary    
# Export results
    if ($ExportPath) {
        Export-Results -OutputPath $ExportPath
    }
    
    Write-SectionHeader "AUDIT COMPLETED"
    Write-ColorOutput "Security audit completed successfully!" "Green"
}
    

function Export-Results {
    param([string]$OutputPath)
    
    if ($OutputPath) {
        Write-SectionHeader "EXPORTING RESULTS"
        
        $timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
        $filename = "SecurityAudit_$env:COMPUTERNAME_$timestamp.txt"
        $fullPath = Join-Path $OutputPath $filename
        
# store output in outptu
        $output = @()
        $output += "Windows Security Audit Report"
        $output += "Generated: $(Get-Date)"
        $output += "Computer: $env:COMPUTERNAME"
        $output += "User: $env:USERNAME"
        $output += "================================================================"
        
        $output += "`n" + (Get-BitLockerStatus | Out-String)
        $output += "`n" + (Get-BootSecurity | Out-String)
        $output += "`n" + (Get-USBPolicies | Out-String)
        $output += "`n" + (Get-ScreenLockPolicies | Out-String)
        $output += "`n" + (Get-AntivirusStatus | Out-String)
        $output += "`n" + (Get-FirewallStatus | Out-String)
        $output += "`n" + (Get-WindowsASMSettings | Out-String)
        $output += "`n" + (Write-SecuritySummary | Out-String)
        
        $output | Out-File -FilePath $fullPath -Encoding UTF8
        Write-ColorOutput "Results exported to: $fullPath" "Green"
    }
}


# Check if admin
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-ColorOutput "This script requires Administrator privileges. Please run as Administrator." "Red"
    exit 1
}
# run
Main -ExportPath $ExportPath
