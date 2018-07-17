#-----------------------------------------------------------------------
# <copyright file="SecureDevVM.ps1" company="RollsRoyce and Microsoft Corporation">
# Copyright (c) RollsRoyce and Microsoft Corporation. All rights reserved.
# THIS CODE AND INFORMATION ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED, 
# INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE.
# </copyright>
# <summary>
#   
#	DSC configuration for Azure Automation DSC prepared to enforce security constraints on developer machine
#
#	Azure Automation Account requires following loaded Modules under Assets section:
#		* xNetworking
#		* xRemoteDesktopAdmin
#		* xSystemSecurity 
#		* cChoco (for using Chocolatey deployment)
#	
#	Variables needed in Azure Automation:
#		* portNo - optional parameter to specify RDP port inside VM (default 27901)
#		* chocoSource - location for Chocolatey packages repository (default "https://chocolatey.org/api/v2/")
#
#	Enforced constraints:
#		* RDP port (RDP port configuration in VM + firewall port)
#		* Enforce Network Level Authentication (NLA) for RDS 
#		* Enforce strong passwords through local security policy
#		* Disables RDP client COM mapping
#		* Disables RDP client drive mapping
#		* Disables RDP client clipboard mapping
#		* Disables RDP client printer mapping
#
#	Packages installed with Chocolatey:
#		* googlechrome
#		* firefox
#		* jdk7
#		* r.studio
#		* notepadplusplus
#		* visualstudicode
#		* python2
#		* azcopy 
#		* microsoftazurestorageexplorer
#		* scala (choco package not working currently so commented) - installed through custom script
#       * intellijidea-community
#       * microsoft-r-open
#
# </summary> = 
#-----------------------------------------------------------------------


Configuration SecureDevVM
# Security Settings for Dev VMs
{
	
	Import-DscResource -ModuleName PSDesiredStateConfiguration, xRemoteDesktopAdmin, xNetworking, xSystemSecurity, cChoco

    # Custom RDP port - needs to be defined in Azure Automation
    $portNoStr = Get-AutomationVariable -Name 'portNo'
	[int]$portNo = [convert]::ToInt32($portNoStr, 10)
    
    # Chocolatey source - needs to be defined in Azure Automation
    $chocoSource = Get-AutomationVariable -Name 'chocoSource'
        	
	Node "DevVMs"
    {
		
		# Changes RDP port to $portNo
		Registry ChangeRDPPort
		{
			Ensure = "Present"
			Key = "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
			ValueName = "PortNumber"
			ValueData = ('{0:x}' -f $portNo)
			ValueType = "Dword"
			Hex = $true
			Force = $true
		}

		# Enforces NLA for RDP
		xRemoteDesktopAdmin RemoteDesktopSettings
        {
           Ensure = 'Present'
           UserAuthentication = 'Secure'
        }

		# Opens incoming port $portNo for RDP
        xFirewall NewRDPPort
        {
            Name = "Custom RDP Port"
            DisplayName = "Custom RDP Port"
            Ensure = "Present"
            Enabled = $true
            Action = "Allow"
            Profile = ("Public", "Private", "Domain")
            Direction = "InBound"
            RemotePort = "Any"
            LocalPort = ([string]$portNo)
            Protocol = "TCP"
            Description = ("Firewall rule for RDP port " + ([string]$portNo))
        }

		# Adjusts some local security settings for enforcing strong passwords
		Script PasswordHarden 
		{
			GetScript = { 
			}
			SetScript = { 
				secedit /export /cfg ${env:appdata}\secpol.cfg
				(get-content ${env:appdata}\secpol.cfg) | Foreach-Object {$_ -replace 'PasswordComplexity = 0', 'PasswordComplexity = 1'} | Out-File ${env:appdata}\secpol.cfg
				(get-content ${env:appdata}\secpol.cfg) | Foreach-Object {$_ -replace 'MinimumPasswordLength = .+$', 'MinimumPasswordLength = 14'} | Out-File ${env:appdata}\secpol.cfg
				secedit /configure /db c:\windows\security\local.sdb /cfg ${env:appdata}\secpol.cfg /areas SECURITYPOLICY
				rm -force ${env:appdata}\secpol.cfg -confirm:$false
			}
			TestScript = { 
				$false 
			}
		}

		# Disable IE Enhanched Security for Admins
		xIEESC DisableIEESCAdmin
        {
            UserRole = "Administrators"
            IsEnabled = $False
        }

		# Disable IE Enhanched Security for Users
		xIEESC DisableIEESCUser
        {
            UserRole = "Users"
            IsEnabled = $False
        }


		# RDP hardening reg keys
		# Disables RDP client audio mapping
		Registry DisableRDPAudio
		{
			Ensure = "Present"
			Key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
			ValueName = "fDisableCam"
			ValueData = "1"
			ValueType = "Dword"
			Force = $true
		}
		# Disables RDP client COM mapping
		Registry DisableRDPCOM
		{
			Ensure = "Present"
			Key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
			ValueName = "fDisableCcm"
			ValueData = "1"
			ValueType = "Dword"
			Force = $true
		}
		# Disables RDP client drive mapping
		Registry DisableRDPDrives
		{
			Ensure = "Present"
			Key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
			ValueName = "fDisableCdm"
			ValueData = "1"
			ValueType = "Dword"
			Force = $true
		}
		# Disables RDP client clipboard mapping
		Registry DisableRDPClipboard
		{
			Ensure = "Present"
			Key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
			ValueName = "fDisableClip"
			ValueData = "1"
			ValueType = "Dword"
			Force = $true
		}
		# Disables RDP client printer mapping
		Registry DisableRDPPrinter
		{
			Ensure = "Present"
			Key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
			ValueName = "fDisableCpm"
			ValueData = "1"
			ValueType = "Dword"
			Force = $true
		}

		# Install Chocolatey client
		cChocoInstaller installChoco 
        { 
            InstallDir = "C:\choco" 
        }

		# Deploy Google Chrome 
		cChocoPackageInstaller googlechrome
        {            
            Name = "googlechrome" 
            #Version = " 53.0.2785.116" 
            Source = $chocoSource
            DependsOn = "[cChocoInstaller]installChoco"
        }

		# Deploy Firefox
		cChocoPackageInstaller firefox
        {            
            Name = "firefox" 
            Source = $chocoSource
            DependsOn = "[cChocoInstaller]installChoco"
        }
		
		# Deploy jdk
		cChocoPackageInstaller jdk7
        {            
            Name = "jdk7" 
            Source = $chocoSource
            DependsOn = "[cChocoInstaller]installChoco"
        }

		# Deploy Python
		cChocoPackageInstaller python2
        {            
            Name = "python2" 
            Source = $chocoSource
            DependsOn = "[cChocoInstaller]installChoco"
        }

		# Deploy r.studio
		cChocoPackageInstaller r.studio
        {            
            Name = "r.studio" 
            Source = $chocoSource
            DependsOn = "[cChocoInstaller]installChoco"
        }

		# Deploy notepadplusplus
		cChocoPackageInstaller notepadplusplus
        {            
            Name = "notepadplusplus" 
            Source = $chocoSource
            DependsOn = "[cChocoInstaller]installChoco"
        }

		# Deploy Visual Studio Code
		cChocoPackageInstaller visualstudiocode
        {            
            Name = "visualstudiocode" 
            Source = $chocoSource
            DependsOn = "[cChocoInstaller]installChoco"
        }

		# Deploy Microsoft Azure Storage Explorer
		cChocoPackageInstaller microsoftazurestorageexplorer
        {            
            Name = "microsoftazurestorageexplorer" 
            Source = $chocoSource
            DependsOn = "[cChocoInstaller]installChoco"
        }

		# Deploy Azure Copy
		cChocoPackageInstaller azcopy
        {            
            Name = "azcopy" 
            Source = $chocoSource
            DependsOn = "[cChocoInstaller]installChoco"
        }

		# Deploy Scala
		# cChocoPackageInstaller scala
        # {            
        #     Name = "scala" 
        #     Source = $chocoSource
        #     DependsOn = "[cChocoInstaller]installChoco"
        # }

        # Deploy intelliJ Community edition
		cChocoPackageInstaller intellijidea-community
        {
            Name = "intellijidea-community"
            Source = $chocoSource
            DependsOn = "[cChocoInstaller]installChoco"
        }

        # Deploy Microsoft R Open
		cChocoPackageInstaller microsoft-r-open
        {
            Name = "microsoft-r-open"
            Source = $chocoSource
            DependsOn = "[cChocoInstaller]installChoco"
        }
	}
}