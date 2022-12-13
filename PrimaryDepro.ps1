# ********************************************************************************
#
# Script Name: PrimaryDepro.ps1
# Version: 1.7
# Author: Heather Asbell
# Date: 12/28/21
# Applies to: Users
#
# Description: This script performs the normal steps involved in terminating 
# access for a specific user, including: Resetting password, removing groups,
# forwarding email, hiding from global address list, and moving to disabled users staging OU.
#
# Note: Skips the following protected users; (Add applicable names here)
# ********************************************************************************

#Connect services
Import-Module ExchangeOnlineManagement
Connect-ExchangeOnline

Write-Host "##############################################"
Write-Host "#                                            #"
Write-Host "#       Begin User Deprovisioning            #"
Write-Host "#                                            #"
Write-Host "##############################################"
Write-Host " "

# Set Variables 
$PathLog = "\\INTERNAL SERVER AND FOLDER ADDRESS HERE"
$ProtectedUsers = "first.last", "first.last2"
$DTStamp = get-date -Format u | foreach {$_ -replace ":", "-"}

#Get username to terminate and verify username isn't protected
Function Get-Username {
	$Global:Username = Read-Host "Enter username to terminate"
	if ($Username -eq $null){
		Write-Host "Username cannot be blank. Please re-enter username"
		Get-Username
	}
	$UserCheck = Get-ADUser $Username
	if ($UserCheck -eq $null){
		Write-Host "Invalid username. Please verify this is the logon id / username for the account"
		Get-Username}
    $Protected = $ProtectedUsers -contains "$Username"
	if ($Protected -eq $True){
        Write-Host "$Username is a protected user and should not be deprovisioned via script."
        Get-Username}
}
Get-Username

#Confirm username input accuracy
$No = "n", "N", "No", "NO"
Write-Host " "
Write-Host "____________________________________________"
$Confirm = Read-Host "Are you sure you want to terminate: $Username (Y/N)"
if ($No -contains $Confirm){
        Get-Username
    }

#Set variables
$UserGroups = (Get-ADPrincipalGroupMembership $Username | Select Name).name
$UserOU = Get-ADUser $Username | select @{l='Parent';e={([adsi]"LDAP://$($_.DistinguishedName)").Parent}}

#Set random password for user
$Passwd = -join ((48..122) | Get-Random -Count 32 | ForEach-Object{[char]$_})
$PasswdSecStr = ConvertTo-SecureString $passwd -AsPlainText -Force
Set-ADAccountPassword -Identity $Username -NewPassword $PasswdSecStr -Reset
$Pwdlastset = (Get-ADUser -Identity $Username -properties passwordlastset | select passwordlastset).passwordlastset
Write-Host "$Username password changed $Pwdlastset."

#Export list of groups user is a Member Of
(Get-ADUser $Username).Name | Add-Content $PathLog\$Username.txt
(Get-ADPrincipalGroupMembership $Username | Select Name).name | Add-Content $PathLog\$Username.txt
Write-Host "$Username groups exported."

#Remove user from all groups except 'Domain Users'
Get-ADPrincipalGroupMembership -Identity $Username | where {$_.Name -notlike "Domain Users"} |% {Remove-ADPrincipalGroupMembership -Identity $Username -MemberOf $_ -Confirm:$false}
Start-Sleep -s 5
$UserGroups2 = (Get-ADPrincipalGroupMembership $Username | Select Name).name
Write-Host "$Username removed from all groups except for $UserGroups2."

#Remove telephone number attributes 
Set-ADUser $Username -Clear ipPhone,Mobile,facsimileTelephoneNumber,telephoneNumber
$Ipphoneval = (Get-ADUser $Username -Properties ipPhone).ipPhone
if ($Ipphoneval -eq $null){
    Write-Host "$Username IPPhone AD attribute has been successfully cleared"
}

#Remove manager attribute from user in AD
Set-ADUser $Username -manager $null
$Manattribute = (Get-ADUser $Username -Properties manager).manager
if ($Manattribute -eq $null){
    Write-Host "$Username manager AD attribute has been successfully cleared"
}

#Get manager name to forward emails
Function Get-Managername {
	$Global:Managername = Read-Host "Enter manager username for email forwarding"
	if ($Managername -eq $null){
		Write-Host "Manager name cannot be blank. Please re-enter"
		Get-Managername
	}
	$SuperCheck = Get-ADUser $Managername
	if ($SuperCheck -eq $null){
		Write-Host "Invalid username. Please verify this is the logon id for the manager"
		Get-Managername
	}
}
Get-Managername

#Get manager SMTP address
$ManSMTP = (Get-ADUser $Managername -Properties mail).mail

#Forward mail to manager
Get-Mailbox $Username | Set-Mailbox -ForwardingSmtpAddress $ManSMTP
$Mannamefwd = (Get-Mailbox $Username | select ForwardingSmtpAddress).forwardingsmtpaddress
Write-Host "Forwarding $Username's mail to: $Mannamefwd"

#Hide user from GAL
Set-ADUser -Identity $Username -Add @{msExchHideFromAddressLists="TRUE"}
$GALstatus = (Get-ADUser $Username -Properties msExchHideFromAddressLists).msExchHideFromAddressLists
Write-Host "$Username hidden from Global Address List: $GALstatus"

#Disable ActiveSync
set-casmailbox -identity $Username -ActiveSyncEnabled $false
$ActiveSync = (Get-casmailbox -Identity $Username).activesyncenabled
Write-Host "ActiveSync Enabled: $ActiveSync"

#Move user to z_disabledUsers_staged' OU
Move-ADObject -Identity (Get-ADuser $Username).objectGUID -TargetPath "OU=z_DisabledUsers_Staged,OU=Users(Managed),DC=YOURDOMAIN,Dc=COM"
$UserOU2 = Get-ADUser $Username | select @{l='Parent';e={([adsi]"LDAP://$($_.DistinguishedName)").Parent}}
Write-Host "$Username moved to OU: $UserOU2"

#Disable and move local admin account
$Localadmin = "$($Username).la"
$LAcheck = Get-ADUser $Localadmin
	if ($LAcheck -eq $null){
		Write-Host "No account found for" $Localadmin
		Add-Content “$PathLog\$username.txt” " "
		Add-Content “$PathLog\$username.txt” "No account found for $Localadmin"
	}else {
		#Change la password
		$Passwd2 = -join ((48..122) | Get-Random -Count 32 | ForEach-Object{[char]$_})
		$PasswdSecStr2 = ConvertTo-SecureString $passwd2 -AsPlainText -Force
		Set-ADAccountPassword -Identity $Localadmin -NewPassword $PasswdSecStr2 -Reset
		$Pwdlastset2 = (Get-ADUser -Identity $Localadmin -properties passwordlastset | select passwordlastset).passwordlastset
		Write-Host "$Localadmin password changed $Pwdlastset2."

		#Delete any la computer security groups
		Get-ADPrincipalGroupMembership -Identity $Localadmin | where {$_.Name -Like "*_administrator*"} | Remove-ADGroup
		
		#Disable la account
		Disable-ADAccount $Localadmin
		$LAdisabled = (Get-ADUser $Localadmin).Enabled

		#Move la account to z_Disabled Users OU
		Move-ADObject -Identity (Get-ADuser $Localadmin).objectGUID -TargetPath "OU=z_Disabled Users,OU=Users(Managed),DC=YOURDOMAIN,Dc=COM"
		$UserOU3 = Get-ADUser $Localadmin | select @{l='Parent';e={([adsi]"LDAP://$($_.DistinguishedName)").Parent}}
		Write-Host "$Username moved to OU: $UserOU3"

		#Write la account actions to logs
		Add-Content “$PathLog\$username.txt” "$Localadmin password last changed $Pwdlastset2"
		Add-Content “$PathLog\$username.txt” "$Localadmin account Enabled: $LAdisabled"
		Add-Content “$PathLog\$username.txt” "$Localadmin moved to $UserOU3"
}

#Append text file confirming actions taken
Add-Content “$PathLog\$username.txt” " "
Add-Content “$PathLog\$username.txt” "DateTime: $DTStamp"
Add-Content “$PathLog\$username.txt” "Password changed: $Pwdlastset"
Add-Content “$PathLog\$username.txt” "Group Membership: $UserGroups2"
Add-Content “$PathLog\$username.txt” "Hidden from GAL: $GALstatus"
Add-Content “$PathLog\$username.txt” "Extension: $Ipphoneval"
Add-Content “$PathLog\$username.txt” "Manager in AD: $Manattribute"
Add-Content “$PathLog\$username.txt” "Forwarding $Username's email to: $Mannamefwd"
Add-Content “$PathLog\$username.txt” "ActiveSync Enabled: $ActiveSync"
Add-Content “$PathLog\$username.txt” "$Username moved to $UserOU2"
Add-Content “$PathLog\$username.txt” "______________________________________________________"
& “$PathLog\$username.txt”


Write-Host "##############################################"
Write-Host "#                                            #"
Write-Host "#            User Deprovisioned              #"
Write-Host "#                                            #"
Write-Host "##############################################"
Write-Host " "
