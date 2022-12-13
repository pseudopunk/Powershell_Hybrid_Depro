# ********************************************************************************
#
# Script Name: Secondary-Depro.ps1
# Version: 1.6
# Author: Heather Asbell
# Date: 12/28/21
# Applies to: Users in z_DisabledUsers_Staged OU
#
# Description: This script performs the secondary tasks for deprovisioning after 
# 30 days including clearing calendar, disabling account, removing licenses, 
# and moving from z_DisabledUsers_Staged to z_Disabled Users OU. Writes log of changes.
#
# ********************************************************************************

# Define Variables 
$Emailusername = "NAME OF SERVICE ACCOUNT USED"
$Encrypted = Get-Content c:\Scripts\scriptsencrypted_password.txt | ConvertTo-SecureString
$Credential = New-Object System.Management.Automation.PsCredential($Emailusername, $Encrypted)
$PathLog = "\\PATH TO LOG LOCATION"
$DTStamp = get-date -Format u | foreach {$_ -replace ":", "-"}
$OUpath = 'OU=z_DisabledUsers_Staged,OU=Users(Managed),DC=YOURDOMAIN ,DC=COM '
$OUpath2 = "OU=z_Disabled Users,OU=Users(Managed),DC=YOURDOMAIN ,DC=COM"

#Connect Services
Import-Module ExchangeOnlineManagement
Start-Sleep -s 5
Connect-ExchangeOnline -Credential $Credential
Connect-MSOLService -Credential $Credential
New-PSDrive -Name "R" -PSProvider FileSystem -Root $Pathlog -Credential $Credential
Start-Sleep -s 5

#Get a list of all enabled users with last password change over 30 days ago.
$Users = (get-aduser –SearchBase $OUpath –filter * -Properties samaccountname, PasswordLastSet | Where-Object {$_.PasswordLastSet -lt (Get-Date).adddays(-30)}).samaccountname
foreach ($Username in $Users) {
Remove-CalendarEvents -identity $Username -CancelOrganizedMeetings -QueryWindowInDays 180 -Confirm:$false
Disable-ADAccount $Username
$UPn = get-aduser $Username | select-object -expand UserPrincipalName
(get-MsolUser -UserPrincipalName $Upn).licenses.AccountSkuId | foreach {
Set-MsolUserLicense -UserPrincipalName $Upn -RemoveLicenses $_
}
Move-ADObject -Identity (Get-ADuser $Username).objectGUID -TargetPath $OUpath2

#Set Variables for logs
$UserDisabled = (Get-ADUser $Username).Enabled
$UserOU = Get-ADUser $Username | select @{l='Parent';e={([adsi]"LDAP://$($_.DistinguishedName)").Parent}}
$Licenses = (get-MsolUser -UserPrincipalName $Upn).licenses.AccountSkuId

#Write Logs
Add-Content “$PathLog\$username.txt” " "
Add-Content “$PathLog\$username.txt” "DateTime: $DTStamp"
Add-Content “$PathLog\$username.txt” "User Licenses: $Licenses"
Add-Content “$PathLog\$username.txt” "Account Enabled: $UserDisabled"
Add-Content “$PathLog\$username.txt” "$Username moved to $UserOU"
Add-Content “$PathLog\$username.txt” "______________________________________________________"
& “$PathLog\$username.txt”
}

Write-Host "##############################################"
Write-Host "#                                            #"
Write-Host "#         Secondary Depro Complete!          #"
Write-Host "#                                            #"
Write-Host "##############################################"
Write-Host " " 
