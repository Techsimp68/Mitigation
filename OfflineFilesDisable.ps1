#Checking if Offline Files are Enabled
$check = Get-WmiObject -Class Win32_OfflineFilesCache -Computer $env:COMPUTERNAME | Select-Object Enabled
$check = [string]$check
$check = ($check.split("="))[1]
$check = ($check.split("}"))[0]

#If Enabled, disable
if ($check -eq $true) {
    $objWMI = [wmiclass]”\\$env:COMPUTERNAME\root\cimv2:win32_offlinefilescache”
    $objWMI.enable($false)
    #restart can be adjusted
    Restart-Computer -Confirm -Wait -For PowerShell -Timeout 300 -Delay 2
    #probably will include a Return here to make script run again
    }
else {
    #probably make a call to start running actual script
    Write-Host "Proceed with Ps1"
    }
