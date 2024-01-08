#Creating Folders/Installing Needed Files
New-Item -ItemType Directory "C:\temp" -Force
New-Item -ItemType Directory "C:\temp\MitigationLogs" -Force
New-Item -ItemType Directory "C:\temp\MitigationFiles" -Force
invoke-webRequest -Uri 'https://raw.githubusercontent.com/raggingsoldier/Mitigation/main/Microsoft.ActiveDirectory.Management%201.dll' -OutFile "C:\temp\MitigationFiles\Microsoft.ActiveDirectory.Management.dll"
invoke-webRequest -Uri 'https://raw.githubusercontent.com/raggingsoldier/Mitigation/main/Microsoft.ActiveDirectory.Management.resources%201.dll' -OutFile "C:\temp\MitigationFiles\Microsoft.ActiveDirectory.Management.resources.dll"
invoke-webRequest -Uri 'https://raw.githubusercontent.com/raggingsoldier/Mitigation/main/ActiveDirectoryPowerShellResources.dll' -OutFile "C:\temp\MitigationFiles\ActiveDirectoryPowerShellResources.dll"
invoke-webRequest -Uri 'https://raw.githubusercontent.com/raggingsoldier/Mitigation/main/ActiveDirectory.psd1' -OutFile "C:\temp\MitigationFiles\ActiveDirectory.psd1"
invoke-webRequest -Uri 'https://raw.githubusercontent.com/raggingsoldier/Mitigation/main/ActiveDirectory.Types.ps1xml' -OutFile "C:\temp\MitigationFiles\ActiveDirectory.Types.ps1xml"
invoke-webRequest -Uri 'https://raw.githubusercontent.com/raggingsoldier/Mitigation/main/ActiveDirectory.Format.ps1xml' -OutFile "C:\temp\MitigationFiles\ActiveDirectory.Format.ps1xml"

#Installing/Importing AD Module (Note: Import-Module will throw error if script is ran a 2nd time, safe to ignore)
Start-Transcript -Path "C:\temp\MitigationLogs\TransferTranscript.txt"
$FunctionFromGitHub = Invoke-WebRequest -uri "https://raw.githubusercontent.com/raggingsoldier/Mitigation/main/annoyingFunction.ps1"
Invoke-Expression $($FunctionFromGitHub.Content)
Import-Module -Name "C:\temp\MitigationFiles\ActiveDirectory.psd1"

#Function to get paths over 250 characters
Function filesOverLength ($homeDirectory) {
    Get-ChildItem -LiteralPath $homeDirectory -Recurse | 
    Where-Object {$_.FullName.length -ge 250} 
}      

#Grab UserName
[string]$domainUser = Get-WmiObject -class Win32_computersystem | Select -ExpandProperty username
$user = $domainUser.split('\')[1]

#Grab SID from Regedit
$objUser = New-Object System.Security.Principal.NTAccount("$user")
$strSID = $objUser.Translate([System.Security.Principal.SecurityIdentifier])
$strSID.Value

#Grab H Drive from AD
$homeDirectory = Get-ADUser -Identity $user -Properties * | Select-Object HomeDirectory
$homeDirectory = "Microsoft.Powershell.Core/filesystem::$homeDirectory"
$homeDirectory = ($homeDirectory.Split("="))[1]
$homeDirectory = ($homeDirectory.Split("}"))[0]

#Variable Parameter
New-Item -ItemType Directory -Path "C:\Users\$user\OneDrive - Xcel Energy Services Inc\H Drive.$env:computername" -Force
[array]$filesToSkip = filesOverLength -homeDirectory $homeDirectory

# Copy Data Over , 
Try {
    RoboCopy $homeDirectory "C:\Users\$user\OneDrive - Xcel Energy Services Inc\H Drive.$env:computername" /XD $filestoSkip /XD "OneNote NoteBooks" /XF $filesToSkip /Mir /XF desktop.ini
} Catch {
    $_.Exception.Message | Out-File -FilePath "C:\temp\MitigationLogs\errorLog.txt"  

#Verification through Hash
} finally {                
    Get-ChildItem -Path ('\\?\UNC\' + $homeDirectory.substring(2)) -Recurse -Exclude *.one, *.onetoc2, *.onepkg |
    Get-FileHash -Algorithm SHA256 | Select-Object -Property Hash | Out-File "C:\temp\MitigationLogs\HDriveHash.txt"
    Get-Childitem -Path "C:\Users\$user\OneDrive - Xcel Energy Services Inc\H Drive.$env:computername" -Recurse |
    Get-FileHash -Algorithm SHA256 | Select-Object -Property Hash | Out-File "C:\temp\MitigationLogs\OneDriveHash.txt"

    $objects =@{
        ReferenceObject = (Get-Content -Path "C:\temp\MitigationLogs\HDriveHash.txt")
        DifferenceObject = (Get-Content -Path "C:\temp\MitigationLogs\OneDriveHash.txt")
    }

    $comparisonResult = Compare-Object @objects
      
    if ($null -eq $comparisonResult) {
        Write-Output("Success the hashes are the Same!")
        Stop-Transcript
    } else {
         Write-Output("Failed the hashes dont match need human interaction!")
         $Error > "C:\temp\MitigationLogs\HashErrors.txt"
         Stop-Transcript
    }
}
        
