New-Item -ItemType Directory "C:\temp" -Force
New-Item -ItemType Directory "C:\temp\logs" -Force
invoke-webRequest -Uri 'https://raw.githubusercontent.com/raggingsoldier/Mitigation/main/Microsoft.ActiveDirectory.Management%201.dll' -OutFile "C:\temp\Microsoft.ActiveDirectory.Management.dll"
invoke-webRequest -Uri 'https://raw.githubusercontent.com/raggingsoldier/Mitigation/main/Microsoft.ActiveDirectory.Management.resources%201.dll' -OutFile "C:\temp\Microsoft.ActiveDirectory.Management.resources.dll"
Start-Transcript -Path "C:\temp\logs\TransferTranscript.txt"
$FunctionFromGitHub = Invoke-WebRequest -uri "https://raw.githubusercontent.com/raggingsoldier/Mitigation/main/annoyingFunction.ps1"
Invoke-Expression $($FunctionFromGitHub.Content)
import-module ActiveDirectory

#new - function to get paths over 250
Function filesOverLength ($homeDirectory) {
    Get-ChildItem -LiteralPath $homeDirectory -Recurse | 
Where-Object {$_.FullName.length -ge 250} 
}      

#Grab UserNamet
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

#Create Folder in One Drive that will hold H Drive Contents
New-Item -ItemType Directory -Path "C:\Users\$user\OneDrive - Xcel Energy Services Inc\H Drive" -Force
[array]$filesToSkip = filesOverLength -homeDirectory $homeDirectory
# Copy Data Over , 
Try {
    RoboCopy $homeDirectory "C:\Users\$user\OneDrive - Xcel Energy Services Inc\H Drive" /XD $filestoSkip /XD "OneNote NoteBooks" /XF $filesToSkip /Mir 
} Catch {
    $_.Exception.Message | Out-File -FilePath "C:\temp\errorLog.txt"  

#Verification through Hash
} finally {                
    Get-ChildItem -Path ('\\?\UNC\' + $homeDirectory.substring(2)) -Recurse -Exclude *.one, *.onetoc2, *.onepkg |
    Get-FileHash -Algorithm SHA1 | Select-Object -Property Hash | Out-File "C:\temp\HDriveHash.txt"
    Get-Childitem -Path "C:\Users\$user\OneDrive - Xcel Energy Services Inc\H Drive" -Recurse |
    Get-FileHash -Algorithm SHA1 | Select-Object -Property Hash | Out-File "C:\temp\OneDriveHash.txt"

    $objects =@{
        ReferenceObject = (Get-Content -Path "C:\temp\HDriveHash.txt")
        DifferenceObject = (Get-Content -Path "C:\temp\OneDriveHash.txt")
    }

    $comparisonResult = Compare-Object @objects
      
    if ($null -eq $comparisonResult) {
        Write-Output("Success the hashes are the Same!")

        #Set-ItemProperty -Path "HKU:\$strSID\Software\Microsoft\OneDrive\Accounts\Business1" -Name "Documents" -Value 1
        #Set-ItemProperty -Path "HKU:\$strSID\Software\Microsoft\OneDrive\Accounts\Business1" -Name "Pictures" -Value 1
        Stop-Transcript
    } else {
         Write-Output("Failed the hashes dont match need human interaction!")
         $Error > "C:\temp\errors.txt"
         Stop-Transcript
    }
}
        
