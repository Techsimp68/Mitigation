Start-Transcript -Path "C:\temp\TransferTranscript.txt"
import-module ActiveDirectory

#new - function to get paths over 250
Function filesOverLength ($homeDirectory) {
    Dir -LiteralPath ('\\?\UNC\' + $homeDirectory.substring(2)) -Recurse | Select-Object -Property FullName, @{Name="FullNameLength";Expression={($_.FullName.Length)}} | 
Where-Object {$_.FullName.length -ge 250}
}      

#Grab UserName
[string]$domainUser = Get-WmiObject -class Win32_computersystem | Select -ExpandProperty username
$user = $domainUser.split('\')[1]

#Grab SID from Regedit
$sid = @( "wmic useraccount where name='$user' get sid" | cmd )
$SID = [string]$sid[-6]

#Grab H Drive from AD
$homeDirectory = Get-PSDrive | Select-object Name, @{n="Root"; e={if ($_.DisplayRoot -eq $null) {$_.Root} else {$_.DisplayRoot}}}| Where-object Name -Contains "H"
[string]$homeDirectory = "Microsoft.Powershell.Core/filesystem::$homeDirectory"
$homeDirectory = $homeDirectory.split('=')[2]
$homeDirectory = $homeDirectory.split('}')[0]

#Create Folder in One Drive that will hold H Drive Contents
New-Item -ItemType Directory -Path "C:\Users\$user\OneDrive - Xcel Energy Services Inc\H Drive" -Force

# Copy Data Over
Try {

    #new - get files over length
    $filesToSkip = filesOverLength -homeDirectory $homeDirectory

    #new - output skipped files to user
    if ($filesToSkip.count -gt 0) {
        Write-Output ("Skipped Files:")

        # Iterate through the list and output each object
        $filesToSkip | ForEach-Object {
            Write-Output $_.FullName
        }
    }

    # new - copy items excluding the ones in the array we just got
    Get-ChildItem -LiteralPath ('\\?\UNC\' + $homeDirectory.substring(2)) -Recurse | Where-Object {$_.FullName -notin $filesToSkip.FullName} | ForEach-Object {
        $relativePath = $_.FullName.Substring(('\\?\UNC\' + $homeDirectory.substring(2)).Length + 1)
        $destinationPath = Join-Path -Path "C:\Users\$user\OneDrive - Xcel Energy Services Inc\H Drive" -ChildPath $relativePath
        Copy-Item -LiteralPath $_.FullName -Destination $destinationPath -Recurse -Force
    }
} Catch {
    $_.Exception.Message | Out-File -FilePath "C:\temp\errorLog.txt"  

#Verification through Hash
} finally {                
    Get-ChildItem -Path ('\\?\UNC\' + $homeDirectory.substring(2)) -Recurse|
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

        #Set-ItemProperty -Path "HKU:\$sid\Software\Microsoft\OneDrive\Accounts\Business1" -Name "Documents" -Value 1
        #Set-ItemProperty -Path "HKU:\$sid\Software\Microsoft\OneDrive\Accounts\Business1" -Name "Pictures" -Value 1
        Stop-Transcript
    } else {
         Write-Output("Failed the hashes dont match need human interaction!")
         $Error > "C:\temp\errors.txt"
         Stop-Transcript
    }
}
            