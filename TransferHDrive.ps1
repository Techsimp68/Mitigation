# NOTE: New stuff is marked with comments that start with "new - "

Start-Transcript -Path "C:\temp\TransferTranscript.txt"
import-module ActiveDirectory

# function to get paths over 250
Function filesOverLength ($homeDirectory) {
    Dir -LiteralPath ('\\?\UNC\' + $homeDirectory.substring(2)) -Recurse | Select-Object -Property FullName, @{Name="FullNameLength";Expression={($_.FullName.Length)}} | Where-Object {$_.FullName.length -ge 250}
}      

# new - function to check if an item is offending the naming guidelines
function itemsToBeSkipped ($items) {
    # an array to collect the files to not copy over
    $forbiddenItems = @()

    # forbidden char string
    $forbiddenChars = '"*:<>?/\|~#%&{}$'

    # forbidden name array
    $forbiddenNames = @('.lock', 'CON', 'PRN', 'AUX', 'NUL', 'COM1', 'COM2', 'COM3', 'COM4', 'COM5', 'COM6', 'COM7', 'COM8', 'COM9', 'LPT1', 'LPT2', 'LPT3', 'LPT4', 'LPT5', 'LPT6', 'LPT7', 'LPT8', 'LPT9', 'desktop.in')

    # tried to do regex matching, not sure if it's correct
    # regex escape is used because the special characters need to be treated as literal characters in this context
    # wildcard matching used in the else if (example $item.Name -like "*.one")
    # character class is used to find files with ANY character from the forbidden char set
    foreach($item in $items) {
        # https://stackoverflow.com/questions/39825440/check-if-a-path-is-a-folder-or-a-file-in-powershell
        $isFolder = Test-Path -Path $item.FullName -PathType Container

        if ($isFolder -and $item.Name -eq "forms") {
            $forbiddenItems += $item.FullName
        } elseif (-not $isFolder -and ($item.Name -match "[$([regex]::Escape($forbiddenChars))]") -or $item.Name -like "*.vti*" -or $item.Name -like "~*" -or $item.Name -like "*.one") {
            $forbiddenItems += $item.FullName
        }

        # check BOTH folders AND files
        if ($forbiddenNames -contains $item.Name) {
            $forbiddenItems += $item.FullName
        }
    }
 
    return $forbiddenItems
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
    # get files over length
    $filesToSkip = filesOverLength -homeDirectory $homeDirectory

    # output skipped files to user
    # new - changed output message to be more clear since we now need to skip many different types of files/folders
    if ($filesToSkip.count -gt 0) {
        Write-Output ("Files skipped because their name was too long:")

        # Iterate through the list and output each object
        $filesToSkip | ForEach-Object {
            Write-Output $_.FullName
        }
    }

    # new - get all files to be processed before copying
    $allItems = Get-ChildItem -LiteralPath ('\\?\UNC\' + $homeDirectory.substring(2)) -Recurse

    # new - call the function to filter out forbidden chars/phrases
    $forbiddenItems = itemsToBeSkipped $allItems

    # new - output skipped files to user
    if ($forbiddenItems.count -gt 0) {
        # note - it shows `" because it is needed to print " in a string
        Write-Output ("Items skipped because they violate naming conventions or have a `".one`" extension")

        # Iterate through the list and output each object
        $forbiddenItems | ForEach-Object {
            Write-Output $_
        }
    }

    # new - copy items excluding the ones in the array we just got
    $filesToCopy = $allFiles | Where-Object { $_.FullName -notin $filesToSkip.FullName -and $_.Name -notin $forbiddenItems }

    # new - it is now in a foreach loop
    foreach ($file in $filesToCopy) {
        $relativePath = $file.FullName.Substring(('\\?\UNC\' + $homeDirectory.substring(2)).Length + 1)
        $destinationPath = Join-Path -Path "C:\Users\$user\OneDrive - Xcel Energy Services Inc\H Drive" -ChildPath $relativePath
        Copy-Item -LiteralPath $file.FullName -Destination $destinationPath -Recurse -Force
    }
} Catch {
    $_.Exception.Message | Out-File -FilePath "C:\temp\errorLog.txt"  
} finally {           
    # Verification through Hash
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
