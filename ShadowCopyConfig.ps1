<#
.SYNOPSIS
    Config-UI for Shadowcopy.
.DESCRIPTION
    Microsoft, in its endless wisdom, removed the shadowcopy UI, aka VSSUIRUN.EXE, from Windows 10/11. Even when you copy that tool from a server some things are missing, the scheduled tasks to create daily shadowcopies doen't works since microsoft crippled vssadmin.exe too.

    This tool is to configure shadowcopy, browse shadowcopies, delete single shadowcopies and change the maximum storage to use for shadowcopies.
    The browse functions shows the path which you can use in CMD, Powershell and explorer as well.

    For the shadowcopy tasks use "ShadowCopyJob.ps1" from https://github.com/Joachim-Otahal/Windows-ShadowCopy .
    This tool will work fine on a server too.
    
.NOTES
    Author: Joachim Otahal / jou@gmx.net / Joachim.Otahal@gmx.net
.LINK
    https://github.com/Joachim-Otahal/Windows-ShadowCopy / https://joumxyzptlk.de
#>

# Versionlog:
# 0.1 Joachim Otahal 25th to 27th March 2022

#################### Konstants

$TimeStamp = Get-Date
$ScriptName = $MyInvocation.MyCommand.Name

#################### Functions

Function Write-Verbose-and-Log {
    param (
        [string]$Message
    )
    Write-Verbose $Message -Verbose
    if ($LogPath) {
        $LogPathFinal=$LogPath.TrimEnd("\") + "\" + $ScriptName.TrimEnd(".ps1") + "_" + ($TimeStamp | Get-Date -Format "yyyy-MM-dd") + ".log"
        Out-File -LiteralPath $LogPathFinal -Append -InputObject $Message
    }
}

#################### PSVerisonCheck

if ([float]([string]$PSVersionTable.PSVersion.Major+"."+[string]$PSVersionTable.PSVersion.Minor) -lt [float]"4.0") {
    Write-Verbose "Powershell must me at least verion 4.0 due to [pscustomobject] usage.`nDownload Version 5.1 (recommended!): https://www.microsoft.com/en-us/download/details.aspx?id=54616" -Verbose
    Start-Sleep 20
    break
}

#################### Check elevated

if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')) {
    Write-Verbose "Not running with administrator rights." # -Verbose
    Start-Process Powershell -ArgumentList $PSCommandPath -Verb RunAs
    #Start-Sleep 20
    break
}

################### Log init with date-time in front.

#################### If there is no sheduled task, create one.
#################### But create it as "Deactivated", to be activated by an admin when needed.


# Init log header

# Write-Verbose-and-Log "########################################################"
# Write-Verbose-and-Log "################## $($TimeStamp | Get-Date -Format 'yyyy-MM-dd HH:mm:ss') #################"

# Current Time as UTC
$CurrentTimeUTC = (Get-Date).ToUniversalTime()
$CurrentTimeUTCDateOnly=$CurrentTimeUTC | Get-Date -Format yyy-MM-dd | Get-Date

# Get Info
# Yes, re-read everything every time since we allow a lot of changes

do {
    # we have to force the array, with only one entry it does not array it
    $ShadowStorage = @(Get-CimInstance Win32_ShadowStorage)
    #$VolumesWithoutShadows =  (Get-CimInstance Win32_Volume).Where({$_.FileSystem -eq "NTFS" -and $ShadowStorage.Volume.DeviceID -notcontains $_.DeviceID}) | Sort-Object DriveLetter
    $Volumes = (Get-CimInstance Win32_Volume).Where({$_.FileSystem -eq "NTFS" -and $_.Name -ilike "?:*"}) | Select-Object Name,Label,DeviceID,Capacity,FreeSpace,Active,AllocatedSpace,MaxSpace,UsedSpace,Volume,DiffVolume | Sort-Object Name
    # Tabletitles
    $Volumes += [pscustomobject]@{Name="Volume";Label="Label";DeviceID="";Capacity="";FreeSpace="";Active="Active";AllocatedSpace="Allocated";MaxSpace="Maximum";UsedSpace="";Volume="";DiffVolume=""}
    # Tablecellwidth
    $Volumes += [pscustomobject]@{Name=6;Label=5;DeviceID=0;Capacity=0;FreeSpace=0;Active=6;AllocatedSpace=9;MaxSpace=10;UsedSpace=0;Volume=0;DiffVolume=10}
    #$Volumes += (Get-CimInstance Win32_Volume).Where({$_.FileSystem -eq "NTFS" -and $_.Name -inotlike "?:*"})
    $ShadowCopyFullList = Get-CimInstance Win32_ShadowCopy
    
    # Fill in which volume has which settings

    for ( $i=0 ; $i -lt $Volumes.Count -2; $i++) {
        $ShadowStorageSingle = $ShadowStorage.Where({$_.Volume.DeviceID -eq $Volumes[$i].DeviceID})[0]
        if ($ShadowStorageSingle.Volume -ne $null) {
            $Volumes[$i].Active = "Yes"
            $Volumes[$i].AllocatedSpace = $ShadowStorageSingle.AllocatedSpace
            $Volumes[$i].MaxSpace = $ShadowStorageSingle.MaxSpace
            $Volumes[$i].UsedSpace = $ShadowStorageSingle.UsedSpace
            $Volumes[$i].Volume = $ShadowStorageSingle.Volume
            $Volumes[$i].DiffVolume = $ShadowStorageSingle.DiffVolume
        } else {
            $Volumes[$i].Active = "No"
        }
    }
    
    # calculate cell width
    
    $Volumes[-1] = [pscustomobject]@{Name=6;Label=5;DeviceID=0;Capacity=0;FreeSpace=0;Active=6;AllocatedSpace=9;MaxSpace=10;UsedSpace=0;Volume=0;DiffVolume=10}
    for ( $i=0 ; $i -lt $Volumes.Count -2; $i++) {
        $length = $Volumes[$i].Name.length
        if ($length -gt $Volumes[-1].Name          ) { $Volumes[-1].Name           = $length }
    
        $length = $Volumes[$i].Label.length
        if ($length -gt $Volumes[-1].Label         ) { $Volumes[-1].Label          = $length }
    
        $length = $Volumes[$i].Active.length
        if ($length -gt $Volumes[-1].Active        ) { $Volumes[-1].Active         = $length }
    
        $length = "$([UInt64]($Volumes[$i].AllocatedSpace / 1073741824)) GB".length
        if ($length -gt $Volumes[-1].AllocatedSpace) { $Volumes[-1].AllocatedSpace = $length }
    
        if ($Volumes[$i].MaxSpace -ne 18446744073709551615 -and $Volumes[$i].MaxSpace -ne 9223372036854775807) {
            $length = "$([UInt64]($Volumes[$i].MaxSpace / 1073741824)) GB".length
            if ($length -gt $Volumes[-1].MaxSpace  ) { $Volumes[-1].MaxSpace       = $length }
        }
    
        if ($Volumes[$i].Active -eq "Yes") {
            if ( $Volumes[$i].DiffVolume.DeviceID -ne $Volumes[$i].DeviceID ) {
                $Volumes[-1].DiffVolume = 49
            }
        }
    }
    
    #Show the list...
    
    $outputstring = "#"*($Volumes[-1].Name +3) +
                    "#"*($Volumes[-1].Label +3) +
                    "#"*($Volumes[-1].Active +3) +
                    "#"*($Volumes[-1].AllocatedSpace +3) +
                    "#"*($Volumes[-1].MaxSpace +3) +
                    "#"*($Volumes[-1].DiffVolume +4)
    Write-Host $outputstring
    $outputstring = "# Volume" + " "*($Volumes[-1].Name -5) +
                    "# Label" + " "*($Volumes[-1].Label -4) +
                    "# Active" + " "*($Volumes[-1].Active -5) +
                    "# Allocated" + " "*($Volumes[-1].AllocatedSpace -8) +
                    "# Maximum" + " "*($Volumes[-1].MaxSpace -6) +
                    "# DiffVolume" + " "*($Volumes[-1].DiffVolume -9) + "#"
    Write-Host $outputstring
    for ( $i=0 ; $i -lt $Volumes.Count -2; $i++) {
        $outputstring = "# $($Volumes[$i].Name)"
        $outputstring = $outputstring + " "*($Volumes[-1].Name - $outputstring.Length+3)
        Write-Host $outputstring -NoNewline
    
        $outputstring = "# $($Volumes[$i].Label)"
        $outputstring = $outputstring + " "*($Volumes[-1].Label - $outputstring.Length+3)
        Write-Host $outputstring -NoNewline
    
        $outputstring = "# $($Volumes[$i].Active)"
        $outputstring = $outputstring + " "*($Volumes[-1].Active - $outputstring.Length+3)
        Write-Host $outputstring -NoNewline
    
        $outputstring = "# $([UInt64]($Volumes[$i].AllocatedSpace / 1073741824)) GB"
        $outputstring = $outputstring + " "*($Volumes[-1].AllocatedSpace - $outputstring.Length+3)
        Write-Host $outputstring -NoNewline
    
        if ($Volumes[$i].MaxSpace -eq 18446744073709551615 -or $Volumes[$i].MaxSpace -eq 9223372036854775807) {
            $outputstring = "# No Limit" + " "*($Volumes[-1].MaxSpace - 7)
            Write-Host $outputstring -NoNewline
        } else {
            $outputstring = "# $([UInt64]($Volumes[$i].MaxSpace / 1073741824)) GB"
            $outputstring = $outputstring + " "*($Volumes[-1].MaxSpace - $outputstring.Length+3)
            Write-Host $outputstring -NoNewline
        }
    
        if ($Volumes[$i].Active -eq "Yes") {
            if ( $Volumes[$i].DiffVolume.DeviceID -eq $Volumes[$i].DeviceID ) {
                $outputstring = "# Same" + " "*($Volumes[-1].DiffVolume - 3) + "#"
                Write-Host $outputstring
            } else {
                $outputstring = "# $($Volumes[$i].DiffVolume.DeviceID)"
                $outputstring = $outputstring + " "*($Volumes[-1].DiffVolume - $outputstring.Length+3) + "#"
                Write-Host $outputstring
            }
        } else {
            $outputstring = "#" + " "*($Volumes[-1].DiffVolume + 2) + "#"
            Write-Host $outputstring
        }
    }
    $outputstring = "#"*($Volumes[-1].Name +3) +
                    "#"*($Volumes[-1].Label +3) +
                    "#"*($Volumes[-1].Active +3) +
                    "#"*($Volumes[-1].AllocatedSpace +3) +
                    "#"*($Volumes[-1].MaxSpace +3) +
                    "#"*($Volumes[-1].DiffVolume +4)
    Write-Host $outputstring
    
    $VolumeToChange = ((Read-Host 'Change which volume (Driveletter, enter "exit" to quit)') -replace '[^a-zA-Z]','').ToUpper()
    if ($VolumeToChange -ne "EXIT" -and $VolumeToChange -ne "QUIT") {
        if ($VolumeToChange.Length -ge 1) {
            $VolumeToChange = $VolumeToChange.Substring(0,1)
        } else {
            $VolumeToChange = "dümmy"
        }
        $VolumeToChange = $Volumes.Where({$_.Name -match $VolumeToChange -and $_.DeviceID -ne ""}).Name
        if ($VolumeToChange -eq $null) {
            Write-Host -BackgroundColor DarkRed " That Volume does not exist "
        } else {
            Write-Host -BackgroundColor DarkGreen " Selected Volume $VolumeToChange "
            $inputhost = ((Read-Host "Choose shadowcopy action for $VolumeToChange :`n(a)vtivate, (d)eactivate, (m)aximum size, (c)reate,`n(b)rowse a single shadowcopy, (r)emove a single shadowcopy, enter nothing to main menu") -replace '[^a-zA-Z]','').ToUpper()
            # Yes yes, I could use switch. SU....
            if ($inputhost -eq "A") {
                Invoke-CimMethod -ClassName Win32_ShadowCopy -MethodName "Create" -Arguments @{Volume=$VolumeToChange} -Verbose | Out-String
                Write-Host "Actviated for Volume $VolumeToChange."
                Write-Host -BackgroundColor DarkGreen "If you want shadowcopy to be persistently activated for $VolumeToChange after you deleted all shadowcopies you will have to change the maximum size.`nSorry, Microsoft crippeled the CIM Methods for Windows 10/11, and this is the way to make it behave like before."
            }
            if ($inputhost -eq "C") {
                Invoke-CimMethod -ClassName Win32_ShadowCopy -MethodName "Create" -Arguments @{Volume=$VolumeToChange} -Verbose | Out-String
            }
            if ($inputhost -eq "D") {
                $ShadowCopyList = $ShadowCopyFullList.Where({$_.VolumeName -eq $Volumes.Where({$_.Name -eq $VolumeToChange})[0].DeviceID })
                for ( $i = 0 ; $i -lt $ShadowCopyList.Count; $i++) {
                    Remove-CimInstance -InputObject $ShadowCopyFullList.Where({$_.ID -eq $($ShadowCopyList[$i].ID)})[0] -Verbose | Out-String
                }
                try {
                    Remove-CimInstance -InputObject $ShadowStorage.Where({$_.Volume.DeviceID -eq $Volumes.Where({$_.Name -eq $VolumeToChange})[0].DeviceID }) -ErrorAction Stop | Out-String
                } catch {
                    Write-Host -BackgroundColor DarkGreen " Informational: Shadowcopy config for $VolumeToChange was not persistent. "
                }
                Write-Host "All shadowcopies von $VolumeToChange deleted and shadowcopy for $VolumeToChange deactivated."
            }
            if ($inputhost -eq "M") {
                $ShadowCopyMaxSize = [UInt64]($Volumes.Where({$_.Name -eq $VolumeToChange })[0].MaxSpace)
                $inputhost2 = ((Read-Host "Choose shadowcopy size for $VolumeToChange : Enter new size in Gigabytes, Percent (XX%) or enter 'Maximum'") -replace '[^a-zA-Z0-9%]','').ToUpper()
                if ($inputhost2.StartsWith("M")) {
                    $ShadowCopyMaxSize = [UInt64]18446744073709551615
                    Write-Host -BackgroundColor DarkGreen ' Informational: Shadowcopy config via CIM is broken for the actualy unlimited value of 18446744073709551615 bytes. The highest bit gets killed. This bug is there since at least Windows Vista / Server 2008 (without R2). '
                } else {
                    if ($inputhost2 -ilike "?%" -or $inputhost2 -ilike "??%") {
                        $ShadowCopyMaxSize = [UInt64]($Volumes.Where({$_.Name -eq $VolumeToChange })[0].Capacity / 100 * [UInt64]($inputhost2 -replace '[^0-9]',''))
                        Write-Host $inputhost2
                    } else {
                        $ShadowCopyMaxSize = [UInt64]([UInt64]($inputhost2 -replace '[^0-9]','') * 1073741824)
                    }
                    if ($ShadowCopyMaxSize -lt ($Volumes.Where({$_.Name -eq $VolumeToChange })[0].AllocatedSpace - 268435456)) {
                        Write-Host "Too small for already allocated size, correcting"
                        $ShadowCopyMaxSize = [UInt64]($Volumes.Where({$_.Name -eq $VolumeToChange })[0].AllocatedSpace + 268435456)
                    }
                    if ($ShadowCopyMaxSize -gt ($Volumes.Where({$_.Name -eq $VolumeToChange })[0].Capacity / 2 )) {
                        Write-Host "Above 50%, correcting"
                        $ShadowCopyMaxSize = [UInt64]($Volumes.Where({$_.Name -eq $VolumeToChange })[0].Capacity / 2)
                    }
                }
                Write-Host "Setting $ShadowCopyMaxSize"
                # Set value
                $ShadowStorage.Where({$_.Volume.DeviceID -eq $Volumes.Where({$_.Name -eq $VolumeToChange})[0].DeviceID })[0].MaxSpace = [UInt64]$ShadowCopyMaxSize
                # actually apply value...
                Set-CimInstance -InputObject $ShadowStorage.Where({$_.Volume.DeviceID -eq $Volumes.Where({$_.Name -eq $VolumeToChange})[0].DeviceID })[0]
            }
            if ($inputhost -eq "R") {
                $ShadowCopyList = $ShadowCopyFullList.Where({$_.VolumeName -eq $Volumes.Where({$_.Name -eq $VolumeToChange})[0].DeviceID })
                for ( $i = 0 ; $i -lt $ShadowCopyList.Count; $i++ ){
                    Write-Host "Shadowcopy Number $i : $($ShadowCopyList[$i].InstallDate | get-date -format "yyyy-MM-dd HH:mm:ss")"
                }
                $inputhost2 = (Read-Host "Choose which shadowcopy to delete. Enter nothing to return") -replace '[^0-9]',''
                if ($inputhost2 -ne "") {
                    $inputhost2 = [int]$inputhost2
                    if ($inputhost2 -ge 0 -and $inputhost2 -lt $ShadowCopyList.Count) {
                        Remove-CimInstance -InputObject $ShadowCopyFullList.Where({$_.ID -eq $($ShadowCopyList[$inputhost2].ID)})[0] -Verbose | Out-String
                    }
                }
            }
            if ($inputhost -eq "B") {
                $ShadowCopyList = $ShadowCopyFullList.Where({$_.VolumeName -eq $Volumes.Where({$_.Name -eq $VolumeToChange})[0].DeviceID }) | Select-Object *,DirectPath
                for ( $i = 0 ; $i -lt $ShadowCopyList.Count; $i++ ){
                    $singleUTC = $ShadowCopyList[$i].InstallDate.ToUniversalTime()
                    $singleGMTString = "@GMT-$($singleUTC.Year).$($singleUTC.Month.ToString().PadLeft(2,"0")).$($singleUTC.Day.ToString().PadLeft(2,"0"))-$($singleUTC.Hour.ToString().PadLeft(2,"0")).$($singleUTC.Minute.ToString().PadLeft(2,"0")).$($singleUTC.Second.ToString().PadLeft(2,"0"))"
                    $ShadowCopyList[$i].DirectPath = "\\localhost\" + $VolumeToChange.Substring(0,1) + '$\' + $singleGMTString
                    Write-Host "Shadowcopy Number $i : $($ShadowCopyList[$i].InstallDate | get-date -format "yyyy-MM-dd HH:mm:ss") : Direct Path for CMD/Powershell/Explorer: $($ShadowCopyList[$i].DirectPath)"
                }
                $inputhost2 = (Read-Host "Choose which shadowcopy to open. Enter nothing to return") -replace '[^0-9]',''
                if ($inputhost2 -ne "") {
                    $inputhost2 = [int]$inputhost2
                    if ($inputhost2 -ge 0 -and $inputhost2 -lt $ShadowCopyList.Count) {
                        Get-ChildItem -Path "$($ShadowCopyList[$inputhost2].DirectPath)"
                        & "$env:SystemRoot\Explorer.exe" "$($ShadowCopyList[$inputhost2].DirectPath)"
                    }
                }
            }
        }
    }
} until ($VolumeToChange -eq "EXIT" -or $VolumeToChange -eq "QUIT")
