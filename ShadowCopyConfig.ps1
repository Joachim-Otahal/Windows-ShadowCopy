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
# 0.1 March 2022 Inital version Joachim Otahal
# 0.2            A little cleanup, Menu adjustment for 80 character screen, browse shows ISO8601 like date, path copy to clipboard
# 0.3 April 2022 Handle volumes mounted in a directory correct, show number of shadowcopies, better menu formatting.
#                Solving the problem to be unable to access the \\localhost\<drive>$\@GMT Path using:
#                https://gist.github.com/jborean93/f60da33b08f8e1d5e0ef545b0a4698a0
#                These Parts (c) 2019, Jordan Borean (@jborean93) <jborean93@gmail.com>
# 0.4 April 2022 Adding Registry setting for MaxShadowCopies

#### Typedefinition to NtFsControlFile/CreateFileW

Add-Type -TypeDefinition @'
using Microsoft.Win32.SafeHandles;
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.AccessControl;

namespace Win32
{
    public class NativeHelpers
    {
        [StructLayout(LayoutKind.Sequential)]
        public struct IO_STATUS_BLOCK
        {
            public UInt32 Status;
            public UInt32 Information;
        }
        
        [StructLayout(LayoutKind.Sequential)]
        public struct NT_Trans_Data
        {
            public UInt32 NumberOfSnapShots;
            public UInt32 NumberOfSnapShotsReturned;
            public UInt32 SnapShotArraySize;
            // Omit SnapShotMultiSZ because we manually get that string based on the struct results
        }

    }

    public class NativeMethods
    {
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern SafeFileHandle CreateFileW(
            string lpFileName,
            FileSystemRights dwDesiredAccess,
            FileShare dwShareMode,
            IntPtr lpSecurityAttributes,
            FileMode dwCreationDisposition,
            UInt32 dwFlagsAndAttributes,
            IntPtr hTemplateFile);

        [DllImport("ntdll.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern UInt32 NtFsControlFile(
            SafeFileHandle hDevice,
            IntPtr Event,
            IntPtr ApcRoutine,
            IntPtr ApcContext,
            ref NativeHelpers.IO_STATUS_BLOCK IoStatusBlock,
            UInt32 FsControlCode,
            IntPtr InputBuffer,
            UInt32 InputBufferLength,
            IntPtr OutputBuffer,
            UInt32 OutputBufferLength);

        [DllImport("ntdll.dll")]
        public static extern UInt32 RtlNtStatusToDosError(
            UInt32 Status);
    }
}
'@

#### Konstants

$TimeStamp = Get-Date
$ScriptName = $MyInvocation.MyCommand.Name
$RegistryPath = "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VSS\Settings"

#################### PSVerisonCheck

if ($PSVersionTable.PSVersion.Major -lt 4) {
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

# Get Info
# Yes, re-read everything every time since we allow changes

Write-Verbose "Gathering information..." -Verbose

do {
    # Get maximumshadowcopies from registry
    $MaxShadowCopies = (Get-ItemProperty -Path $RegistryPath).MaxShadowCopies
    # we have to force the array, with only one entry it does not array it
    $ShadowStorage = @(Get-CimInstance Win32_ShadowStorage)
    #$VolumesWithoutShadows =  (Get-CimInstance Win32_Volume).Where({$_.FileSystem -eq "NTFS" -and $ShadowStorage.Volume.DeviceID -notcontains $_.DeviceID}) | Sort-Object DriveLetter
    $Volumes = @((Get-CimInstance Win32_Volume).Where({$_.FileSystem -eq "NTFS" -and $_.Name -ilike "?:*"}) | Select-Object Name,Label,DeviceID,Capacity,FreeSpace,Active,Shadows,AllocatedSpace,MaxSpace,UsedSpace,Volume,DiffVolume | Sort-Object Name)
    # Tabletitles
    $Volumes += [pscustomobject]@{Name="Volume";Label="Label";DeviceID="";Capacity="";FreeSpace="";Active="Active";Shadows="Shadows";AllocatedSpace="Allocated";MaxSpace="Maximum";UsedSpace="";Volume="";DiffVolume=""}
    # Tablecellwidth
    $Volumes += [pscustomobject]@{Name=6;Label=5;DeviceID=0;Capacity=0;FreeSpace=0;Active=6;Shadows=7;AllocatedSpace=9;MaxSpace=10;UsedSpace=0;Volume=0;DiffVolume=10}
    #$Volumes += (Get-CimInstance Win32_Volume).Where({$_.FileSystem -eq "NTFS" -and $_.Name -inotlike "?:*"})
    $ShadowCopyFullList = @(Get-CimInstance Win32_ShadowCopy)

    # Fill in which volume has which settings

    for ( $i=0 ; $i -lt $Volumes.Count -2; $i++) {
        $ShadowStorageSingle = $ShadowStorage.Where({$_.Volume.DeviceID -eq $Volumes[$i].DeviceID})[0]
        if ($ShadowStorageSingle.Volume -ne $null) {
            $Volumes[$i].Active         = "Yes"
            $Volumes[$i].Shadows        = $ShadowCopyFullList.Where({$_.VolumeName -eq $Volumes[$i].DeviceID}).count
            $Volumes[$i].AllocatedSpace = $ShadowStorageSingle.AllocatedSpace
            $Volumes[$i].MaxSpace       = $ShadowStorageSingle.MaxSpace
            $Volumes[$i].UsedSpace      = $ShadowStorageSingle.UsedSpace
            $Volumes[$i].Volume         = $ShadowStorageSingle.Volume
            $Volumes[$i].DiffVolume     = $ShadowStorageSingle.DiffVolume
        } else {
            $Volumes[$i].Active         = "No"
        }
    }

    # Can be done more elegant, but not today :D
    # calculate cell width

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
                    "#"*($Volumes[-1].Shadows +3) +
                    "#"*($Volumes[-1].AllocatedSpace +3) +
                    "#"*($Volumes[-1].MaxSpace +3) +
                    "#"*($Volumes[-1].DiffVolume +4)
    Write-Host $outputstring
    $outputstring = "# Volume" + " "*($Volumes[-1].Name -5) +
                    "# Label" + " "*($Volumes[-1].Label -4) +
                    "# Active" + " "*($Volumes[-1].Active -5) +
                    "# Shadows" + " "*($Volumes[-1].Shadows -6) +
                    "# Allocated" + " "*($Volumes[-1].AllocatedSpace -8) +
                    "# Maximum" + " "*($Volumes[-1].MaxSpace -6) +
                    "# DiffVolume" + " "*($Volumes[-1].DiffVolume -9) + "#"
    Write-Host $outputstring
    for ( $i=0 ; $i -lt $Volumes.Count -2; $i++) {
        $outputstring  = "# $($Volumes[$i].Name)"
        $outputstring += " "*($Volumes[-1].Name - $outputstring.Length+3)
        Write-Host $outputstring -NoNewline

        $outputstring  = "# $($Volumes[$i].Label)"
        $outputstring += " "*($Volumes[-1].Label - $outputstring.Length+3)
        Write-Host $outputstring -NoNewline

        $outputstring  = "# $($Volumes[$i].Active)"
        $outputstring += " "*($Volumes[-1].Active - $outputstring.Length+3)
        Write-Host $outputstring -NoNewline

        $outputstring  = "# $($Volumes[$i].Shadows)"
        $outputstring += " "*($Volumes[-1].Shadows - $outputstring.Length+3)
        Write-Host $outputstring -NoNewline

        $outputstring  = "# $([UInt64]($Volumes[$i].AllocatedSpace / 1073741824)) GB"
        $outputstring += " "*($Volumes[-1].AllocatedSpace - $outputstring.Length+3)
        Write-Host $outputstring -NoNewline

        if ($Volumes[$i].MaxSpace -eq 18446744073709551615 -or $Volumes[$i].MaxSpace -eq 9223372036854775807) {
            $outputstring = "# No Limit" + " "*($Volumes[-1].MaxSpace - 7)
            Write-Host $outputstring -NoNewline
        } else {
            $outputstring  = "# $([UInt64]($Volumes[$i].MaxSpace / 1073741824)) GB"
            $outputstring += " "*($Volumes[-1].MaxSpace - $outputstring.Length+3)
            Write-Host $outputstring -NoNewline
        }
    
        if ($Volumes[$i].Active -eq "Yes") {
            if ( $Volumes[$i].DiffVolume.DeviceID -eq $Volumes[$i].DeviceID ) {
                $outputstring = "# Same" + " "*($Volumes[-1].DiffVolume - 3) + "#"
                Write-Host $outputstring
            } else {
                $outputstring  = "# $($Volumes[$i].DiffVolume.DeviceID)"
                $outputstring += " "*($Volumes[-1].DiffVolume - $outputstring.Length+3) + "#"
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
                    "#"*($Volumes[-1].Shadows +3) +
                    "#"*($Volumes[-1].AllocatedSpace +3) +
                    "#"*($Volumes[-1].MaxSpace +3) +
                    "#"*($Volumes[-1].DiffVolume +4)
    Write-Host $outputstring
    if ($MaxShadowCopies -eq $null) {
        Write-Host "# Registry value for MaxShadowCopies not set. Default is 16 for clients OS, 64 for server OS."
    } else {
        Write-Host "# Registry value for MaxShadowCopies is $MaxShadowCopies."
    }

    Write-Host "Choose Volume by Driveletter or Mountpoint.`nMAX to change registry for maximum number of shadow copies per volume."
    $VolumeToChange = ((Read-Host 'EXIT to quit.') -replace '[^a-zA-Z:\\]','').ToUpper()
    if ($VolumeToChange -notlike "EXI*" -and $VolumeToChange -notlike "QUI*"-and $VolumeToChange -notlike "MAX*") {
        $VolumeToChange = $Volumes.Where({$_.Name -ilike "$VolumeToChange*" -and $_.DeviceID -ne ""})[0].Name
        if ($VolumeToChange -eq $null) {
            Write-Host -BackgroundColor DarkRed " That Volume does not exist "
        } else {
            Write-Host -BackgroundColor DarkGreen " Selected Volume $VolumeToChange "
            Write-Host -ForegroundColor Yellow -BackgroundColor DarkGray -NoNewline "A"
            Write-Host -NoNewline "ctivate, "
            Write-Host -ForegroundColor Yellow -BackgroundColor DarkGray -NoNewline "d"
            Write-Host -NoNewline "eactivate, "
            Write-Host -ForegroundColor Yellow -BackgroundColor DarkGray -NoNewline "m"
            Write-Host -NoNewline "aximum size, "
            Write-Host -ForegroundColor Yellow -BackgroundColor DarkGray -NoNewline "c"
            Write-Host "reate," -NoNewline
            Write-Host -ForegroundColor Yellow -BackgroundColor DarkGray -NoNewline "o"
            Write-Host "pen or " -NoNewline
            Write-Host -ForegroundColor Yellow -BackgroundColor DarkGray -NoNewline "r"
            Write-Host "emove a single shadowcopy.`nEnter nothing to get back to the main menu " -NoNewline
            $inputhost = ((Read-Host "(a|d|m|c|o)") -replace '[^a-zA-Z]','').ToUpper()
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
                Write-Host -BackgroundColor Red "Delete $($ShadowCopyList.Count) shadowcopies and deactivate for Volume $($VolumeToChange) (y/n):" -NoNewline
                $inputhost2 = ((Read-Host) -replace '[^yY]','').ToUpper()
                if ($inputhost2 -eq "Y") {
                    for ( $i = 0 ; $i -lt $ShadowCopyList.Count; $i++) {
                        Remove-CimInstance -InputObject $ShadowCopyFullList.Where({$_.ID -eq $($ShadowCopyList[$i].ID)})[0] -Verbose | Out-String
                    }
                    try {
                        Remove-CimInstance -InputObject $ShadowStorage.Where({$_.Volume.DeviceID -eq $Volumes.Where({$_.Name -eq $VolumeToChange})[0].DeviceID }) -ErrorAction Stop | Out-String
                    } catch {
                        Write-Host -BackgroundColor DarkGreen " Informational: Shadowcopy config for $VolumeToChange was not persistent. "
                    }
                    Write-Host "All shadowcopies von $VolumeToChange deleted and shadowcopy for $VolumeToChange deactivated."
                } else {
                    Write-Host "Nothing was deleted, nothing got deactivated."
                }

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
            if ($inputhost -eq "B" -or $inputhost -eq "O") {
                $ShadowCopyList = $ShadowCopyFullList.Where({$_.VolumeName -eq $Volumes.Where({$_.Name -eq $VolumeToChange})[0].DeviceID }) | Select-Object *,DirectPath
                $ShadowCopyBasePath = "\\localhost\" + $VolumeToChange.Substring(0,1) + '$'
                for ( $i = 0 ; $i -lt $ShadowCopyList.Count; $i++ ){
                    $SingleGMTString = "@GMT-" + $ShadowCopyList[$i].InstallDate.ToUniversalTime().ToString("yyyy.MM.dd-HH.mm.ss")
                    $ShadowCopyList[$i].DirectPath = $ShadowCopyBasePath + '\' + $SingleGMTString
                    Write-Host "$i $($ShadowCopyList[$i].InstallDate.ToString("yyyy-MM-dd HH:mm:ss")), Direct Path: $($ShadowCopyList[$i].DirectPath)"
                }

                # Make the ShadowCopy actually accesible (Credits to Jordan Borean (@jborean93) <jborean93@gmail.com>)
                $Handle = [Win32.NativeMethods]::CreateFileW(
                    $ShadowCopyBasePath,
                    [System.Security.AccessControl.FileSystemRights]"ListDirectory, ReadAttributes, Synchronize",
                    [System.IO.FileShare]::ReadWrite,
                    [System.IntPtr]::Zero,
                    [System.IO.FileMode]::Open,
                    0x02000000,  # FILE_FLAG_BACKUP_SEMANTICS
                    [System.IntPtr]::Zero
                )
                if ($Handle.IsInvalid) {
                    $LastError = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                    $Msg = Get-LastWin32ExceptionMessage -ErrorCode $LastError
                    Write-Error -Message "CreateFileW($ShadowCopyBasePath) failed - $Msg"
                }
                # Set the initial buffer size to the size of NT_Trans_Data + 2 chars. We do this so we can get the actual buffer
                # size that is contained in the NT_Trans_Data struct. A char is 2 bytes (UTF-16) and we expect 2 of them
                $TransDataSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][Win32.NativeHelpers+NT_Trans_Data])
                $BufferSize = $TransDataSize + 4
                $OutBuffer = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($BufferSize)
                $IOBlock = New-Object -TypeName Win32.NativeHelpers+IO_STATUS_BLOCK
                # Actually triggering, after that the access works.
                $Result = [Win32.NativeMethods]::NtFsControlFile($Handle, [System.IntPtr]::Zero, [System.IntPtr]::Zero,
                    [System.IntPtr]::Zero, [Ref]$IOBlock, 0x00144064, [System.IntPtr]::Zero, 0, $OutBuffer, $BufferSize)
                if ($Result -ne 0) {
                    # If the result was not 0 we need to convert the NTSTATUS code to a Win32 code
                    $Win32Error = [Win32.NativeMethods]::RtlNtStatusToDosError($Result)
                    $Msg = Get-LastWin32ExceptionMessage -ErrorCode $Win32Error
                    Write-Error -Message "NtFsControlFile failed - $Msg"
                }
                # Cleanup handles
                [System.Runtime.InteropServices.Marshal]::FreeHGlobal($OutBuffer)
                $Handle.Dispose()

                $inputhost2 = (Read-Host "Choose which shadowcopy to open. Enter nothing to return") -replace '[^0-9]',''
                if ($inputhost2 -ne "") {
                    $inputhost2 = [int]$inputhost2
                    if ($inputhost2 -ge 0 -and $inputhost2 -lt $ShadowCopyList.Count) {


                        Write-Host -BackgroundColor DarkGreen "Contents of $($ShadowCopyList[$inputhost2].DirectPath) at $($ShadowCopyList[$inputhost2].InstallDate | get-date -format "yyyy-MM-dd HH:mm:ss")"
                        Get-ChildItem -Path "$($ShadowCopyList[$inputhost2].DirectPath)"
                        & "$env:SystemRoot\Explorer.exe" "$($ShadowCopyList[$inputhost2].DirectPath)"
                        Set-Clipboard -Value $ShadowCopyList[$inputhost2].DirectPath -Verbose
                        Write-Host -BackgroundColor DarkGreen "Path $($ShadowCopyList[$inputhost2].DirectPath) has been copied to clipboard, ready to paste in Explorer/CMD/Powershell"
                    }
                }
            }
        }
    }
    if ($VolumeToChange -like "MAX*") {
        If ($MaxShadowCopies -eq $null) {
            Write-Host "Value is not set. Default is 16 for client OS, 64 for server OS."
        } 
        $inputhost = [int]((Read-Host "Set new MaxShadowCopies value from 1 to 512. 0 to clear the value from the registy.") -replace '[^0-9]','')
        if ($inputhost -eq 0) {
            Remove-ItemProperty -Path $RegistryPath -Name MaxShadowCopies -Verbose -ErrorAction Ignore
        }
        if ($inputhost -gt 0 -and $inputhost -le 512) {
            if ($MaxShadowCopies -eq $null) {
                New-ItemProperty -Path $RegistryPath -Name "MaxShadowCopies" -PropertyType DWord -Value $inputhost
            } else {
                Set-ItemProperty -Path $RegistryPath -Name "MaxShadowCopies" -Value $inputhost -Verbose
            }
        }
    }
} until ($VolumeToChange -eq "EXIT" -or $VolumeToChange -eq "QUIT")
