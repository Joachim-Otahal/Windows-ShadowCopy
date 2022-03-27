<#
.SYNOPSIS
    If the shadowcopies are several days old we only need to keep one per day, every second day or every fourth day, thereby extending the time we can go back greatly.
.DESCRIPTION
    If the shadowcopies are several days old we only need to keep one per day, every second day or every fourth day, thereby extending the time we can go back greatly.
    Every time this script is called with -CreateShadowCopy:$true it will create a schadowcopy. For example every two hours.
    Every time this script is called with -Confirm:$true it will remove older schadowcopy with these default settings, else it will show wwhat it would remove:
        If the schadowcopy is more than two days keep only the last schadowcopy of that day.
        If the schadowcopy is more than eight days old keep only the "even day in the month" schadowcopies.
        If the schadowcopy is more than 16 days old keep only the "every fourth day in the month" schadowcopies.
    The set maximum number of schadowcopies in the registry, by default 64 per volume, is not exceeded. Check HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\VSS\Settings, DWORD MaxShadowCopies.

    Requirements: Only Volumes which have ShadowCopy activated are addressed. Powershell must be at least Version 3.0. Only testet on Server 2008 R2 and Windows 7 up to Server 2022 and Windows 11 with Powershell 5.1 or higher.

    When run from normal "run with powershell" it will evelate itself when needed.
    When run with "run with powerhsell" and a volume without activated shadowcopy is found it will ask whether to activate shadowcopy for that volume with a timeout of ten seconds.
    When run with "run with powerhsell" this script will create a deactivated scheduled task named "ShadowCopyJob-created-by-script", to run at 4:05, 8:05, 12:05, 16:05, and 20:05 each day local time, ready for the admin to inspect and activate.

    In Windows 10 Microsoft removed the GUI to activate shadowcopy, use this command in an administrative powershell to activate and create the first shadowcopy (or run this script, it will ask):
    Invoke-CimMethod -ClassName Win32_ShadowCopy -MethodName "Create" -Arguments @{Volume="J:\"}

    An extended config tool is ShadowCopyConfig.ps1 available from https://github.com/Joachim-Otahal/Windows-ShadowCopy ,

.PARAMETER KeepDaily
    Only remove several-times-per-day schadowcopies if they are older than this amount of days.
.PARAMETER KeepEvenDay
    Only remove schadowcopies if they on uneven days and older than this amount of days.
.PARAMETER KeepEveryFourthDay
    Only remove schadowcopies if they NOT on every fourth day and older than this amount of days.
.PARAMETER MaximumShadowCopies
    Only keep these number of ShadowCopies. Default: Keep all. The value in the registry overrides this setting.
.PARAMETER LogPath
    The PATH, not file, where to store the log. Each day a new log is created.
.PARAMETER Confirm
    If not set to $true it will only show which shaodowcopies would be deleted. Default is $false.
.PARAMETER CreateShadowCopy
    If not set to $true it will not create a ShadowCopy. Default is $false.
.EXAMPLE
    ShadowCopyCleanUpJob.ps1 -KeepDaily 1 -KeepEvenDay 4 -KeepEveryFourthDay 8 -MaximumShadowCopies 15 -Confirm:$true -CreateShadowCopy:$true
.NOTES
    Author: Joachim Otahal / jou@gmx.net / Joachim.Otahal@gmx.net
.LINK
    https://github.com/Joachim-Otahal/Windows-ShadowCopy / https://joumxyzptlk.de
#>


#### Information
#
# This creates shadowscopyies of all drives where Shadowcopy is activated.
# Emulates and extends NetApp SVM-schadowcopy behaviour: Anything > 2 days keep only daily, > seven days keep only even days, > 15 days keep every fourth day
# Whether it will create every 2 hours or twice a day depends on your scheduled task. Can be every Minute if you want to kill your performance.

# Versionlog:
# 1.0 Joachim Otahal 19th to 23rd March 2022

param (
    [int]$KeepDaily = 2,
    [int]$KeepEvenDay = 8,
    [int]$KeepEveryFourthDay = 16,
    [int]$MaximumShadowCopies = 65535,
    [bool]$Confirm = $false,
    [bool]$CreateShadowCopy = $false,
    [string]$LogPath
)

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

if ([float]([string]$PSVersionTable.PSVersion.Major+"."+[string]$PSVersionTable.PSVersion.Minor) -lt [float]"3.0") {
    Write-Verbose "Powershell must me at least verion 3.0 due to Get-CimInstance usage.`nDownload Version 5.1 (recommended!): https://www.microsoft.com/en-us/download/details.aspx?id=54616`nDownload Version 3: https://www.microsoft.com/en-us/download/details.aspx?id=34595" -Verbose
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

$TaskName = "ShadowCopyJob-created-by-script"
try {
    $null = Get-ScheduledTask -TaskName $TaskName -ErrorAction Stop
} catch {
    Write-Verbose-and-Log "Sheduled Task not found, creating one with five times per day - but deactivated."
    $TaskDescription = "ShadowCopyJob - Task created by script on $TimeStamp `nGreetings from Joachim Otahal, Germany."
    $TaskArgument = '-Command "& '+ "'" + $MyInvocation.MyCommand.Path + "'" + ' -Confirm:$true -CreateShadowCopy:$true -MaximumShadowCopies 40 -LogPath ' + "'" + $MyInvocation.MyCommand.Path.TrimEnd($MyInvocation.MyCommand.Name) + "'" + '"'
    $TaskAction = New-ScheduledTaskAction -Execute '%windir%\System32\WindowsPowerShell\v1.0\Powershell.exe' -Argument $TaskArgument
    #$TaskTrigger =  New-ScheduledTaskTrigger -Once -At "2000-01-01 00:05" -RepetitionInterval "06:00" -RandomDelay "00:05"
    $TaskTrigger =  @(
        $(New-ScheduledTaskTrigger -Daily -At "04:05" -RandomDelay "00:03")
        $(New-ScheduledTaskTrigger -Daily -At "08:05" -RandomDelay "00:03")
        $(New-ScheduledTaskTrigger -Daily -At "12:05" -RandomDelay "00:03")
        $(New-ScheduledTaskTrigger -Daily -At "16:05" -RandomDelay "00:03")
        $(New-ScheduledTaskTrigger -Daily -At "20:05" -RandomDelay "00:03")
    )
    $TaskPrincipal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    #$TaskSettings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 2) -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
    Register-ScheduledTask -Action $TaskAction -Trigger $TaskTrigger -TaskName $TaskName -Principal $TaskPrincipal -Description $TaskDescription
    Disable-ScheduledTask -TaskName $TaskName -Verbose
}

# Init log header

Write-Verbose-and-Log "########################################################"
Write-Verbose-and-Log "################## $($TimeStamp | Get-Date -Format 'yyyy-MM-dd HH:mm:ss') #################"

# Current Time as UTC
$CurrentTimeUTC = (Get-Date).ToUniversalTime()
$CurrentTimeUTCDateOnly=$CurrentTimeUTC | Get-Date -Format yyy-MM-dd | Get-Date

# Get Info

# we have to force the array, with only one entry it does not array it
$ShadowStorage = @(Get-CimInstance Win32_ShadowStorage)
$VolumesWithoutShadows =  (Get-CimInstance Win32_Volume).Where({$_.FileSystem -eq "NTFS" -and $ShadowStorage.Volume.DeviceID -notcontains $_.DeviceID}) | Sort-Object Name
$Volumes = (Get-CimInstance Win32_Volume).Where({$_.FileSystem -eq "NTFS" -and $ShadowStorage.Volume.DeviceID -contains $_.DeviceID}) | Sort-Object Name
$ShadowCopyFullList = Get-CimInstance Win32_ShadowCopy
if ([Environment]::UserInteractive) {
    foreach ($Volume in $VolumesWithoutShadows.Where({$_.DriveLetter -ne $null})) {
        Write-Verbose-and-Log "Volume $($Volume.DriveLetter) has no active shadowcopy - activate? (yes/ja / no/nein, 10 seconds timeout)"
        $count = [int]0
        # clear buffer
        $host.UI.RawUI.FlushInputBuffer()
        $key = $null
        # wait 10 seconds for a key...
        while($count -le 100 -and $key -eq $null )
        {
            if($host.UI.RawUI.KeyAvailable) {
                $key = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyUp")
            }
            Start-Sleep -Milliseconds 100
            $count++
        }
        # 89 = yes, 74 = ja
        if ($key.VirtualKeyCode -eq 89 -or $key.VirtualKeyCode -eq 74) {
            Write-Verbose-and-Log "$($Volume.Name) Create initial shadowcopy"
            Invoke-CimMethod -ClassName Win32_ShadowCopy -MethodName "Create" -Arguments @{Volume="$($Volume.Name)"} -Verbose
        } else {
            Write-Verbose-and-Log "Volume $($Volume.Name) shadowcopy settings not changed."
        }
    }
}

foreach ($Volume in $Volumes) {
    $MaximumShadowCopiesVolume=$MaximumShadowCopies
    Write-Verbose-and-Log "################ $($Volume.Name) ################"
    if (!$Confirm) { Write-Verbose-and-Log ('-Confirm is not set to $true, no schadowcopies for ' + "$($Volume.Name) will be deleted") }
    # Clean up old schadowcopies
    # We add a "only Day exact, no time" field as System.DateTime datafield, force sort by date newest at the end (should be anyway, but I don't trust it)
    $ShadowCopyList = $ShadowCopyFullList.Where({$_.VolumeName -eq $Volume.DeviceID}) |
        Select-Object *,@{Name="InstallDateUTC";Expression={$_.InstallDate.ToUniversalTime()}},@{Name="InstallDateUTCDateOnly";Expression={$_.InstallDate.ToUniversalTime() | 
        Get-Date -Format yyyy-MM-dd | Get-Date}} | Sort-Object InstallDate
    
    if ($ShadowCopyList.Count -gt 0) {
        # After $KeepDaily days: Keep only last schadowcopy of the day, after eight days keep only even days
        for ($AddDays = -$KeepDaily; $CurrentTimeUTCDateOnly.AddDays($AddDays+1) -gt $ShadowCopyList[0].InstallDateUTCDateOnly ; $AddDays--) {
            # Wenn > $AddDays Tage alt und mehr als ein schadowcopy da dann nuke alles vor den letzten schadowcopy am Tag.
            $ShadowCopyPerDay = $ShadowCopyList.Where({$_.InstallDateUTCDateOnly -eq $CurrentTimeUTCDateOnly.AddDays($AddDays)})
            if ($ShadowCopyPerDay.Count -gt "0" ) {
                $KeepNotify = $true
                # Nuke all daily except the last of the day
                for ($i = 0 ; $i+1 -lt $ShadowCopyPerDay.Count; $i++) {
                    Write-Verbose-and-Log "$($Volume.Name) $($ShadowCopyPerDay[$i].InstallDateUTC) Delete: More than $KeepDaily days old and we have $($ShadowCopyPerDay.Count) shadowcopies of that day."
                    $MaximumShadowCopiesVolume--
                    if ($Confirm) { Remove-CimInstance -InputObject $ShadowCopyFullList.Where({$_.ID -eq $($ShadowCopyPerDay[$i].ID)})[0] -Verbose}
                }
                # Nuke of that day when "day of month" uneven and and older than $KeepEveryDay
                # Nuke of that day when "day of month" is not every fourth and and older than $KeepEveryFourthDay
                if ( ( $AddDays -le -$KeepEvenDay -and [int]($ShadowCopyPerDay[-1].InstallDateUTC.Day / 2) * 2 -ne [int]$ShadowCopyPerDay[-1].InstallDateUTC.Day ) -or
                     ( $AddDays -le -$KeepEveryFourthDay -and [int]($ShadowCopyPerDay[-1].InstallDateUTC.Day / 4) * 4 -ne [int]$ShadowCopyPerDay[-1].InstallDateUTC.Day ) )  {
                    Write-Verbose-and-Log "$($Volume.Name) $($ShadowCopyPerDay[-1].InstallDateUTC) Delete: More than $(-$AddDays+1) days old and uneven or not every fourth"
                    $MaximumShadowCopiesVolume--
                    $KeepNotify = $false
                    if ($Confirm) { Remove-CimInstance -InputObject $ShadowCopyFullList.Where({$_.ID -eq $($ShadowCopyPerDay[-1].ID)})[0] -Verbose}
                }
                if ($KeepNotify) { Write-Verbose-and-Log "$($Volume.Name) $($ShadowCopyPerDay[-1].InstallDateUTC) Keeping!" }
            } else {
                Write-Verbose-and-Log "$($Volume.Name) $($CurrentTimeUTCDateOnly.AddDays($AddDays)) No shadowcopies found"
            }
        }
    }
    # Is the amount of shadowcopies still above MaximumShadowCopies? If yes, refresh shadowcopy list and remove those too many.
    if ($MaximumShadowCopiesVolume -lt 0 -or $ShadowCopyList.Count -gt $MaximumShadowCopies) {
        $ShadowCopyFullList = Get-CimInstance Win32_ShadowCopy
        $ShadowCopyList = $ShadowCopyFullList.Where({$_.VolumeName -eq $Volume.DeviceID}) | Sort-Object InstallDate
        Write-Verbose-and-Log "$($Volume.Name) Delete: Shadowcopies $($ShadowCopyList[0..($ShadowCopyList.Count - $MaximumShadowCopies - 1)].InstallDate) exceeding the maximum number of $MaximumShadowCopies."
        if ($Confirm) {
            for ($i = 0 ; $i -lt $MaximumShadowCopies - 1; $i++) {
                Remove-CimInstance -InputObject $ShadowCopyFullList.Where({$_.ID -eq $ShadowCopyList[$i].ID})[0] -Verbose
            }
        }
    }
    if (!$Confirm) { Write-Verbose-and-Log ('-Confirm is not set to $true, no schadowcopies for ' + "$($Volume.Name) have been deleted") }

    # Create a new schadowcopy
    if ($CreateShadowCopy) {
        Write-Verbose-and-Log "$($Volume.Name) Create new shadowcopy"
        Invoke-CimMethod -ClassName Win32_ShadowCopy -MethodName "Create" -Arguments @{Volume="$($Volume.Name)"} -Verbose
    } else {
        Write-Verbose-and-Log ('-CreateSchadowCopy is not set to $true, no new shadowcopy for ' + "$($Volume.Name) has been created")
    }
}

if ([Environment]::UserInteractive) {
    Write-Verbose "`nDone!`nWaiting 60 seconds before exit so you can save a screenshot (or press any key)." -Verbose
    $count = [int]0
    # clear buffer
    $host.UI.RawUI.FlushInputBuffer()
    $key = $null
    # wait 10 seconds for a key...
    while($count -le 600 -and $key -eq $null )
    {
        if($host.UI.RawUI.KeyAvailable) {
            $key = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyUp")
        }
        Start-Sleep -Milliseconds 100
        $count++
    }
}

