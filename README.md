Here are tools to handle Windows Shadowcopy more efficient. Or at all, since Microsoft removed the config-GUI tools from Windows 10 and Windows 11.
Both have been tested with Powershell 3.0 and 5.1 on Server 2008 (without R2), Vista up to Windows 11 and Server 2022. 

# ShadowCopyConfig.ps1

This is the config tool, in the end replaces the former VSSUIRUN which is still on Server, but not on client OS.

### Usage

Run with right-click -> "Run with PowerShell". It will ask for evelation when not yet ran with admin rights.
* It will show a menu of all local drives which have a drive letter or a mountpoint. ![image](https://github.com/Joachim-Otahal/Windows-ShadowCopy/assets/10100281/16c761d8-8eac-4cce-b376-bdca73414d0d)
 

* You can activate, deactivate, set the maximum size to use for shadowcopies, change the maximum number of shadowcopies per volume handled by the OS and selectively delete or open a shadowcopy. When you choose to open a shadowcopy it will open the explorer at the right point and copy the direct path, for example "\\localhost\F$\@GMT-2022.03.26-07.05.16", to the clipboard which can be used directly in CMD, powershell, robocopy, FreeCommander and so on. ![image](https://user-images.githubusercontent.com/10100281/162098713-349d3373-a8eb-4af5-bd20-b3ad2ddc5e80.png)


# ShadowCopyJob.ps1

This script is for a job to create shadowcopies. It has two major modes of operation: Interactive, aka manually via right-click -> "Run with PowerShell", and from the task sheduler.

### Note:
You will have to delete the autocreated task if you update from a version before 8th April of 2022 due to -Confirm was replaced with -Cleanup

### Usage:
When run manually via  -> "Run with PowerShell" it will do following actions:
* It will ask for evelation when needed.
* It will check which volumes have shadowcopy activated, and for those which don't have it activated it will ask whether it should activate shadowcopy. If you choose to activate it will create the first shadowcopy for that volume right away.
* For all other volumes: It will show what it WOULD do, which shadowcopy it would clean up and which shadowcopy would be created.
* It will check the task sheduler whether this script is already added as task. If not it will create a task with the default settings, but leave it deactivated for your to check.

You can inspect the created task before enabling it. If you move the script delete the task and re-run it, it will be recreatred.

### The created task uses following setting:
* Create a shadowcopy for all drives which have it activated at 04:05, 08:05, 12:05, 16:05 and 20:05 hours.
* Purging: Shadowcopies which are older than two days, but it will keep the last shadowcopy for each day.
* Purging: Shadowcopies which are older than eight days, keep only shadowcopies from EVEN days (April 2nd, April 4th, April 6th and so on).
* Purging: Shadowcopies which are older than 16 days, keep only shadowcopies from each fourth day (May 4th, May 8th, May 12th and so on).
* Purging: All shadowcopies which are beyond the limit of 40 shadowcopies per volume (Windows default is 64).

### Result:
* We have more shadowcopies per day for short time mistakes, by default five. (Microsoft default: two per day).
* We have shadowcopies which go more than three month into the past. (Microsoft default: ~ 32 days)
* We only need 40 shadowcopies to achieve that compared to the default limit of 64 shadowcopies.
* Other shadowcopy settings, like how much of the drive can be used for shadowcopies, are not overridden and followed.

