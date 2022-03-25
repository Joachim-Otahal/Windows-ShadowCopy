Here are tools to handlw Windows Shadowcopy more efficient. Or at all, since Microsoft removed the Config-GUI tools from Windows 10 and Windows 11.



# ShadowCopyCleanUpJob.ps1

This script is for a job to create shadowcopies. It has two major modes of operation: Interactive, aka manually via right-click -> "Run with PowerShell", and from the task sheduler.

### Usage:
When run manually via  -> "Run with PowerShell" it will do following actions:
* It will ask for evelation when needed.
* It will check which volume have shadowcopy activated, and for which which don't have it activated it will ask whether it should activate shadowcopy. If you choose to activate it will create the first shadowcopy for that volume right away.
* For all other volumes: It will show what it WOULD do, which shadowcopy it would clean up and which shadowcopy would be created.
* It will check the task sheduler whether this script is already added as Task. If not it will create a task with the default settings, but leave it deactivated for your to check.

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

