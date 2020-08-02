# CheekyBlinder

UPDATED to include image load and thread creation callbacks.

Enumerating and removing kernel callbacks using signed vulnerable drivers

Accompanying blog post: https://br-sn.github.io/Removing-Kernel-Callbacks-Using-Signed-Drivers/

WARNING: running this program might cause BSODs, run at your own risk.

Vulnerable driver can be downloaded from http://download-eu2.guru3d.com/afterburner/%5BGuru3D.com%5D-MSIAfterburnerSetup462Beta2.zip


Lots of code re-used from:
- https://github.com/gentilkiwi/mimikatz/
- https://github.com/RedCursorSecurityConsulting/PPLKiller

## Build instructions

Should build fine on VS2019, build for x64 only.

## Usage instructions

Run elevated. 
Arguments and examples:
```
cheekyblinder.exe /proc: lists the current process notification callbacks present on the system

cheekyblinder.exe /delpro <address>: removes the callback at <address> (use the address from the output of /process)

cheekyblinder.exe /img: lists the current image load notification callbacks present on the system

cheekyblinder.exe /delimg <address>: removes the image load callback at <address> (use the address from the output of /process)

cheekyblinder.exe /thread: lists the current thread creation notification callbacks present on the system

cheekyblinder.exe /delthread <address>: removes the thread creation callback at <address> (use the address from the output of /process)

cheekyblinder.exe /installDriver: installs the driver RTCore64.sys (place in same folder)

cheekyblinder.exe /uninstallDriver: removes the driver
```

## To do

I'll add more callbacks when I have time. 

Use the mimikatz pattern search to find the array rather than hacky offsets. PRs welcome

