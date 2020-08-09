# CheekyBlinder

UPDATED to include image load and thread creation callbacks.

Accompanying blog post: https://br-sn.github.io/Removing-Kernel-Callbacks-Using-Signed-Drivers/

## TL:DR

Anti-Virus and Endpoint Detection & Response products use kernel callbacks to get visibility on system events, such as:
- Process Creation
- Loading Images (exe/dll)
- Thread Creation
- File Creation
- Registry modification
- Object creation

Entering kernel memory as an administrator is not considered a security boundary, but how to go about it? 

Drivers have free access to kernel memory to perform their tasks. Vulnerable drivers exist that allow full kernel memory read/write operations. This program is a Proof of Concept that allows for the enumeration and modification of some of these kernel callbacks using a signed, vulnerable MSI driver. This can be used to view and remove the sources of telemetry the endpoint security products use and thus lead to the blinding of these products.

For now, Windows 1909/2004 is supported for the following callbacks only:
- Loading Images
- Thread Creation
- Process Creation

Future updates aim to include:
- Registry modifications
- Object creation
- Minifilter callbacks (file creation/modification and more)


The vulnerable driver can be downloaded from http://download-eu2.guru3d.com/afterburner/%5BGuru3D.com%5D-MSIAfterburnerSetup462Beta2.zip

Lots of code re-used from:
- https://github.com/gentilkiwi/mimikatz/
- https://github.com/RedCursorSecurityConsulting/PPLKiller

## Build instructions

Should build fine on VS2019, build for x64 only.

## Usage instructions

WARNING: running this program might cause BSODs, run at your own risk.

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

