#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <shellapi.h> 

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shell32.lib")

#define TARGET_EXE "Endfield.exe"
#define DLL_NAME "d3d11.dll"

static char g_base_dir[MAX_PATH];
static char g_dll_path[MAX_PATH];

BOOL is_admin(void) {
    BOOL r = FALSE;
    PSID g = NULL;
    SID_IDENTIFIER_AUTHORITY a = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(&a, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &g)) {
        CheckTokenMembership(NULL, g, &r);
        FreeSid(g);
    }
    return r;
}

DWORD find_process(const char *n) {
    HANDLE s = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (s == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32 p;
    p.dwSize = sizeof(p);
    DWORD pid = 0;
    if (Process32First(s, &p)) {
        do {
            if (_stricmp(p.szExeFile, n) == 0) {
                pid = p.th32ProcessID;
                break;
            }
        } while (Process32Next(s, &p));
    }
    CloseHandle(s);
    return pid;
}

BOOL inject(DWORD pid, const char *d) {
    HANDLE p = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!p) return FALSE;
    size_t l = strlen(d) + 1;
    LPVOID m = VirtualAllocEx(p, NULL, l, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!m) {
        CloseHandle(p);
        return FALSE;
    }
    WriteProcessMemory(p, m, d, l, NULL);
    HANDLE t = CreateRemoteThread(p, NULL, 0, (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA"), m, 0, NULL);
    if (t) {
        WaitForSingleObject(t, 5000);
        CloseHandle(t);
    }
    VirtualFreeEx(p, m, 0, MEM_RELEASE);
    CloseHandle(p);
    return t != NULL;
}

int main(void) {
    printf("\n[3DMigoto Loader]\n\n");

    if (!is_admin()) {
        char szPath[MAX_PATH];
        SHELLEXECUTEINFOA sei = {0}; 

        printf("Requesting Administrator privileges...\n");
        
        if (GetModuleFileNameA(NULL, szPath, MAX_PATH)) {
            sei.cbSize = sizeof(sei);
            sei.lpVerb = "runas";
            sei.lpFile = szPath;
            sei.hwnd = NULL;
            sei.nShow = SW_NORMAL;
            
            if (!ShellExecuteExA(&sei)) {
                 printf("Error: User rejected UAC prompt.\n");
                 Sleep(3000);
                 return 1;
            }
        }
        return 0;
    }

    GetModuleFileNameA(NULL, g_base_dir, MAX_PATH);
    char *s = strrchr(g_base_dir, '\\');
    if (s) *s = '\0';

    snprintf(g_dll_path, MAX_PATH, "%s\\%s", g_base_dir, DLL_NAME);

    printf("Ready.\n");
    printf("Waiting for %s...\n\n", TARGET_EXE);

    DWORD pid = 0;
    while ((pid = find_process(TARGET_EXE)) == 0) {
        Sleep(100);
    }

    Sleep(10);

    if (inject(pid, g_dll_path)) {
        printf("Injection successful.\n\n");
    } else {
        printf("Injection failed.\n\n");
    }

    printf("Closing in 5 seconds...\n");
    Sleep(5000);

    return 0;
}