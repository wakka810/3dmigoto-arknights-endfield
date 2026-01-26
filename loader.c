#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shell32.lib")

#define TARGET_EXE "Endfield.exe"
#define DLL_NAME "d3d11.dll"
#define INI_NAME "d3dx.ini"

static char g_base_dir[MAX_PATH];
static char g_dll_path[MAX_PATH];
static char g_ini_path[MAX_PATH];

typedef struct {
    DWORD cbSize;
    ULONG fMask;
    HWND hwnd;
    LPCSTR lpVerb;
    LPCSTR lpFile;
    LPCSTR lpParameters;
    LPCSTR lpDirectory;
    int nShow;
    HINSTANCE hInstApp;
    void *lpIDList;
    LPCSTR lpClass;
    HKEY hkeyClass;
    DWORD dwHotKey;
    union {
        HANDLE hIcon;
        HANDLE hMonitor;
    };
    HANDLE hProcess;
} MY_SHELLEXECUTEINFOA;

typedef BOOL (WINAPI *PFN_ShellExecuteExA)(MY_SHELLEXECUTEINFOA *pExecInfo);

BOOL get_process_path(DWORD pid, char *path, DWORD size) {
    HANDLE p = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!p) return FALSE;
    
    DWORD pathSize = size;
    BOOL result = QueryFullProcessImageNameA(p, 0, path, &pathSize);
    CloseHandle(p);
    return result;
}

BOOL update_ini_target(const char *ini_path, const char *process_path) {
    FILE *f = fopen(ini_path, "r");
    if (!f) {
        printf("Error: Cannot open %s\n", ini_path);
        return FALSE;
    }
    
    fseek(f, 0, SEEK_END);
    long file_size = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    char *content = (char *)malloc(file_size + 1);
    if (!content) {
        fclose(f);
        return FALSE;
    }
    
    size_t read_size = fread(content, 1, file_size, f);
    content[read_size] = '\0';
    fclose(f);
    
    char *new_content = (char *)malloc(file_size + MAX_PATH + 100);
    if (!new_content) {
        free(content);
        return FALSE;
    }
    new_content[0] = '\0';
    
    char *line_start = content;
    char *line_end;
    BOOL modified = FALSE;
    
    while ((line_end = strchr(line_start, '\n')) != NULL || *line_start != '\0') {
        char line[2048];
        size_t line_len;
        
        if (line_end) {
            line_len = line_end - line_start;
            strncpy(line, line_start, line_len);
            line[line_len] = '\0';
        } else {
            strcpy(line, line_start);
            line_len = strlen(line);
        }
        
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        
        if (_strnicmp(p, "target", 6) == 0) {
            char *eq = strchr(p, '=');
            if (eq) {
                char new_line[MAX_PATH + 32];
                snprintf(new_line, sizeof(new_line), "target = %s", process_path);
                strcat(new_content, new_line);
                modified = TRUE;
            } else {
                strcat(new_content, line);
            }
        } else {
            strcat(new_content, line);
        }
        
        if (line_end) {
            strcat(new_content, "\n");
            line_start = line_end + 1;
        } else {
            break;
        }
    }
    
    free(content);
    
    if (!modified) {
        printf("Warning: 'target' line not found in ini\n");
        free(new_content);
        return FALSE;
    }
    
    f = fopen(ini_path, "w");
    if (!f) {
        printf("Error: Cannot write to %s\n", ini_path);
        free(new_content);
        return FALSE;
    }
    
    fputs(new_content, f);
    fclose(f);
    free(new_content);
    
    printf("Updated ini target to: %s\n", process_path);
    return TRUE;
}

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
    DWORD dwRights = PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ;
    HANDLE p = OpenProcess(dwRights, FALSE, pid);
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
        
        printf("Requesting Administrator privileges...\n");

        if (GetModuleFileNameA(NULL, szPath, MAX_PATH)) {
            HMODULE hShell32 = LoadLibraryA("shell32.dll");
            if (hShell32) {
                PFN_ShellExecuteExA pShellExecuteExA = (PFN_ShellExecuteExA)GetProcAddress(hShell32, "ShellExecuteExA");
                if (pShellExecuteExA) {
                    MY_SHELLEXECUTEINFOA sei = {0};
                    sei.cbSize = sizeof(sei);
                    sei.lpVerb = "runas";
                    sei.lpFile = szPath;
                    sei.hwnd = NULL;
                    sei.nShow = SW_NORMAL;

                    if (!pShellExecuteExA(&sei)) {
                        printf("Error: User rejected UAC prompt.\n");
                        Sleep(3000);
                        FreeLibrary(hShell32);
                        return 1;
                    }
                }
                FreeLibrary(hShell32);
            }
        }
        return 0;
    }

    GetModuleFileNameA(NULL, g_base_dir, MAX_PATH);
    char *s = strrchr(g_base_dir, '\\');
    if (s) *s = '\0';

    snprintf(g_dll_path, MAX_PATH, "%s\\%s", g_base_dir, DLL_NAME);
    snprintf(g_ini_path, MAX_PATH, "%s\\%s", g_base_dir, INI_NAME);

    printf("Ready.\n");
    printf("Waiting for %s...\n\n", TARGET_EXE);

    DWORD pid = 0;
    while ((pid = find_process(TARGET_EXE)) == 0) {
        Sleep(100);
    }

    printf("Process found (PID: %lu)\n", pid);

    char process_path[MAX_PATH];
    if (get_process_path(pid, process_path, MAX_PATH)) {
        printf("Process path: %s\n", process_path);
        update_ini_target(g_ini_path, process_path);
    } else {
        printf("Warning: Could not get process path\n");
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
