#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <tlhelp32.h>
#include <tchar.h>

// Retrieves PID of process name by using API calls CreateToolhelp32Snapshot & Process32First & Process32Next
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

	// DLL path
	LPCSTR DllPath = "Hello.dll";

	// handle to the specified process.
	printf("Getting handle to process");
	getchar();
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);
	printf("0x%d \n", hProcess);


	// Allocate memory for the DLL path in the target process
	// length of the path string + null terminator
	printf("Create Memory on remote process for DLL Path\n");
	getchar();
	LPVOID pDllPath = VirtualAllocEx(hProcess, 0, strlen(DllPath) + 1, MEM_COMMIT, PAGE_READWRITE);
	printf("%p \n", pDllPath);


	// Write DLL path inside the memory which allocated before
	// in the target process
	WriteProcessMemory(hProcess, pDllPath, (LPVOID)DllPath, strlen(DllPath) + 1, 0);
	printf("Write DLL path %s at %p \n", DllPath, pDllPath);
	getchar();

	// Retrieves function address of Kernel32.LoadLibraryA
	HMODULE Modulea = GetModuleHandleA("Kernel32.dll");
	FARPROC Function_address = GetProcAddress(Modulea, "LoadLibraryA");
	printf("Getting  Kernel32.LoadLibrary Adrdress: %p \n", Function_address);
	getchar();

	// Create a remote thread in the target process
	// calls LoadLibraryA as our dllpath as an argument -> program loads our dll
	HANDLE hLoadThread = CreateRemoteThread(hProcess, 0, 0, (LPTHREAD_START_ROUTINE)Function_address, pDllPath, 0, 0);
	printf("Create remote thread to load DLL on remote process");
	getchar();

	// Wait for the execution of our loader thread to finish
	WaitForSingleObject(hLoadThread, INFINITE);

	// Free the memory allocated for our dll path
	VirtualFreeEx(hProcess, pDllPath, strlen(DllPath) + 1, MEM_RELEASE);
	return 0;
}
