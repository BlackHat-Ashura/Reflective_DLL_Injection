#include <Windows.h>
#include <stdio.h>

#include "GetProcOffset.hpp"



DWORD RVA2Offset(DWORD RVA, LPVOID peBase) {
	DWORD offset = 0;

	IMAGE_NT_HEADERS64* pNTHdr = (IMAGE_NT_HEADERS64*)((DWORD64)peBase + ((IMAGE_DOS_HEADER*)peBase)->e_lfanew);
	IMAGE_SECTION_HEADER* pSectionHdr = (IMAGE_SECTION_HEADER*)((DWORD64)&pNTHdr->OptionalHeader + pNTHdr->FileHeader.SizeOfOptionalHeader);

	DWORD sections = pNTHdr->FileHeader.NumberOfSections;
	for(int index = 0; index < sections; index++) {
		if (RVA >= pSectionHdr[index].VirtualAddress && RVA < (pSectionHdr[index].VirtualAddress + pSectionHdr[index].SizeOfRawData)) {
			offset = (RVA - pSectionHdr[index].VirtualAddress) + pSectionHdr[index].PointerToRawData;
			break;
		}
	}
	return offset;
}

DWORD GetProcOffset(LPVOID dllContent, CHAR* exportName) {
	DWORD procOffset = 0;
	DWORD64 pNTHdr = (DWORD64)dllContent + ((IMAGE_DOS_HEADER*)dllContent)->e_lfanew;
	DWORD exportDirAddr = ((IMAGE_NT_HEADERS64*)pNTHdr)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

	IMAGE_EXPORT_DIRECTORY* pExportDir = (IMAGE_EXPORT_DIRECTORY*)((DWORD64)dllContent + RVA2Offset(exportDirAddr, dllContent));

	DWORD* pEAT = (DWORD*)((DWORD64)dllContent + RVA2Offset(pExportDir->AddressOfFunctions, dllContent));
	DWORD* pExportFuncNamesTable = (DWORD*)((DWORD64)dllContent + RVA2Offset(pExportDir->AddressOfNames, dllContent));
	WORD* pOrdinalsTable = (WORD*)((DWORD64)dllContent + RVA2Offset(pExportDir->AddressOfNameOrdinals, dllContent));
	
	for (DWORD i = 0; i < pExportDir->NumberOfNames; i++) {
		CHAR* sTmpFuncName = (CHAR*)dllContent + RVA2Offset(pExportFuncNamesTable[i], dllContent);
		if (!strcmp(exportName, sTmpFuncName)) {
			WORD ordinal = pOrdinalsTable[i];
			procOffset = RVA2Offset(pEAT[ordinal], dllContent);
			break;
		}
	}
	return procOffset;
}