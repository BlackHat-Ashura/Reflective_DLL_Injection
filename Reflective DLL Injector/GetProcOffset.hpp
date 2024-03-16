#ifndef GetProcOffset_HPP
#define GetProcOffset_HPP

DWORD RVA2Offset(DWORD RVA, LPVOID peBase);
DWORD GetProcOffset(LPVOID dllContent, CHAR* exportName);

#endif