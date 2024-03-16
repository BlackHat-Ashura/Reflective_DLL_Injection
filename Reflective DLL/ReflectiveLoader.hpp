#ifndef REFLECTIVELOADER_HPP
#define REFLECTIVELOADER_HPP

#define TO_LOWERCASE(out, c1) (out = (c1 <= L'Z' && c1 >= L'A') ? (c1 - L'A') + L'a': c1)

typedef FARPROC(WINAPI* GetProcAddress_t) (HMODULE, LPCSTR);
typedef LPVOID(WINAPI* VirtualAlloc_t) (LPVOID, SIZE_T, DWORD, DWORD);
typedef HMODULE(WINAPI* LoadLibraryA_t) (LPCSTR);
typedef BOOL(WINAPI* pDLLEntry)(HINSTANCE dll, DWORD reason, LPVOID reserved);
// typedef BOOL(WINAPI* FreeLibrary_t) (HMODULE);
typedef BOOL(WINAPI* VirtualProtect_t) (LPVOID, SIZE_T, DWORD, PDWORD);

extern "C" void Reflect();

#endif