#include <Windows.h>

#include "ReflectiveLoader.hpp"

#pragma comment(linker, "/export:Reflect")

void Go() {
    ::MessageBoxW(NULL, L"##### Reflective DLL injection in action. #####\n\nThis is MessageBox from Go function.", L"MessageBox", NULL);
    return;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    //Go();
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        Go();
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

