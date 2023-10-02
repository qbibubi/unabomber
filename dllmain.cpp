#include "pch.h"
#include <windows.h>
#include <string>

using PrototypeRand = int;
PrototypeRand prototypeRand = rand();

int hookedRand() 
{
	return MessageBoxA(NULL, "ELo", "Dziwko", NULL);
}

BOOL APIENTRY DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    switch (fdwReason)
    {   
    case DLL_PROCESS_ATTACH: 
    {
		uint32_t hModule = reinterpret_cast<uint32_t>(GetModuleHandleA(NULL));
		PIMAGE_DOS_HEADER dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(hModule);
		PIMAGE_NT_HEADERS ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(hModule + dosHeader->e_lfanew);
		IMAGE_DATA_DIRECTORY importsDirectory = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
		PIMAGE_IMPORT_DESCRIPTOR importDescriptor = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(importsDirectory.VirtualAddress + hModule);

		LPCSTR libraryName = NULL;
		HMODULE library = NULL;
		PIMAGE_IMPORT_BY_NAME functionName = NULL;

		while (importDescriptor->Name != NULL)
		{
			libraryName = reinterpret_cast<LPCSTR>(importDescriptor->Name) + hModule;
			library = LoadLibraryA(libraryName);

			if (library)
			{
				PIMAGE_THUNK_DATA originalFirstThunk = reinterpret_cast<PIMAGE_THUNK_DATA>(hModule + importDescriptor->OriginalFirstThunk);
				PIMAGE_THUNK_DATA firstThunk = reinterpret_cast<PIMAGE_THUNK_DATA>(hModule + importDescriptor->FirstThunk);

				while (originalFirstThunk->u1.AddressOfData != NULL)
				{
					functionName = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(hModule + originalFirstThunk->u1.AddressOfData);

					if (std::string(functionName->Name).compare("rand") == 0)
					{
						DWORD oldProtect = NULL;
						VirtualProtect(reinterpret_cast<LPVOID>(&firstThunk->u1.Function), 8, PAGE_READWRITE, &oldProtect);

						firstThunk->u1.Function = reinterpret_cast<DWORD_PTR>(hookedRand);
					}
					++originalFirstThunk;
					++firstThunk;
				}
			}
			importDescriptor++;
		}

        break;
    }
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

