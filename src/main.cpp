#include <windows.h>
#include <string>




using PrototypeRand = int;
PrototypeRand prototypeRand = rand();
int hookedRand() 
{
	// { ... }
	MessageBoxW(NULL, L"Injected inside", L"Injected!", NULL);
	return 0;
}


void IATHookFunction(uint32_t hModule, PIMAGE_IMPORT_DESCRIPTOR importDescriptor, LPCSTR libraryName, HMODULE library) 
{
	while (importDescriptor->Name != NULL) 
	{
		PIMAGE_IMPORT_BY_NAME functionName = NULL;
		libraryName = reinterpret_cast<LPCSTR>(importDescriptor->Name) + hModule;
		library = LoadLibraryA(libraryName);

		if (!library) 
			return;

		PIMAGE_THUNK_DATA originalFirstThunk = reinterpret_cast<PIMAGE_THUNK_DATA>(hModule + importDescriptor->OriginalFirstThunk);
		PIMAGE_THUNK_DATA firstThunk = reinterpret_cast<PIMAGE_THUNK_DATA>(hModule + importDescriptor->FirstThunk);

		while (originalFirstThunk->u1.AddressOfData != NULL) 
		{
			functionName = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(hModule + originalFirstThunk->u1.AddressOfData);

			if (std::string(functionName->Name).compare("rand") != 0)
			{
				return;
			}

			DWORD oldProtect = NULL;
			VirtualProtect(reinterpret_cast<LPVOID>(&firstThunk->u1.Function), 8, PAGE_READWRITE, &oldProtect);
			firstThunk->u1.Function = reinterpret_cast<DWORD_PTR>(hookedRand);

			++originalFirstThunk;
			++firstThunk;
		}

		++importDescriptor;
	}
}


int main()
{
	auto const baseAddress = reinterpret_cast<uint32_t>(GetModuleHandleA(NULL));
	auto const dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(baseAddress);
	auto const ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(baseAddress + dosHeader->e_lfanew);

	auto const importsDirectory = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	auto const importDescriptor = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(importsDirectory.VirtualAddress + baseAddress);

	LPCSTR libraryName{};
	HMODULE library{};

	IATHookFunction(baseAddress, importDescriptor, libraryName, library);

	return 0;
}