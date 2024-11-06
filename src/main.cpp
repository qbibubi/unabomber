#include <iostream>
#include <format>
#include <string_view>
#include <cstdint>
#include <windows.h>
#include <TlHelp32.h>

#define LOG(message) std::cout << std::format("[ {}:{} ]: {}", __FUNCTION__, __LINE__, message) << std::endl;

using namespace std::string_view_literals;

static auto constexpr TargetProgram = "WINMINE.EXE"sv;

[[nodiscard]] static DWORD GetProcessId(std::string_view processName)
{
    DWORD processId = { 0 };

    HANDLE const hProcessList = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessList == INVALID_HANDLE_VALUE)
    {
        LOG("CreateToolhelp32Snapshot failed");
        return processId;
    }

    PROCESSENTRY32 processEntry = { .dwSize { sizeof(PROCESSENTRY32) } };
    if (!Process32First(hProcessList, &processEntry))
    {
        LOG("Process32First failed");
        CloseHandle(hProcessList);
        return processId;
    }

    do
    {
        if (std::string_view(processEntry.szExeFile).compare(processName.data()))
        {
            continue;
        }

        processId = processEntry.th32ProcessID;
        LOG(std::format("Found {} (PID: {})", processName.data(), processId));

        CloseHandle(hProcessList);
        return processId;
    }
    while (Process32Next(hProcessList, &processEntry));
}

// template<typename T = void>
// [[nodiscard]] static bool HookIAT(std::string_view hookedFunctionName, T* hookedFunctionPointer)
// {
//     // WINMINE.EXE is a 32-bit executable
//     auto const baseAddress = reinterpret_cast<uint32_t>(hModule);
//
//
//     auto const dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(baseAddress);
//     auto const ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(baseAddress + dosHeader->e_lfanew);
//
//     auto const importsDirectoryVA = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
//     auto importDescriptor = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(importsDirectoryVA + baseAddress);
//
//     while (importDescriptor->Name)
//     {
//         PIMAGE_IMPORT_BY_NAME functionName;
//         moduleFunctionName = reinterpret_cast<LPCSTR>(importDescriptor->Name);
//
//         HANDLE hModule = LoadLibraryA(libraryName);
//         if (!hModule)
//         {
//             Log("LoadLibrary failed");
//             return false;
//         }
//
//         auto originalFirstThunk = reinterpret_cast<PIMAGE_THUNK_DATA>(baseAddress + importDescriptor->OriginalFirstThunk);
//         auto firstThunk = reinterpret_cast<PIMAGE_THUNK_DATA>(baseAddress + importDescriptor->FirstThunk);
//
//         while (originalFirstThunk->u1.AddressOfData)
//         {
//             functionName = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(baseAddress + originalFirstThunk->u1.AddressOfData);
//             if (std::string_view(functionName->Name).compare(hookedFunctionName.data()) != 0)
//             {
//                 continue;
//             }
//
//             DWORD oldProtect;
//             VirtualProtect(reinterpret_cast<LPVOID>(&firstThunk->u1.Function), 8, PAGE_READWRITE, &oldProtect);
//             firstThunk->u1.Function = reinterpret_cast<DWORD_PTR>(hookedFunctionPointer);
//             VirtualProtect(reinterpret_cast<LPVOID>(&firstThunk->u1.Function), 8, oldProtect, &oldProtect);
//
//             ++originalFirstThunk;
//             ++firstThunk;
//         }
//
//         ++importDescriptor;
//     }
// }

int main()
{
    DWORD const processId = GetProcessId("WINMINE.EXE");
    if (processId == 0)
    {
        LOG("Process does not exist");
        return 1;
    }

    HANDLE const process = OpenProcess(PROCESS_ALL_ACCESS, false, processId);
    if (process == 0)
    {
        LOG("OpenProcess failed");
        return 1;
    }

    return 0;
}
