#include <iostream>
#include <filesystem>
#include <vector>
#include <cwctype>

#include <frozen/set.h>
#include <frozen/string.h>
#include <frozen/unordered_map.h>

#include <MinHook.h>

#include <shlobj_core.h>
#include <phnt_windows.h>
#include <phnt.h>

#include "cx.h"
#include "xorstr.h"

#include "version_proxy.inl"

namespace fs = std::filesystem;
using namespace frozen::string_literals;

constexpr size_t MiVariant_FC3  = frozen::hash_string("FC3ModInstaller.exe"_s);
constexpr size_t MiVariant_FC4  = frozen::hash_string("FC4ModInstaller.exe"_s);
constexpr size_t MiVariant_FCP  = frozen::hash_string("FCPModInstaller.exe"_s);
constexpr size_t MiVariant_FC5  = frozen::hash_string("FC5ModInstaller.exe"_s);
constexpr size_t MiVariant_FCND = frozen::hash_string("FCNDModInstaller.exe"_s);
constexpr size_t MiVariant_FC6  = frozen::hash_string("FC6ModInstaller.exe"_s);

size_t g_Variant = 0;

static constexpr auto s_ExtWhiteList = frozen::make_set<size_t>({
    frozen::hash_string(L".a3"_s),
    frozen::hash_string(L".a4"_s),
    frozen::hash_string(L".a5"_s),
    frozen::hash_string(L".ae"_s),
});

static constexpr auto s_HideList = frozen::make_set<size_t>({
    // extracted from FC3 ModInstaller
    frozen::hash_string(L"emp.dll"_s),
    frozen::hash_string(L"uplay_r2.ini"_s),
    frozen::hash_string(L"codex.ini"_s),
    frozen::hash_string(L"origins.ini"_s),
    frozen::hash_string(L"orbit_api.ini"_s),
    frozen::hash_string(L"steam_api.ini"_s),
    frozen::hash_string(L"doge.dll"_s),
    frozen::hash_string(L"uplay_r164.dll"_s),
    frozen::hash_string(L"uplay_r1_loader64.3dm"_s),
    frozen::hash_string(L"uplay_r1_loader64.cdx"_s),

    // my own additions
    frozen::hash_string(L"uplay_r1_loader64.ubi"_s),
    frozen::hash_string(L"LumaPlay_x64.exe"_s),
    frozen::hash_string(L"LumaPlay_x64.dll"_s),
    frozen::hash_string(L"LumaPlay.ini"_s),
    frozen::hash_string(L"CPY.ini"_s),
    frozen::hash_string(L"UbiAPI.dll"_s),

    // hide ourselves
    frozen::hash_string(L"version.dll"_s)
});

static constexpr std::pair<size_t, std::tuple<std::array<uint8_t, 16>, size_t>> s_SpoofTable[] {
        // latest == cracked, no need to spoof  other binaries
        { frozen::hash_string(L"FC3.dll"_s)                   ^ MiVariant_FC3,  { cx::s_to_ba<"D442707DD13CAEDA2B18379CE0DA28E5">(), 29994856  } },
        { frozen::hash_string(L"FC3_d3d11.dll"_s)             ^ MiVariant_FC3,  { cx::s_to_ba<"9C4ACEFE5A1EBD6C7EF7E3B7B20A3EA6">(), 30057832  } },
        { frozen::hash_string(L"uplay_r1_loader.dll"_s)       ^ MiVariant_FC3,  { cx::s_to_ba<"6D133AB121D761017FDAAFF9D4D1F568">(), 300048    } },
        { frozen::hash_string(L"ubiorbitapi_r2_loader.dll"_s) ^ MiVariant_FC3,  { cx::s_to_ba<"F4C38E31A6E8D29E6A0A75DA98A69DCD">(), 329232    } },

        // latest == cracked, no need to spoof  other binaries
        { frozen::hash_string(L"steam_api.dll"_s)             ^ MiVariant_FC4,  { cx::s_to_ba<"11984DB972855DD266FDDDE5F47C87ED">(), 105152    } },
        { frozen::hash_string(L"steam_api64.dll"_s)           ^ MiVariant_FC4,  { cx::s_to_ba<"0E9EB69BE2D5CB05F0E6BC0F586B6A7C">(), 119488    } },
        { frozen::hash_string(L"uplay_r1_loader64.dll"_s)     ^ MiVariant_FC4,  { cx::s_to_ba<"9274BB3E1962BCF90898CE0B6557858E">(), 575704    } },

        { frozen::hash_string(L"dbdata.dll"_s)                ^ MiVariant_FCP,  { cx::s_to_ba<"B8258748D95FAFAB53C76010027846DC">(), 309448    } },
        { frozen::hash_string(L"FCPrimal.exe"_s)              ^ MiVariant_FCP,  { cx::s_to_ba<"8EC18A6710AB3AE5E173FC1F8801F0FB">(), 122244776 } },
        { frozen::hash_string(L"FCSplash.exe"_s)              ^ MiVariant_FCP,  { cx::s_to_ba<"30D043E34DA56486A083C2B3C3A3E3C5">(), 3230952   } },
        { frozen::hash_string(L"steam_api.dll"_s)             ^ MiVariant_FCP,  { cx::s_to_ba<"11984DB972855DD266FDDDE5F47C87ED">(), 105152    } },
        { frozen::hash_string(L"steam_api64.dll"_s)           ^ MiVariant_FCP,  { cx::s_to_ba<"0E9EB69BE2D5CB05F0E6BC0F586B6A7C">(), 119488    } },
        { frozen::hash_string(L"uplay_r1_loader64.dll"_s)     ^ MiVariant_FCP,  { cx::s_to_ba<"D7BA91C689D04AFD55C837AC4D458C53">(), 327880    } },

        { frozen::hash_string(L"dbdata.dll"_s)                ^ MiVariant_FC5,  { cx::s_to_ba<"EC306AD782776DC065066D37E69D4802">(), 533848    } },
        { frozen::hash_string(L"FarCry5.exe"_s)               ^ MiVariant_FC5,  { cx::s_to_ba<"2068DBE735E742CD3E34084C4C2D32FF">(), 212800    } },
        { frozen::hash_string(L"FC_m64.dll"_s)                ^ MiVariant_FC5,  { cx::s_to_ba<"7E03334E7BECD6788FAD9EBC758326FB">(), 246875968 } },
        { frozen::hash_string(L"steam_api64.dll"_s)           ^ MiVariant_FC5,  { cx::s_to_ba<"3A0B908E4D059125DD79D9014F5B67A9">(), 249120    } },
        { frozen::hash_string(L"uplay_r1_loader64.dll"_s)     ^ MiVariant_FC5,  { cx::s_to_ba<"24D4DB836B473A13F502B3A8488CDED9">(), 546136    } },

        { frozen::hash_string(L"dbdata.dll"_s)                ^ MiVariant_FCND, { cx::s_to_ba<"EC306AD782776DC065066D37E69D4802">(), 533848    } },
        { frozen::hash_string(L"FarCryNewDawn.exe"_s)         ^ MiVariant_FCND, { cx::s_to_ba<"4703368D5B6E912394D7D4579A7E4905">(), 124736    } },
        { frozen::hash_string(L"FC_m64.dll"_s)                ^ MiVariant_FCND, { cx::s_to_ba<"9EC69DF9D2F8B082B3C7481694894E5C">(), 457920832 } },
        { frozen::hash_string(L"steam_api.dll"_s)             ^ MiVariant_FCND, { cx::s_to_ba<"11984DB972855DD266FDDDE5F47C87ED">(), 105152    } },
        { frozen::hash_string(L"steam_api64.dll"_s)           ^ MiVariant_FCND, { cx::s_to_ba<"0E9EB69BE2D5CB05F0E6BC0F586B6A7C">(), 119488    } },
        { frozen::hash_string(L"uplay_r1_loader64.dll"_s)     ^ MiVariant_FCND, { cx::s_to_ba<"1B0E4AA78445DBEDF69DBA010EB107C1">(), 551256    } },

        { frozen::hash_string(L"dbdata.dll"_s)                ^ MiVariant_FC6,  { cx::s_to_ba<"FF8CA7D0AABEAA338A27E012C7ECDC32">(), 413256    } },
        { frozen::hash_string(L"FarCry6.exe"_s)               ^ MiVariant_FC6,  { cx::s_to_ba<"1EDE24C6EBF58105590819D3B8C867CA">(), 138064    } },
        { frozen::hash_string(L"FC_m64d3d12.dll"_s)           ^ MiVariant_FC6,  { cx::s_to_ba<"06C93EA976209B6389B838E82D728AF5">(), 522031440 } },
        { frozen::hash_string(L"upc_r2_loader64.dll"_s)       ^ MiVariant_FC6,  { cx::s_to_ba<"62D3DBDD9F92F9221D60A1C4E28CCF5B">(), 413336    } },
};
static constexpr auto s_Spoof = frozen::make_unordered_map(s_SpoofTable);

struct FileSpoofEntry_t {
    HANDLE             hFile    = nullptr;
    LPVOID             lpBuffer = nullptr;
    BCRYPT_HASH_HANDLE hHash    = nullptr;

    decltype(s_Spoof)::const_iterator spoofRef = s_Spoof.cend();
};
std::vector<FileSpoofEntry_t> g_SpoofEntries;

#define ORIG(x, ...) \
    ((decltype(hook_ ## x) *)(o_ ## x))(__VA_ARGS__)

LPVOID o_CreateFileW;
HANDLE __stdcall hook_CreateFileW(LPCWSTR               lpFileName,
                                  DWORD                 dwDesiredAccess,
                                  DWORD                 dwShareMode,
                                  LPSECURITY_ATTRIBUTES lpSecurityAttributes,
                                  DWORD                 dwCreationDisposition,
                                  DWORD                 dwFlagsAndAttributes,
                                  HANDLE                hTemplateFile)
{
    auto handle = ORIG(CreateFileW,
                       lpFileName,
                       dwDesiredAccess,
                       dwShareMode,
                       lpSecurityAttributes,
                       dwCreationDisposition,
                       dwFlagsAndAttributes,
                       hTemplateFile);

    constexpr size_t hash_gameHashesList = frozen::hash_string(L"GameHashes.list"_s);

    fs::path filePath = fs::path(lpFileName);

    size_t fileExtHash = frozen::hash_string(filePath.extension().wstring());
    if (s_ExtWhiteList.find(fileExtHash) != s_ExtWhiteList.end()) {
        return handle;
    }

    std::wstring fileName = filePath.filename().wstring();
    size_t fileNameHash = frozen::hash_string(fileName);

    if (fileNameHash == g_Variant) {
        return handle;
    }

    if (fileNameHash == hash_gameHashesList) {
        return nullptr;
    }

    FileSpoofEntry_t entry{};
    entry.hFile = handle;

    if (auto it = s_Spoof.find(fileNameHash ^ g_Variant); it != s_Spoof.end()) {
        entry.spoofRef = it;
    }

    g_SpoofEntries.push_back(entry);

    return handle;
}

LPVOID o_ReadFile;
BOOL __stdcall hook_ReadFile(HANDLE       hFile,
                             LPVOID       lpBuffer,
                             DWORD        nNumberOfBytesToRead,
                             LPDWORD      lpNumberOfBytesRead,
                             LPOVERLAPPED lpOverlapped)
{
    for (auto &entry : g_SpoofEntries) {
        if (entry.hFile == hFile) {
            if (entry.lpBuffer == nullptr) {
                entry.lpBuffer = lpBuffer;
            }
            else if (entry.hHash != nullptr) {
                SetLastError(ERROR_HANDLE_EOF);
                return FALSE;
            }

            break;
        }
    }

    return ORIG(ReadFile,
                hFile,
                lpBuffer,
                nNumberOfBytesToRead,
                lpNumberOfBytesRead,
                lpOverlapped);
}

LPVOID o_CloseHandle;
BOOL __stdcall hook_CloseHandle(HANDLE hObject) {
    auto result = ORIG(CloseHandle, hObject);

    for (auto it = g_SpoofEntries.begin(); it != g_SpoofEntries.end(); ++it) {
        if (it->hFile == hObject) {
            g_SpoofEntries.erase(it);
            break;
        }
    }

    return result;
}

LPVOID o_GetFileAttributesExW;
BOOL __stdcall hook_GetFileAttributesExW(LPCWSTR                lpFileName,
                                         GET_FILEEX_INFO_LEVELS fInfoLevelId,
                                         LPVOID                 lpFileInformation)
{
    fs::path filePath(lpFileName);
    std::wstring fileName = filePath.filename().wstring();
    size_t fileNameHash = frozen::hash_string(fileName);

    if (s_HideList.find(fileNameHash) != s_HideList.end()) {
        SetLastError(ERROR_PATH_NOT_FOUND);
        return FALSE;
    }

    auto result = ORIG(GetFileAttributesExW,
                       lpFileName,
                       fInfoLevelId,
                       lpFileInformation);

    if (auto it = s_Spoof.find(fileNameHash ^ g_Variant); it != s_Spoof.end()) {
        auto *info = (LPWIN32_FILE_ATTRIBUTE_DATA)lpFileInformation;
        ULARGE_INTEGER fileSize;
        fileSize.QuadPart = std::get<1>(it->second);
        info->nFileSizeHigh = fileSize.HighPart;
        info->nFileSizeLow = fileSize.LowPart;
    }

    return result;
}

LPVOID o_GetStdHandle;
HANDLE __stdcall hook_GetStdHandle(DWORD nStdHandle) {
    // disable console logging for obfuscation
    return nullptr;
}

LPVOID o_BCryptHashData;
NTSTATUS __stdcall hook_BCryptHashData(BCRYPT_HASH_HANDLE hHash,
                                       PUCHAR             pbInput,
                                       ULONG              cbInput,
                                       ULONG              dwFlags)
{
    auto result = ORIG(BCryptHashData,
                       hHash,
                       pbInput,
                       cbInput,
                       dwFlags);

    if (!NT_SUCCESS(result)) {
        return result;
    }

    for (auto &entry : g_SpoofEntries) {
        if (entry.lpBuffer == pbInput) {
            entry.hHash = hHash;
            break;
        }
    }

    return result;
}

LPVOID o_BCryptFinishHash;
NTSTATUS __stdcall hook_BCryptFinishHash(BCRYPT_HASH_HANDLE hHash,
                                         PUCHAR             pbOutput,
                                         ULONG              cbOutput,
                                         ULONG              dwFlags)
{
    auto result = ORIG(BCryptFinishHash,
                       hHash,
                       pbOutput,
                       cbOutput,
                       dwFlags);

    if (!NT_SUCCESS(result)) {
        return result;
    }

    #pragma unroll(128)
    for (auto &entry : g_SpoofEntries) {
        if (entry.spoofRef != s_Spoof.end() && entry.hHash == hHash) {
            #pragma unroll(16)
            for (auto i = 0u; i < 16; i++) {
                *(pbOutput + i) = std::get<0>(entry.spoofRef->second)[i];
            }
            entry.hHash = nullptr;
            break;
        }
    }

    return result;
}

LPVOID o_NtQueryDirectoryFile;
NTSTATUS __stdcall hook_NtQueryDirectoryFile(HANDLE                 FileHandle,
                                             HANDLE                 Event,
                                             PIO_APC_ROUTINE        ApcRoutine,
                                             PVOID                  ApcContext,
                                             PIO_STATUS_BLOCK       IoStatusBlock,
                                             PVOID                  FileInformation,
                                             ULONG                  Length,
                                             FILE_INFORMATION_CLASS FileInformationClass,
                                             BOOLEAN                ReturnSingleEntry,
                                             PUNICODE_STRING        FileName,
                                             BOOLEAN                RestartScan)
{
    auto result = ORIG(NtQueryDirectoryFile,
                       FileHandle,
                       Event,
                       ApcRoutine,
                       ApcContext,
                       IoStatusBlock,
                       FileInformation,
                       Length,
                       FileInformationClass,
                       ReturnSingleEntry,
                       FileName,
                       RestartScan);

    if (!NT_SUCCESS(result)) {
        return result;
    }

    if (FileInformationClass == FileFullDirectoryInformation) {
        void *endPos = (uint8_t *)FileInformation + Length;
        auto *curInfo = (PFILE_FULL_DIR_INFORMATION)FileInformation;
        auto *prevInfo = curInfo;

        while (curInfo < endPos) {
            std::wstring fileName(curInfo->FileName, curInfo->FileNameLength / sizeof(wchar_t));

            std::transform(fileName.begin(),
                           fileName.end(),
                           fileName.begin(),
                           std::towlower);

            size_t fileNameHash = frozen::hash_string((std::wstring_view)fileName);

            if (s_HideList.find(fileNameHash) != s_HideList.end())  {
                prevInfo->FileIndex = curInfo->FileIndex;
                prevInfo->NextEntryOffset += curInfo->NextEntryOffset;
            }

            if (auto it = s_Spoof.find(fileNameHash ^ g_Variant); it != s_Spoof.end()) {
                curInfo->EndOfFile.QuadPart = std::get<1>(it->second);
            }

            if (curInfo->NextEntryOffset == NULL) {
                break;
            }

            prevInfo = curInfo;
            curInfo = (FILE_FULL_DIR_INFORMATION *)((uint8_t *)(curInfo) + curInfo->NextEntryOffset);
        }
    }

    return result;
}

LPVOID o_ShellExecuteExW;
BOOL __stdcall hook_ShellExecuteExW(SHELLEXECUTEINFOW *pExecInfo) {
    // prevent Ubisoft/Steam store links from opening
    return TRUE;
}

LPVOID o_socket;
SOCKET __stdcall hook_socket(int af,
                             int type,
                             int protocol)
{
    // disable networking
    return INVALID_SOCKET;
}


#undef ORIG

BOOL __stdcall DllMain(HINSTANCE hinstDLL,
                       DWORD     fdwReason,
                       LPVOID    lpvReserved)
{
    if (fdwReason == DLL_PROCESS_ATTACH) {
        {
            auto fn = (decltype(IsDebuggerPresent) *)GetProcAddress(GetModuleHandleA(xorstr_("kernel32")),
                                                                    xorstr_("IsDebuggerPresent"));
            if (fn()) {
                return FALSE;
            }
        }

        InitProxy();

        if (MH_Initialize() != MH_OK) {
            return 0;
        }

        {
            TCHAR moduleName[MAX_PATH]{};
            GetModuleFileNameA(nullptr, moduleName, MAX_PATH);
            std::string moduleFilename = fs::path(moduleName).filename().string();
            g_Variant = frozen::hash_string((std::string_view)moduleFilename);
        }

        auto hook = [] (LPCSTR pszModule,
                        LPCSTR pszProcName,
                        LPVOID pDetour,
                        LPVOID *ppOriginal)
        {
            HMODULE hModule;
            LPVOID  pTarget;

            hModule = GetModuleHandleA(pszModule);
            if (hModule == nullptr) {
                return MH_ERROR_MODULE_NOT_FOUND;
            }

            pTarget = (LPVOID)GetProcAddress(hModule, pszProcName);
            if (pTarget == nullptr) {
                return MH_ERROR_FUNCTION_NOT_FOUND;
            }

            return MH_CreateHook(pTarget, pDetour, ppOriginal);
        };

#define HOOK(lib, func)                                                              \
    if (hook(xorstr_(#lib), xorstr_(#func), &hook_ ## func, &o_ ## func) != MH_OK) { \
        return 0;                                                                    \
    }

        HOOK(kernel32, CreateFileW)
        HOOK(kernel32, ReadFile)
        HOOK(kernel32, CloseHandle)
        HOOK(kernel32, GetFileAttributesExW)
        HOOK(kernel32, GetStdHandle)

        if (LoadLibraryA(xorstr_("bcrypt.dll")) == nullptr) {
            return 0;
        }

        HOOK(bcrypt, BCryptHashData)
        HOOK(bcrypt, BCryptFinishHash)

        HOOK(ntdll, NtQueryDirectoryFile)

        HOOK(shell32, ShellExecuteExW)

        if (LoadLibraryA(xorstr_("ws2_32.dll")) == nullptr) {
            return 0;
        }

        HOOK(ws2_32, socket)

#undef HOOK

        MH_EnableHook(MH_ALL_HOOKS);
    }

    return 1;
}