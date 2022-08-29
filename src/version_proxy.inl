#define POPULATE()                    \
    PROXY(GetFileVersionInfoA)        \
    PROXY(GetFileVersionInfoByHandle) \
    PROXY(GetFileVersionInfoExA)      \
    PROXY(GetFileVersionInfoExW)      \
    PROXY(GetFileVersionInfoSizeA)    \
    PROXY(GetFileVersionInfoSizeExA)  \
    PROXY(GetFileVersionInfoSizeExW)  \
    PROXY(GetFileVersionInfoSizeW)    \
    PROXY(GetFileVersionInfoW)        \
    PROXY(VerFindFileA)               \
    PROXY(VerFindFileW)               \
    PROXY(VerInstallFileA)            \
    PROXY(VerInstallFileW)            \
    PROXY(VerLanguageNameA)           \
    PROXY(VerLanguageNameW)           \
    PROXY(VerQueryValueA)             \
    PROXY(VerQueryValueW)


#define PROXY(x) \
    FARPROC o_ ## x; __attribute__((naked)) void _ ## x () { asm { jmp [o_ ## x] } }

POPULATE()

#undef PROXY

inline void InitProxy() {
    std::wstring versionPath;
    {
        PWSTR tmp;
        SHGetKnownFolderPath(FOLDERID_System, 0, nullptr, &tmp);
        versionPath = tmp;
        CoTaskMemFree(tmp);
    }

    versionPath += L"\\version.dll";

    auto hVersion = LoadLibraryW(versionPath.c_str());

#define PROXY(x) \
    o_ ## x = GetProcAddress(hVersion, xorstr_(#x));

    POPULATE();

#undef PROXY
}

#undef POPULATE