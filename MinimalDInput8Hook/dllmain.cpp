// dllmain.cpp : Defines the entry point for the DLL application.
#include "stdafx.h"
#include "DInput8.h"
#include "Hook.h"
#include "CustomHooks.h"

#include "pch.h"
#include "proxydll.h"
#include "resource.h"

#include <memory>
#include <string>
#include <optional>
#include <cassert>

#include <filesystem>
#include <iostream>

struct ThreadData {
	HMODULE hModule;
};

namespace {

template <class T>
class LimitedString : private std::basic_string<T> {
public:
    LimitedString(const T* cstr) : std::basic_string<T>{ cstr } {};
    LimitedString(std::basic_string<T>&& string) :
        std::basic_string<T>{ std::move(string) } {}
    using std::basic_string<T>::find_last_of;
    using std::basic_string<T>::substr;
    using std::basic_string<T>::length;
    using std::basic_string<T>::c_str;

    LimitedString(LimitedString&&) noexcept = default;
    LimitedString(const LimitedString&) = delete;
    LimitedString(const std::basic_string<T>&) = delete;
    LimitedString& operator=(const LimitedString&) = delete;
};

typedef LimitedString<WCHAR> STDWSTRING;

class FileHandleWrapper {
public:
    FileHandleWrapper(HANDLE handle) noexcept : _handle{ handle } {}

    HANDLE operator *() const {
        return _handle;
    }

    BOOL operator !() const {
        return !_handle;
    }

    FileHandleWrapper(FileHandleWrapper&& wrapper) noexcept :
        _handle{ wrapper._handle } {
        wrapper._handle = NULL;
    }

    void reset() {
        if (!_handle) {
            return;
        }
        CloseHandle(_handle);
        _handle = NULL;
    }

    ~FileHandleWrapper() {
        reset();
    }

private:
    HANDLE _handle;

    FileHandleWrapper(const FileHandleWrapper&) = delete;
    FileHandleWrapper& operator=(const FileHandleWrapper&) = delete;
};

class FileData {
public:
    FileData(FileHandleWrapper&& hFile, STDWSTRING&& filename, BOOL erase) :
        _hFile{ std::move(hFile) },
        _filename{ std::move(filename) },
        _erase{ erase } {
    }

    ~FileData() {
        if (!_hFile || !_erase) {
            return;
        }
        _hFile.reset();
        DeleteFile(getFilenameAsLpcwstr());
    }

    LPCWSTR getFilenameAsLpcwstr() const {
        return _filename.c_str();
    }

    FileData(FileData&&) noexcept = default;
    FileData(const FileData&) = delete;
    FileData& operator=(const FileData&) = delete;

private:
    FileHandleWrapper _hFile;
    STDWSTRING _filename;
    BOOL _erase;
};

std::optional<STDWSTRING> GetModulePath(HMODULE hModule) {
    WCHAR wcModuleFilename[MAX_PATH + 1];
    const DWORD szModuleFilename = GetModuleFileName(hModule, wcModuleFilename, MAX_PATH);
    if (szModuleFilename == 0) {
        return std::nullopt;
    }
    const STDWSTRING moduleFilename{ wcModuleFilename };
    const size_t lastSlash = moduleFilename.find_last_of(L'\\');
    return { STDWSTRING { moduleFilename.substr(0, lastSlash + 1) } };
}

std::optional<FileData> WriteDataToFile(const STDWSTRING& modulePath, LPVOID pExe, DWORD szExe, const std::optional<STDWSTRING>& filename, BOOL eraseOnClose) {
    WCHAR tempFile[MAX_PATH + 1];
    if (!filename) {
        const UINT uUnique = GetTempFileName(modulePath.c_str(), L"FLS", 0, tempFile);
        if (uUnique == 0) {
            return std::nullopt;
        }
    }
    else {
        wcscpy_s(tempFile, MAX_PATH + 1, modulePath.c_str());
        const auto modulePathLength = modulePath.length();
        wcscpy_s(tempFile + modulePathLength,
            MAX_PATH + 1 - modulePathLength, filename->c_str());
    }
    FileHandleWrapper hFile{ CreateFile(tempFile,
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ, NULL, filename ? CREATE_NEW : CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL, NULL) };
    if (*hFile == INVALID_HANDLE_VALUE) {
        return std::nullopt;
    }
    DWORD nBytesWritten;
    const BOOL bSuccess = WriteFile(*hFile, pExe, szExe, &nBytesWritten, NULL);
    if (!bSuccess || (nBytesWritten != szExe)) {
        return std::nullopt;
    }
    FileHandleWrapper hFileRead{ CreateFile(tempFile, GENERIC_READ,
            FILE_SHARE_READ, NULL, OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL, NULL) };
    if (!hFileRead) {
        return std::nullopt;
    }
    return FileData{ std::move(hFileRead), std::move(tempFile), eraseOnClose };
}

std::optional<FileData> WriteResourceToFile(HMODULE hModule, const STDWSTRING& modulePath, int resourceIndex, std::optional<STDWSTRING> filename = std::nullopt, BOOL eraseOnClose = TRUE) {
    const HRSRC hRes = FindResource(
        hModule, MAKEINTRESOURCE(resourceIndex), RT_RCDATA);
    if (!hRes) {
        return std::nullopt;
    }
    const DWORD szData = SizeofResource(hModule, hRes);
    if (szData == 0) {
        return std::nullopt;
    }
    const HGLOBAL hData = LoadResource(hModule, hRes);
    if (!hData) {
        return std::nullopt;
    }
    const LPVOID pData = LockResource(hData);
    if (!pData) {
        return std::nullopt;
    }
    return { WriteDataToFile(modulePath, pData, szData, filename, eraseOnClose) };
}

DWORD ExecuteAndWaitForExe(const FileData&& exeData) {
    STARTUPINFO startupInfo;
    ZeroMemory(&startupInfo, sizeof(startupInfo));
    startupInfo.cb = sizeof(startupInfo);

    PROCESS_INFORMATION processInformation;
    ZeroMemory(&processInformation, sizeof(processInformation));

    // The string used to hold the command line cannot be const because the
    // CreateProcess function reserves the right to modify this string.
    WCHAR wcCommandLine[]{ L"module.exe /q" };

    const BOOL bSuccess = CreateProcess(
        exeData.getFilenameAsLpcwstr(),
        wcCommandLine,
        NULL,  // lpProcessAttributes
        NULL,  // lpThreadAttributes
        FALSE, // bInheritHandles
        0,     // dwCreationFlags
        NULL,  // lpEnvironment
        NULL,  // lpCurrentDirectory
        &startupInfo,
        &processInformation);
    if (!bSuccess) {
        return 1;
    }

    WaitForSingleObject(processInformation.hProcess, INFINITE);
    CloseHandle(processInformation.hProcess);
    CloseHandle(processInformation.hThread);
    return 0;
}

DWORD WINAPI ThreadProc(LPVOID lpParameter) {
    const std::unique_ptr<ThreadData> pData{ reinterpret_cast<ThreadData*>(lpParameter) };
    constexpr LPCWSTR lpMutexName{ L"Local\\FastLoadingRunOnceMutex" };
    auto&& hMutex{ CreateMutex(NULL, TRUE, lpMutexName) };
    if (!hMutex) {
        return 1;
    }
    if (WaitForSingleObject(hMutex, 0) != WAIT_OBJECT_0) {
        return 1;
    }
    auto&& modulePath{ GetModulePath(pData->hModule) };
    if (!modulePath) {
        return 1;
    }
    auto&& exeData{ WriteResourceToFile(
            pData->hModule, *modulePath, IDR_FPSEXE) };
    if (!exeData) {
        return 1;
    }
    auto&& configData{ WriteResourceToFile(
            pData->hModule, *modulePath, IDR_FPSCONFIG,
            L"FastLoading.xml", FALSE) };
    return ExecuteAndWaitForExe(std::move(*exeData));
}

} // anonymous namespace

int Init(HMODULE hModule)
{
	// Load the original dinput8.dll from the system directory
	char DInputDllName[MAX_PATH];
	GetSystemDirectoryA(DInputDllName, MAX_PATH);
	strcat_s(DInputDllName, "\\dinput8.dll");
	DInput8DLL = LoadLibraryA(DInputDllName);
	if (DInput8DLL > (HMODULE)31)
	{
		OriginalFunction = (DirectInput8Create_t)GetProcAddress(DInput8DLL, "DirectInput8Create");
	}
	InitializeHooking();

	//SetupHooks();

	DisableThreadLibraryCalls(hModule);
	ThreadData* const pData = new ThreadData{ hModule };
	const HANDLE hThread = CreateThread(NULL, 0, ThreadProc, pData, 0, NULL /*lpThreadId*/);
	if (!hThread) {
		return FALSE;
	}
}

/*
    Cleanup for tmp file not deleted
*/
bool CleanupFastLoadingTmpFiles(const STDWSTRING& modulePath) {
    for (const auto& entry : std::filesystem::directory_iterator(modulePath.c_str())) {
        if (entry.is_regular_file()) {
            const auto& filename = entry.path().filename().wstring();
            if (filename.find(L"FLS") == 0) { // Match prefix
                if (!DeleteFile(entry.path().c_str())) {
                    // Handle case where file cannot be deleted
                    DWORD error = GetLastError();
                    std::wcerr << L"Failed to delete file: " << entry.path().c_str()
                        << L" (Error code: " << error << L")\n";
                }
            }
        }
    }
}

BOOL APIENTRY DllMain(HMODULE Module, DWORD  ReasonForCall, LPVOID Reserved)
{
	switch (ReasonForCall)
	{
	case DLL_PROCESS_ATTACH:
		Init(Module);
		break;
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
        auto&& modulePath{ GetModulePath(Module) };
        if (modulePath) {
            CleanupFastLoadingTmpFiles(*modulePath);
        }
		break;
	}
	return TRUE;
}

