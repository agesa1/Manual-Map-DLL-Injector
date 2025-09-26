#include "injector.h" 
#include <windows.h>
#include <tlhelp32.h>
#include <string>
#include <iostream>
#include <fstream>

bool FileExists(const std::string& path) {
    std::ifstream f(path.c_str());
    return f.good();
}

DWORD GetProcessIdByName(const std::wstring& name) {
    PROCESSENTRY32W entry;
    entry.dwSize = sizeof(entry);
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
    DWORD pid = 0;
    if (Process32FirstW(snapshot, &entry)) {
        do {
            if (name == entry.szExeFile) {
                pid = entry.th32ProcessID;
                break;
            }
        } while (Process32NextW(snapshot, &entry));
    }
    CloseHandle(snapshot);
    return pid;
}

int main() {
    SetConsoleOutputCP(65001);

    std::cout << "DLL 1NJ3CT0R";
    std::string dllPath = "hello-world-x64.dll";
    std::wstring targetProc = L"integrity.exe";


    if (!FileExists(dllPath)) {
        std::cout << "[-] DLL not found in the current directory!\nPress any key to exit...";
        std::cin.get();
        return 1;
    }
    std::cout << "[+] DLL found automatically.\n";

    DWORD PID = 0;
    std::cout << "[*] Waiting for application to start...\n";
    while ((PID = GetProcessIdByName(targetProc)) == 0) {
        Sleep(1000); 
    }
    std::wcout << L"[+] PID: " << PID << L"]\n";

    TOKEN_PRIVILEGES priv = { 0 };
    HANDLE hToken = NULL;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        priv.PrivilegeCount = 1;
        priv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &priv.Privileges[0].Luid))
            AdjustTokenPrivileges(hToken, FALSE, &priv, 0, NULL, NULL);
        CloseHandle(hToken);
    }

    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);
    if (!hProc) {
        std::cout << "OpenProcess failed! Error: " << GetLastError() << "\nPress any key to exit...";
        std::cin.get();
        return -2;
    }

    std::ifstream File(dllPath, std::ios::binary | std::ios::ate);
    if (File.fail()) {
        std::cout << "Failed to open DLL file!\nPress any key to exit...";
        CloseHandle(hProc);
        std::cin.get();
        return -3;
    }
    auto FileSize = File.tellg();
    if (FileSize < 0x1000) {
        std::cout << "DLL file size is too small!\nPress any key to exit...";
        File.close();
        CloseHandle(hProc);
        std::cin.get();
        return -4;
    }

    BYTE* pSrcData = new BYTE[(UINT_PTR)FileSize];
    if (!pSrcData) {
        std::cout << "Memory allocation failed!\nPress any key to exit...";
        File.close();
        CloseHandle(hProc);
        std::cin.get();
        return -5;
    }
    File.seekg(0, std::ios::beg);
    File.read((char*)(pSrcData), FileSize);
    File.close();

    std::cout << "[*] Injecting...\n";
    if (!ManualMapDll(hProc, pSrcData, FileSize)) {
        delete[] pSrcData;
        CloseHandle(hProc);
        std::cout << "[!] Injection failed!\nPress any key to exit...";
        std::cin.get();
        return -6;
    }
    delete[] pSrcData;
    CloseHandle(hProc);

    std::cout << "[+] Success! DLL injected.\nPress any key to exit...";
    std::cin.get();
    return 0;
}
