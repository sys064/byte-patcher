#include <vector>
#include <cstdint>
#include <iostream>
#include <sstream>
#include <string>
#include <wininet.h>
#pragma comment(lib, "wininet.lib")

class binfb_t {
public:
    explicit binfb_t(HMODULE mod);
    void patches();
};

binfb_t::binfb_t(HMODULE mod)
{
    SetConsoleTitleA("Cracked by the binfbs");
}

std::string DownloadSignatures(const std::string& url) {
    std::string data;
    HINTERNET hInternet = InternetOpenA("UserAgent", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (hInternet) {
        HINTERNET hConnect = InternetOpenUrlA(hInternet, url.c_str(), NULL, 0, INTERNET_FLAG_PRAGMA_NOCACHE | INTERNET_FLAG_KEEP_CONNECTION, 0);
        if (hConnect) {
            char buffer[4096];
            DWORD bytesRead;
            while (InternetReadFile(hConnect, buffer, sizeof(buffer), &bytesRead) && bytesRead > 0) {
                data.append(buffer, bytesRead);
            }
            InternetCloseHandle(hConnect);
        }
        InternetCloseHandle(hInternet);
    }
    return data;
}

void patch_vmp()
{
    unsigned long old_protect = 0;
    const auto ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll)
        return;

    unsigned char callcode = *reinterpret_cast<unsigned char*>(reinterpret_cast<uintptr_t>(GetProcAddress(ntdll, "NtQuerySection")) + 4) - 1;
    unsigned char restore[] = { 0x4C, 0x8B, 0xD1, 0xB8, callcode };

    const auto nt_protect_virtual_mem = reinterpret_cast<uintptr_t>(GetProcAddress(ntdll, "NtProtectVirtualMemory"));
    if (!nt_protect_virtual_mem)
        return;

    VirtualProtect(reinterpret_cast<LPVOID>(nt_protect_virtual_mem), sizeof(restore), PAGE_EXECUTE_READWRITE, &old_protect);
    memcpy(reinterpret_cast<void*>(nt_protect_virtual_mem), restore, sizeof(restore));
    VirtualProtect(reinterpret_cast<LPVOID>(nt_protect_virtual_mem), sizeof(restore), old_protect, &old_protect);
}

void fill_with_nop(std::uintptr_t addr)
{
    unsigned long old_protect;
    VirtualProtect(reinterpret_cast<LPVOID>(addr), 1, PAGE_EXECUTE_READWRITE, &old_protect);
    *reinterpret_cast<uint8_t*>(addr) = 0x90; // NOP instruction
    VirtualProtect(reinterpret_cast<LPVOID>(addr), 1, old_protect, &old_protect);
}

void fill_with_je(std::uintptr_t addr)
{
    unsigned long old_protect;
    VirtualProtect(reinterpret_cast<LPVOID>(addr), 1, PAGE_EXECUTE_READWRITE, &old_protect);
    *reinterpret_cast<uint8_t*>(addr) = 0x74; // JE instruction
    VirtualProtect(reinterpret_cast<LPVOID>(addr), 1, old_protect, &old_protect);
}

void binfb_t::patches()
{
    // Download signatures from PasteBin link
    std::string signaturesData = DownloadSignatures("https://pastebin.com/raw/0JnMtgNy");
    if (signaturesData.empty()) {
        MessageBoxA(NULL, "Failed to download signatures data", "Error", MB_OK | MB_ICONERROR);
        return;
    }

    // Parse the downloaded data to extract signatures
    std::vector<std::pair<std::uintptr_t, std::string>> signatures;
    std::istringstream iss(signaturesData);
    std::string line;
    while (std::getline(iss, line)) {
        std::istringstream lineStream(line);
        std::string addrStr, opcode, description;
        if (lineStream >> addrStr >> opcode >> std::ws) {
            std::getline(lineStream, description, '|');
            std::uintptr_t address = std::stoull(addrStr, nullptr, 16);
            signatures.emplace_back(address, opcode + "|" + description);
        }
    }

    // Loop through each signature to find the addresses of the instructions
    for (const auto& sig : signatures) {
        std::uintptr_t address = sig.first;
        std::string signature = sig.second;

        // Split the signature into opcode and description
        size_t pos = signature.find("|");
        if (pos == std::string::npos) {
            MessageBoxA(NULL, "Invalid signature format", "Error", MB_OK | MB_ICONERROR);
            continue;
        }
        std::string opcode = signature.substr(0, pos);
        std::string description = signature.substr(pos + 1);

        // Replace each byte of the instruction with NOP
        for (size_t i = 0; i < opcode.size(); i += 3) {
            fill_with_nop(address + i / 3);
        }

        // If the description contains "NOP", continue to the next signature
        if (description.find("NOP") != std::string::npos)
            continue;

        // If the description contains "JNE2JE", replace JNE with JE
        if (description.find("JNE2JE") != std::string::npos) {
            fill_with_je(address);
        }
    }

    MessageBoxA(NULL, "Cracked by binfb", "Cracked", MB_OK);
}

void core(HMODULE mod)
{
    std::uintptr_t integrity = scanner()->find_pattern("E8 ? ? ? ? 48 8D 4D 17").get();

    if (is_bad_ptr(integrity))
    {
        MessageBoxA(NULL, "Integrity check not found", "Bin-fb", MB_OK);
    }
    else
    {
        MessageBoxA(NULL, "Integrity check successfully bypassed", "Bin-fb", MB_OK);
        mem_hook->NopMemory(integrity);
    }

    binfb_t* cheat = new binfb_t(mod);
    patch_vmp();
    cheat->patches();
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    if (ul_reason_for_call == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(hModule);
        DisableThreadLibraryCalls(GetModuleHandleA(0));

        CreateThread(0, 0, (LPTHREAD_START_ROUTINE)core, hModule, 0, 0);
    }

    return TRUE;
