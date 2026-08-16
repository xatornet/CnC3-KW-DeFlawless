#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <algorithm>
#include <cmath>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <mutex>
#include <string>
#include <vector>

extern "C" IMAGE_DOS_HEADER __ImageBase;

namespace {
struct Settings {
    bool enabled = true;
    bool logging = true;
    bool passthrough = false;
    float additionalFov = 0.0f;
    float defaultAspect = 1.777777791f;
    float fovMax = 110.0f;
};

Settings g_settings;
HMODULE g_game = nullptr;
std::vector<void*> g_stubs;
std::mutex g_logMutex;
volatile LONG g_hookCalls = 0;

std::string Directory() {
    char path[MAX_PATH]{};
    GetModuleFileNameA(reinterpret_cast<HMODULE>(&__ImageBase), path, MAX_PATH);
    std::string result(path);
    return result.substr(0, result.find_last_of("\\/") + 1);
}

void Log(const char* format, ...) {
    if (!g_settings.logging)
        return;
    char message[1024]{};
    va_list args;
    va_start(args, format);
    _vsnprintf_s(message, sizeof(message), _TRUNCATE, format, args);
    va_end(args);
    SYSTEMTIME now{};
    GetLocalTime(&now);
    char line[1200]{};
    std::snprintf(line, sizeof(line), "[%02u:%02u:%02u.%03u] %s\n", now.wHour, now.wMinute,
        now.wSecond, now.wMilliseconds, message);
    OutputDebugStringA(line);
    std::lock_guard<std::mutex> lock(g_logMutex);
    std::ofstream file(Directory() + "KaneDeFlawless.log", std::ios::app);
    if (file)
        file << line;
}

std::string IniPath() { return Directory() + "KaneDeFlawless.ini"; }

void ReadSettings() {
    const std::string path = IniPath();
    g_settings.logging = GetPrivateProfileIntA("General", "Logging", 1, path.c_str()) != 0;
    g_settings.enabled = GetPrivateProfileIntA("Display", "Enabled", 1, path.c_str()) != 0;
    g_settings.passthrough = GetPrivateProfileIntA("Debug", "Passthrough", 0, path.c_str()) != 0;
    char value[64]{};
    const auto readFloat = [&](const char* key, const char* fallback, float minimum, float maximum) {
        GetPrivateProfileStringA("Display", key, fallback, value, sizeof(value), path.c_str());
        const float parsed = std::strtof(value, nullptr);
        return std::isfinite(parsed) ? std::clamp(parsed, minimum, maximum) : std::strtof(fallback, nullptr);
    };
    g_settings.additionalFov = readFloat("AdditionalFOV", "0.0", -30.0f, 30.0f);
    g_settings.defaultAspect = readFloat("DefaultAspectRatio", "1.777777791", 0.5f, 4.0f);
    g_settings.fovMax = readFloat("FOVMax", "110.0", 30.0f, 110.0f);
    Log("INI: enabled=%d passthrough=%d additionalFOV=%.3f aspect=%.6f fovMax=%.3f",
        g_settings.enabled, g_settings.passthrough, g_settings.additionalFov,
        g_settings.defaultAspect, g_settings.fovMax);
}

float AspectRatio() {
    HWND window = FindWindowW(nullptr, L"Command & Conquer(tm) 3: La Ira de Kane");
    if (!window)
        window = GetForegroundWindow();
    RECT client{};
    if (!window || !GetClientRect(window, &client) || client.bottom <= 0)
        return g_settings.defaultAspect;
    return static_cast<float>(client.right) / static_cast<float>(client.bottom);
}

void __cdecl CorrectFov(float* value) {
    if (!value || !g_settings.enabled)
        return;
    const LONG call = InterlockedIncrement(&g_hookCalls);
    const float aspect = AspectRatio();
    if (aspect <= 0.0f)
        return;
    const float degrees = *value * 57.29577951308232f;
    const float corrected = 2.0f * std::atan(
        std::tan(degrees * 0.008726646259971648f) * aspect / g_settings.defaultAspect
    ) * 57.29577951308232f + g_settings.additionalFov;
    const float limited = std::clamp(corrected, 1.0f, g_settings.fovMax);
    *value = limited * 0.017453292519943295f;
    if (call <= 10 || call % 5000 == 0)
        Log("HOOK call=%ld inputRad=%.6f outputRad=%.6f aspect=%.6f", call,
            degrees * 0.017453292519943295f, *value, aspect);
}

bool Match(const uint8_t* address, const std::vector<int>& pattern) {
    for (size_t i = 0; i < pattern.size(); ++i)
        if (pattern[i] >= 0 && address[i] != static_cast<uint8_t>(pattern[i]))
            return false;
    return true;
}

struct MatchPoint { uint8_t* address; size_t patchOffset; };

std::vector<MatchPoint> FindMatches() {
    auto* base = reinterpret_cast<uint8_t*>(g_game);
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS32*>(base + dos->e_lfanew);
    const auto* section = IMAGE_FIRST_SECTION(nt);
    const std::vector<std::pair<std::vector<int>, size_t>> patterns = {
        {{0x74,-1,0xF3,0x0F,0x10,0x05,-1,-1,-1,-1,0xEB,-1,0xF3,0x0F,0x10,0x05,-1,-1,-1,-1,0xD9,0x05}, 20},
        {{0x74,-1,0xF3,0x0F,0x10,0x05,-1,-1,-1,-1,0xEB,-1,0xF3,0x0F,0x10,0x05,-1,-1,-1,-1,0xF3,0x0F,-1,-1,-1,0xD9,0x05}, 25}
    };
    std::vector<MatchPoint> result;
    for (WORD s = 0; s < nt->FileHeader.NumberOfSections; ++s) {
        if (std::strncmp(reinterpret_cast<const char*>(section[s].Name), ".text", 5) != 0)
            continue;
        auto* start = base + section[s].VirtualAddress;
        for (const auto& item : patterns) {
            for (size_t offset = 0; offset + item.first.size() <= section[s].Misc.VirtualSize; ++offset) {
                if (Match(start + offset, item.first))
                    result.push_back({start + offset, item.second});
            }
        }
    }
    Log("SCAN: matches=%zu", result.size());
    return result;
}

void* MakeStub(uint8_t* patch, const uint8_t original[6]) {
    if (g_settings.passthrough) {
        std::vector<uint8_t> code = {original[0],original[1],original[2],original[3],original[4],original[5],0xE9,0,0,0,0};
        auto* stub = static_cast<uint8_t*>(VirtualAlloc(nullptr, code.size(), MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE));
        if (!stub) return nullptr;
        std::memcpy(stub, code.data(), code.size());
        *reinterpret_cast<int32_t*>(stub + 7) = static_cast<int32_t>(reinterpret_cast<uintptr_t>(patch + 6) - reinterpret_cast<uintptr_t>(stub + 11));
        return stub;
    }
    std::vector<uint8_t> code = {
        0x9C,0x60,0x89,0xE5,0x83,0xE4,0xF0,
        original[0],original[1],original[2],original[3],original[4],original[5],
        0x81,0xEC,0x20,0x02,0x00,0x00,0x0F,0xAE,0x04,0x24,0xDB,0xE3,0x83,0xEC,0x08,
        0xF3,0x0F,0x11,0x84,0x24,0x08,0x02,0x00,0x00,0x8D,0x84,0x24,0x08,0x02,0x00,0x00,0x50,
        0xE8,0,0,0,0,0x83,0xC4,0x04,0x0F,0xAE,0x4C,0x24,0x08,
        0xF3,0x0F,0x10,0x84,0x24,0x08,0x02,0x00,0x00,0x89,0xEC,0x61,0x9D,0xE9,0,0,0,0
    };
    auto* stub = static_cast<uint8_t*>(VirtualAlloc(nullptr, code.size(), MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE));
    if (!stub) return nullptr;
    std::memcpy(stub, code.data(), code.size());
    *reinterpret_cast<int32_t*>(stub + 46) = static_cast<int32_t>(reinterpret_cast<uintptr_t>(&CorrectFov) - reinterpret_cast<uintptr_t>(stub + 50));
    const size_t jump = code.size() - 4;
    *reinterpret_cast<int32_t*>(stub + jump) = static_cast<int32_t>(reinterpret_cast<uintptr_t>(patch + 6) - reinterpret_cast<uintptr_t>(stub + jump + 4));
    FlushInstructionCache(g_game, stub, code.size());
    return stub;
}

bool Install() {
    if (!g_settings.enabled) return true;
    const auto matches = FindMatches();
    for (const auto& item : matches) {
        auto* patch = item.address + item.patchOffset;
        if (patch[0] != 0xD9 || patch[1] != 0x05) continue;
        uint8_t original[6]{};
        std::memcpy(original, patch, sizeof(original));
        auto* stub = static_cast<uint8_t*>(MakeStub(patch, original));
        if (!stub) return false;
        DWORD oldProtect = 0;
        if (!VirtualProtect(patch, 6, PAGE_EXECUTE_READWRITE, &oldProtect)) return false;
        patch[0] = 0xE9;
        *reinterpret_cast<int32_t*>(patch + 1) = static_cast<int32_t>(reinterpret_cast<uintptr_t>(stub) - reinterpret_cast<uintptr_t>(patch + 5));
        patch[5] = 0x90;
        VirtualProtect(patch, 6, oldProtect, &oldProtect);
        FlushInstructionCache(g_game, patch, 6);
        g_stubs.push_back(stub);
        Log("INSTALL: patch=%p stub=%p", static_cast<void*>(patch), static_cast<void*>(stub));
    }
    Log("INSTALL: installed=%zu/%zu", g_stubs.size(), matches.size());
    return !g_stubs.empty();
}

DWORD WINAPI Startup(void*) {
    Sleep(5000);
    ReadSettings();
    Log("STARTUP: KaneDeFlawless loaded game=%p", static_cast<void*>(g_game));
    Install();
    return 0;
}
}

BOOL APIENTRY DllMain(HMODULE module, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(module);
        g_game = GetModuleHandleW(nullptr);
        HANDLE thread = CreateThread(nullptr, 0, Startup, nullptr, 0, nullptr);
        if (thread) CloseHandle(thread);
    }
    return TRUE;
}
