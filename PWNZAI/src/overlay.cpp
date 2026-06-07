#pragma execution_character_set("utf-8")
#pragma warning(disable: 4068)
#pragma push_macro("max")
#pragma push_macro("min")
#undef max
#undef min

#include "overlay.h"
#include "auth.h"
#include "aimbot.h"
#include "detector.h"
#include "AimbotTarget.h"
#include "network_2pc.h"
#include "imgui.h"
#include "imgui_impl_win32.h"
#include "imgui_impl_dx11.h"
#include "implot.h"
#include <dwmapi.h>
#include <string>
#include <cmath>
#include <fstream>
#include <sstream>
#include <mmsystem.h>
#include <dxgi.h>
#include <shellapi.h>
#include <algorithm>
#include <cctype>
#include <ctime>
#include <cstdlib>
#include <chrono>
#include <thread>
#include <atomic>
#include <filesystem>
#include <map>
#include <memory>
#include <set>
#include <mutex>
#include <unordered_map>
#include <functional>

#include <iphlpapi.h>
#include <shlobj.h>
#include <wincrypt.h>
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "crypt32.lib")

#include "protect.h"
#include "xorstr.hpp"
#include "VMProtectSDK.h"

#pragma comment(lib, "dwmapi.lib")
#pragma comment(lib, "winmm.lib")

ID3D11Device* g_pd3dDevice = nullptr;
ID3D11DeviceContext* g_pd3dDeviceContext = nullptr;
IDXGISwapChain* g_pSwapChain = nullptr;
ID3D11RenderTargetView* g_mainRenderTargetView = nullptr;

extern std::vector<Detection> g_shared_heads;
extern std::mutex g_heads_mutex;
extern std::atomic<float> g_inference_jitter;
extern std::atomic<float> g_last_inference_time;
extern std::atomic<float> g_last_capture_time;
extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

int Overlay::active_tab = 0;
int Overlay::active_bind_id = -1;

LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    if (ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam)) return true;
    if (msg == WM_DESTROY) { PostQuitMessage(0); return 0; }
    return DefWindowProc(hWnd, msg, wParam, lParam);
}

// ============================================================
// DeepCleanTraces
// ============================================================
void Overlay::DeepCleanTraces() {
    VMProtectBeginUltra("DeepCleanTraces");
    MUTATE_SIGNATURE;
    try {
        HMODULE hDns = LoadLibraryA(XOR("dnsapi.dll"));
        if (hDns) {
            auto FlushCache = (BOOL(WINAPI*)())GetProcAddress(hDns, XOR("DnsFlushResolverCache"));
            if (FlushCache) FlushCache();
            FreeLibrary(hDns);
        }
        HMODULE hIphlp = LoadLibraryA(XOR("Iphlpapi.dll"));
        if (hIphlp) {
            typedef DWORD(WINAPI* FlushPathFunc)(int);
            typedef DWORD(WINAPI* FlushNetFunc)(DWORD);
            auto pFlushPath = (FlushPathFunc)GetProcAddress(hIphlp, XOR("FlushIpPathTable"));
            auto pFlushNet = (FlushNetFunc)GetProcAddress(hIphlp, XOR("FlushIpNetTable"));
            if (pFlushPath) pFlushPath(0);
            if (pFlushNet) pFlushNet(0);
            FreeLibrary(hIphlp);
        }
        SHFILEOPSTRUCTA fo = { 0 };
        fo.wFunc = FO_DELETE;
        fo.pFrom = "%TEMP%\\*\0";
        fo.fFlags = FOF_SILENT | FOF_NOCONFIRMATION | FOF_NOERRORUI;
        SHFileOperationA(&fo);
        char* userProfile = nullptr; size_t len = 0;
        _dupenv_s(&userProfile, &len, "USERPROFILE");
        if (userProfile) {
            std::string ne_path = std::string(userProfile) + "\\AppData\\Local\\NetEase";
            char double_null_path[MAX_PATH];
            memset(double_null_path, 0, sizeof(double_null_path));
            strncpy_s(double_null_path, ne_path.c_str(), ne_path.length());
            fo.pFrom = double_null_path;
            SHFileOperationA(&fo);
            free(userProfile);
        }
    }
    catch (...) {}
    PlaySoundA(XOR("C:\\Windows\\Media\\chimes.wav"), NULL, SND_FILENAME | SND_ASYNC);
    VMProtectEnd();
}

// ============================================================
// SpoofMAC
// ============================================================
void Overlay::SpoofMAC() {
    VMProtectBeginUltra("SpoofMAC");
    MUTATE_SIGNATURE;
    const char* hex = "0123456789ABCDEF";
    std::string new_mac = "02";
    for (int i = 0; i < 10; ++i) new_mac += hex[rand() % 16];
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        XOR("SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e972-e325-11ce-bfc1-08002be10318}"),
        0, KEY_READ | KEY_WRITE, &hKey) == ERROR_SUCCESS) {
        char subkey[256]; DWORD index = 0; DWORD subkeySize = sizeof(subkey);
        while (RegEnumKeyExA(hKey, index++, subkey, &subkeySize, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
            HKEY hSubKey;
            if (RegOpenKeyExA(hKey, subkey, 0, KEY_READ | KEY_WRITE, &hSubKey) == ERROR_SUCCESS) {
                char busType[256];
                DWORD busSize = sizeof(busType);
                if (RegQueryValueExA(hSubKey, XOR("BusType"), NULL, NULL, (LPBYTE)busType, &busSize) == ERROR_SUCCESS) {
                    RegSetValueExA(hSubKey, XOR("NetworkAddress"), 0, REG_SZ,
                        (const BYTE*)new_mac.c_str(), new_mac.length() + 1);
                }
                RegCloseKey(hSubKey);
            }
            subkeySize = sizeof(subkey);
        }
        RegCloseKey(hKey);
    }
    PlaySoundA(XOR("C:\\Windows\\Media\\tada.wav"), NULL, SND_FILENAME | SND_ASYNC);
    VMProtectEnd();
}

// ============================================================
// LoadAuth, SaveAuth, FetchHardwareInfo
// ============================================================
void Overlay::LoadAuth() {
    std::ifstream file(XOR("pwnz_auth.txt"));
    if (file.is_open()) {
        file.getline(auth_username, 64);
        file.getline(auth_password, 64);
        file.close();
        if (strlen(auth_username) > 0 && strlen(auth_password) > 0) {
            is_auto_logging_in = true;
        }
    }
}

void Overlay::SaveAuth() {
    std::ofstream file(XOR("pwnz_auth.txt"));
    if (file.is_open()) {
        file << auth_username << "\n" << auth_password;
        file.close();
    }
}

void Overlay::FetchHardwareInfo() {
    DWORD volSerial = 0;
    if (GetVolumeInformationA(XOR("C:\\"), NULL, 0, &volSerial, NULL, NULL, NULL, 0)) {
        snprintf(hwid_str, sizeof(hwid_str), XOR("PWNZ-%08X-%04X"), volSerial, (volSerial ^ 0xABCD));
    }
    HKEY hKey; DWORD bufSize = sizeof(cpu_str);
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, XOR("HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0"), 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegQueryValueExA(hKey, XOR("ProcessorNameString"), NULL, NULL, (LPBYTE)cpu_str, &bufSize); RegCloseKey(hKey);
    }
    IDXGIFactory1* factory = nullptr;
    if (SUCCEEDED(CreateDXGIFactory1(__uuidof(IDXGIFactory1), (void**)&factory))) {
        IDXGIAdapter1* adapter = nullptr; IDXGIAdapter1* bestAdapter = nullptr; SIZE_T maxVRAM = 0;
        for (UINT i = 0; factory->EnumAdapters1(i, &adapter) != DXGI_ERROR_NOT_FOUND; ++i) {
            DXGI_ADAPTER_DESC1 desc; adapter->GetDesc1(&desc);
            if (desc.DedicatedVideoMemory > maxVRAM) { maxVRAM = desc.DedicatedVideoMemory; if (bestAdapter) bestAdapter->Release(); bestAdapter = adapter; }
            else adapter->Release();
        }
        if (bestAdapter) {
            DXGI_ADAPTER_DESC1 desc; bestAdapter->GetDesc1(&desc);
            size_t converted = 0; wcstombs_s(&converted, gpu_str, sizeof(gpu_str), desc.Description, _TRUNCATE);
            bestAdapter->Release();
        }
        factory->Release();
    }
}

// ============================================================
// LoadConfig (с unordered_map)
// ============================================================
void Overlay::LoadConfig(Aimbot* aim) {
    VMProtectBeginUltra("LoadConfig");
    std::string config_data = "";
    std::ifstream file_bin(XOR("pwnz_enc.bin"), std::ios::binary);
    if (file_bin.is_open()) {
        std::vector<BYTE> buffer((std::istreambuf_iterator<char>(file_bin)), std::istreambuf_iterator<char>());
        file_bin.close();
        if (!buffer.empty()) {
            DATA_BLOB DataIn, DataOut;
            DataIn.pbData = buffer.data();
            DataIn.cbData = (DWORD)buffer.size();
            if (CryptUnprotectData(&DataIn, NULL, NULL, NULL, NULL, 0, &DataOut)) {
                config_data = std::string((char*)DataOut.pbData, DataOut.cbData);
                LocalFree(DataOut.pbData);
            }
        }
    }
    else {
        std::ifstream file_ini(XOR("pwnz_cfg.ini"));
        if (file_ini.is_open()) {
            config_data.assign(std::istreambuf_iterator<char>(file_ini), std::istreambuf_iterator<char>());
            file_ini.close();
        }
        else {
            VMProtectEnd();
            return;
        }
    }
    if (config_data.empty()) { VMProtectEnd(); return; }

    auto safe_stof = [](std::string s) {
        std::replace(s.begin(), s.end(), ',', '.');
        std::istringstream iss(s);
        iss.imbue(std::locale("C"));
        float f = 0.0f;
        iss >> f;
        return f;
        };
    auto safe_stod = [](std::string s) {
        std::replace(s.begin(), s.end(), ',', '.');
        std::istringstream iss(s);
        iss.imbue(std::locale("C"));
        double d = 0.0;
        iss >> d;
        return d;
        };

    std::unordered_map<std::string, std::function<void(const std::string&)>> handlers;

    handlers["lifetime_seconds"] = [&](const std::string& v) { lifetime_seconds = safe_stod(v); };
    handlers["aim_max_sens"] = [&](const std::string& v) { aim_max_sens = safe_stof(v); };
    handlers["aim_min_sens"] = [&](const std::string& v) { aim_min_sens = safe_stof(v); };
    handlers["fov_aimbot"] = [&](const std::string& v) { fov_aimbot = safe_stof(v); };
    handlers["is_russian"] = [&](const std::string& v) { is_russian = std::stoi(v); };
    handlers["aim_offset_x"] = [&](const std::string& v) { aim_offset_x = safe_stof(v); };
    handlers["aim_offset_y"] = [&](const std::string& v) { aim_offset_y = safe_stof(v); };
    handlers["aim_key_main"] = [&](const std::string& v) { aim_key_main = std::stoi(v); };
    handlers["aim_key_sub"] = [&](const std::string& v) { aim_key_sub = std::stoi(v); };
    handlers["ai_confidence_body"] = [&](const std::string& v) { ai_confidence_body = safe_stof(v); };
    handlers["ai_confidence_head"] = [&](const std::string& v) { ai_confidence_head = safe_stof(v); };
    handlers["min_box_area_body"] = [&](const std::string& v) { min_box_area_body = safe_stof(v); };
    handlers["min_box_area_head"] = [&](const std::string& v) { min_box_area_head = safe_stof(v); };
    handlers["disable_all_visuals_when_hidden"] = [&](const std::string& v) { disable_all_visuals_when_hidden = std::stoi(v); };
    handlers["custom_res_w"] = [&](const std::string& v) { custom_res_w = std::stoi(v); };
    handlers["custom_res_h"] = [&](const std::string& v) { custom_res_h = std::stoi(v); };
    handlers["aim_smoother"] = [&](const std::string& v) { aim_smoother = safe_stof(v); };
    handlers["fov_scan"] = [&](const std::string& v) { fov_scan = safe_stof(v); };
    handlers["aim_kill_delay"] = [&](const std::string& v) { aim_kill_delay = safe_stof(v); };
    handlers["obs_bypass"] = [&](const std::string& v) { obs_bypass = std::stoi(v); };
    handlers["menu_scale"] = [&](const std::string& v) { menu_scale = safe_stof(v); };
    handlers["hardware_type"] = [&](const std::string& v) { hardware_type = std::stoi(v); };
    handlers["com_port"] = [&](const std::string& v) { com_port = std::stoi(v); };
    handlers["aim_deadzone"] = [&](const std::string& v) { aim_deadzone = safe_stof(v); };
    handlers["draw_crosshair"] = [&](const std::string& v) { draw_crosshair = std::stoi(v); };
    handlers["hit_chance"] = [&](const std::string& v) { hit_chance = safe_stof(v); };
    handlers["menu_width"] = [&](const std::string& v) { menu_width = safe_stof(v); };
    handlers["menu_height"] = [&](const std::string& v) { menu_height = safe_stof(v); };
    handlers["trigger_enable"] = [&](const std::string& v) { trigger_enable = std::stoi(v); };
    handlers["trigger_delay"] = [&](const std::string& v) { trigger_delay = safe_stof(v); };
    handlers["trigger_target"] = [&](const std::string& v) { trigger_target = std::stoi(v); };
    handlers["trigger_key"] = [&](const std::string& v) { trigger_key = std::stoi(v); };
    handlers["rcs_enable"] = [&](const std::string& v) { rcs_enable = std::stoi(v); };
    handlers["rcs_pitch"] = [&](const std::string& v) { rcs_pitch = safe_stof(v); };
    handlers["rcs_yaw"] = [&](const std::string& v) { rcs_yaw = safe_stof(v); };
    handlers["eco_mode"] = [&](const std::string& v) { eco_mode = std::stoi(v); };
    handlers["memory_enemy_frames"] = [&](const std::string& v) { memory_enemy_frames = std::stoi(v); };
    handlers["refresh_rate_idx"] = [&](const std::string& v) { refresh_rate_idx = std::stoi(v); };
    handlers["auto_confidence"] = [&](const std::string& v) { auto_confidence = std::stoi(v); };
    handlers["sticky_aim"] = [&](const std::string& v) { sticky_aim = std::stoi(v); };
    handlers["enable_pose_adaptive"] = [&](const std::string& v) { enable_pose_adaptive = std::stoi(v); };
    handlers["accent_color_0"] = [&](const std::string& v) { accent_color[0] = safe_stof(v); };
    handlers["accent_color_1"] = [&](const std::string& v) { accent_color[1] = safe_stof(v); };
    handlers["accent_color_2"] = [&](const std::string& v) { accent_color[2] = safe_stof(v); };
    handlers["target_monitor"] = [&](const std::string& v) { target_monitor = std::stoi(v); };
    handlers["enable_dma_fuser"] = [&](const std::string& v) { enable_dma_fuser = std::stoi(v); };
    handlers["enable_dynamic_fov"] = [&](const std::string& v) { enable_dynamic_fov = std::stoi(v); };
    handlers["aim_toggle_key"] = [&](const std::string& v) { aim_toggle_key = std::stoi(v); };
    handlers["aim_target_lock"] = [&](const std::string& v) { aim_target_lock = std::stoi(v); };
    handlers["aim_dynamic_smooth"] = [&](const std::string& v) { aim_dynamic_smooth = std::stoi(v); };
    handlers["aim_switch_delay"] = [&](const std::string& v) { aim_switch_delay = std::stoi(v); };
    handlers["aim_lock_x"] = [&](const std::string& v) { aim_lock_x = std::stoi(v); };
    handlers["aim_lock_y"] = [&](const std::string& v) { aim_lock_y = std::stoi(v); };
    handlers["aim_curve_type"] = [&](const std::string& v) { aim_curve_type = std::stoi(v); };
    handlers["selected_preset"] = [&](const std::string& v) { selected_preset = std::stoi(v); };
    handlers["esp_thickness"] = [&](const std::string& v) { esp_thickness = safe_stof(v); };
    handlers["esp_style"] = [&](const std::string& v) { esp_style = std::stoi(v); };
    handlers["color_esp_visible_0"] = [&](const std::string& v) { color_esp_visible[0] = safe_stof(v); };
    handlers["color_esp_visible_1"] = [&](const std::string& v) { color_esp_visible[1] = safe_stof(v); };
    handlers["color_esp_visible_2"] = [&](const std::string& v) { color_esp_visible[2] = safe_stof(v); };
    handlers["color_esp_hidden_0"] = [&](const std::string& v) { color_esp_hidden[0] = safe_stof(v); };
    handlers["color_esp_hidden_1"] = [&](const std::string& v) { color_esp_hidden[1] = safe_stof(v); };
    handlers["color_esp_hidden_2"] = [&](const std::string& v) { color_esp_hidden[2] = safe_stof(v); };
    handlers["neural_nms"] = [&](const std::string& v) { neural_nms = safe_stof(v); };
    handlers["neural_max_det"] = [&](const std::string& v) { neural_max_det = std::stoi(v); };
    handlers["enable_exclusion_zone"] = [&](const std::string& v) { enable_exclusion_zone = std::stoi(v); };
    handlers["excl_x1"] = [&](const std::string& v) { excl_x1 = safe_stof(v); };
    handlers["excl_y1"] = [&](const std::string& v) { excl_y1 = safe_stof(v); };
    handlers["excl_x2"] = [&](const std::string& v) { excl_x2 = safe_stof(v); };
    handlers["excl_y2"] = [&](const std::string& v) { excl_y2 = safe_stof(v); };
    handlers["ai_model"] = [&](const std::string& v) { ai_model = std::stoi(v); };
    handlers["humanizer_enable"] = [&](const std::string& v) { humanizer_enable = std::stoi(v); };
    handlers["hum_reaction_delay"] = [&](const std::string& v) { hum_reaction_delay = safe_stof(v); };
    handlers["hum_overshoot_chance"] = [&](const std::string& v) { hum_overshoot_chance = safe_stof(v); };
    handlers["hum_randomize_bone"] = [&](const std::string& v) { hum_randomize_bone = std::stoi(v); };
    handlers["hum_tremor_scale"] = [&](const std::string& v) { hum_tremor_scale = safe_stof(v); };
    handlers["max_move_step"] = [&](const std::string& v) { max_move_step = safe_stof(v); };
    handlers["head_height_ratio"] = [&](const std::string& v) { head_height_ratio = safe_stof(v); };
    handlers["sticky_zone_factor"] = [&](const std::string& v) { sticky_zone_factor = safe_stof(v); };
    handlers["sticky_damping"] = [&](const std::string& v) { sticky_damping = safe_stof(v); };
    handlers["hum_micro_movements"] = [&](const std::string& v) { hum_micro_movements = std::stoi(v); };
    handlers["hum_micro_amplitude"] = [&](const std::string& v) { hum_micro_amplitude = safe_stof(v); };
    handlers["hum_reaction_jitter"] = [&](const std::string& v) { hum_reaction_jitter = safe_stof(v); };
    handlers["motion_tuning_enabled"] = [&](const std::string& v) { motion_tuning_enabled = std::stoi(v); };
    handlers["kalman_enable"] = [&](const std::string& v) { kalman_enable = std::stoi(v); };
    handlers["kalman_q"] = [&](const std::string& v) { kalman_q = safe_stof(v); };
    handlers["kalman_r"] = [&](const std::string& v) { kalman_r = safe_stof(v); };
    handlers["oe_enable"] = [&](const std::string& v) { oe_enable = std::stoi(v); };
    handlers["oe_mincutoff"] = [&](const std::string& v) { oe_mincutoff = safe_stof(v); };
    handlers["oe_beta"] = [&](const std::string& v) { oe_beta = safe_stof(v); };
    handlers["confidence_fusion_enable"] = [&](const std::string& v) { confidence_fusion_enable = std::stoi(v); };
    handlers["esp_oe_enable"] = [&](const std::string& v) { esp_oe_enable = std::stoi(v); };
    handlers["esp_oe_mincutoff"] = [&](const std::string& v) { esp_oe_mincutoff = safe_stof(v); };
    handlers["esp_oe_beta"] = [&](const std::string& v) { esp_oe_beta = safe_stof(v); };
    handlers["pid_enable"] = [&](const std::string& v) { pid_enable = std::stoi(v); };
    handlers["pid_kp"] = [&](const std::string& v) { pid_kp = safe_stof(v); };
    handlers["pid_ki"] = [&](const std::string& v) { pid_ki = safe_stof(v); };
    handlers["pid_kd"] = [&](const std::string& v) { pid_kd = safe_stof(v); };
    handlers["enable_spoofer"] = [&](const std::string& v) { enable_spoofer = std::stoi(v); };
    handlers["spoofer_vid"] = [&](const std::string& v) { strncpy(spoofer_vid, v.c_str(), 4); };
    handlers["spoofer_pid"] = [&](const std::string& v) { strncpy(spoofer_pid, v.c_str(), 4); };
    handlers["auto_spoof"] = [&](const std::string& v) { auto_spoof = std::stoi(v); };
    handlers["byte_track_thresh"] = [&](const std::string& v) { byte_track_thresh = safe_stof(v); };
    handlers["byte_track_buffer"] = [&](const std::string& v) { byte_track_buffer = std::stoi(v); };
    handlers["byte_match_thresh"] = [&](const std::string& v) { byte_match_thresh = safe_stof(v); };
    handlers["byte_frame_rate"] = [&](const std::string& v) { byte_frame_rate = std::stoi(v); };
    handlers["use_advanced_sticky_aim"] = [&](const std::string& v) { use_advanced_sticky_aim = std::stoi(v); };
    handlers["sticky_threshold"] = [&](const std::string& v) { sticky_threshold = safe_stof(v); };
    handlers["sticky_frames_keep"] = [&](const std::string& v) { sticky_frames_keep = std::stoi(v); };
    handlers["prediction_method"] = [&](const std::string& v) { prediction_method = std::stoi(v); };
    handlers["mouse_sensitivity"] = [&](const std::string& v) { mouse_sensitivity = safe_stof(v); };
    handlers["mouse_yaw"] = [&](const std::string& v) { mouse_yaw = safe_stof(v); };
    handlers["mouse_pitch"] = [&](const std::string& v) { mouse_pitch = safe_stof(v); };
    handlers["fovX"] = [&](const std::string& v) { fovX = safe_stof(v); };
    handlers["fovY"] = [&](const std::string& v) { fovY = safe_stof(v); };
    handlers["min_speed_multiplier"] = [&](const std::string& v) { min_speed_multiplier = safe_stof(v); };
    handlers["max_speed_multiplier"] = [&](const std::string& v) { max_speed_multiplier = safe_stof(v); };
    handlers["snap_radius"] = [&](const std::string& v) { snap_radius = safe_stof(v); };
    handlers["near_radius"] = [&](const std::string& v) { near_radius = safe_stof(v); };
    handlers["speed_curve_exponent"] = [&](const std::string& v) { speed_curve_exponent = safe_stof(v); };
    handlers["snap_boost_factor"] = [&](const std::string& v) { snap_boost_factor = safe_stof(v); };
    handlers["kalman_compensate_detection_delay"] = [&](const std::string& v) { kalman_compensate_detection_delay = std::stoi(v); };
    handlers["kalman_additional_prediction_ms"] = [&](const std::string& v) { kalman_additional_prediction_ms = safe_stof(v); };
    handlers["prediction_interval"] = [&](const std::string& v) { prediction_interval = safe_stof(v); };
    handlers["disable_headshot"] = [&](const std::string& v) { disable_headshot = std::stoi(v); };

    std::istringstream stream(config_data);
    std::string line;
    while (std::getline(stream, line)) {
        auto delim = line.find('=');
        if (delim != std::string::npos) {
            std::string key = line.substr(0, delim);
            std::string val = line.substr(delim + 1);
            auto it = handlers.find(key);
            if (it != handlers.end()) {
                try {
                    it->second(val);
                }
                catch (const std::exception& e) {
                    OutputDebugStringA(("Config parse error: " + key + " - " + e.what()).c_str());
                }
            }
        }
    }
    VMProtectEnd();
}

// ============================================================
// SaveConfig
// ============================================================
void Overlay::SaveConfig(Aimbot* aim) {
    VMProtectBeginUltra("SaveConfig");
    std::ostringstream ss;
    ss.imbue(std::locale("C"));
    ss << "version=6\n";
    ss << "lifetime_seconds=" << lifetime_seconds << "\n";
    ss << "aim_max_sens=" << aim_max_sens << "\n";
    ss << "aim_min_sens=" << aim_min_sens << "\n";
    ss << "fov_aimbot=" << fov_aimbot << "\n";
    ss << "is_russian=" << is_russian << "\n";
    ss << "aim_offset_x=" << aim_offset_x << "\n";
    ss << "aim_offset_y=" << aim_offset_y << "\n";
    ss << "aim_key_main=" << aim_key_main << "\n";
    ss << "aim_key_sub=" << aim_key_sub << "\n";
    ss << "ai_confidence_body=" << ai_confidence_body << "\n";
    ss << "ai_confidence_head=" << ai_confidence_head << "\n";
    ss << "min_box_area_body=" << min_box_area_body << "\n";
    ss << "min_box_area_head=" << min_box_area_head << "\n";
    ss << "disable_all_visuals_when_hidden=" << disable_all_visuals_when_hidden << "\n";
    ss << "custom_res_w=" << custom_res_w << "\n";
    ss << "custom_res_h=" << custom_res_h << "\n";
    ss << "aim_smoother=" << aim_smoother << "\n";
    ss << "fov_scan=" << fov_scan << "\n";
    ss << "aim_kill_delay=" << aim_kill_delay << "\n";
    ss << "obs_bypass=" << obs_bypass << "\n";
    ss << "menu_scale=" << menu_scale << "\n";
    ss << "hardware_type=" << hardware_type << "\n";
    ss << "com_port=" << com_port << "\n";
    ss << "aim_deadzone=" << aim_deadzone << "\n";
    ss << "draw_crosshair=" << draw_crosshair << "\n";
    ss << "hit_chance=" << hit_chance << "\n";
    ss << "menu_width=" << menu_width << "\n";
    ss << "menu_height=" << menu_height << "\n";
    ss << "trigger_enable=" << trigger_enable << "\n";
    ss << "trigger_delay=" << trigger_delay << "\n";
    ss << "trigger_target=" << trigger_target << "\n";
    ss << "trigger_key=" << trigger_key << "\n";
    ss << "rcs_enable=" << rcs_enable << "\n";
    ss << "rcs_pitch=" << rcs_pitch << "\n";
    ss << "rcs_yaw=" << rcs_yaw << "\n";
    ss << "eco_mode=" << eco_mode << "\n";
    ss << "memory_enemy_frames=" << memory_enemy_frames << "\n";
    ss << "refresh_rate_idx=" << refresh_rate_idx << "\n";
    ss << "auto_confidence=" << auto_confidence << "\n";
    ss << "sticky_aim=" << sticky_aim << "\n";
    ss << "enable_pose_adaptive=" << enable_pose_adaptive << "\n";
    ss << "accent_color_0=" << accent_color[0] << "\n";
    ss << "accent_color_1=" << accent_color[1] << "\n";
    ss << "accent_color_2=" << accent_color[2] << "\n";
    ss << "target_monitor=" << target_monitor << "\n";
    ss << "enable_dma_fuser=" << enable_dma_fuser << "\n";
    ss << "enable_dynamic_fov=" << enable_dynamic_fov << "\n";
    ss << "aim_toggle_key=" << aim_toggle_key << "\n";
    ss << "aim_target_lock=" << aim_target_lock << "\n";
    ss << "aim_dynamic_smooth=" << aim_dynamic_smooth << "\n";
    ss << "aim_switch_delay=" << aim_switch_delay << "\n";
    ss << "aim_lock_x=" << aim_lock_x << "\n";
    ss << "aim_lock_y=" << aim_lock_y << "\n";
    ss << "aim_curve_type=" << aim_curve_type << "\n";
    ss << "selected_preset=" << selected_preset << "\n";
    ss << "esp_thickness=" << esp_thickness << "\n";
    ss << "esp_style=" << esp_style << "\n";
    ss << "color_esp_visible_0=" << color_esp_visible[0] << "\n";
    ss << "color_esp_visible_1=" << color_esp_visible[1] << "\n";
    ss << "color_esp_visible_2=" << color_esp_visible[2] << "\n";
    ss << "color_esp_hidden_0=" << color_esp_hidden[0] << "\n";
    ss << "color_esp_hidden_1=" << color_esp_hidden[1] << "\n";
    ss << "color_esp_hidden_2=" << color_esp_hidden[2] << "\n";
    ss << "neural_nms=" << neural_nms << "\n";
    ss << "neural_max_det=" << neural_max_det << "\n";
    ss << "enable_exclusion_zone=" << enable_exclusion_zone << "\n";
    ss << "excl_x1=" << excl_x1 << "\n";
    ss << "excl_y1=" << excl_y1 << "\n";
    ss << "excl_x2=" << excl_x2 << "\n";
    ss << "excl_y2=" << excl_y2 << "\n";
    ss << "ai_model=" << ai_model << "\n";
    ss << "humanizer_enable=" << humanizer_enable << "\n";
    ss << "hum_reaction_delay=" << hum_reaction_delay << "\n";
    ss << "hum_overshoot_chance=" << hum_overshoot_chance << "\n";
    ss << "hum_randomize_bone=" << hum_randomize_bone << "\n";
    ss << "hum_tremor_scale=" << hum_tremor_scale << "\n";
    ss << "max_move_step=" << max_move_step << "\n";
    ss << "head_height_ratio=" << head_height_ratio << "\n";
    ss << "sticky_zone_factor=" << sticky_zone_factor << "\n";
    ss << "sticky_damping=" << sticky_damping << "\n";
    ss << "hum_micro_movements=" << hum_micro_movements << "\n";
    ss << "hum_micro_amplitude=" << hum_micro_amplitude << "\n";
    ss << "hum_reaction_jitter=" << hum_reaction_jitter << "\n";
    ss << "motion_tuning_enabled=" << motion_tuning_enabled << "\n";
    ss << "kalman_enable=" << kalman_enable << "\n";
    ss << "kalman_q=" << kalman_q << "\n";
    ss << "kalman_r=" << kalman_r << "\n";
    ss << "oe_enable=" << oe_enable << "\n";
    ss << "oe_mincutoff=" << oe_mincutoff << "\n";
    ss << "oe_beta=" << oe_beta << "\n";
    ss << "confidence_fusion_enable=" << confidence_fusion_enable << "\n";
    ss << "esp_oe_enable=" << esp_oe_enable << "\n";
    ss << "esp_oe_mincutoff=" << esp_oe_mincutoff << "\n";
    ss << "esp_oe_beta=" << esp_oe_beta << "\n";
    ss << "pid_enable=" << pid_enable << "\n";
    ss << "pid_kp=" << pid_kp << "\n";
    ss << "pid_ki=" << pid_ki << "\n";
    ss << "pid_kd=" << pid_kd << "\n";
    ss << "enable_spoofer=" << enable_spoofer << "\n";
    ss << "spoofer_vid=" << spoofer_vid << "\n";
    ss << "spoofer_pid=" << spoofer_pid << "\n";
    ss << "auto_spoof=" << auto_spoof << "\n";
    ss << "byte_track_thresh=" << byte_track_thresh << "\n";
    ss << "byte_track_buffer=" << byte_track_buffer << "\n";
    ss << "byte_match_thresh=" << byte_match_thresh << "\n";
    ss << "byte_frame_rate=" << byte_frame_rate << "\n";
    ss << "use_advanced_sticky_aim=" << use_advanced_sticky_aim << "\n";
    ss << "sticky_threshold=" << sticky_threshold << "\n";
    ss << "sticky_frames_keep=" << sticky_frames_keep << "\n";
    ss << "prediction_method=" << prediction_method << "\n";
    ss << "mouse_sensitivity=" << mouse_sensitivity << "\n";
    ss << "mouse_yaw=" << mouse_yaw << "\n";
    ss << "mouse_pitch=" << mouse_pitch << "\n";
    ss << "fovX=" << fovX << "\n";
    ss << "fovY=" << fovY << "\n";
    ss << "min_speed_multiplier=" << min_speed_multiplier << "\n";
    ss << "max_speed_multiplier=" << max_speed_multiplier << "\n";
    ss << "snap_radius=" << snap_radius << "\n";
    ss << "near_radius=" << near_radius << "\n";
    ss << "speed_curve_exponent=" << speed_curve_exponent << "\n";
    ss << "snap_boost_factor=" << snap_boost_factor << "\n";
    ss << "kalman_compensate_detection_delay=" << kalman_compensate_detection_delay << "\n";
    ss << "kalman_additional_prediction_ms=" << kalman_additional_prediction_ms << "\n";
    ss << "prediction_interval=" << prediction_interval << "\n";
    ss << "disable_headshot=" << disable_headshot << "\n";

    std::string config_str = ss.str();
    DATA_BLOB DataIn;
    DATA_BLOB DataOut;
    DataIn.pbData = (BYTE*)config_str.c_str();
    DataIn.cbData = (DWORD)config_str.length();
    if (CryptProtectData(&DataIn, L"PWNZ_CFG", NULL, NULL, NULL, 0, &DataOut)) {
        std::ofstream file_bin(XOR("pwnz_enc.bin"), std::ios::binary);
        if (file_bin.is_open()) {
            file_bin.write((char*)DataOut.pbData, DataOut.cbData);
            file_bin.close();
        }
        LocalFree(DataOut.pbData);
        DeleteFileA(XOR("pwnz_cfg.ini"));
    }
    VMProtectEnd();
}

// ============================================================
// ResetDefaults, ApplySafeSettings
// ============================================================
void Overlay::ResetDefaults() {
    draw_esp = true; draw_fov = true; draw_fov_neural = true; draw_watermark = true; draw_crosshair = false;
    disable_all_visuals_when_hidden = true;
    aim_enable = true; aim_max_sens = 2.0f; aim_min_sens = 0.5f; aim_kill_delay = 0.09f; aim_target = 0;
    aim_key_main = VK_RBUTTON; aim_key_sub = 0; aim_toggle_key = 0; eco_mode = true;
    aim_deadzone = 2.0f; aim_smoother = 15.0f; sticky_aim = false;
    fov_aimbot = 190.0f; fov_scan = 192.0f;
    aim_offset_x = 0.0f; aim_offset_y = 0.0f; ai_model = 0;
    ai_confidence_body = 48.0f; ai_confidence_head = 35.0f;
    min_box_area_body = 150.0f; min_box_area_head = 40.0f;
    hit_chance = 90.0f; auto_confidence = false;
    custom_res_w = 1920; custom_res_h = 1080;
    obs_bypass = true; menu_scale = 100.0f; menu_width = 1150.0f; menu_height = 680.0f;
    hardware_type = 0; com_port = 2; trigger_enable = false; trigger_delay = 0.05f; trigger_target = 0; trigger_key = 0;
    rcs_enable = false; rcs_pitch = 1.0f; rcs_yaw = 0.0f;
    refresh_rate_idx = 0; memory_enemy_frames = 3; enable_pose_adaptive = false;
    accent_color[0] = 0.0f; accent_color[1] = 0.8f; accent_color[2] = 1.0f;
    target_monitor = 0; enable_dma_fuser = false; enable_dynamic_fov = false;
    aim_target_lock = true; aim_dynamic_smooth = false; aim_switch_delay = 0; aim_lock_x = false; aim_lock_y = false; aim_curve_type = 0;
    selected_preset = 0; esp_thickness = 1.5f; esp_style = 0; neural_nms = 0.45f; neural_max_det = 5;
    humanizer_enable = true; hum_reaction_delay = 15.0f; hum_overshoot_chance = 5.0f;
    hum_randomize_bone = false; hum_tremor_scale = 1.0f;
    enable_exclusion_zone = false; excl_x1 = 0; excl_y1 = 0; excl_x2 = 0; excl_y2 = 0;
    max_move_step = 50.0f;
    head_height_ratio = 0.1f;
    sticky_zone_factor = 0.5f;
    sticky_damping = 0.3f;
    hum_micro_movements = true;
    hum_micro_amplitude = 0.8f;
    hum_reaction_jitter = 2.0f;
    motion_tuning_enabled = true;
    kalman_enable = true; kalman_q = 0.05f; kalman_r = 0.2f;
    oe_enable = true; oe_mincutoff = 1.0f; oe_beta = 0.05f;
    confidence_fusion_enable = true;
    esp_oe_enable = true; esp_oe_mincutoff = 0.5f; esp_oe_beta = 0.01f;
    pid_enable = false;
    pid_kp = 0.2f;
    pid_ki = 0.01f;
    pid_kd = 0.1f;
    enable_spoofer = false;
    strcpy(spoofer_vid, "046D");
    strcpy(spoofer_pid, "C07E");
    auto_spoof = false;
    byte_track_thresh = 0.5f;
    byte_track_buffer = 30;
    byte_match_thresh = 0.8f;
    byte_frame_rate = 30;
    use_advanced_sticky_aim = true;
    sticky_threshold = 50.0f;
    sticky_frames_keep = 3;
    prediction_method = 1;
    mouse_sensitivity = 1.0f;
    mouse_yaw = 0.022f;
    mouse_pitch = 0.022f;
    fovX = 106.0f;
    fovY = 74.0f;
    min_speed_multiplier = 0.1f;
    max_speed_multiplier = 0.1f;
    snap_radius = 1.5f;
    near_radius = 25.0f;
    speed_curve_exponent = 3.0f;
    snap_boost_factor = 1.15f;
    kalman_compensate_detection_delay = true;
    kalman_additional_prediction_ms = 0.0f;
    prediction_interval = 0.01f;
    disable_headshot = false;
    DeleteFileA(XOR("pwnz_cfg.ini"));
    DeleteFileA(XOR("pwnz_enc.bin"));
}

void Overlay::ApplySafeSettings() {
    aim_max_sens = 1.5f; aim_min_sens = 0.8f;
    aim_smoother = 14.0f;
    aim_deadzone = 1.5f;
    aim_kill_delay = 0.15f;
    fov_aimbot = 120.0f; fov_scan = 180.0f;
    memory_enemy_frames = 3; aim_target = 0;
    enable_dynamic_fov = true; ai_confidence_body = 50.0f; ai_confidence_head = 40.0f;
    aim_dynamic_smooth = true;
    aim_curve_type = 3;
    aim_switch_delay = 150;
    sticky_aim = false; auto_confidence = true; eco_mode = true;
    aim_target_lock = true; humanizer_enable = true;
    max_move_step = 50.0f;
    head_height_ratio = 0.105f;
    sticky_zone_factor = 0.5f;
    sticky_damping = 0.3f;
    hum_micro_movements = true;
    hum_micro_amplitude = 0.7f;
    hum_reaction_jitter = 1.5f;
    kalman_enable = true; kalman_q = 0.05f; kalman_r = 0.2f;
    oe_enable = true; oe_mincutoff = 1.0f; oe_beta = 0.05f;
    confidence_fusion_enable = true;
    esp_oe_enable = true; esp_oe_mincutoff = 0.5f; esp_oe_beta = 0.01f;
    pid_enable = false;
    pid_kp = 0.15f;
    pid_ki = 0.005f;
    pid_kd = 0.08f;
    enable_spoofer = false;
    auto_spoof = false;
    byte_track_thresh = 0.45f;
    byte_track_buffer = 45;
    byte_match_thresh = 0.75f;
    byte_frame_rate = 30;
    use_advanced_sticky_aim = true;
    sticky_threshold = 60.0f;
    sticky_frames_keep = 2;
    prediction_method = 1;
    mouse_sensitivity = 1.0f;
    mouse_yaw = 0.022f;
    mouse_pitch = 0.022f;
    fovX = 106.0f;
    fovY = 74.0f;
    min_speed_multiplier = 0.07f;
    max_speed_multiplier = 0.18f;
    snap_radius = 2.0f;
    near_radius = 30.0f;
    speed_curve_exponent = 3.0f;
    snap_boost_factor = 1.2f;
    kalman_compensate_detection_delay = true;
    kalman_additional_prediction_ms = 10.0f;
    prediction_interval = 0.02f;
    disable_headshot = false;
}

// ============================================================
// Вспомогательные UI методы
// ============================================================
bool Overlay::DrawToggleOnly(const char* str_id, bool* v, ImU32 accent_u32) {
    bool changed = false;
    ImVec2 p = ImGui::GetCursorScreenPos(); ImDrawList* draw_list = ImGui::GetWindowDrawList();
    float height = ImGui::GetFrameHeight(); float width = height * 1.8f; float radius = height * 0.50f;
    ImGui::InvisibleButton(str_id, ImVec2(width, height));
    if (ImGui::IsItemClicked()) { *v = !*v; changed = true; }
    float t = *v ? 1.0f : 0.0f; ImU32 col_bg = *v ? accent_u32 : IM_COL32(60, 50, 80, 255);
    draw_list->AddRectFilled(p, ImVec2(p.x + width, p.y + height), col_bg, height * 0.5f);
    draw_list->AddCircleFilled(ImVec2(p.x + radius + t * (width - radius * 2.0f), p.y + radius), radius - 2.0f, IM_COL32(255, 255, 255, 255));
    return changed;
}

bool Overlay::DrawToggle(const char* label, const char* str_id, bool* v, ImU32 accent_u32, const char* help) {
    ImGui::Text("%s", label);
    float w = ImGui::GetColumnWidth();
    float text_w = ImGui::CalcTextSize(label).x;
    float offset = w - (help ? 65.0f : 45.0f);
    if (offset < text_w + 15.0f) offset = text_w + 15.0f;
    ImGui::SameLine(offset);
    bool changed = DrawToggleOnly(str_id, v, accent_u32);
    if (help) HelpMarker(help);
    return changed;
}

bool Overlay::CustomSliderFloat(const char* label, const char* label_id, float* v, float v_min, float v_max, const char* format, ImVec4 accent_vec, const char* help) {
    ImGui::Text("%s", label);
    float w = ImGui::GetColumnWidth();
    float text_w = ImGui::CalcTextSize(label).x;
    float offset = w - (help ? 130.0f : 105.0f);
    if (offset < text_w + 15.0f) offset = text_w + 15.0f;
    ImGui::SameLine(offset);
    char buf[32]; snprintf(buf, sizeof(buf), format, *v);
    ImGui::TextColored(accent_vec, "%s", buf);
    float item_w = w - (help ? 45.0f : 25.0f);
    if (item_w < 50.0f) item_w = 50.0f;
    ImGui::PushItemWidth(item_w);
    bool changed = ImGui::SliderFloat(label_id, v, v_min, v_max, "");
    ImGui::PopItemWidth();
    if (help) HelpMarker(help);
    return changed;
}

bool Overlay::CustomSliderInt(const char* label, const char* label_id, int* v, int v_min, int v_max, const char* format, ImVec4 accent_vec, const char* help) {
    ImGui::Text("%s", label);
    float w = ImGui::GetColumnWidth();
    float text_w = ImGui::CalcTextSize(label).x;
    float offset = w - (help ? 130.0f : 105.0f);
    if (offset < text_w + 15.0f) offset = text_w + 15.0f;
    ImGui::SameLine(offset);
    char buf[32]; snprintf(buf, sizeof(buf), format, *v);
    ImGui::TextColored(accent_vec, "%s", buf);
    float item_w = w - (help ? 45.0f : 25.0f);
    if (item_w < 50.0f) item_w = 50.0f;
    ImGui::PushItemWidth(item_w);
    bool changed = ImGui::SliderInt(label_id, v, v_min, v_max, "");
    ImGui::PopItemWidth();
    if (help) HelpMarker(help);
    return changed;
}

bool Overlay::CustomCombo(const char* label, const char* label_id, int* current_item, const char* const items[], int items_count, const char* help) {
    ImGui::Text("%s", label);
    float w = ImGui::GetColumnWidth();
    float text_w = ImGui::CalcTextSize(label).x;
    float offset = w - (help ? 165.0f : 140.0f);
    if (offset < text_w + 15.0f) offset = text_w + 15.0f;
    ImGui::SameLine(offset);
    ImGui::PushItemWidth(120.0f);
    bool changed = ImGui::Combo(label_id, current_item, items, items_count);
    ImGui::PopItemWidth();
    if (help) HelpMarker(help);
    return changed;
}

bool Overlay::DrawKeybinder(const char* label, int* vk_key, int id, const char* help) {
    bool changed = false;
    ImGui::Text("%s", label);
    float w = ImGui::GetColumnWidth();
    float text_w = ImGui::CalcTextSize(label).x;
    float offset = w - (help ? 125.0f : 100.0f);
    if (offset < text_w + 15.0f) offset = text_w + 15.0f;
    ImGui::SameLine(offset);
    std::string btn_label;
    if (active_bind_id == id) {
        btn_label = is_russian ? u8"[ Нажми ]" : "[ Press ]";
        for (int i = 1; i < 256; i++) {
            if (GetAsyncKeyState(i) & 0x8000) { if (i == VK_ESCAPE) *vk_key = 0; else *vk_key = i; active_bind_id = -1; changed = true; break; }
        }
    }
    else {
        if (*vk_key == 0) btn_label = "None";
        else if (*vk_key == VK_LBUTTON) btn_label = "LMB";
        else if (*vk_key == VK_RBUTTON) btn_label = "RMB";
        else { char keyName[32]; if (GetKeyNameTextA(MapVirtualKeyA(*vk_key, MAPVK_VK_TO_VSC) << 16, keyName, sizeof(keyName))) btn_label = keyName; else btn_label = "VK"; }
    }
    if (ImGui::Button((btn_label + "##" + std::to_string(id)).c_str(), ImVec2(100, 25))) active_bind_id = id;
    if (help) HelpMarker(help);
    return changed;
}

void Overlay::HelpMarker(const char* desc) {
    ImGui::SameLine(0.0f, 5.0f);
    ImGui::TextColored(ImVec4(0.4f, 0.4f, 0.4f, 1.0f), "(?)");
    if (ImGui::IsItemHovered()) {
        ImGui::BeginTooltip();
        ImGui::PushTextWrapPos(ImGui::GetFontSize() * 25.0f);
        ImGui::TextUnformatted(desc);
        ImGui::PopTextWrapPos();
        ImGui::EndTooltip();
    }
}

bool Overlay::BeginPanel(const char* name, ImVec2 size, ImVec4 accent_vec, bool has_toggle, bool* toggle_val, ImU32 accent_u32) {
    bool changed = false;
    ImGui::BeginChild(name, size, true, ImGuiWindowFlags_NoScrollbar);
    std::string display_name = name; size_t hash_pos = display_name.find("###");
    if (hash_pos != std::string::npos) display_name = display_name.substr(0, hash_pos);
    ImGui::PushStyleColor(ImGuiCol_Text, accent_vec);
    ImGui::Text("%s", display_name.c_str());
    ImGui::PopStyleColor();
    if (has_toggle && toggle_val) {
        ImGui::SameLine(ImGui::GetWindowWidth() - 45.0f);
        ImGui::SetCursorPosY(ImGui::GetCursorPosY() - 2);
        if (DrawToggleOnly((std::string("##Tog") + std::string(name)).c_str(), toggle_val, accent_u32)) changed = true;
    }
    ImGui::Spacing();
    return changed;
}

void Overlay::EndPanel() { ImGui::EndChild(); }

// ============================================================
// ============================================================
// RenderAimbotTab (вкладка Aimbot)
// ============================================================
void Overlay::RenderAimbotTab(float content_w, float content_h, const ImVec4& acc_vec, ImU32 acc_u32, bool& cfg_changed) {
    ImGui::Columns(1, nullptr, false);

    const char* tgts[] = { "Head", "Body", "Auto" };

    if (BeginPanel("AimCore", ImVec2(0, 200), acc_vec, true, &aim_enable, acc_u32)) cfg_changed = true;
    if (DrawKeybinder("Main Bind:", &aim_key_main, 1, u8"Основная кнопка активации.")) cfg_changed = true;
    if (DrawKeybinder("Sub Bind:", &aim_key_sub, 2, u8"Дополнительная кнопка.")) cfg_changed = true;
    if (DrawKeybinder("Toggle Core:", &aim_toggle_key, 3, u8"Включение/выключение аимбота.")) cfg_changed = true;
    if (CustomCombo("Target Part:", "##tgt", &aim_target, tgts, 3, u8"Часть тела для прицеливания.")) cfg_changed = true;
    EndPanel();

    ImGui::Columns(1);
}
// ============================================================
// RenderVisualsTab (вкладка Visuals)
// ============================================================
void Overlay::RenderVisualsTab(float content_w, float content_h, const ImVec4& acc_vec, ImU32 acc_u32, bool& cfg_changed) {
    ImGui::Columns(2, nullptr, false);
    ImGui::SetColumnWidth(0, content_w * 0.5f);

    if (BeginPanel("HUD Display", ImVec2(0, 250), acc_vec)) cfg_changed = true;
    if (DrawToggle("Draw ESP Boxes:", "##e", &draw_esp, acc_u32, u8"ESP рамки.")) cfg_changed = true;
    if (DrawToggle("Draw AimFOV:", "##fa", &draw_fov, acc_u32, u8"Радиус аимбота.")) cfg_changed = true;
    if (DrawToggle("Draw NeuralFOV:", "##fn", &draw_fov_neural, acc_u32, u8"Радиус нейросети.")) cfg_changed = true;
    if (DrawToggle("Draw Crosshair:", "##crs", &draw_crosshair, acc_u32, u8"Кастомное перекрестие.")) cfg_changed = true;
    if (DrawToggle("Watermark FPS:", "##wm", &draw_watermark, acc_u32, u8"Информация о FPS.")) cfg_changed = true;
    EndPanel();

    if (BeginPanel("ESP Customizer", ImVec2(0, content_h - 250 - 20), acc_vec)) cfg_changed = true;
    const char* e_styles[] = { "Full Box", "Corners Only" };
    if (CustomCombo("Box Style", "##ebx", &esp_style, e_styles, 2, u8"Стиль рамок.")) cfg_changed = true;
    if (CustomSliderFloat("Box Thickness", "##ethck", &esp_thickness, 1.0f, 5.0f, "%.1f px", acc_vec, u8"Толщина линий.")) cfg_changed = true;

    ImGui::Spacing(); ImGui::Separator(); ImGui::Spacing();
    ImGui::TextColored(ImVec4(1.0f, 1.0f, 0.0f, 1.0f), "ESP Smoothing Filter:");
    if (DrawToggle("Enable OneEuro Filter", "##esp_oe_en", &esp_oe_enable, acc_u32, u8"Сглаживание ESP.")) cfg_changed = true;
    if (esp_oe_enable) {
        if (CustomSliderFloat("ESP MinCutoff", "##esp_oe_mc", &esp_oe_mincutoff, 0.1f, 5.0f, "%.2f", acc_vec, u8"Min cutoff.")) cfg_changed = true;
        if (CustomSliderFloat("ESP Beta", "##esp_oe_b", &esp_oe_beta, 0.001f, 0.2f, "%.3f", acc_vec, u8"Beta.")) cfg_changed = true;
    }

    ImGui::Spacing(); ImGui::Separator(); ImGui::Spacing();
    ImGui::TextColored(acc_vec, "ESP Colors:");
    if (ImGui::ColorEdit3("Visible Color", color_esp_visible, ImGuiColorEditFlags_NoInputs)) cfg_changed = true;
    if (ImGui::ColorEdit3("Hidden Color", color_esp_hidden, ImGuiColorEditFlags_NoInputs)) cfg_changed = true;
    EndPanel();

    ImGui::NextColumn();

    if (BeginPanel("Optimization", ImVec2(0, 120), acc_vec)) cfg_changed = true;
    if (DrawToggle("Stealth Mode:", "##stl", &disable_all_visuals_when_hidden, acc_u32, u8"Скрывать графику при закрытом меню.")) cfg_changed = true;
    EndPanel();

    if (BeginPanel("Information", ImVec2(0, content_h - 120 - 20), acc_vec)) cfg_changed = true;
    ImGui::TextColored(acc_vec, "[?] Visual Framework");
    ImGui::TextWrapped(u8"Графический движок PWNZ работает поверх аппаратного оверлея DWM API.");
    EndPanel();

    ImGui::Columns(1);
}

// ============================================================
// RenderNeuralTab (вкладка Neural)
// ============================================================
void Overlay::RenderNeuralTab(float content_w, float content_h, const ImVec4& acc_vec, ImU32 acc_u32, bool& cfg_changed) {
    ImGui::Columns(3, nullptr, false);
    ImGui::SetColumnWidth(0, content_w * 0.33f);
    ImGui::SetColumnWidth(1, content_w * 0.33f);

    if (BeginPanel("AI Engine", ImVec2(0, 310), acc_vec)) cfg_changed = true;
    const char* models[] = { "BogX-Nano.onnx", "BogX-Lite.onnx", "BogX-Pro.onnx", "BogX-Ultra.onnx" };
    if (CustomCombo("Model:", "##mdl", &ai_model, models, 4, u8"Выбор модели нейросети.")) cfg_changed = true;
    ImGui::Spacing();
    if (ImGui::Button("Reload Model", ImVec2(150, 30))) apply_model_flag = true;
    ImGui::Spacing(); ImGui::Spacing();

    if (DrawToggle("Auto Confidence:", "##aconf", &auto_confidence, acc_u32, u8"Автоматическая регулировка порогов.")) cfg_changed = true;

    if (CustomSliderFloat("Confidence Body:", "##cnf_body", &ai_confidence_body, 0.0f, 100.0f, "%.0f%%", acc_vec, u8"Порог тела.")) cfg_changed = true;
    if (CustomSliderFloat("Confidence Head:", "##cnf_head", &ai_confidence_head, 0.0f, 100.0f, "%.0f%%", acc_vec, u8"Порог головы.")) cfg_changed = true;
    if (CustomSliderFloat("Min Box Area Body:", "##min_area_body", &min_box_area_body, 30.0f, 500.0f, "%.0f px²", acc_vec, u8"Мин. площадь тела.")) cfg_changed = true;
    if (CustomSliderFloat("Min Box Area Head:", "##min_area_head", &min_box_area_head, 10.0f, 200.0f, "%.0f px²", acc_vec, u8"Мин. площадь головы.")) cfg_changed = true;
    if (CustomSliderFloat("Hit Chance:", "##htc", &hit_chance, 0.0f, 100.0f, "%.0f%%", acc_vec, u8"Вероятность срабатывания.")) cfg_changed = true;
    EndPanel();

    if (BeginPanel("Inference Optimization", ImVec2(0, content_h - 310 - 20), acc_vec)) cfg_changed = true;
    if (CustomSliderFloat("NMS Threshold", "##nms", &neural_nms, 0.1f, 0.9f, "%.2f", acc_vec, u8"Порог NMS.")) cfg_changed = true;
    if (CustomSliderInt("Max Targets", "##mxdet", &neural_max_det, 1, 20, "%d", acc_vec, u8"Макс. целей.")) cfg_changed = true;
    EndPanel();

    ImGui::NextColumn();

    if (BeginPanel("Target Offsets (X/Y)", ImVec2(0, 160), acc_vec)) cfg_changed = true;
    ImGui::Spacing();
    ImGui::TextColored(ImVec4(0.5f, 0.5f, 0.5f, 1.0f), u8"Смещение точки прицела");
    ImGui::Spacing();
    ImGui::Text("Shift X (L/R):"); ImGui::SameLine(ImGui::GetColumnWidth() - 120.0f);
    ImGui::PushItemWidth(80.0f);
    if (ImGui::InputFloat("##offx", &aim_offset_x, 1.0f, 5.0f, "%.0f")) cfg_changed = true;
    ImGui::PopItemWidth();
    HelpMarker(u8"Смещение по X.");
    ImGui::Spacing();
    ImGui::Text("Shift Y (U/D):"); ImGui::SameLine(ImGui::GetColumnWidth() - 120.0f);
    ImGui::PushItemWidth(80.0f);
    if (ImGui::InputFloat("##offy", &aim_offset_y, 1.0f, 5.0f, "%.0f")) cfg_changed = true;
    ImGui::PopItemWidth();
    HelpMarker(u8"Смещение по Y.");
    EndPanel();

    const char* ez_title = is_russian ? u8"Слепая Зона (Игнор своего скина)###PnlEZ" : "Exclusion Zone###PnlEZ";
    if (BeginPanel(ez_title, ImVec2(0, content_h - 160 - 20), acc_vec, true, &enable_exclusion_zone, acc_u32)) cfg_changed = true;
    if (ImGui::Button(u8"Нарисовать Зону", ImVec2(ImGui::GetContentRegionAvail().x - 50.0f, 30))) {
        is_drawing_zone = true;
    }
    ImGui::SameLine(); HelpMarker(u8"Выделить зону игнорирования.");
    if (ImGui::Button(u8"Очистить Зону", ImVec2(ImGui::GetContentRegionAvail().x - 50.0f, 30))) {
        excl_x1 = excl_y1 = excl_x2 = excl_y2 = 0;
        cfg_changed = true;
    }
    EndPanel();

    ImGui::NextColumn();

    if (BeginPanel("FOV Settings", ImVec2(0, 160), acc_vec)) cfg_changed = true;
    ImGui::Spacing();
    if (CustomSliderFloat("Aim FOV:", "##f_a", &fov_aimbot, 10.0f, 500.0f, "%.0f px", acc_vec, u8"Радиус аимбота.")) cfg_changed = true;
    if (DrawToggle("Dynamic FOV:", "##dfov", &enable_dynamic_fov, acc_u32, u8"Адаптивный FOV.")) cfg_changed = true;
    ImGui::Spacing();
    if (CustomSliderFloat("Neural FOV:", "##f_n", &fov_scan, 10.0f, 500.0f, "%.0f px", acc_vec, u8"Радиус сканирования нейросети.")) cfg_changed = true;
    EndPanel();

    if (BeginPanel("Advanced Detection", ImVec2(0, 250), acc_vec)) cfg_changed = true;
    if (CustomSliderInt("Memory Enemy:", "##mem_en", &memory_enemy_frames, 0, 30, "%d frm", acc_vec, u8"Количество кадров памяти.")) cfg_changed = true;
    const char* hz_opts[] = { u8"Без лимита", "60 Hz", "75 Hz", "120 Hz", "144 Hz", "165 Hz", "240 Hz", "360 Hz" };
    if (CustomCombo("Frame Rate:", "##hz", &refresh_rate_idx, hz_opts, 8, u8"Ограничитель кадров оверлея.")) cfg_changed = true;
    EndPanel();

    ImGui::Columns(1);
}

// ============================================================
// ============================================================
// RenderNeuralTab (вкладка Neural)
// ============================================================
void Overlay::RenderNeuralTab(float content_w, float content_h, const ImVec4& acc_vec, ImU32 acc_u32, bool& cfg_changed) {
    ImGui::Columns(3, nullptr, false);
    ImGui::SetColumnWidth(0, content_w * 0.33f);
    ImGui::SetColumnWidth(1, content_w * 0.33f);

    if (BeginPanel("AI Engine", ImVec2(0, 310), acc_vec)) cfg_changed = true;
    const char* models[] = { "BogX-Nano.onnx", "BogX-Lite.onnx", "BogX-Pro.onnx", "BogX-Ultra.onnx" };
    if (CustomCombo("Model:", "##mdl", &ai_model, models, 4, u8"Выбор модели нейросети.")) cfg_changed = true;
    ImGui::Spacing();
    if (ImGui::Button("Reload Model", ImVec2(150, 30))) apply_model_flag = true;
    ImGui::Spacing(); ImGui::Spacing();

    if (DrawToggle("Auto Confidence:", "##aconf", &auto_confidence, acc_u32, u8"Автоматическая регулировка порогов.")) cfg_changed = true;

    if (CustomSliderFloat("Confidence Body:", "##cnf_body", &ai_confidence_body, 0.0f, 100.0f, "%.0f%%", acc_vec, u8"Порог тела.")) cfg_changed = true;
    if (CustomSliderFloat("Confidence Head:", "##cnf_head", &ai_confidence_head, 0.0f, 100.0f, "%.0f%%", acc_vec, u8"Порог головы.")) cfg_changed = true;
    if (CustomSliderFloat("Min Box Area Body:", "##min_area_body", &min_box_area_body, 30.0f, 500.0f, "%.0f px²", acc_vec, u8"Мин. площадь тела.")) cfg_changed = true;
    if (CustomSliderFloat("Min Box Area Head:", "##min_area_head", &min_box_area_head, 10.0f, 200.0f, "%.0f px²", acc_vec, u8"Мин. площадь головы.")) cfg_changed = true;
    if (CustomSliderFloat("Hit Chance:", "##htc", &hit_chance, 0.0f, 100.0f, "%.0f%%", acc_vec, u8"Вероятность срабатывания.")) cfg_changed = true;
    EndPanel();

    if (BeginPanel("Inference Optimization", ImVec2(0, content_h - 310 - 20), acc_vec)) cfg_changed = true;
    if (CustomSliderFloat("NMS Threshold", "##nms", &neural_nms, 0.1f, 0.9f, "%.2f", acc_vec, u8"Порог NMS.")) cfg_changed = true;
    if (CustomSliderInt("Max Targets", "##mxdet", &neural_max_det, 1, 20, "%d", acc_vec, u8"Макс. целей.")) cfg_changed = true;
    EndPanel();

    ImGui::NextColumn();

    if (BeginPanel("Target Offsets (X/Y)", ImVec2(0, 160), acc_vec)) cfg_changed = true;
    ImGui::Spacing();
    ImGui::TextColored(ImVec4(0.5f, 0.5f, 0.5f, 1.0f), u8"Смещение точки прицела");
    ImGui::Spacing();
    ImGui::Text("Shift X (L/R):"); ImGui::SameLine(ImGui::GetColumnWidth() - 120.0f);
    ImGui::PushItemWidth(80.0f);
    if (ImGui::InputFloat("##offx", &aim_offset_x, 1.0f, 5.0f, "%.0f")) cfg_changed = true;
    ImGui::PopItemWidth();
    HelpMarker(u8"Смещение по X.");
    ImGui::Spacing();
    ImGui::Text("Shift Y (U/D):"); ImGui::SameLine(ImGui::GetColumnWidth() - 120.0f);
    ImGui::PushItemWidth(80.0f);
    if (ImGui::InputFloat("##offy", &aim_offset_y, 1.0f, 5.0f, "%.0f")) cfg_changed = true;
    ImGui::PopItemWidth();
    HelpMarker(u8"Смещение по Y.");
    EndPanel();

    const char* ez_title = is_russian ? u8"Слепая Зона (Игнор своего скина)###PnlEZ" : "Exclusion Zone###PnlEZ";
    if (BeginPanel(ez_title, ImVec2(0, content_h - 160 - 20), acc_vec, true, &enable_exclusion_zone, acc_u32)) cfg_changed = true;
    if (ImGui::Button(u8"Нарисовать Зону", ImVec2(ImGui::GetContentRegionAvail().x - 50.0f, 30))) {
        is_drawing_zone = true;
    }
    ImGui::SameLine(); HelpMarker(u8"Выделить зону игнорирования.");
    if (ImGui::Button(u8"Очистить Зону", ImVec2(ImGui::GetContentRegionAvail().x - 50.0f, 30))) {
        excl_x1 = excl_y1 = excl_x2 = excl_y2 = 0;
        cfg_changed = true;
    }
    EndPanel();

    ImGui::NextColumn();

    if (BeginPanel("FOV Settings", ImVec2(0, 160), acc_vec)) cfg_changed = true;
    ImGui::Spacing();
    if (CustomSliderFloat("Aim FOV:", "##f_a", &fov_aimbot, 10.0f, 500.0f, "%.0f px", acc_vec, u8"Радиус аимбота.")) cfg_changed = true;
    if (DrawToggle("Dynamic FOV:", "##dfov", &enable_dynamic_fov, acc_u32, u8"Адаптивный FOV.")) cfg_changed = true;
    ImGui::Spacing();
    if (CustomSliderFloat("Neural FOV:", "##f_n", &fov_scan, 10.0f, 500.0f, "%.0f px", acc_vec, u8"Радиус сканирования нейросети.")) cfg_changed = true;
    EndPanel();

    if (BeginPanel("Advanced Detection", ImVec2(0, 250), acc_vec)) cfg_changed = true;
    if (CustomSliderInt("Memory Enemy:", "##mem_en", &memory_enemy_frames, 0, 30, "%d frm", acc_vec, u8"Количество кадров памяти.")) cfg_changed = true;
    const char* hz_opts[] = { u8"Без лимита", "60 Hz", "75 Hz", "120 Hz", "144 Hz", "165 Hz", "240 Hz", "360 Hz" };
    if (CustomCombo("Frame Rate:", "##hz", &refresh_rate_idx, hz_opts, 8, u8"Ограничитель кадров оверлея.")) cfg_changed = true;
    EndPanel();

    ImGui::Columns(1);
}

// ============================================================
    const char* tabs_en[] = { "Aimbot", "Visuals", "Neural", "Profile", "Hardware\\2PC", "HW Check", "Metrics" };
    const char* tabs_ru[] = { u8"Аимбот", u8"Визуалы", u8"Нейросеть", u8"Профиль", u8"Hardware\\2PC", u8"Проверка HW", u8"Метрики" };
    for (int i = 0; i < 7; i++) {
        if (active_tab == i) { ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.12f, 0.10f, 0.18f, 1.0f)); ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 1.0f, 1.0f, 1.0f)); }
        else { ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.0f, 0.0f, 0.0f, 0.0f)); ImGui::PushStyleColor(ImGuiCol_Text, acc_vec); }
        ImVec2 p_min = ImGui::GetCursorScreenPos();
        if (ImGui::Button(is_russian ? tabs_ru[i] : tabs_en[i], ImVec2(150, 45))) active_tab = i;
        if (active_tab == i) ImGui::GetWindowDrawList()->AddRectFilled(p_min, ImVec2(p_min.x + 4, p_min.y + 45), acc_u32);
        ImGui::PopStyleColor(2);
    }

    switch (active_tab) {
    case 0: RenderAimbotTab(content_w, content_h, acc_vec, acc_u32, cfg_changed); break;
    case 1: RenderVisualsTab(content_w, content_h, acc_vec, acc_u32, cfg_changed); break;
    case 2: RenderNeuralTab(content_w, content_h, acc_vec, acc_u32, cfg_changed); break;
    case 3: RenderProfileTab(content_w, content_h, acc_vec, acc_u32, cfg_changed); break;
    case 4: RenderHardwareTab(content_w, content_h, acc_vec, acc_u32, cfg_changed); break;
    case 5: RenderHWCheckTab(content_w, content_h, acc_vec, acc_u32, cfg_changed); break;
    case 6: RenderMetricsTab(content_w, content_h, acc_vec, acc_u32, cfg_changed); break;
    }

    ImGui::EndChild();
    ImGui::EndGroup();
    ImGui::End();

    RenderHWTutorial();
}

// ============================================================
// Основной Render (короткий, вызывает всё остальное)
// ============================================================
void Overlay::Render(const std::vector<Detection>& detections, int screen_w, int screen_h, int roi_w, int roi_h, Aimbot* aim, bool show_menu) {
    bool cfg_changed = false;
    static bool was_aim_toggle_pressed = false;
    if (aim_toggle_key != 0) {
        if (GetAsyncKeyState(aim_toggle_key) & 0x8000) {
            if (!was_aim_toggle_pressed) { aim_enable = !aim_enable; was_aim_toggle_pressed = true; cfg_changed = true; }
        }
        else { was_aim_toggle_pressed = false; }
    }
    if (is_first_frame_init) is_first_frame_init = false;
    ImVec4 acc_vec = ImVec4(accent_color[0], accent_color[1], accent_color[2], 1.0f);
    ImU32 acc_u32 = ImGui::ColorConvertFloat4ToU32(acc_vec);
    is_menu_open = show_menu;

    // Экраны аутентификации
    if (is_auto_logging_in || is_loading || !is_authenticated) {
        if (is_auto_logging_in) RenderAutoLogin(acc_vec, acc_u32);
        else if (is_loading) RenderLoadingScreen(acc_vec, acc_u32);
        else if (!is_authenticated) RenderAuthWindow(acc_vec, acc_u32);
        return;
    }

    ImGui::GetIO().FontGlobalScale = menu_scale / 100.0f;
    if (obs_bypass) {
        SetWindowDisplayAffinity(hwnd, WDA_EXCLUDEFROMCAPTURE);
    } else {
        SetWindowDisplayAffinity(hwnd, WDA_NONE);
    }
    ImGui_ImplDX11_NewFrame(); ImGui_ImplWin32_NewFrame();
    POINT m_pt;
    if (GetCursorPos(&m_pt)) ImGui::GetIO().MousePos = ImVec2((float)m_pt.x, (float)m_pt.y);
    ImGui::NewFrame();
    lifetime_seconds += ImGui::GetIO().DeltaTime;

    static float open_anim_time = 0.0f;
    static bool was_open_anim = false;
    if (show_menu && !was_open_anim) open_anim_time = 0.0f;
    was_open_anim = show_menu;
    float window_alpha = 1.0f;
    if (show_menu && !is_drawing_zone) {
        open_anim_time += ImGui::GetIO().DeltaTime;
        if (open_anim_time < 0.5f) {
            window_alpha = (open_anim_time / 0.5f) * (0.8f + 0.2f * std::sin(open_anim_time * 60.0f));
            if (window_alpha > 1.0f) window_alpha = 1.0f;
        }
        else { window_alpha = 1.0f; }
        ImGui::PushStyleVar(ImGuiStyleVar_Alpha, window_alpha);
    }

    bool should_draw_visuals = !(!show_menu && disable_all_visuals_when_hidden);
    if (should_draw_visuals) {
        RenderVisualsAndZone(detections, aim);
    }

    if (show_menu && !is_drawing_zone) {
        RenderMenu(detections, aim, cfg_changed);
        if (show_menu) ImGui::PopStyleVar();
    }

    static bool was_capturing = false;
    bool need_capture = false;
    if (is_drawing_zone) need_capture = true;
    if (ImGui::GetIO().WantCaptureMouse) need_capture = true;
    if (was_capturing && (GetAsyncKeyState(VK_LBUTTON) & 0x8000)) need_capture = true;
    was_capturing = need_capture;
    ToggleClickability(need_capture);
    if (cfg_changed) SaveConfig(aim);

    ImGui::Render();
    const float clear_color_with_alpha[4] = { 0,0,0,0 };
    g_pd3dDeviceContext->OMSetRenderTargets(1, &g_mainRenderTargetView, NULL);
    if (enable_dma_fuser) {
        const float fuser_bg[4] = { 0,0,0,1 };
        g_pd3dDeviceContext->ClearRenderTargetView(g_mainRenderTargetView, fuser_bg);
    }
    else {
        g_pd3dDeviceContext->ClearRenderTargetView(g_mainRenderTargetView, clear_color_with_alpha);
    }
    ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());
    g_pSwapChain->Present(0, 0);
}