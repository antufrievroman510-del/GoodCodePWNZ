#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <d3d11.h>
#include <vector>
#include <string>
#include <mutex>
#include <memory>
#include "detector.h"
#include "aimbot.h"
#include "network_2pc.h"
#include "imgui.h"
#include "implot.h"

class OneEuroFilter {
private:
    double mincutoff, beta, dcutoff;
    double x_prev, dx_prev, t_prev;
    bool first_time;
    double alpha(double cutoff, double dt);
public:
    OneEuroFilter(double mincutoff = 1.0, double beta = 0.0, double dcutoff = 1.0);
    void UpdateParams(double mc, double b);
    void Reset();
    double Filter(double x, double t);
};

extern std::vector<Detection> g_shared_heads;
extern std::mutex g_heads_mutex;

struct MacroStep { int type; int val; std::string display_text; };
struct ChatMessage { std::string text; bool is_user; };

class Overlay {
public:
    // ---- Ñîñòîÿíèå (âñå ïîëÿ îñòàþòñÿ êàê ó âàñ) ----
    bool is_loading = true;
    float load_progress = 0.0f;
    int current_tip_idx = 0;
    bool is_auto_logging_in = false;
    float auto_login_anim_time = 0.0f;
    bool is_authenticated = false;
    bool is_register_mode = false;
    char auth_username[64] = "";
    char auth_password[64] = "";
    std::string auth_status_msg = "";
    float auth_status_col[3] = { 1,1,1 };
    float last_auth_check_time = 0.0f;
    std::string user_expiry_date = "1970-01-01 00:00:00";

    // Aimbot basic settings
    bool aim_enable = true;
    int aim_target = 0;
    int aim_key_main = VK_RBUTTON;
    int aim_key_sub = 0;
    int aim_toggle_key = 0;

    // Hardware settings
    int hardware_type = 0;
    int com_port = 2;
    bool apply_hw_flag = false;

    // Neural settings
    int ai_model = 0;
    float ai_confidence_body = 48.0f;
    float ai_confidence_head = 35.0f;
    bool auto_confidence = false;
    float min_box_area_body = 150.0f;
    float min_box_area_head = 40.0f;
    float neural_nms = 0.45f;
    int neural_max_det = 5;

    // Menu settings
    float menu_scale = 100.0f;
    float menu_width = 1150.0f;
    float menu_height = 720.0f;
    float accent_color[3] = { 0,0.8f,1 };
    bool is_russian = true;
    bool obs_bypass = true;
    bool eco_mode = true;

    // ---- Îñíîâíûå ìåòîäû ----
    bool Initialize();
    bool Update();
    void Render(const std::vector<Detection>& detections, int screen_w, int screen_h, int roi_w, int roi_h, Aimbot* aim, bool show_menu);
    void ToggleClickability(bool clickable);
    void Cleanup(Aimbot* aim);
    void SaveConfig(Aimbot* aim);
    void ResetDefaults();
    void ApplySafeSettings();
    void DeepCleanTraces();
    void SpoofMAC();
    void LoadAuth();
    void SaveAuth();
    void ProcessChatInput(std::string input);
    void RenderChatWindow();
    void RenderHWTutorial();
    std::string ToLower(std::string s);

    // ---- Ìåòîäû âêëàäîê (îáúÿâëåíû, ðåàëèçîâàíû â overlay.cpp èç ñòàðîãî) ----
    void RenderAimbotTab(float content_w, float content_h, const ImVec4& acc_vec, ImU32 acc_u32, bool& cfg_changed);
    void RenderVisualsTab(float content_w, float content_h, const ImVec4& acc_vec, ImU32 acc_u32, bool& cfg_changed);
    void RenderNeuralTab(float content_w, float content_h, const ImVec4& acc_vec, ImU32 acc_u32, bool& cfg_changed);
    void RenderPwnzAITab(float content_w, float content_h, const ImVec4& acc_vec, ImU32 acc_u32, bool& cfg_changed);
    void RenderProfileTab(float content_w, float content_h, const ImVec4& acc_vec, ImU32 acc_u32, bool& cfg_changed);
    void RenderHardwareTab(float content_w, float content_h, const ImVec4& acc_vec, ImU32 acc_u32, bool& cfg_changed);
    void RenderSecurityTab(float content_w, float content_h, const ImVec4& acc_vec, ImU32 acc_u32, bool& cfg_changed);
    void RenderTelemetryTab(float content_w, float content_h, const ImVec4& acc_vec, ImU32 acc_u32, bool& cfg_changed);
    void RenderHWCheckTab(float content_w, float content_h, const ImVec4& acc_vec, ImU32 acc_u32, bool& cfg_changed);
    void RenderXTierTab(float content_w, float content_h, const ImVec4& acc_vec, ImU32 acc_u32, bool& cfg_changed);
    void RenderMetricsTab(float content_w, float content_h, const ImVec4& acc_vec, ImU32 acc_u32, bool& cfg_changed);

    // ---- Íîâûå ìåòîäû äëÿ ðàçáèâêè Render ----
    void RenderAutoLogin(const ImVec4& acc_vec, ImU32 acc_u32);
    void RenderLoadingScreen(const ImVec4& acc_vec, ImU32 acc_u32);
    void RenderAuthWindow(const ImVec4& acc_vec, ImU32 acc_u32);
    void RenderVisualsAndZone(const std::vector<Detection>& detections, Aimbot* aim);
    void RenderMenu(const std::vector<Detection>& detections, Aimbot* aim, bool& cfg_changed);

private:
    bool DrawToggleOnly(const char* str_id, bool* v, ImU32 accent_u32);
    bool DrawToggle(const char* label, const char* str_id, bool* v, ImU32 accent_u32, const char* help = nullptr);
    bool CustomSliderFloat(const char* label, const char* label_id, float* v, float v_min, float v_max, const char* format, ImVec4 accent_vec, const char* help = nullptr);
    bool CustomSliderInt(const char* label, const char* label_id, int* v, int v_min, int v_max, const char* format, ImVec4 accent_vec, const char* help = nullptr);
    bool CustomCombo(const char* label, const char* label_id, int* current_item, const char* const items[], int items_count, const char* help = nullptr);
    bool DrawKeybinder(const char* label, int* vk_key, int id, const char* help = nullptr);
    void HelpMarker(const char* desc);
    bool BeginPanel(const char* name, ImVec2 size, ImVec4 accent_vec, bool has_toggle = false, bool* toggle_val = nullptr, ImU32 accent_u32 = 0);
    void EndPanel();

    static int active_tab;
    static int active_bind_id;

    HWND hwnd;
    ID3D11Device* g_pd3dDevice = nullptr;
    ID3D11DeviceContext* g_pd3dDeviceContext = nullptr;
    IDXGISwapChain* g_pSwapChain = nullptr;
    ID3D11RenderTargetView* g_mainRenderTargetView = nullptr;
    UINT sync_interval = 0;

    bool CreateDeviceD3D(HWND hWnd);
    void CleanupDeviceD3D();
    void CreateRenderTarget();
    void CleanupRenderTarget();
    void LoadConfig(Aimbot* aim);
    void FetchHardwareInfo();

    // 2PC Network module
    std::unique_ptr<Network2PC> network_2pc;
};