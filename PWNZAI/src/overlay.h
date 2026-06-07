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

    bool draw_esp = true;
    bool draw_fov = true;
    bool draw_fov_neural = true;
    bool draw_watermark = true;
    bool draw_crosshair = false;
    bool disable_all_visuals_when_hidden = true;
    float esp_thickness = 1.5f;
    int esp_style = 0;
    float color_esp_visible[3] = { 1,0.2f,0.2f };
    float color_esp_hidden[3] = { 0.7f,0.2f,1 };
    bool esp_oe_enable = true;
    float esp_oe_mincutoff = 0.5f;
    float esp_oe_beta = 0.01f;
    OneEuroFilter espFilterX, espFilterY, espFilterW, espFilterH;
    bool was_empty_last_frame = true;

    bool aim_enable = true;
    float aim_max_sens = 2.0f;
    float aim_min_sens = 1.0f;
    float aim_smoother = 10.0f;
    bool sticky_aim = false;
    float aim_kill_delay = 0.09f;
    int aim_target = 0;
    int aim_key_main = VK_RBUTTON;
    int aim_key_sub = 0;
    int aim_toggle_key = 0;
    bool enable_exclusion_zone = false;
    bool is_drawing_zone = false;
    float excl_x1 = 0, excl_y1 = 0, excl_x2 = 0, excl_y2 = 0;
    float fov_aimbot = 190.0f, fov_scan = 192.0f;
    bool enable_dynamic_fov = false;
    float aim_offset_x = 0, aim_offset_y = 0;
    int ai_model = 0;
    float ai_confidence_body = 48.0f;
    float ai_confidence_head = 35.0f;
    bool auto_confidence = false;
    float hit_chance = 90.0f;
    bool apply_model_flag = false;
    float min_box_area_body = 150.0f;
    float min_box_area_head = 40.0f;
    float neural_nms = 0.45f;
    int neural_max_det = 5;
    int refresh_rate_idx = 0;
    bool is_first_frame_init = true;
    int memory_enemy_frames = 3;
    bool eco_mode = true;
    bool obs_bypass = true;
    float menu_scale = 100.0f;
    float menu_width = 1150.0f;
    float menu_height = 720.0f;
    bool unload_flag = false;
    int hardware_type = 0;
    int com_port = 2;
    bool apply_hw_flag = false;
    float accent_color[3] = { 0,0.8f,1 };
    bool is_benchmarking = false;
    float bench_prog = 0.0f;
    bool bench_done = false;
    int target_monitor = 0;
    bool enable_dma_fuser = false;
    float last_ping_ms = -1.0f;
    int selected_preset = 0;
    bool show_hw_tutorial = false;
    int tutorial_hw_selected = 0;
    bool is_menu_open = false;
    bool is_russian = true;
    double lifetime_seconds = 0.0;
    char hwid_str[64] = "UNKNOWN", cpu_str[128] = "CPU", gpu_str[128] = "GPU", os_str[64] = "Windows 10/11";
    float max_move_step = 50.0f;
    float lock_radius_base = 200.0f;
    float lock_radius_scale = 3.0f;
    float head_height_ratio = 0.1f;
    float sticky_zone_factor = 0.5f;
    float sticky_damping = 0.3f;
    bool hum_micro_movements = true;
    float hum_micro_amplitude = 0.8f;
    float hum_reaction_jitter = 2.0f;
    float byte_track_thresh = 0.5f;
    int byte_track_buffer = 30;
    float byte_match_thresh = 0.8f;
    int byte_frame_rate = 30;
    bool use_advanced_sticky_aim = true;
    float sticky_threshold = 50.0f;
    int sticky_frames_keep = 3;
    int prediction_method = 1;

    float mouse_sensitivity = 1.0f;
    float mouse_yaw = 0.022f;
    float mouse_pitch = 0.022f;
    float fovX = 106.0f;
    float fovY = 74.0f;
    int detection_resolution = 960;

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
    void RenderProfileTab(float content_w, float content_h, const ImVec4& acc_vec, ImU32 acc_u32, bool& cfg_changed);
    void RenderHardwareTab(float content_w, float content_h, const ImVec4& acc_vec, ImU32 acc_u32, bool& cfg_changed);
    void RenderHWCheckTab(float content_w, float content_h, const ImVec4& acc_vec, ImU32 acc_u32, bool& cfg_changed);
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