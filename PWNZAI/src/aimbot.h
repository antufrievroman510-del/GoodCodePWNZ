#pragma once

#define NOMINMAX
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN 
#endif

#include <winsock2.h>
#include <windows.h>
#include <vector>
#include <string>

#include "detector.h"

class Aimbot {
public:
    int hardware_type = 0;
    int com_port = 3;
    HANDLE hSerial = INVALID_HANDLE_VALUE;
    SOCKET udp_socket = INVALID_SOCKET;
    sockaddr_in udp_addr;
    std::string net_ip = "192.168.1.100";
    int net_port = 3333;

    bool InitHardware();
    void CloseHardware();
    void SendHardwareMove(int x, int y);
    void SendHardwareClick();
    void ResetTarget();
    void Update(const std::vector<Detection>& detections, int screen_w, int screen_h,
        bool is_new_frame, long long current_time_ms, float zoom_scale = 1.0f);
};
