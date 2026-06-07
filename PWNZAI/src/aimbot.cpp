#include "aimbot.h"

bool Aimbot::InitHardware() {
    return true;
}

void Aimbot::CloseHardware() {
}

void Aimbot::SendHardwareMove(int x, int y) {
}

void Aimbot::SendHardwareClick() {
}

void Aimbot::ResetTarget() {
}

void Aimbot::Update(const std::vector<Detection>& detections, int screen_w, int screen_h,
    bool is_new_frame, long long current_time_ms, float zoom_scale) {
}
