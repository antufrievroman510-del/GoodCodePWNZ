#pragma once
#include <windows.h>
#include <iostream>
#include <thread>
#include <chrono>

class MouseDriver {
private:
    HANDLE hDriver;
    bool use_fallback; // Флаг для использования безотказного метода SendInput

    // Структура пакета для официального драйвера Logitech
    struct MOUSE_IO {
        char button;
        char x;
        char y;
        char wheel;
        char unk1;
    };

public:
    MouseDriver() {
        // Пытаемся подключиться к драйверу G-Hub
        hDriver = CreateFileA("\\\\.\\LG_VK_MKD_Device", GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);

        if (hDriver == INVALID_HANDLE_VALUE) {
            // [ФИКС]: Если драйвер заблокирован, включаем 100% рабочий метод
            use_fallback = true;
            std::cout << "[!] Драйвер Logitech G-Hub ЗАБЛОКИРОВАН или не найден!" << std::endl;
            std::cout << "[+] Включаю резервный метод Windows API (SendInput). Аимбот БУДЕТ работать." << std::endl;
        }
        else {
            use_fallback = false;
            std::cout << "[+] Успешное подключение к драйверу Logitech (Ring 0)!" << std::endl;
        }
    }

    ~MouseDriver() {
        if (hDriver != INVALID_HANDLE_VALUE) {
            CloseHandle(hDriver);
        }
    }

    bool IsInitialized() const {
        return true; // Теперь всегда true, потому что у нас есть резервный метод!
    }

    void Move(int dx, int dy) {
        if (use_fallback) {
            // Безотказный метод движения мыши
            INPUT input = { 0 };
            input.type = INPUT_MOUSE;
            input.mi.dwFlags = MOUSEEVENTF_MOVE;
            input.mi.dx = dx;
            input.mi.dy = dy;
            SendInput(1, &input, sizeof(INPUT));
        }
        else {
            // Аппаратный метод через драйвер
            MOUSE_IO buffer = { 0, static_cast<char>(dx), static_cast<char>(dy), 0, 0 };
            DWORD bytesReturned;
            DeviceIoControl(hDriver, 0x2A2010, &buffer, sizeof(buffer), nullptr, 0, &bytesReturned, nullptr);
        }
    }

    void Click(int button_code) {
        if (use_fallback) {
            INPUT input = { 0 };
            input.type = INPUT_MOUSE;
            if (button_code == 1) input.mi.dwFlags = MOUSEEVENTF_LEFTDOWN;
            else if (button_code == 2) input.mi.dwFlags = MOUSEEVENTF_RIGHTDOWN;
            SendInput(1, &input, sizeof(INPUT));

            std::this_thread::sleep_for(std::chrono::milliseconds(20)); // Имитация пальца

            if (button_code == 1) input.mi.dwFlags = MOUSEEVENTF_LEFTUP;
            else if (button_code == 2) input.mi.dwFlags = MOUSEEVENTF_RIGHTUP;
            SendInput(1, &input, sizeof(INPUT));
        }
        else {
            MOUSE_IO buffer = { static_cast<char>(button_code), 0, 0, 0, 0 };
            DWORD bytesReturned;
            DeviceIoControl(hDriver, 0x2A2010, &buffer, sizeof(buffer), nullptr, 0, &bytesReturned, nullptr);

            std::this_thread::sleep_for(std::chrono::milliseconds(20));

            buffer.button = 0;
            DeviceIoControl(hDriver, 0x2A2010, &buffer, sizeof(buffer), nullptr, 0, &bytesReturned, nullptr);
        }
    }
};