#pragma once
#include <string>

std::string GetHWID();
// ������ ������� ������������� ���������� ���� �������� �� ������
std::string SendAuthRequest(const std::string& username, const std::string& password, bool is_register, std::string& out_expiry);