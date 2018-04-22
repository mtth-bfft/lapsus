#pragma once
#pragma warning(push, 3)
#include <Windows.h>
#pragma warning(pop)

#define PASSWORD_LEN 14

int generateSecurePassword(LPWSTR pwzPassword, UCHAR ucCharacters);