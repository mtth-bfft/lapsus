#pragma once
#pragma warning(push, 3)
#include <Windows.h>
#pragma warning(pop)

LPSTR base64Decode(LPCSTR inStr, DWORD dwInLen, DWORD *dwOutLen);
LPSTR base64Encode(PUCHAR inStr, DWORD dwInLen, DWORD *dwOutLen);