#include <stdio.h>
#include <tchar.h>
#include "base64.h"

static const char base64EncodingTable[] = {
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
    'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
    'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
    'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
    'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
    'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
    'w', 'x', 'y', 'z', '0', '1', '2', '3',
    '4', '5', '6', '7', '8', '9', '+', '/' };

static const unsigned char base64DecodingTable[256] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3e, 0x00, 0x00, 0x00, 0x3f,
    0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
    0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
    0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

LPSTR base64Encode(PUCHAR inStr, DWORD dwInLen, DWORD *dwOutLen)
{
    static const int mod_table[] = { 0, 2, 1 };
    LPSTR res = NULL;

    if (inStr == NULL || dwOutLen == NULL)
        return NULL;

    *dwOutLen = 4 * ((dwInLen + 2) / 3);
    res = HeapAlloc(GetProcessHeap(), 0, *dwOutLen);
    if (res == NULL)
    {
        _tprintf(TEXT(" [!] Out of memory"));
        return NULL;
    }
    for (DWORD i = 0, j = 0; i < dwInLen; )
    {
        DWORD octet_a = i < dwInLen ? inStr[i++] : 0;
        DWORD octet_b = i < dwInLen ? inStr[i++] : 0;
        DWORD octet_c = i < dwInLen ? inStr[i++] : 0;
        DWORD triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;

        res[j++] = base64EncodingTable[(triple >> 3 * 6) & 0x3F];
        res[j++] = base64EncodingTable[(triple >> 2 * 6) & 0x3F];
        res[j++] = base64EncodingTable[(triple >> 1 * 6) & 0x3F];
        res[j++] = base64EncodingTable[(triple >> 0 * 6) & 0x3F];
    }
    for (int i = 0; i < mod_table[dwInLen % 3]; i++)
        res[*dwOutLen - 1 - i] = '=';

    return res;
}

LPSTR base64Decode(LPCSTR inStr, DWORD dwInLen, DWORD *dwOutLen)
{
    LPSTR res = NULL;

    if (inStr == NULL || dwOutLen == NULL || dwInLen % 4 != 0)
        return NULL;

    *dwOutLen = dwInLen / 4 * 3;
    if (inStr[dwInLen - 1] == '=') (*dwOutLen)--;
    if (inStr[dwInLen - 2] == '=') (*dwOutLen)--;

    res = HeapAlloc(GetProcessHeap(), 0, *dwOutLen);
    if (res == NULL)
    {
        wprintf(TEXT(" [!] Out of memory"));
        return NULL;
    }
    for (DWORD i = 0, j = 0; i < dwInLen; )
    {
        DWORD sextet_a = inStr[i] == '=' ? 0 & i++ : base64DecodingTable[inStr[i++]];
        DWORD sextet_b = inStr[i] == '=' ? 0 & i++ : base64DecodingTable[inStr[i++]];
        DWORD sextet_c = inStr[i] == '=' ? 0 & i++ : base64DecodingTable[inStr[i++]];
        DWORD sextet_d = inStr[i] == '=' ? 0 & i++ : base64DecodingTable[inStr[i++]];
        DWORD triple = (sextet_a << 3 * 6)
            + (sextet_b << 2 * 6)
            + (sextet_c << 1 * 6)
            + (sextet_d << 0 * 6);

        if (j < *dwOutLen) res[j++] = (triple >> 2 * 8) & 0xFF;
        if (j < *dwOutLen) res[j++] = (triple >> 1 * 8) & 0xFF;
        if (j < *dwOutLen) res[j++] = (triple >> 0 * 8) & 0xFF;
    }
    return res;
}