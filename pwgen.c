#include <stdio.h>
#include "pwgen.h"

static LPCWSTR pwzPasswordChars = L"abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789:/-+()_%";

int isPasswordCompliant(LPCWSTR pwzPassword)
{
    int lowercase = 0;
    int uppercase = 0;
    int digit = 0;
    int symbol = 0;
    size_t n = wcslen(pwzPassword);
    for (DWORD i = 0; i < n; i++)
    {
        if (pwzPassword[i] >= L'A' && pwzPassword[i] <= L'Z')
            uppercase++;
        else if (pwzPassword[i] >= L'a' && pwzPassword[i] <= 'z')
            lowercase++;
        else if (pwzPassword[i] >= L'0' && pwzPassword[i] <= '9')
            digit++;
        else
            symbol++;
    }
    return (lowercase > 0 && uppercase > 0 && digit > 0 && symbol > 0);
}

int generateSecurePassword(LPWSTR pwzPassword, UCHAR ucCharacters)
{
    int res = 0;
    HCRYPTPROV hCrypt;
    int freeCtx = 0;
    UCHAR ucRandByte = 0;
    const UCHAR ucMaxRandByte = (UCHAR)wcslen(pwzPasswordChars);

    if (!CryptAcquireContext(&hCrypt, NULL, MS_STRONG_PROV, PROV_RSA_FULL,
        CRYPT_VERIFYCONTEXT | CRYPT_SILENT))
    {
        res = GetLastError();
        wprintf(TEXT(" [!] CryptAcquireContext() failed (code %d)\n"), res);
        goto cleanup;
    }
    freeCtx = 1;

    do {
        for (int i = 0; i < ucCharacters; i++)
        {
            do
            {
                if (!CryptGenRandom(hCrypt, 1, &ucRandByte))
                {
                    res = GetLastError();
                    wprintf(TEXT(" [!] CryptGenRandom(1) failed (code %d)\n"), res);
                    goto cleanup;
                }
            } while (ucRandByte >= ucMaxRandByte);
            pwzPassword[i] = pwzPasswordChars[ucRandByte];
        }
    } while (!isPasswordCompliant(pwzPassword));

cleanup:
    if (freeCtx)
        CryptReleaseContext(hCrypt, 0);
    return res;
}
