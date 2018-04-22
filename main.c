#pragma warning(push, 3)
#include <Windows.h>
#include <WinCrypt.h>
#include <LM.h>
#include <sddl.h>
#include <stdio.h>
#pragma warning(pop)
#include "base64.h"
#include "pwgen.h"

#define MAXIMUM_ACCOUNT_NAME_LENGTH 104
#define MAXIMUM_HOSTNAME_LENGTH 64 // per DNS label limits

double getTimeFromStart()
{
    static LARGE_INTEGER frequency = { 0 };
    static LARGE_INTEGER start = { 0 };
    LARGE_INTEGER now;

    if (frequency.QuadPart == 0)
        QueryPerformanceFrequency(&frequency);
    if (start.QuadPart == 0)
        QueryPerformanceCounter(&start);

    QueryPerformanceCounter(&now);
    return (double)(now.QuadPart - start.QuadPart) / frequency.QuadPart;
}

int memoryMapFile(LPCWSTR pwzPath, PVOID *pOut, SIZE_T *pOutLen)
{
    int res = 0;
    HANDLE hFile = INVALID_HANDLE_VALUE;
    HANDLE hMapping = INVALID_HANDLE_VALUE;
    LARGE_INTEGER liFileSize = { 0 };

    hFile = CreateFile(pwzPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        res = GetLastError();
        wprintf(TEXT(" [!] Unable to open file at %s (code %d)\n"), pwzPath, res);
        goto cleanup;
    }
    if (!GetFileSizeEx(hFile, &liFileSize))
    {
        res = GetLastError();
        wprintf(TEXT(" [!] Unable to read file %s size (code %d)\n"), pwzPath, res);
        goto cleanup;
    }
    if (liFileSize.QuadPart == 0)
    {
        res = 0;
        *pOut = NULL;
        *pOutLen = 0;
        CloseHandle(hFile);
        goto cleanup;
    }
    hMapping = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (hMapping == NULL)
    {
        res = GetLastError();
        wprintf(TEXT(" [!] Unable to map %s into memory (code %d)\n"), pwzPath, res);
        goto cleanup;
    }
    *pOut = MapViewOfFile(hMapping, FILE_MAP_COPY, 0, 0, 0);
    if (*pOut == NULL)
    {
        res = GetLastError();
        wprintf(TEXT(" [!] Unable to map %s into memory (code %d)\n"), pwzPath, res);
        goto cleanup;
    }
    *pOutLen = (SIZE_T)liFileSize.QuadPart;

cleanup:
    return res;
}

int loadKeyFromFile(LPCWSTR pwzKeyPath, HCRYPTKEY *hKey)
{
    int res = 0;
    PVOID pPrivKey = NULL;
    SIZE_T privKeySize = 0;
    HCRYPTPROV hCrypt = (HCRYPTPROV)NULL;
    int freeCtx = 0;

    res = memoryMapFile(pwzKeyPath, &pPrivKey, &privKeySize);
    if (res != 0)
        goto cleanup;

    if (!CryptAcquireContext(&hCrypt, NULL, MS_STRONG_PROV, PROV_RSA_FULL,
        CRYPT_VERIFYCONTEXT | CRYPT_SILENT))
    {
        res = GetLastError();
        wprintf(TEXT(" [!] CryptAcquireContext() failed (code %d)\n"), res);
        goto cleanup;
    }
    freeCtx = 1;
    if (!CryptImportKey(hCrypt, pPrivKey, (DWORD)privKeySize, (HCRYPTKEY)NULL, 0, hKey))
    {
        res = GetLastError();
        wprintf(TEXT(" [!] Failed to import key from %s (code %d)\n"), pwzKeyPath, res);
        goto cleanup;
    }

cleanup: // hCrypt is never released with the current code design
    return res;
}

int generateKeyPair(LPCWSTR pwzPubkeyPath, LPCWSTR pwzPrivkeyPath, DWORD dwKeyBits)
{
    int res = 0;
    HANDLE hPrivKey = INVALID_HANDLE_VALUE;
    HANDLE hPubKey = INVALID_HANDLE_VALUE;
    HCRYPTPROV hCrypt = (HCRYPTPROV)NULL;
    HCRYPTKEY hKey = (HCRYPTKEY)NULL;
    int freeCtx = 0;
    DWORD dwKeyBlobSize = 0;
    DWORD dwBytesWritten = 0;
    PVOID pKeyBlob = NULL;

    hPrivKey = CreateFile(pwzPrivkeyPath, GENERIC_WRITE, 0, NULL, CREATE_NEW, 0, NULL);
    if (hPrivKey == INVALID_HANDLE_VALUE)
    {
        res = GetLastError();
        wprintf(TEXT(" [!] Unable to create private key at %s (code %d)\n"),
            pwzPrivkeyPath, res);
        goto cleanup;
    }
    hPubKey = CreateFile(pwzPubkeyPath, GENERIC_WRITE, 0, NULL, CREATE_NEW, 0, NULL);
    if (hPubKey == INVALID_HANDLE_VALUE)
    {
        res = GetLastError();
        wprintf(TEXT(" [!] Unable to create public key at %s (code %d)\n"),
            pwzPubkeyPath, res);
        goto cleanup;
    }
    if (!CryptAcquireContext(&hCrypt, NULL, MS_STRONG_PROV, PROV_RSA_FULL,
        CRYPT_VERIFYCONTEXT | CRYPT_SILENT))
    {
        res = GetLastError();
        wprintf(TEXT(" [!] CryptAcquireContext() failed (code %d)\n"), res);
        goto cleanup;
    }
    freeCtx = 1;
    wprintf(TEXT(" [+] Generating a %d-bit RSA key pair...\n"), dwKeyBits);
    if (!CryptGenKey(hCrypt, CALG_RSA_KEYX, CRYPT_EXPORTABLE | (dwKeyBits << 16), &hKey))
    {
        res = GetLastError();
        wprintf(TEXT(" [!] Unable to generate %d-bit RSA key (code %d)\n"), dwKeyBits, res);
        goto cleanup;
    }
    CryptExportKey(hKey, (HCRYPTKEY)NULL, PRIVATEKEYBLOB, 0, NULL, &dwKeyBlobSize);
    pKeyBlob = HeapAlloc(GetProcessHeap(), 0, dwKeyBlobSize);
    if (pKeyBlob == NULL)
    {
        res = ERROR_OUTOFMEMORY;
        wprintf(TEXT(" [!] Out of memory\n"));
        goto cleanup;
    }
    if (!CryptExportKey(hKey, (HCRYPTKEY)NULL, PRIVATEKEYBLOB, 0, pKeyBlob, &dwKeyBlobSize))
    {
        res = GetLastError();
        wprintf(TEXT(" [!] CryptExportKey(PRIVATEKEYBLOB) failed (code %d)\n"), res);
        goto cleanup;
    }
    if (!WriteFile(hPrivKey, pKeyBlob, dwKeyBlobSize, &dwBytesWritten, NULL))
    {
        SecureZeroMemory(pKeyBlob, dwKeyBlobSize);
        res = GetLastError();
        wprintf(TEXT(" [!] WriteFile() failed (code %d)\n"), res);
        goto cleanup;
    }
    SecureZeroMemory(pKeyBlob, dwKeyBlobSize);
    wprintf(TEXT(" [+] Private key written to %s, you should store it offline\n"), pwzPrivkeyPath);

    CryptExportKey(hKey, (HCRYPTKEY)NULL, PUBLICKEYBLOB, 0, NULL, &dwKeyBlobSize);
    pKeyBlob = HeapReAlloc(GetProcessHeap(), 0, pKeyBlob, dwKeyBlobSize);
    if (pKeyBlob == NULL)
    {
        res = ERROR_OUTOFMEMORY;
        wprintf(TEXT(" [!] Out of memory\n"));
        goto cleanup;
    }
    if (!CryptExportKey(hKey, (HCRYPTKEY)NULL, PUBLICKEYBLOB, 0, pKeyBlob, &dwKeyBlobSize))
    {
        res = GetLastError();
        wprintf(TEXT(" [!] CryptExportKey(PUBLICKEYBLOB) failed (code %d)\n"), res);
        goto cleanup;
    }
    if (!WriteFile(hPubKey, pKeyBlob, dwKeyBlobSize, &dwBytesWritten, NULL))
    {
        res = GetLastError();
        wprintf(TEXT(" [!] WriteFile() failed (code %d)\n"), res);
        goto cleanup;
    }

cleanup:
    if (hPrivKey != INVALID_HANDLE_VALUE)
        CloseHandle(hPrivKey);
    if (hPubKey != INVALID_HANDLE_VALUE)
        CloseHandle(hPubKey);
    if (freeCtx)
        CryptReleaseContext(hCrypt, 0);
    return res;
}

// dwBufferLength should be at least MAXIMUM_ACCOUNT_NAME_LENGTH wchars
// to ensure compatibility
int getBuiltInAdminLogin(LPWSTR pwzUserName, DWORD dwBufferLength)
{
    int res = 0;
    DWORD dwMachineSIDSize = SECURITY_MAX_SID_SIZE;
    WCHAR pwzHostname[MAXIMUM_HOSTNAME_LENGTH + 1] = { 0 };
    DWORD dwHostnameSize = MAXIMUM_HOSTNAME_LENGTH + 1;
    WCHAR pwzDomain[MAXIMUM_HOSTNAME_LENGTH + 1] = { 0 };
    DWORD dwDomainSize = MAXIMUM_HOSTNAME_LENGTH + 1;
    PSID pMachineSID = NULL;
    PSID pLocalAdminSID = NULL;
    LPWSTR pwzLocalAdminSIDStr = NULL;
    DWORD dwSubAuthorities[8] = { 0 };
    UCHAR ucAuthorityCnt = 0;
    SID_NAME_USE sidUse = 0;

    pMachineSID = (PSID)HeapAlloc(GetProcessHeap(), 0, dwMachineSIDSize);
    if (pMachineSID == NULL)
    {
        res = ENOMEM;
        goto cleanup;
    }
    if (!GetComputerName(pwzHostname, &dwHostnameSize))
    {
        res = GetLastError();
        wprintf(TEXT(" [!] GetComputerName() failed (code %d)\n"), res);
        goto cleanup;
    }
    if (!LookupAccountName(TEXT(""), pwzHostname, pMachineSID, &dwMachineSIDSize,
        pwzDomain, &dwDomainSize, &sidUse))
    {
        res = GetLastError();
        wprintf(TEXT(" [!] LookupAccountName() failed (code %d)\n"), res);
        goto cleanup;
    }
    if (!IsValidSid(pMachineSID))
    {
        res = 1;
        wprintf(TEXT(" [!] LookupAccountName() returned an invalid machine SID\n"));
        goto cleanup;
    }
    for (ucAuthorityCnt = 0; ucAuthorityCnt < *GetSidSubAuthorityCount(pMachineSID); ucAuthorityCnt++)
        dwSubAuthorities[ucAuthorityCnt] = *GetSidSubAuthority(pMachineSID, ucAuthorityCnt);
    dwSubAuthorities[ucAuthorityCnt++] = DOMAIN_USER_RID_ADMIN;

    if (!AllocateAndInitializeSid(GetSidIdentifierAuthority(pMachineSID), ucAuthorityCnt,
        dwSubAuthorities[0], dwSubAuthorities[1], dwSubAuthorities[2], dwSubAuthorities[3],
        dwSubAuthorities[4], dwSubAuthorities[5], dwSubAuthorities[6], dwSubAuthorities[7],
        &pLocalAdminSID))
    {
        res = GetLastError();
        wprintf(TEXT(" [!] AllocateAndInitializeSid() failed (code %d)\n"), res);
        goto cleanup;
    }
    if (!ConvertSidToStringSid(pLocalAdminSID, &pwzLocalAdminSIDStr))
    {
        res = GetLastError();
        wprintf(TEXT(" [!] ConvertSidToStringSid() failed (code %d)\n"), res);
        goto cleanup;
    }
    wprintf(TEXT(" [+] Built-in administrator SID: %s\n"), pwzLocalAdminSIDStr);
    dwDomainSize = MAXIMUM_HOSTNAME_LENGTH + 1;
    if (!LookupAccountSid(TEXT(""), pLocalAdminSID, pwzUserName, &dwBufferLength,
        pwzDomain, &dwDomainSize, &sidUse))
    {
        res = GetLastError();
        wprintf(TEXT(" [!] LookupAccountSidLocal() failed (code %d)\n"), res);
        goto cleanup;
    }
    wprintf(TEXT(" [+] Built-in administrator login: '%s'\n"), pwzUserName);

cleanup:
    if (pMachineSID != NULL)
        HeapFree(GetProcessHeap(), 0, pMachineSID);
    if (pLocalAdminSID != NULL)
        FreeSid(pLocalAdminSID);
    if (pwzLocalAdminSIDStr != NULL)
        LocalFree(pwzLocalAdminSIDStr);
    return 0;
}

int encryptPassword(LPCWSTR pwzNewPassword, LPCWSTR pwzPubKeyPath, LPSTR *pzEncryptedPwd)
{
    int res = 0;
    HCRYPTKEY hPubKey;
    PVOID pEncryptedPwd = NULL;
    DWORD dwUTF8Size = 0;
    DWORD dwEncryptedSize = 0;
    DWORD dwbase64Len = 0;

    if (pwzNewPassword == NULL || pzEncryptedPwd == NULL)
        return STATUS_INVALID_PARAMETER;

    res = loadKeyFromFile(pwzPubKeyPath, &hPubKey);
    if (res != 0)
        goto cleanup;

    dwUTF8Size = WideCharToMultiByte(CP_UTF8, 0, pwzNewPassword, -1, NULL, 0, NULL, NULL);
    if (dwUTF8Size == 0)
    {
        res = GetLastError();
        wprintf(TEXT(" [!] Failed to get password length in UTF-8 (code %d)\n"), res);
        goto cleanup;
    }
    dwEncryptedSize = dwUTF8Size;
    if (!CryptEncrypt(hPubKey, (HCRYPTHASH)NULL, TRUE, 0, NULL, &dwEncryptedSize, dwUTF8Size))
    {
        res = GetLastError();
        wprintf(TEXT(" [!] Failed to get encrypted password length (code %d)\n"), res);
        goto cleanup;
    }
    pEncryptedPwd = HeapAlloc(GetProcessHeap(), 0, dwEncryptedSize);
    if (pEncryptedPwd == NULL)
    {
        res = ERROR_OUTOFMEMORY;
        wprintf(TEXT(" [!] Out of memory\n"));
        goto cleanup;
    }
    if (WideCharToMultiByte(CP_UTF8, 0, pwzNewPassword, -1, pEncryptedPwd, dwEncryptedSize, NULL, NULL) == 0)
    {
        res = GetLastError();
        wprintf(TEXT(" [!] Failed to get password length in UTF-8 (code %d)\n"), res);
        goto cleanup;
    }
    if (!CryptEncrypt(hPubKey, (HCRYPTHASH)NULL, TRUE, 0, pEncryptedPwd, &dwUTF8Size, dwEncryptedSize))
    {
        res = GetLastError();
        wprintf(TEXT(" [!] Failed to encrypt new password (code %d)\n"), res);
        goto cleanup;
    }

    *pzEncryptedPwd = base64Encode(pEncryptedPwd, dwEncryptedSize, &dwbase64Len);

cleanup:
    if (pEncryptedPwd != NULL)
    {
        SecureZeroMemory(pEncryptedPwd, dwEncryptedSize);
        HeapFree(GetProcessHeap(), 0, pEncryptedPwd);
    }
    return res;
}

int writeToDB(LPCWSTR pwzUsername, LPCSTR pzEncryptedPwd, LPCWSTR pwzDBPath, int timeoutSecs)
{
    int res = 0;
    CHAR pzHostname[MAXIMUM_HOSTNAME_LENGTH + 1] = { 0 };
    DWORD dwHostnameSize = MAXIMUM_HOSTNAME_LENGTH + 1;
    CHAR pzUsername[MAXIMUM_ACCOUNT_NAME_LENGTH + 1] = { 0 };
    DWORD dwUTF8Size = MAXIMUM_ACCOUNT_NAME_LENGTH + 1;
    LPSTR pzDBLine = NULL;
    HANDLE hDBFile = INVALID_HANDLE_VALUE;
    DWORD dwSleepDelay = 500;
    DWORD dwBytesWritten = 0;

    // First DB field is the UTF-8 hostname
    if (!GetComputerNameA(pzHostname, &dwHostnameSize))
    {
        res = GetLastError();
        wprintf(TEXT(" [!] GetComputerName() failed (code %d)\n"), res);
        goto cleanup;
    }

    // Second DB field is the UTF-8 username
    if (WideCharToMultiByte(CP_UTF8, 0, pwzUsername, -1, pzUsername, dwUTF8Size, NULL, NULL) == 0)
    {
        res = GetLastError();
        wprintf(TEXT(" [!] Failed to get username in UTF-8 (code %d)\n"), res);
        goto cleanup;
    }

    pzDBLine = HeapAlloc(GetProcessHeap(), 0, dwHostnameSize + dwUTF8Size + strlen(pzEncryptedPwd));
    if (pzDBLine == NULL)
    {
        res = ERROR_OUTOFMEMORY;
        wprintf(TEXT(" [!] Out of memory\n"));
        goto cleanup;
    }

    snprintf(pzDBLine, dwHostnameSize + dwUTF8Size + strlen(pzEncryptedPwd), "%s,%s,%s\n",
        pzHostname, pzUsername, pzEncryptedPwd);

    getTimeFromStart();
    while (getTimeFromStart() < timeoutSecs)
    {
        hDBFile = CreateFile(pwzDBPath, FILE_APPEND_DATA, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
        if (hDBFile != INVALID_HANDLE_VALUE)
            break;
        res = GetLastError();
        Sleep(dwSleepDelay);
        dwSleepDelay = (dwSleepDelay * 105) / 100;
        wprintf(TEXT(" [!] Failed to acquire lock on DB file, waiting...\n"));
    }
    if (hDBFile == INVALID_HANDLE_VALUE)
    {
        wprintf(TEXT(" [!] Failed to open DB file, timed out after %d secs\n"), timeoutSecs);
        goto cleanup;
    }
    wprintf(TEXT(" [+] Opened DB file at %s\n"), pwzDBPath);

    if (SetFilePointer(hDBFile, 0, NULL, FILE_END) == INVALID_SET_FILE_POINTER)
    {
        res = GetLastError();
        wprintf(TEXT(" [!] Failed to seek endo of DB file (code %d)\n"), res);
        goto cleanup;
    }
    if (!WriteFile(hDBFile, pzDBLine, (DWORD)strlen(pzDBLine), &dwBytesWritten, NULL))
    {
        res = GetLastError();
        wprintf(TEXT(" [!] Failed to write to DB file (code %d)\n"), res);
        goto cleanup;
    }
    wprintf(TEXT(" [+] Password registered in DB.\n"));

cleanup:
    if (pzDBLine != NULL)
        HeapFree(GetProcessHeap(), 0, pzDBLine);
    if (hDBFile != INVALID_HANDLE_VALUE)
        CloseHandle(hDBFile);
    return res;
}

int decryptFromDB(LPCWSTR pwzDBPath, LPCWSTR pwzPrivKeyPath, LPCWSTR pwzQueryHostname, LPCWSTR pwzQueryUsername)
{
    int res = 0;
    HCRYPTKEY hPrivKey = (HCRYPTKEY)NULL;
    CHAR pzQueryHostname[MAXIMUM_HOSTNAME_LENGTH + 1] = { 0 };
    CHAR pzQueryUsername[MAXIMUM_ACCOUNT_NAME_LENGTH + 1] = { 0 };
    PCHAR pScanLinesCtx = NULL;
    PCHAR pScanFieldsCtx = NULL;
    PCHAR pDBContents = NULL;
    SIZE_T dbContentsLen = 0;
    PCHAR pLine = NULL;
    DWORD dwLineNum = 0;
    PCSTR pzHostname = NULL;
    PCSTR pzUsername = NULL;
    PCSTR pzEncodedPwd = NULL;
    PCHAR pEncryptedPwd = NULL;
    DWORD dwEncryptedPwdSize = 0;

    res = loadKeyFromFile(pwzPrivKeyPath, &hPrivKey);
    if (res != 0)
        goto cleanup;
    res = memoryMapFile(pwzDBPath, &pDBContents, &dbContentsLen);
    if (res != 0)
        goto cleanup;
    if (pwzQueryUsername != NULL && WideCharToMultiByte(CP_UTF8, 0, pwzQueryUsername,
        -1, pzQueryUsername, sizeof(pzQueryUsername), NULL, NULL) == 0)
    {
        res = GetLastError();
        wprintf(TEXT(" [!] Failed to convert username to UTF-8 (code %d)\n"), res);
        goto cleanup;
    }
    if (pwzQueryHostname != NULL && WideCharToMultiByte(CP_UTF8, 0, pwzQueryHostname,
        -1, pzQueryHostname, sizeof(pzQueryHostname), NULL, NULL) == 0)
    {
        res = GetLastError();
        wprintf(TEXT(" [!] Failed to convert hostname to UTF-8 (code %d)\n"), res);
        goto cleanup;
    }

    pLine = strtok_s(pDBContents, "\n", &pScanLinesCtx);
    while (pLine != NULL)
    {
        pzHostname = strtok_s(pLine, ",", &pScanFieldsCtx);
        pzUsername = strtok_s(NULL, ",", &pScanFieldsCtx);
        pzEncodedPwd = strtok_s(NULL, ",", &pScanFieldsCtx);
        if (pzHostname == NULL || pzUsername == NULL || pzEncodedPwd == NULL)
        {
            wprintf(TEXT(" [!] Malformed line %d in %s\n"), dwLineNum, pwzDBPath);
            goto nextline;
        }
        else if (pwzQueryHostname != NULL && _stricmp(pzHostname, pzQueryHostname) != 0 || \
            pwzQueryUsername != NULL && _stricmp(pzUsername, pzQueryUsername) != 0)
        {
            goto nextline;
        }
        pEncryptedPwd = base64Decode(pzEncodedPwd, (DWORD)strlen(pzEncodedPwd), &dwEncryptedPwdSize);
        if (!CryptDecrypt(hPrivKey, (HCRYPTHASH)NULL, TRUE, 0, (PBYTE)pEncryptedPwd, &dwEncryptedPwdSize))
        {
            res = GetLastError();
            wprintf(TEXT(" [!] Unable to decrypt password at line %d in %s (code %d)\n"), dwLineNum, pwzDBPath, res);
            goto nextline;
        }
        ((PCHAR)pEncryptedPwd)[dwEncryptedPwdSize] = '\0';
        printf("%s,%s,%s\n", pzHostname, pzUsername, pEncryptedPwd);

    nextline: pLine = strtok_s(NULL, "\n", &pScanLinesCtx);
        dwLineNum++;
    }

cleanup:
    return res;
}

void print_usage()
{
    printf("\n"
    "Lapsus.exe v1.0 - Local Administrator password randomizer\n"
    "\n"
    "Arguments:\n"
    "    /genkey <pub_key> <priv_key> [<key_size_in_bits>]\n"
    "    /randomize <pub_key> <db> <account_name>|RID500 [<timeout secs>]\n"
    "    /decrypt <priv_key> <db> [<machine_name>[\\<account_name>]]\n"
    "\n"
    "Example: .\\Lapsus.exe /genkey \\\\filer\\share\\pub.key .\\priv.key 4096\n"
    "         .\\Lapsus.exe /randomize \\\\filer\\share\\pub.key \\\\filer\\share\\db.csv RID500\n"
    "         .\\Lapsus.exe /decrypt .\\priv.key \\\\filer\\share\\db.csv\n"
    "\n"
    "Note: be careful to store the private key in a secure location, and make sure\n"
    "the CSV db file is accessible with APPEND_DATA permission for Everyone, and is\n"
    "owned and readable only by a privileged group like Domain Admins. For instance, use:\n"
    "    type nul > db.csv\n"
    "    icacls db.csv /grant:r \"MYDOM\\Domain Admins:(F)\" /grant:r \"*S-1-1-0:(Rc,S,AD)\"\n"
    "    icacls db.csv /inheritance:r\n"
    "    icacls db.csv /setowner \"MYDOM\\Domain Admins\""
    "\n");
}

int wmain(int argc, WCHAR *argv[])
{
    int res = 0;
    DWORD dwKeyBits = 2048;
    DWORD dwTimeoutSecs = 3600;
    LPCWSTR pwzPubKeyPath = NULL;
    LPCWSTR pwzPrivKeyPath = NULL;
    LPCWSTR pwzDBPath = NULL;
    LPWSTR pwzHostname = NULL;
    LPCWSTR pwzUsername = NULL;
    LPSTR pzEncryptedPwd = NULL;
    WCHAR pwzBuiltinAdminLogin[MAXIMUM_ACCOUNT_NAME_LENGTH] = { 0 };
    WCHAR pwzNewPassword[PASSWORD_LEN + 1] = { 0 };

    if (argc >= 4 && argc <= 5 && _wcsicmp(argv[1], TEXT("/genkey")) == 0)
    {
        pwzPubKeyPath = argv[2];
        pwzPrivKeyPath = argv[3];
        if (argc == 5)
            dwKeyBits = _wtoi(argv[4]);
        if (dwKeyBits == 0 || (dwKeyBits % 8) != 0)
        {
            wprintf(TEXT("Error: invalid key size, must be a multiple of 8 bits\n"));
            return 1;
        }
        res = generateKeyPair(pwzPubKeyPath, pwzPrivKeyPath, dwKeyBits);
    }
    else if (argc >= 5 && argc <= 6 && _wcsicmp(argv[1], TEXT("/randomize")) == 0)
    {
        pwzPubKeyPath = argv[2];
        pwzDBPath = argv[3];
        pwzUsername = argv[4];
        if (argc == 6)
            dwTimeoutSecs = _wtoi(argv[5]);
        if (dwTimeoutSecs == 0)
        {
            wprintf(TEXT("Error: invalid timeout, must be a number of seconds\n"));
            return 1;
        }
        if (_wcsicmp(pwzUsername, TEXT("rid500")) == 0)
        {
            res = getBuiltInAdminLogin(pwzBuiltinAdminLogin, MAXIMUM_ACCOUNT_NAME_LENGTH);
            if (res != 0)
                goto cleanup;
            pwzUsername = pwzBuiltinAdminLogin;
        }
        res = generateSecurePassword(pwzNewPassword, PASSWORD_LEN);
        if (res != 0)
            goto cleanup;
        res = encryptPassword(pwzNewPassword, pwzPubKeyPath, &pzEncryptedPwd);
        if (res != 0)
            goto cleanup;
        res = writeToDB(pwzUsername, pzEncryptedPwd, pwzDBPath, dwTimeoutSecs);
        if (res != 0)
            goto cleanup;
        USER_INFO_1003 newInfo = { 0 };
        newInfo.usri1003_password = pwzNewPassword;
        res = NetUserSetInfo(TEXT(""), pwzUsername, 1003, (LPBYTE)&newInfo, NULL);
        if (res != 0)
        {
            wprintf(TEXT(" [!] Error: unable to set %s password (code %d)\n"), pwzUsername, res);
            goto cleanup;
        }
        wprintf(TEXT(" [+] Successfully set %s password\n"), pwzUsername);
    }
    else if (argc >= 4 && argc <= 5 && _wcsicmp(argv[1], TEXT("/decrypt")) == 0)
    {
        pwzPrivKeyPath = argv[2];
        pwzDBPath = argv[3];
        if (argc == 5)
        {
            pwzHostname = argv[4];
            WCHAR *separator = wcsstr(pwzHostname, TEXT("\\"));
            if (separator != NULL)
            {
                pwzUsername = separator + 1;
                *separator = TEXT('\0');
            }
        }
        res = decryptFromDB(pwzDBPath, pwzPrivKeyPath, pwzHostname, pwzUsername);
    }
    else
    {
        print_usage();
        return 1;
    }

cleanup:
    return res;
}
