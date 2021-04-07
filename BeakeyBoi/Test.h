#pragma once

#include <Windows.h>
#include <bcrypt.h>
#include <cwchar>

#include "Dll.h"

inline VOID
Mcpy(PBYTE src, PBYTE dst, SIZE_T size) {
	for (int i = 0; i < size; dst[i++] = src[i]);
}

#define NT_SUCCESS(Status)          (((NTSTATUS)(Status)) >= 0)
#define STATUS_UNSUCCESSFUL         ((NTSTATUS)0xC0000001L)

inline VOID
TestDecryption(PBYTE pbCipherDll, SIZE_T cbCipherDll, PBYTE rgbDllAES128Key, PBYTE rgbDllIV)
{
	NTSTATUS			status = STATUS_UNSUCCESSFUL;
	BYTE				rgbTestAES128Key[16] = {};
	BYTE				rgbTestIV[16] = {};
	BCRYPT_HANDLE		hTestAesAlg = nullptr;
	DWORD				cbTestData = 0;
	PBYTE				pbTestKeyObject = nullptr;
	DWORD				cbTestBlockLen = 0;
	PBYTE				pbTestIV = nullptr;
	BCRYPT_KEY_HANDLE	hTestKey = nullptr;
	DWORD				cbTestKeyObject = 0;
	DWORD				cbTestRawData = 0;
	PBYTE				pbTestRawData = nullptr;

	Mcpy(pbCipherDll, rgbTestAES128Key, 16);
	Mcpy(&pbCipherDll[16], rgbTestIV, 16);

	wprintf(L"[+] Dumping dll recovered creds\n");
	HexDump(rgbTestAES128Key, sizeof(rgbTestAES128Key));
	HexDump(rgbTestIV, sizeof(rgbTestIV));

	if (memcmp(rgbTestAES128Key, rgbDllAES128Key, sizeof(rgbTestAES128Key)) == 0)
		wprintf(L"[+] Key test passed\n");
	else
		wprintf(L"[-] Key test failed\n");

	if (memcmp(rgbTestIV, rgbDllIV, sizeof(rgbTestIV)) == 0)
		wprintf(L"[+] IV test passed\n");
	else
		wprintf(L"[-] IV test failed\n");

	// Open an algorithm handle.
	if (!NT_SUCCESS(status = BCryptOpenAlgorithmProvider(
		&hTestAesAlg,
		BCRYPT_AES_ALGORITHM,
		nullptr,
		0)))
	{
		goto Cleanup;
	}

	// Calculate the size of the buffer to hold the KeyObject.
	if (!NT_SUCCESS(status = BCryptGetProperty(
		hTestAesAlg,
		BCRYPT_OBJECT_LENGTH,
		(PBYTE)&cbTestKeyObject,
		sizeof(DWORD),
		&cbTestData,
		0)))
	{
		goto Cleanup;
	}

	// Allocate the key object on the heap.
	pbTestKeyObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbTestKeyObject);

	// Calculate the block length for the IV.
	if (!NT_SUCCESS(status = BCryptGetProperty(
		hTestAesAlg,
		BCRYPT_BLOCK_LENGTH,
		(PBYTE)&cbTestBlockLen,
		sizeof(DWORD),
		&cbTestData,
		0)))
	{
		goto Cleanup;
	}

	// Calculate the block length for the IV.
	if (!NT_SUCCESS(status = BCryptGetProperty(
		hTestAesAlg,
		BCRYPT_BLOCK_LENGTH,
		(PBYTE)&cbTestBlockLen,
		sizeof(DWORD),
		&cbTestData,
		0)))
	{
		goto Cleanup;
	}
	
	// Allocate a buffer for the IV. The buffer is consumed during the 
	// encrypt/decrypt process.
	pbTestIV = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbTestBlockLen);

	Mcpy(rgbTestIV, pbTestIV, 16);

	if (!NT_SUCCESS(status = BCryptSetProperty(
		hTestAesAlg,
		BCRYPT_CHAINING_MODE,
		(PBYTE)BCRYPT_CHAIN_MODE_CBC,
		sizeof(BCRYPT_CHAIN_MODE_CBC),
		0)))
	{
		goto Cleanup;
	}

	// Generate the key from supplied input key bytes.
	if (!NT_SUCCESS(status = BCryptGenerateSymmetricKey(
		hTestAesAlg,
		&hTestKey,
		pbTestKeyObject,
		cbTestKeyObject,
		(PBYTE)rgbTestAES128Key,
		sizeof(rgbTestAES128Key),
		0)))
	{
		goto Cleanup;
	}
	
	// Get the output buffer size.
	if (!NT_SUCCESS(status = BCryptDecrypt(
		hTestKey,
		&pbCipherDll[32],
		cbCipherDll,
		nullptr,
		pbTestIV,
		cbTestBlockLen,
		nullptr,
		0,
		&cbTestRawData,
		BCRYPT_BLOCK_PADDING)))
	{
		goto Cleanup;
	}

	pbTestRawData = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbTestRawData);

	if (!NT_SUCCESS(status = BCryptDecrypt(
		hTestKey,
		&pbCipherDll[32],
		cbCipherDll,
		nullptr,
		pbTestIV,
		cbTestBlockLen,
		pbTestRawData,
		cbTestRawData,
		&cbTestRawData,
		BCRYPT_BLOCK_PADDING)))
	{
		goto Cleanup;
	}

	// Compare decrypted with original
	if (memcmp(rgbRawDll, pbTestRawData, sizeof(rgbRawDll)) == 0)
		wprintf(L"[+] Dll decryption test passed\n");
	else
		wprintf(L"[-] Dll decryption test failed\n");

Cleanup:

	if (hTestAesAlg)
		BCryptCloseAlgorithmProvider(hTestAesAlg, 0);

	if (hTestKey)
		BCryptDestroyKey(hTestKey);

	if (pbTestRawData)
		HeapFree(GetProcessHeap(), 0, pbTestRawData);

	if (pbTestKeyObject)
		HeapFree(GetProcessHeap(), 0, pbTestKeyObject);

	if (pbTestIV)
		HeapFree(GetProcessHeap(), 0, pbTestIV);
}