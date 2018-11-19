#include "memprotect.h"

#include <cstdint>
#include <cstdio>

#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

int main()
{
	memprotect::Init();

	//void* p = VirtualAlloc(nullptr, 4096, MEM_RESERVE, PAGE_READWRITE);
	void* p = VirtualAlloc(nullptr, 16, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	auto* a = reinterpret_cast<uint32_t*>(p);
	a[0] = 42;

	MEMORY_BASIC_INFORMATION mbi;
	VirtualQuery(p, &mbi, sizeof(mbi));





	//uint8_t* psa = MemToShadow(p);
	//psa[0] = 5;

	//DWORD oldProtect = 0;
	//BOOL res = VirtualProtect(p, 4096, PAGE_READONLY, &oldProtect);

	//uint32_t x = a[0];
	//a[1] = 29;

	for (int i = 0; i < 5; ++i)
	{
		::printf("&a[%d] = %p\n", i, a + i);
	}


	::printf("------------ stage 0\n");
	a[0] = 0;
	a[1] = 1;
	a[2] = 2;
	a[3] = 3;
	a[4] = 4;

	memprotect::ProtectAddress(&a[3]);

	::printf("------------ stage 1\n");
	a[0] = 10;
	a[1] = 11;
	a[2] = 12;
	a[3] = 13;
	a[4] = 14;

	memprotect::ProtectAddress(&a[1]);

	::printf("------------ stage 2\n");
	a[0] = 20;
	a[1] = 21;
	a[2] = 22;
	a[3] = 23;
	a[4] = 24;


	memprotect::UnprotectAddress(&a[3]);

	::printf("------------ stage 3\n");
	a[0] = 30;
	a[1] = 31;
	a[2] = 32;
	a[3] = 33;
	a[4] = 34;

	memprotect::UnprotectAddress(&a[1]);

	::printf("------------ stage 4\n");
	a[0] = 40;
	a[1] = 41;
	a[2] = 42;
	a[3] = 43;
	a[4] = 44;

	::printf("Hello World!\n");

	memprotect::Shutdown();
}

