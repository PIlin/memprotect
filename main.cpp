#include "memprotect.h"

#define  _CRT_SECURE_NO_WARNINGS


#include <cstdint>
#include <cstdio>

#include <array>
#include <thread>

#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>




void Test(void* p)
{
	auto* a = reinterpret_cast<uint32_t*>(p);
	a[0] = 42;

	for (int i = 0; i < 5; ++i)
	{
		::printf("&a[%d] = %p\n", i, a + i);
	}


	::printf("------------ stage 0 - tid %d\n", GetCurrentThreadId());
	a[0] = 0;
	a[1] = 1;
	a[2] = 2;
	a[3] = 3;
	a[4] = 4;

	memprotect::ProtectAddress(&a[3]);


	::printf("------------ stage 1 - tid %d\n", GetCurrentThreadId());
	a[0] = 10;
	a[1] = 11;
	a[2] = 12;
	a[3] = 13;
	a[4] = 14;

	memprotect::ProtectAddress(&a[1]);

	::printf("------------ stage 2 - tid %d\n", GetCurrentThreadId());
	a[0] = 20;
	a[1] = 21;
	a[2] = 22;
	a[3] = 23;
	a[4] = 24;


	memprotect::UnprotectAddress(&a[3]);

	::printf("------------ stage 3 - tid %d\n", GetCurrentThreadId());
	a[0] = 30;
	a[1] = 31;
	a[2] = 32;
	a[3] = 33;
	a[4] = 34;

	memprotect::UnprotectAddress(&a[1]);

	::printf("------------ stage 4 - tid %d\n", GetCurrentThreadId());
	a[0] = 40;
	a[1] = 41;
	a[2] = 42;
	a[3] = 43;
	a[4] = 44;
}


void TestWithOwnMem()
{
	void* p = VirtualAlloc(nullptr, 16, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	Test(p);
	VirtualFree(p, 0, MEM_RELEASE);
}

void TestMultipleThreadsOwnMem()
{
	std::array<std::thread, 16> threads;
	for (std::thread& t : threads)
		t = std::thread(&TestWithOwnMem);

	for (std::thread& t : threads)
		t.join();
}

void TestMultipleThreadsSharedPage()
{
	void* p = VirtualAlloc(nullptr, 16, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	std::array<std::thread, 16> threads;

	char* a = (char*)p;
	for (std::thread& t : threads)
	{
		t = std::thread(&Test, a);
		a += 64;
	}
	for (std::thread& t : threads)
		t.join();
	VirtualFree(p, 0, MEM_RELEASE);
}


int main()
{
	memprotect::Init();

	//TestWithOwnMem();
	//TestMultipleThreadsOwnMem();
	TestMultipleThreadsSharedPage();


	memprotect::Shutdown();
}

