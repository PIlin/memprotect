#include "memprotect.h"

#define  _CRT_SECURE_NO_WARNINGS

#include <cassert>
#include <cstdint>
#include <cstdio>

#include <array>
#include <thread>
#include <mutex>
#include <condition_variable>

#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>



struct SBarrier
{
	std::mutex mutex;
	std::condition_variable cv;
	std::condition_variable cvProd;
	int counter = 0;

	void Enter()
	{
		std::unique_lock<std::mutex> lock(mutex);
		counter++;
		cvProd.notify_one();
		cv.wait(lock);
	}

	void ProdWait(int target)
	{
		std::unique_lock<std::mutex> lock(mutex);
		cvProd.wait(lock, [&]() { return counter >= target; });
		
		assert(counter == target);
		counter = 0;
		cv.notify_all();
	}
};

void Test(void* p, SBarrier* pb)
{
	SetThreadDescription(GetCurrentThread(), L"Test");

	auto* a = reinterpret_cast<uint32_t*>(p);
	a[0] = 42;

	for (int i = 0; i < 5; ++i)
	{
		::printf("&a[%d] = %p\n", i, a + i);
	}

	if (pb)
	{
		pb->Enter();
	}

	for (int i = 0; i < 1000; ++i)
	{
		//::printf("------------ stage 0 - tid %d\n", GetCurrentThreadId());
		a[0] = 0;
		a[1] = 1;
		a[2] = 2;
		a[3] = 3;
		a[4] = 4;

		memprotect::ProtectAddress(&a[3]);


		//::printf("------------ stage 1 - tid %d\n", GetCurrentThreadId());
		a[0] = 10;
		a[1] = 11;
		a[2] = 12;
		a[3] = 13;
		a[4] = 14;

		memprotect::ProtectAddress(&a[1]);

		//::printf("------------ stage 2 - tid %d\n", GetCurrentThreadId());
		a[0] = 20;
		a[1] = 21;
		a[2] = 22;
		a[3] = 23;
		a[4] = 24;


		memprotect::UnprotectAddress(&a[3]);

		//::printf("------------ stage 3 - tid %d\n", GetCurrentThreadId());
		a[0] = 30;
		a[1] = 31;
		a[2] = 32;
		a[3] = 33;
		a[4] = 34;

		memprotect::UnprotectAddress(&a[1]);

		//::printf("------------ stage 4 - tid %d\n", GetCurrentThreadId());
		a[0] = 40;
		a[1] = 41;
		a[2] = 42;
		a[3] = 43;
		a[4] = 44;
	}
}


void TestWithOwnMem(SBarrier* pb)
{
	void* p = VirtualAlloc(nullptr, 16, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	Test(p, pb);
	VirtualFree(p, 0, MEM_RELEASE);
}

void TestMultipleThreadsOwnMem()
{
	SBarrier bar;
	std::array<std::thread, 16> threads;
	for (std::thread& t : threads)
		t = std::thread(&TestWithOwnMem, &bar);

	bar.ProdWait((int)threads.size());

	for (std::thread& t : threads)
		t.join();
}

void TestMultipleThreadsSharedPage()
{
	void* p = VirtualAlloc(nullptr, 16, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	std::array<std::thread, 16> threads;

	SBarrier bar;

	char* a = (char*)p;
	for (std::thread& t : threads)
	{
		t = std::thread(&Test, a, &bar);
		a += 64;
	}

	bar.ProdWait((int)threads.size());

	for (std::thread& t : threads)
		t.join();
	VirtualFree(p, 0, MEM_RELEASE);
}


int main()
{
	SetThreadDescription(GetCurrentThread(), L"Main");

	memprotect::Init();

	//TestWithOwnMem(nullptr);
	//TestMultipleThreadsOwnMem();
	TestMultipleThreadsSharedPage();


	memprotect::Shutdown();
}

