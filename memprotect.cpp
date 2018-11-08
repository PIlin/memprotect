
#include "X86DisassemblerDecoder.h"

#include <iostream>

#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

using uptr = uintptr_t;
using u64 = uint64_t;
using u32 = uint32_t;
using u8 = uint8_t;



static const u64 kDefaultShadowScale = 3;
static const u64 kDefaultShadowSentinel = ~(uptr)0;
static const u64 kDefaultShadowOffset64 = 1ULL << 44;


uptr __asan_shadow_memory_dynamic_address = kDefaultShadowSentinel;
uptr kHighMemEnd/*, kMidMemBeg, kMidMemEnd*/;
uptr kPageSizeCached;

#define SHADOW_SCALE kDefaultShadowScale
#define SHADOW_OFFSET __asan_shadow_memory_dynamic_address

#define SHADOW_GRANULARITY (1ULL << SHADOW_SCALE)
#define MEM_TO_SHADOW(mem) (((mem) >> SHADOW_SCALE) + (SHADOW_OFFSET))

#define kLowMemBeg      0
#define kLowMemEnd      (SHADOW_OFFSET ? SHADOW_OFFSET - 1 : 0)

#define kHighMemBeg     (MEM_TO_SHADOW(kHighMemEnd) + 1)

#define kLowShadowBeg   SHADOW_OFFSET
#define kLowShadowEnd   MEM_TO_SHADOW(kLowMemEnd)

#define kHighShadowBeg  MEM_TO_SHADOW(kHighMemBeg)
#define kHighShadowEnd  MEM_TO_SHADOW(kHighMemEnd)

//# define kMidShadowBeg MEM_TO_SHADOW(kMidMemBeg)
//# define kMidShadowEnd MEM_TO_SHADOW(kMidMemEnd)

#define kZeroBaseShadowStart 0
#define kZeroBaseMaxShadowStart (1 << 18)
#define kShadowGapBeg   (kLowShadowEnd ? kLowShadowEnd + 1 : kZeroBaseShadowStart)
//#define kShadowGapEnd   ((kMidMemBeg ? kMidShadowBeg : kHighShadowBeg) - 1)
#define kShadowGapEnd   (kHighShadowBeg - 1)


void Report(const char* szFormat, ...)
{
	va_list args;
	va_start(args, szFormat);
	::vprintf(szFormat, args);
	va_end(args);
}

uptr RoundUpTo(uptr size, uptr boundary)
{
	return (size + boundary - 1) & ~(boundary - 1);
}

uptr RoundDownTo(uptr x, uptr boundary) {
	return x & ~(boundary - 1);
}


uptr GetPageSize() {
	SYSTEM_INFO si;
	GetSystemInfo(&si);
	return si.dwPageSize;
}


uptr GetMmapGranularity() 
{
	SYSTEM_INFO si;
	GetSystemInfo(&si);
	return si.dwAllocationGranularity;
}

uptr GetMaxUserVirtualAddress() {
	SYSTEM_INFO si;
	GetSystemInfo(&si);
	return (uptr)si.lpMaximumApplicationAddress;
}

uptr GetPageSize();

uptr GetPageSizeCached() {
	return kPageSizeCached;
}


bool MemoryRangeIsAvailable(uptr range_start, uptr range_end) 
{
	MEMORY_BASIC_INFORMATION mbi;
	VirtualQuery((void*)range_start, &mbi, sizeof(mbi));
	return mbi.Protect == PAGE_NOACCESS && (uptr)mbi.BaseAddress + mbi.RegionSize >= range_end;
}

uptr FindAvailableMemoryRange(uptr size, uptr alignment, uptr left_padding, uptr address = 0) 
{
	while (true) {
		MEMORY_BASIC_INFORMATION info;
		if (!::VirtualQuery((void*)address, &info, sizeof(info)))
			return 0;

		if (info.State == MEM_FREE) {
			uptr shadow_address = RoundUpTo((uptr)info.BaseAddress + left_padding, alignment);
			if (shadow_address + size < (uptr)info.BaseAddress + info.RegionSize)
				return shadow_address;
		}

		// Move to the next region.
		address = (uptr)info.BaseAddress + info.RegionSize;
	}
	return 0;
}

uptr FindDynamicShadowStart() 
{
	uptr granularity = GetMmapGranularity();
	uptr alignment = 8 * granularity;
	uptr left_padding = granularity;
	uptr space_size = kHighShadowEnd + left_padding;
	uptr shadow_start = FindAvailableMemoryRange(space_size, alignment, granularity);
	return shadow_start;
}

void PrintAddressSpaceLayout() {
	::printf("|| `[%p, %p]` || HighMem    ||\n",
		(void*)kHighMemBeg, (void*)kHighMemEnd);
	::printf("|| `[%p, %p]` || HighShadow ||\n",
		(void*)kHighShadowBeg, (void*)kHighShadowEnd);
	//if (kMidMemBeg) {
	//	//::printf("|| `[%p, %p]` || ShadowGap3 ||\n",
	//	//	(void*)kShadowGap3Beg, (void*)kShadowGap3End);
	//	::printf("|| `[%p, %p]` || MidMem     ||\n",
	//		(void*)kMidMemBeg, (void*)kMidMemEnd);
	//	//::printf("|| `[%p, %p]` || ShadowGap2 ||\n",
	//	//	(void*)kShadowGap2Beg, (void*)kShadowGap2End);
	//	::printf("|| `[%p, %p]` || MidShadow  ||\n",
	//		(void*)kMidShadowBeg, (void*)kMidShadowEnd);
	//}
	::printf("|| `[%p, %p]` || ShadowGap  ||\n",
		(void*)kShadowGapBeg, (void*)kShadowGapEnd);
	if (kLowShadowBeg) {
		::printf("|| `[%p, %p]` || LowShadow  ||\n",
			(void*)kLowShadowBeg, (void*)kLowShadowEnd);
		::printf("|| `[%p, %p]` || LowMem     ||\n",
			(void*)kLowMemBeg, (void*)kLowMemEnd);
	}
	::printf("MemToShadow(shadow): %p %p %p %p",
		(void*)MEM_TO_SHADOW(kLowShadowBeg),
		(void*)MEM_TO_SHADOW(kLowShadowEnd),
		(void*)MEM_TO_SHADOW(kHighShadowBeg),
		(void*)MEM_TO_SHADOW(kHighShadowEnd));
	//if (kMidMemBeg) {
	//	::printf(" %p %p",
	//		(void*)MEM_TO_SHADOW(kMidShadowBeg),
	//		(void*)MEM_TO_SHADOW(kMidShadowEnd));
	//}
	::printf("\n");
	::printf("SHADOW_SCALE: %d\n", (int)SHADOW_SCALE);
	::printf("SHADOW_GRANULARITY: %d\n", (int)SHADOW_GRANULARITY);
	::printf("SHADOW_OFFSET: 0x%zx\n", (uptr)SHADOW_OFFSET);
}

static void InitializeHighMemEnd() {
	kHighMemEnd = GetMaxUserVirtualAddress();
	// Increase kHighMemEnd to make sure it's properly
	// aligned together with kHighMemBeg:
	kHighMemEnd |= SHADOW_GRANULARITY * GetMmapGranularity() - 1;
}

void* MmapFixedNoAccess(uptr fixed_addr, uptr size, const char *name) {
	(void)name; // unsupported
	void *res = VirtualAlloc((LPVOID)fixed_addr, size,
		MEM_RESERVE, PAGE_NOACCESS);
	if (res == 0)
		Report("WARNING: failed to mprotect %p (%zd) bytes at %p (error code: %d)\n",
			size, size, fixed_addr, GetLastError());
	return res;
}


void* MmapFixedNoReserve(uptr fixed_addr, uptr size, const char *name) {
	// FIXME: is this really "NoReserve"? On Win32 this does not matter much,
	// but on Win64 it does.
	(void)name;  // unsupported
#if 1
  // On asan/Windows64, use MEM_COMMIT would result in error
  // 1455:ERROR_COMMITMENT_LIMIT.
  // Asan uses exception handler to commit page on demand.
	void *p = VirtualAlloc((LPVOID)fixed_addr, size, MEM_RESERVE, PAGE_READWRITE);
#else
	void *p = VirtualAlloc((LPVOID)fixed_addr, size, MEM_RESERVE | MEM_COMMIT,
		PAGE_READWRITE);
#endif
	if (p == 0)
		Report("ERROR: failed to allocate %p (%zd) bytes at %p (error code: %d)\n",
			size, size, fixed_addr, GetLastError());
	return p;
}

void ReserveShadowMemoryRange(uptr beg, uptr end, const char *name) {
	uptr size = end - beg + 1;
	//DecreaseTotalMmap(size);  // Don't count the shadow against mmap_limit_mb.
	void *res = MmapFixedNoReserve(beg, size, name);
	if (res != (void *)beg) {
		Report(
			"ReserveShadowMemoryRange failed while trying to map 0x%zx bytes. "
			"Perhaps you're using ulimit -v\n",
			size);
		::abort();
	}
}

static void ProtectGap(uptr addr, uptr size) {
	void *res = MmapFixedNoAccess(addr, size, "shadow gap");
	if (addr == (uptr)res) return;
	// A few pages at the start of the address space can not be protected.
	// But we really want to protect as much as possible, to prevent this memory
	// being returned as a result of a non-FIXED mmap().
	if (addr == kZeroBaseShadowStart) {
		uptr step = GetMmapGranularity();
		while (size > step && addr < kZeroBaseMaxShadowStart) {
			addr += step;
			size -= step;
			void *res = MmapFixedNoAccess(addr, size, "shadow gap");
			if (addr == (uptr)res) return;
		}
	}

	Report(
		"ERROR: Failed to protect the shadow gap. "
		"ASan cannot proceed correctly. ABORTING.\n");
	::abort();
}


void InitializeShadowMemory() 
{
	kPageSizeCached = GetPageSize();

	// Set the shadow memory address to uninitialized.
	__asan_shadow_memory_dynamic_address = kDefaultShadowSentinel;

	uptr shadow_start = kLowShadowBeg;
	// Detect if a dynamic shadow address must used and find a available location
	// when necessary. When dynamic address is used, the macro |kLowShadowBeg|
	// expands to |__asan_shadow_memory_dynamic_address| which is
	// |kDefaultShadowSentinel|.
	bool full_shadow_is_available = false;
	if (shadow_start == kDefaultShadowSentinel) 
	{
		__asan_shadow_memory_dynamic_address = 0;
		//CHECK_EQ(0, kLowShadowBeg);
		shadow_start = FindDynamicShadowStart();
	}
	// Update the shadow memory address (potentially) used by instrumentation.
	__asan_shadow_memory_dynamic_address = shadow_start;

	if (kLowShadowBeg) shadow_start -= GetMmapGranularity();

	if (!full_shadow_is_available)
		full_shadow_is_available =
		MemoryRangeIsAvailable(shadow_start, kHighShadowEnd);

//#if SANITIZER_LINUX && defined(__x86_64__) && defined(_LP64) && \
//    !ASAN_FIXED_MAPPING
//	if (!full_shadow_is_available) {
//		kMidMemBeg = kLowMemEnd < 0x3000000000ULL ? 0x3000000000ULL : 0;
//		kMidMemEnd = kLowMemEnd < 0x3000000000ULL ? 0x4fffffffffULL : 0;
//	}
//#endif

	PrintAddressSpaceLayout();

	if (full_shadow_is_available) {
		// mmap the low shadow plus at least one page at the left.
		if (kLowShadowBeg)
			ReserveShadowMemoryRange(shadow_start, kLowShadowEnd, "low shadow");
		// mmap the high shadow.
		ReserveShadowMemoryRange(kHighShadowBeg, kHighShadowEnd, "high shadow");
		// protect the gap.
		ProtectGap(kShadowGapBeg, kShadowGapEnd - kShadowGapBeg + 1);
		//CHECK_EQ(kShadowGapEnd, kHighShadowBeg - 1);
	}
	//else if (kMidMemBeg &&
	//	MemoryRangeIsAvailable(shadow_start, kMidMemBeg - 1) &&
	//	MemoryRangeIsAvailable(kMidMemEnd + 1, kHighShadowEnd)) {
	//	//CHECK(kLowShadowBeg != kLowShadowEnd);
	//	// mmap the low shadow plus at least one page at the left.
	//	ReserveShadowMemoryRange(shadow_start, kLowShadowEnd, "low shadow");
	//	// mmap the mid shadow.
	//	ReserveShadowMemoryRange(kMidShadowBeg, kMidShadowEnd, "mid shadow");
	//	// mmap the high shadow.
	//	ReserveShadowMemoryRange(kHighShadowBeg, kHighShadowEnd, "high shadow");
	//	// protect the gaps.
	//	ProtectGap(kShadowGapBeg, kShadowGapEnd - kShadowGapBeg + 1);
	//	//ProtectGap(kShadowGap2Beg, kShadowGap2End - kShadowGap2Beg + 1);
	//	//ProtectGap(kShadowGap3Beg, kShadowGap3End - kShadowGap3Beg + 1);
	//}
	else {
		Report(
			"Shadow memory range interleaves with an existing memory mapping. "
			"ASan cannot proceed correctly. ABORTING.\n");
		Report("ASan shadow was supposed to be located in the [%p-%p] range.\n",
			shadow_start, kHighShadowEnd);
		//MaybeReportLinuxPIEBug();
		//DumpProcessMap();
		///Die();
		::abort();
	}
}

static inline bool AddrIsInLowShadow(uptr a) { return a >= kLowShadowBeg && a <= kLowShadowEnd; }
static inline bool AddrIsInHighShadow(uptr a) { return a >= kHighShadowBeg && a <= kHighMemEnd; }
static inline bool AddrIsInShadow(uptr a) { return AddrIsInLowShadow(a) || AddrIsInHighShadow(a); }

static inline uint8_t* MemToShadow(uptr a) { return (uint8_t*)MEM_TO_SHADOW(a); }
static inline uint8_t* MemToShadow(void* a) { return MemToShadow((uptr)a); }


static int reader(const struct reader_info* info, uint8_t* byte, uint64_t address) 
{
	if (address - info->offset >= info->size)
		// out of buffer range
		return -1;

	*byte = info->code[address - info->offset];

	return 0;
};


static void* s_trampolinePage = nullptr;



static __declspec(noinline) void RestoreGuard(void* addr)
{
	const uptr pageSize = GetPageSizeCached();
	VirtualProtect(addr, pageSize, PAGE_READWRITE | PAGE_GUARD, nullptr);
}

static __declspec(noinline) void VirtualProtectWrapper(void* addr, uptr pageSize)
{
	DWORD oldProtect = 0;
	BOOL res = VirtualProtect(addr, pageSize, PAGE_READWRITE | PAGE_GUARD, &oldProtect);
	if (!res)
		Report("Can't restore protection");
}

void InitTrampoline()
{
	void* p = &VirtualProtectWrapper;

	uptr granularity = GetMmapGranularity();
	uptr alignment = 8 * granularity;

	uptr pageAddr = (uptr)p;
	do {
		pageAddr = FindAvailableMemoryRange(4096, granularity, 0, pageAddr);
		s_trampolinePage = VirtualAlloc((void*)pageAddr, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (s_trampolinePage == nullptr)
		{
			Report("Unable to commit trampoline page %d\n", GetLastError());
		}
	} while (pageAddr != (uptr)s_trampolinePage);
}

#define W(x) *out++ = x
static u8* Write(u8* out, u8 a) { W(a); return out; }
static u8* Write(u8* out, u8 a, u8 b) { W(a); W(b); return out; }
static u8* Write(u8* out, u8 a, u8 b, u8 c) { W(a); W(b); W(c); return out; }
static u8* Write(u8* out, u8 a, u8 b, u8 c, u8 d) { W(a); W(b); W(c); W(d); return out; }
static u8* Write(u8* out, u8 a, u8 b, u8 c, u8 d, u8 e) { W(a); W(b); W(c); W(d); W(e); return out; }
static u8* Write(u8* out, u8 a, u8 b, u8 c, u8 d, u8 e, u8 f) { W(a); W(b); W(c); W(d); W(e); W(f); return out; }
#undef W
static u8* WriteU64(u8* out, u64 val)
{
	::memcpy(out, &val, 8);
	return out + 8;
}
static u8* WriteU32(u8* out, u32 val)
{
	::memcpy(out, &val, 4);
	return out + 4;
}
static u8* WriteMovAbsR8(u8* out, u64 val) { return WriteU64(Write(out, 0x49, 0xb8), val); }
static u8* WriteMovAbsR9(u8* out, u64 val) { return WriteU64(Write(out, 0x49, 0xb9), val); }
static u8* WriteMovAbsRAX(u8* out, u64 val) { return WriteU64(Write(out, 0x48, 0xb8), val); }
static u8* WriteMovAbsRCX(u8* out, u64 val) { return WriteU64(Write(out, 0x48, 0xb9), val); }
static u8* WriteMovAbsRDX(u8* out, u64 val) { return WriteU64(Write(out, 0x48, 0xba), val); }

static u8* WriteMovR8D(u8* out, u32 val) { return WriteU32(Write(out, 0x41, 0xb8), val); }

static u8* WritePushRAX(u8* out) { return Write(out, 0x50); }
static u8* WritePushRCX(u8* out) { return Write(out, 0x51); }
static u8* WritePushRDX(u8* out) { return Write(out, 0x52); }
static u8* WritePushR8(u8* out) { return Write(out, 0x41, 0x50); }
static u8* WritePushR9(u8* out) { return Write(out, 0x41, 0x51); }

static u8* WritePopRAX(u8* out) { return Write(out, 0x58); }
static u8* WritePopRCX(u8* out) { return Write(out, 0x59); }
static u8* WritePopRDX(u8* out) { return Write(out, 0x5a); }
static u8* WritePopR8(u8* out) { return Write(out, 0x41, 0x58); }
static u8* WritePopR9(u8* out) { return Write(out, 0x41, 0x59); }

static u8* WriteXorR9D(u8* out) { return Write(out, 0x45, 0x31, 0xc9); }

template <size_t N>
u8* CopyN(const u8 arr[N], u8* out)
{
	return std::copy(arr, arr + N, out);
}

u8* Copy(const u8* arr, size_t n, u8* out)
{
	return std::copy(arr, arr + n, out);
}

void PrepareTrampoline(PCONTEXT pContext, uptr page, uptr pageSize)
{
	InternalInstruction instruction = {};
	reader_info info;
	u8* pRip = (u8*)pContext->Rip;
	info.code = pRip;
	info.size = 16;
	info.offset = 0;

	if (decodeInstruction(&instruction, reader, &info, 0, MODE_64BIT))
	{
		Report("Can't decode intstruction");
		::abort();
	}
	const size_t instLen = instruction.length;

	u8* p = (u8*)s_trampolinePage;

	p = Copy(pRip, instLen, p); // original op
	
	p = WritePushRDX(p);
	p = WritePushR9(p);
	p = WritePushR8(p);
	p = WritePushRCX(p);
	p = WritePushRAX(p);

	p = WriteMovAbsRCX(p, page);
	p = WriteMovAbsRDX(p, pageSize);
	//p = WriteMovR8D(p, PAGE_READWRITE | PAGE_GUARD);
	//p = WriteXorR9D(p);

	void* vp = &VirtualProtectWrapper;
	int64_t jump = (uptr)vp - ((uptr)p + 5);
	if (abs(jump) < 0x100000000)
	{
		p = Write(p, 0xE8); // call
		p = WriteU32(p, (u32)(int32_t)jump);
	}
	else
	{
		Report("can't construct jump");
		::abort();
	}
	
	p = WritePopRAX(p);
	p = WritePopRCX(p);
	p = WritePopR8(p);
	p = WritePopR9(p);
	p = WritePopRDX(p);

	p = Write(p, 0xff, 0x25, 0x0, 0, 0, 0); // jmp    QWORD PTR [rip+0x0]  
	p = WriteU64(p, (u64)(pRip + instLen));
	p = WriteU64(p, 0x9090909090909090); // nop

	pContext->Rip = (uptr)s_trampolinePage;
}


LONG WINAPI ExceptionHandler(EXCEPTION_POINTERS* pExceptionInfo)
{
	const EXCEPTION_RECORD& rec = *pExceptionInfo->ExceptionRecord;
	if (rec.ExceptionCode != EXCEPTION_ACCESS_VIOLATION && rec.ExceptionCode != EXCEPTION_GUARD_PAGE)
		return EXCEPTION_CONTINUE_SEARCH;

	const uptr addr = (uptr)rec.ExceptionInformation[1];

	if (rec.ExceptionCode == EXCEPTION_ACCESS_VIOLATION)
	{
		if (AddrIsInShadow(addr))
		{
			uptr pageSize = GetPageSizeCached();
			uptr page = RoundDownTo(addr, pageSize);

			uptr result = (uptr)VirtualAlloc((LPVOID)page, pageSize, MEM_COMMIT, PAGE_READWRITE);
			if (result != page)
				return EXCEPTION_CONTINUE_SEARCH;
			return EXCEPTION_CONTINUE_EXECUTION;
		}
	}

	const uptr opWrite = 1;
	const uptr op = rec.ExceptionInformation[0];
	if (op == opWrite)
	{
		uint8_t* psa = MemToShadow(addr);
		if (psa[0] > 0)
		{
			Report("Violation of address write protection %p, resetting protection\n", addr);
			psa[0] = 0;
		}

		uptr pageSize = GetPageSizeCached();
		uptr page = RoundDownTo(addr, pageSize);
		PrepareTrampoline(pExceptionInfo->ContextRecord, page, pageSize);
		return EXCEPTION_CONTINUE_EXECUTION;
	}

	return EXCEPTION_CONTINUE_SEARCH;
}


void __declspec(noinline)  ProtectAddress(void* p)
{
	uptr addr = (uptr)p;
	uint8_t* psa = MemToShadow(p);
	if (psa[0] > 0)   // may trigger shadow memory allocation
		return; // already protected

	const uptr pageSize = GetPageSizeCached();
	uptr page = RoundDownTo(addr, pageSize);

	DWORD oldProtect = 0;
	//RestoreGuard((void*)page);
	BOOL res = VirtualProtect((void*)page, pageSize, PAGE_READWRITE | PAGE_GUARD, &oldProtect);
	if (res != 0)
	{
		psa[0] = 1;
	}
}

void __declspec(noinline)  UnprotectAddress(void* p)
{
	uint8_t* psa = MemToShadow(p);
	if (psa[0] == 0)   // may trigger shadow memory allocation
		return; // already un-protected

	psa[0] = 0;

	// todo: unprotect page
}


int main()
{
	InitializeHighMemEnd();
	InitializeShadowMemory();
	InitTrampoline();

	AddVectoredExceptionHandler(TRUE, ExceptionHandler);

	//void* p = VirtualAlloc(nullptr, 4096, MEM_RESERVE, PAGE_READWRITE);
	void* p = VirtualAlloc(nullptr, 16, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	uint64_t* a = reinterpret_cast<uint64_t*>(p);
	a[0] = 42;

	MEMORY_BASIC_INFORMATION mbi;
	VirtualQuery(p, &mbi, sizeof(mbi));


	//uint8_t* psa = MemToShadow(p);
	//psa[0] = 5;

	//DWORD oldProtect = 0;
	//BOOL res = VirtualProtect(p, 4096, PAGE_READONLY, &oldProtect);

	//uint32_t x = a[0];
	//a[1] = 29;

	a[0] = 0;
	a[1] = 1;
	a[2] = 2;
	a[3] = 3;
	a[4] = 4;

	ProtectAddress(&a[3]);

	a[0] = 10;
	a[1] = 11;
	a[2] = 12;
	a[3] = 13;
	a[4] = 14;

	ProtectAddress(&a[2]);

	a[0] = 20;
	a[1] = 21;
	a[2] = 22;
	//a[3] = 23;
	a[4] = 24;

	//UnprotectAddress(&a[3]);

	a[3] = 23;

    std::cout << "Hello World!\n"; 
}

