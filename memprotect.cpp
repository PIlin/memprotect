#include <iostream>

#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

using uptr = uintptr_t;
using u64 = uint64_t;



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

uptr FindAvailableMemoryRange(uptr size, uptr alignment, uptr left_padding) 
{
	uptr address = 0;
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

static inline uptr MemToShadow(uptr a) { return MEM_TO_SHADOW(a); }
static inline uptr MemToShadow(void* a) { return MemToShadow((uptr)a); }


LONG WINAPI ExceptionHandler(EXCEPTION_POINTERS* pExceptionInfo)
{
	const EXCEPTION_RECORD& rec = *pExceptionInfo->ExceptionRecord;
	if (rec.ExceptionCode != EXCEPTION_ACCESS_VIOLATION)
		return EXCEPTION_CONTINUE_SEARCH;

	const uptr op = rec.ExceptionInformation[0];
	const uptr addr = (uptr)rec.ExceptionInformation[1];

	if (!AddrIsInShadow(addr)) 
		return EXCEPTION_CONTINUE_SEARCH;

	uptr pageSize = GetPageSizeCached();
	uptr page = RoundDownTo(addr, pageSize);

	uptr result = (uptr)VirtualAlloc((LPVOID)page, pageSize, MEM_COMMIT, PAGE_READWRITE);
	if (result != page)
		return EXCEPTION_CONTINUE_SEARCH;
	return EXCEPTION_CONTINUE_EXECUTION;
}

int main()
{
	InitializeHighMemEnd();
	InitializeShadowMemory();

	AddVectoredExceptionHandler(TRUE, ExceptionHandler);



	//void* p = VirtualAlloc(nullptr, 4096, MEM_RESERVE, PAGE_READWRITE);
	void* p = VirtualAlloc(nullptr, 16, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	uint32_t* a = reinterpret_cast<uint32_t*>(p);
	a[0] = 42;

	MEMORY_BASIC_INFORMATION mbi;
	VirtualQuery(p, &mbi, sizeof(mbi));


	uptr sa = MemToShadow(p);
	uint8_t* psa = reinterpret_cast<uint8_t*>(sa);
	psa[0] = 5;

	DWORD oldProtect = 0;
	BOOL res = VirtualProtect(p, 4096, PAGE_READONLY, &oldProtect);

	uint32_t x = a[0];
	a[1] = 29;



    std::cout << "Hello World!\n"; 
}

