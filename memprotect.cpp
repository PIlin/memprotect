#include <cassert>
#include <iostream>
#include <atomic>

#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>


#if 0
#define NODISCARD [[nodiscard]]
#else
#define NODISCARD
#endif

#define NOINLINE __declspec(noinline)

namespace memprotect 
{

using uptr = uintptr_t;
using u64 = uint64_t;
using u32 = uint32_t;
using u16 = uint16_t;
using u8 = uint8_t;


static const u64 kMemBytesInShadowBitScale = 2; // 2^3=8 bytes, 2^2=4 bytes
static const u64 kDefaultShadowScale = 3 + kMemBytesInShadowBitScale;
static const u64 kDefaultShadowSentinel = ~(uptr)0;
static const u64 kDefaultShadowOffset64 = 1ULL << 44;

static HANDLE g_ExceptionHandlerHandle;


uptr __asan_shadow_memory_dynamic_address = kDefaultShadowSentinel;
uptr kHighMemBeg, kHighMemEnd/*, kMidMemBeg, kMidMemEnd*/;
uptr kProtectedShadowGapBeg, kProtectedShadowGapSize;
uptr kPageSizeCached;

#define SHADOW_SCALE kDefaultShadowScale
#define SHADOW_OFFSET __asan_shadow_memory_dynamic_address

#define SHADOW_GRANULARITY (1ULL << SHADOW_SCALE)
#define MEM_TO_SHADOW(mem) (((mem) >> SHADOW_SCALE) + (SHADOW_OFFSET))

#define kLowMemBeg      0
#define kLowMemEnd      (SHADOW_OFFSET ? SHADOW_OFFSET - 1 : 0)

//#define kHighMemBeg     (MEM_TO_SHADOW(kHighMemEnd) + 1)

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

union TPageInfo
{
	using Base = u16;
	struct SInfo
	{
		Base counter : 15;
		Base lock : 1;
	};

	SInfo info;
	Base data;
};

//using TPageInfo = u16;
static const u64 kPageInfoRecordSize = sizeof(TPageInfo);
uptr kPageInfoScale = kDefaultShadowSentinel;
uptr __asan_page_info_memory_dynamic_address = kDefaultShadowSentinel;
#define PAGEINFO_OFFSET __asan_page_info_memory_dynamic_address
#define PAGEADDR_TO_PAGEINFO(mem) (((mem) / kPageInfoScale) + (PAGEINFO_OFFSET))
#define MEM_TO_PAGEINFO(mem) PAGEADDR_TO_PAGEINFO(RoundDownTo((mem), kPageSizeCached))

#define kPageInfoBeg  PAGEINFO_OFFSET
#define kPageInfoEnd  (MEM_TO_PAGEINFO(kHighMemEnd) + (kPageInfoRecordSize - 1))


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
	::printf("|| `[%p, %p]` || ShadowGapPr||\n",
		(void*)kProtectedShadowGapBeg, (void*)(kProtectedShadowGapBeg + kProtectedShadowGapSize - 1));
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
	::printf("page size: %zd\n", GetPageSizeCached());
}

static void InitializeHighMemEnd() {
	kHighMemEnd = GetMaxUserVirtualAddress();
	// Increase kHighMemEnd to make sure it's properly
	// aligned together with kHighMemBeg:
	kHighMemEnd |= SHADOW_GRANULARITY * GetMmapGranularity() - 1;
}

void* MmapFixedNoAccess(uptr fixed_addr, uptr size, const char *name) {
	(void)name; // unsupported
	//::printf("MmapFixedNoAccess VirtualAlloc %s RESERVE %p %zu", name, (void*)fixed_addr, size);
	void *res = VirtualAlloc((LPVOID)fixed_addr, size, MEM_RESERVE, PAGE_NOACCESS);
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
	//::printf("MmapFixedNoReserve VirtualAlloc %s RESERVE %p %zu\n", name, (void*)fixed_addr, size);
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

void MmapFixedRelease(uptr addr, uptr size, const char* name)
{
	//::printf("MmapFixedRelease VirtualAlloc %s RELEASE %p %zu\n", name, (void*)addr, size);
	BOOL res = VirtualFree((LPVOID)addr, 0, MEM_RELEASE);
	if (res == 0)
	{
		Report("Failed to release %p (error code: %d)\n", (void*)addr, GetLastError());
	}
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

void ReleaseShadowMemoryRange(uptr beg, uptr end, const char* name)
{
	const uptr size = end - beg + 1;
	MmapFixedRelease(beg, size, name);
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

	const uptr mmapGranularity = GetMmapGranularity();

	if (kLowShadowBeg) shadow_start -= mmapGranularity;

	kHighMemBeg = (MEM_TO_SHADOW(kHighMemEnd) + 1) + mmapGranularity;
	kHighMemBeg &= ~(mmapGranularity * SHADOW_GRANULARITY - 1);

	if (!full_shadow_is_available)
		full_shadow_is_available =
		MemoryRangeIsAvailable(shadow_start, kHighShadowEnd);

	kProtectedShadowGapBeg = RoundUpTo(kShadowGapBeg, mmapGranularity);
	kProtectedShadowGapSize = RoundDownTo(kShadowGapEnd - kShadowGapBeg + 1, mmapGranularity);

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
		ProtectGap(kProtectedShadowGapBeg, kProtectedShadowGapSize);
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

void ShutdownShadowMemory()
{
	ReleaseShadowMemoryRange(kProtectedShadowGapBeg, kProtectedShadowGapBeg + kProtectedShadowGapSize - 1, "shadow gap");
	ReleaseShadowMemoryRange(kHighShadowBeg, kHighShadowEnd, "high shadow");
	if (kLowShadowBeg)
		ReleaseShadowMemoryRange(kLowShadowBeg - GetMmapGranularity(), kLowShadowEnd, "low shadow");

	__asan_shadow_memory_dynamic_address = kDefaultShadowSentinel;
}

uptr FindDynamicPageInfoStart()
{
	uptr granularity = GetMmapGranularity();
	uptr alignment = 8 * granularity;
	uptr left_padding = granularity;
	uptr end = kPageInfoEnd;
	uptr space_size = end + left_padding;
	uptr pageinfo_start = FindAvailableMemoryRange(space_size, alignment, granularity);
	return pageinfo_start;
}

void PrintAddressSpacePageInfoLayout() {
	::printf("|| `[%p, %p]` || PageInfo   ||\n",
		(void*)kPageInfoBeg, (void*)kPageInfoEnd);
}


void InitializePageInfoMemory()
{
	kPageInfoScale = GetPageSizeCached() / kPageInfoRecordSize;


	__asan_page_info_memory_dynamic_address = 0;
	uptr pageinfo_start = FindDynamicPageInfoStart();
	__asan_page_info_memory_dynamic_address = pageinfo_start;

	bool fullRangeIsAvailable = false;
	if (!fullRangeIsAvailable)
		fullRangeIsAvailable =
		MemoryRangeIsAvailable(pageinfo_start, kPageInfoEnd);

	PrintAddressSpacePageInfoLayout();

	assert(pageinfo_start == kPageInfoBeg);

	if (fullRangeIsAvailable) 
	{
		ReserveShadowMemoryRange(pageinfo_start, kPageInfoEnd, "page info");
	}
	else 
	{
		Report(
			"Page info mapping interleaves with an existing memory mapping. "
			"ASan cannot proceed correctly. ABORTING.\n");
		Report("ASan page info was supposed to be located in the [%p-%p] range.\n",
			pageinfo_start, kPageInfoEnd);
		::abort();
	}
}

void ShutdownPageInfoMemory()
{
	ReleaseShadowMemoryRange(kPageInfoBeg, kPageInfoEnd, "page info");
	__asan_page_info_memory_dynamic_address = kDefaultShadowSentinel;
}

static inline bool AddrIsInLowShadow(uptr a) { return a >= kLowShadowBeg && a <= kLowShadowEnd; }
static inline bool AddrIsInHighShadow(uptr a) { return a >= kHighShadowBeg && a <= kHighMemEnd; }
static inline bool AddrIsInShadow(uptr a) { return AddrIsInLowShadow(a) || AddrIsInHighShadow(a); }

static inline bool AddrIsInPageInfo(uptr a) { return kPageInfoBeg <= a && a <= kPageInfoEnd; }

static inline u8* MemToShadow(uptr a) { return (u8*)MEM_TO_SHADOW(a); }
static inline u8* MemToShadow(void* a) { return MemToShadow((uptr)a); }

static inline TPageInfo* MemToPageInfo(uptr a) { return (TPageInfo*)MEM_TO_PAGEINFO(a); }
static inline TPageInfo* MemToPageInfo(void* a) { return MemToPageInfo((uptr)a); }

static inline TPageInfo* PageToPageInfo(uptr a) { return (TPageInfo*)PAGEADDR_TO_PAGEINFO(a); }
static inline TPageInfo* PageToPageInfo(void* a) { return PageToPageInfo((uptr)a); }


static inline u8 AddrToShadowBitIndex(uptr addr)
{
	addr >>= kMemBytesInShadowBitScale;
	uptr mask = ((1ull << 3) - 1ull);
	return u8(addr & mask);
}

static inline u8 AddrToShadowBitMask(uptr addr) { return 1 << AddrToShadowBitIndex(addr); }
static inline u8 AddrToShadowBitMask(void* addr) { return AddrToShadowBitMask((uptr)addr); }

static inline bool IsMemProtected(u8 shadowByte, u8 bitMask) { return (shadowByte & bitMask) != 0; }
NODISCARD static inline u8 SetMemProtected(u8 shadowByte, u8 bitMask) { return (shadowByte | bitMask); }
NODISCARD static inline u8 ResetMemProtected(u8 shadowByte, u8 bitMask){ return (shadowByte & (~bitMask)); }


NODISCARD NOINLINE static TPageInfo LockPageInfo(TPageInfo* pPageInfo)
{
	std::atomic<TPageInfo>* ptr = reinterpret_cast<std::atomic<TPageInfo>*>(pPageInfo);

	TPageInfo expected, locked;

	// https://software.intel.com/sites/default/files/managed/9e/bc/64-ia-32-architectures-optimization-manual.pdf
	// Example 2-4.  Contended Locks with Increasing Back-off Example

	int mask = 1;
	int const max = 64; //MAX_BACKOFF

	do
	{
		while (true)
		{
			expected = ptr->load(std::memory_order_relaxed);
			if (expected.info.lock == 0)
				break;

			for (int i = mask; i; --i)
			{
				_mm_pause();
			}
			mask = mask < max ? mask << 1 : max;    // mask <<= 1  up to a max
		}

		locked = expected;
		locked.info.lock = 1;
	} while (!ptr->compare_exchange_weak(expected, locked, std::memory_order_acquire, std::memory_order_relaxed));

	return locked;
}

static void UnlockPageInfo(TPageInfo* pPageInfo, TPageInfo newValue)
{
	assert(newValue.info.lock != 0);

	std::atomic<TPageInfo>* ptr = reinterpret_cast<std::atomic<TPageInfo>*>(pPageInfo);
	TPageInfo unlocked = newValue;
	unlocked.info.lock = 0;

	//ptr->exchange(unlock)
	ptr->store(unlocked, std::memory_order_release);
}

//struct SLockPageInfoScope
//{
//	TPageInfo* pPageInfo;
//	SLockPageInfoScope(TPageInfo* pPageInfo)
//		: pPageInfo(pPageInfo)
//	{
//		LockPageInfo(pPageInfo);
//	}
//
//	~SLockPageInfoScope()
//	{
//		UnlockPageInfo(pPageInfo);
//	}
//};

struct SGuardProcessingState
{
	enum class EState { None, TemporaryUnprotected };
	EState state = EState::None;
	void* page = nullptr;
	TPageInfo pi;
};

static thread_local SGuardProcessingState guardProcessingState;

LONG WINAPI ExceptionHandlerWithStep(EXCEPTION_POINTERS* pExceptionInfo)
{
	const EXCEPTION_RECORD& rec = *pExceptionInfo->ExceptionRecord;
	if (rec.ExceptionCode == EXCEPTION_ACCESS_VIOLATION)
	{
		const uptr addr = (uptr)rec.ExceptionInformation[1];

		if (AddrIsInShadow(addr) || AddrIsInPageInfo(addr))
		{
			uptr pageSize = GetPageSizeCached();
			uptr page = RoundDownTo(addr, pageSize);

			uptr result = (uptr)VirtualAlloc((LPVOID)page, pageSize, MEM_COMMIT, PAGE_READWRITE);
			if (result != page)
				return EXCEPTION_CONTINUE_SEARCH;
			return EXCEPTION_CONTINUE_EXECUTION;
		}

		const uptr opWrite = 1;
		const uptr op = rec.ExceptionInformation[0];
		if (op == opWrite)
		{
			auto& state = guardProcessingState;

			//::printf("FAULT %p %d tid %d\n", rec.ExceptionAddress, (int)state.state, GetCurrentThreadId());

			if (state.state != SGuardProcessingState::EState::None)
			{
				Report("Wrong state to process access violation\n");
				::abort();
			}

			const u8 bitMask = AddrToShadowBitMask(addr);
			uint8_t* psa = MemToShadow(addr);
			if (IsMemProtected(psa[0], bitMask))
			{
				//Report("Violation of address write protection %p, ecxeption addr %p\n", addr, rec.ExceptionAddress);
			}

			const uptr pageSize = GetPageSizeCached();
			const uptr page = RoundDownTo(addr, pageSize);

			TPageInfo* pPageInfo = PageToPageInfo(page);
			TPageInfo pi = LockPageInfo(pPageInfo);

			DWORD oldProtect = 0;
			//::printf("-- temp remove protect on page %p\n", (void*)page);
			const BOOL res = VirtualProtect((void*)page, pageSize, PAGE_READWRITE, &oldProtect);
			assert(oldProtect == PAGE_READONLY);
			if (res == 0)
			{
				Report("Unable to remove protection from page %p for address %p: err %d\n", page, addr, GetLastError());
				::abort();
			}

			pExceptionInfo->ContextRecord->EFlags |= 0x100;
			state.state = SGuardProcessingState::EState::TemporaryUnprotected;
			state.page = (void*)page;
			state.pi = pi;
			return EXCEPTION_CONTINUE_EXECUTION;
		}
	}
	else if (rec.ExceptionCode == EXCEPTION_SINGLE_STEP)
	{
		auto& state = guardProcessingState;

		//::printf("STEP  %p %d tid %d\n", rec.ExceptionAddress, (int)state.state, GetCurrentThreadId());

		if (state.state == SGuardProcessingState::EState::TemporaryUnprotected)
		{
			void* page = state.page;
			TPageInfo pi = state.pi;

			state.state = SGuardProcessingState::EState::None;
			state.page = nullptr;

			
			const uptr pageSize = GetPageSizeCached();
			DWORD oldProtect = 0;
			//::printf("-- restore protect on page %p\n", (void*)page);
			const BOOL res = VirtualProtect(page, pageSize, PAGE_READONLY, &oldProtect);
			assert(oldProtect == PAGE_READWRITE);
			if (res == 0)
			{
				Report("Unable to set protection back to page %p\n", page);
				::abort();
			}

			TPageInfo* pPageInfo = PageToPageInfo(page);
			UnlockPageInfo(pPageInfo, pi);

			return EXCEPTION_CONTINUE_EXECUTION;
		}
	}

	return EXCEPTION_CONTINUE_SEARCH;
}



bool ProtectAddress(void* p)
{
	uptr addr = (uptr)p;

	const u8 bitMask = AddrToShadowBitMask(addr);
	u8* psa = MemToShadow(p);

	if (IsMemProtected(psa[0], bitMask))   // may trigger shadow memory allocation
		return true; // already protected

	const uptr pageSize = GetPageSizeCached();
	const uptr page = RoundDownTo(addr, pageSize);

	TPageInfo* pPageInfo = PageToPageInfo(page);
	
	TPageInfo pi = LockPageInfo(pPageInfo);

	bool isPageProtected = (pi.info.counter != 0);
	if (!isPageProtected)
	{
		DWORD oldProtect = 0;
		BOOL res = VirtualProtect((void*)page, pageSize, PAGE_READONLY, &oldProtect);
		if (res != 0)
		{
			isPageProtected = true;
		}
	}
	bool result = false;
	if (isPageProtected)
	{
		psa[0] = SetMemProtected(psa[0], bitMask);
		pi.info.counter += 1;

		result = true;
	}

	UnlockPageInfo(pPageInfo, pi);

	return result;
}

bool UnprotectAddress(void* p)
{
	uptr addr = (uptr)p;

	const u8 bitMask = AddrToShadowBitMask(p);
	uint8_t* psa = MemToShadow(p);
	if (!IsMemProtected(psa[0], bitMask))   // may trigger shadow memory allocation
		return true; // already un-protected

	const uptr pageSize = GetPageSizeCached();
	const uptr page = RoundDownTo(addr, pageSize);
	TPageInfo* pPageInfo = PageToPageInfo(page);

	TPageInfo pi = LockPageInfo(pPageInfo);

	bool isPageProtected = (pi.info.counter != 0);
	if (!isPageProtected)
	{
		Report("PageInfo and shadow info are out of sync");
		::abort();
		return false;
	}

	psa[0] = ResetMemProtected(psa[0], bitMask);
	pi.info.counter -= 1;

	bool result = true;
	if (pi.info.counter == 0)
	{
		DWORD oldProtect = 0;
		BOOL res = VirtualProtect((void*)page, pageSize, PAGE_READWRITE, &oldProtect);
		assert(oldProtect == PAGE_READONLY);
		if (res == 0)
		{
			Report("Unable to remove page protection %d", GetLastError()); 
			result = false;
		}
	}

	UnlockPageInfo(pPageInfo, pi);

	return result;
}


void Tests()
{
	if (GetPageSizeCached() == 4096)
	{
		assert(MemToPageInfo(0ull) == (TPageInfo*)kPageInfoBeg + 0);
		assert(MemToPageInfo(56) == (TPageInfo*)kPageInfoBeg + 0);
		assert(MemToPageInfo(4095) == (TPageInfo*)kPageInfoBeg + 0);
		assert(MemToPageInfo(4097) == (TPageInfo*)kPageInfoBeg + 1);
		assert(MemToPageInfo(0x7FFFFFFFFFFF) == (TPageInfo*)(kPageInfoEnd - 1));
	}

	if (kMemBytesInShadowBitScale == 3)
	{
		assert(AddrToShadowBitIndex(0ull) == 0);
		assert(AddrToShadowBitIndex(7) == 0);
		assert(AddrToShadowBitIndex(8) == 1);
		assert(AddrToShadowBitIndex(17) == 2);
		assert(AddrToShadowBitIndex(63) == 7);
		assert(AddrToShadowBitIndex(65) == 0);
	}
	else if (kMemBytesInShadowBitScale == 2)
	{
		assert(AddrToShadowBitIndex(0ull) == 0);
		assert(AddrToShadowBitIndex(3) == 0);
		assert(AddrToShadowBitIndex(4) == 1);
		assert(AddrToShadowBitIndex(9) == 2);
		assert(AddrToShadowBitIndex(31) == 7);
		assert(AddrToShadowBitIndex(32) == 0);
	}
}


void Init()
{
	InitializeHighMemEnd();
	InitializeShadowMemory();
	InitializePageInfoMemory();
	
	Tests();

	g_ExceptionHandlerHandle = AddVectoredExceptionHandler(TRUE, ExceptionHandlerWithStep);
}


void Shutdown()
{
	RemoveVectoredExceptionHandler(g_ExceptionHandlerHandle);
	ShutdownPageInfoMemory();
	ShutdownShadowMemory();
}


} // namespace memprotect

