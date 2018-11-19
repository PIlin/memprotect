#pragma once

namespace memprotect
{
	void Init();
	void Shutdown();

	bool ProtectAddress(void* p);
	bool UnprotectAddress(void* p);

} // namespace memprotect
