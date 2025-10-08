#include "pch.h"
#include <process.h>
#include <windows.h>
#include <array>
#include <string>
#include <atomic>

/*
* One of the difficulties of inline hooking is that we need to determine how many bytes to overwrite at the target function.
* When I researched this topic, I have seen some articles hardcoding the number of bytes to overwrite but this is somewhat not reliable.
* The best way to determine the number of bytes to overwrite is to disassemble the target function and calculate the number of bytes
* and have to do more something as in article below. This is not trivial and I do not want to implement that in here.
* If you want to try to implement this, maybe read this article: https://kylehalladay.com/blog/2020/11/13/Hooking-By-Example.html
*
* In this code, we have flow as follows:
* HookedFunction -> RelayFunction -> OurHookFunction -> TrampolineFunction -> OriginalFunction
* I am not sure about it will run on any other device or not, but at least it works on my Windows 11 x64 machine =))
*
*/

using PrototypeCreateFileW = HANDLE(WINAPI*)(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
PrototypeCreateFileW pOriginalCreateFileW = CreateFileW;
PrototypeCreateFileW pTrampolineCreateFileW = nullptr;

// flag to prevent re-entrancy in the hook function
std::atomic<bool> disableHook{ false };

// This function return pointer to pointer slot that holds the real address of the target function
void** GetThunkPointerSlot(void* thunkAddr)
{
	/*
	we have the instruction of pOriginalCreateFileW starts with :
	FF 25 9A 27 03 00    jmp         qword ptr[7FFF80C09880h]
						 jmp         qword ptr [rip+disp32]
	The intrusction jumps indirectly through a pointer in IAT. That pointer in that table points to the real CreateFileW function.
	So we need to read that pointer and update it to point to our function.
	*/

	if (!thunkAddr)
		return nullptr;
	uint8_t* instr = (uint8_t*)thunkAddr;
	// check if the instruction is indeed a jmp qword ptr [rip+disp32]
	if (instr[0] != 0xFF || instr[1] != 0x25)
		return nullptr;

	int32_t disp32;
	memcpy(&disp32, instr + 2, sizeof(disp32));
	//calculate the next instruction address after the jmp instruction
	uint8_t* instrNext = instr + 6;
	void** ptrAddr = reinterpret_cast<void**>(instrNext + disp32);
	return ptrAddr;
}

// Create a stub that jumps to the target address using an absolute jump (mov rax, addr; jmp rax)
void* MakeTrampolineStub(void* target)
{
	constexpr size_t STUB_SIZE = 12;
	uint8_t stub[STUB_SIZE] = {
		/*mov rax, 0xCCCCCCCCCCCCCCCC*/
		0x48, 0xB8, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,

		/*jmp rax*/
		0xFF, 0xE0
	};
	uint64_t addr = (uint64_t)target;
	memcpy(&stub[2], &addr, sizeof(addr));

	void* mem = VirtualAlloc(nullptr, STUB_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!mem)
		return nullptr;
	memcpy(mem, stub, STUB_SIZE);
	FlushInstructionCache(GetCurrentProcess(), mem, STUB_SIZE);
	return mem;
}

void* AllocatePageNearAddress(void* targetAddr) {
	if (!targetAddr)
		return nullptr;
	SYSTEM_INFO sysInfo;
	GetSystemInfo(&sysInfo);
	const uintptr_t allocGran = (uintptr_t)sysInfo.dwAllocationGranularity;
	const uintptr_t minApp = (uintptr_t)sysInfo.lpMinimumApplicationAddress;
	const uintptr_t maxApp = (uintptr_t)sysInfo.lpMaximumApplicationAddress;
	// start searching from the nearest aligned address
	uintptr_t base = (uintptr_t)targetAddr & ~(allocGran - 1);
	const int64_t SEARCH_RADIUS = 0x7FFF0000; // ~2GB
	uintptr_t lowBound = (uintptr_t)std::max<int64_t>((int64_t)minApp, (int64_t)base - SEARCH_RADIUS);
	uintptr_t highBound = (uintptr_t)std::min<int64_t>((int64_t)maxApp, (int64_t)base + SEARCH_RADIUS);
	const size_t MAX_STEPS = 32768;
	for (size_t step = 0; step < MAX_STEPS; ++step) {
		// try base + step*allocGran, base - step*allocGran alternately 
		uintptr_t tryAddr;
		if ((step & 1) == 0) {
			tryAddr = base + ((step / 2) * allocGran);
		}
		else {
			uintptr_t delta = ((step + 1) / 2) * allocGran;
			if (base < delta)
				continue;
			tryAddr = base - delta;
		}
		if (tryAddr < lowBound || tryAddr > highBound) continue;
		void* p = VirtualAlloc((LPVOID)tryAddr, allocGran, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (p)
			return p;
	}
	return nullptr;
}

static std::wstring StripDevicePrefix(const std::wstring& p) {
	if (p.size() >= 4 && p[0] == L'\\' && p[1] == L'\\' && p[2] == L'?' && p[3] == L'\\') {
		/* remove prefix \\?\ */
		return p.substr(4);
	}
	return p;
}

// Detour function
HANDLE WINAPI HookedCreateFileW(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile)
{
	if (disableHook.load(std::memory_order_relaxed))
		return pTrampolineCreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
	HANDLE h = pTrampolineCreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);

	if (lpFileName) {
		std::wstring fullPath(lpFileName);
		fullPath = StripDevicePrefix(fullPath);
		for (auto& c : fullPath)
			if (c == L'/')
				c = L'\\';

		const std::wstring target = L"C:\\1.txt";
		if (_wcsicmp(fullPath.c_str(), target.c_str()) == 0) {
				disableHook.store(true);
				MessageBoxW(NULL, L"Detect trying to open C:\\1.txt", L"Inline Hooking!", MB_OK | MB_ICONINFORMATION);
				disableHook.store(false);
		}
	}
	return h;
}

unsigned __stdcall InstallHook(void* pArguments)
{
	// ptrSlot save addresss of the pointer that points to the real CreateFileW function
	void** ptrSlot = GetThunkPointerSlot((void*)pOriginalCreateFileW);
	if (!ptrSlot)
		return 1;

	void* origTarget = nullptr;
	// origTarget is the real address of CreateFileW
	__try { origTarget = *ptrSlot; }
	__except (EXCEPTION_EXECUTE_HANDLER) { return 1; }
	if (!origTarget)
		return 1;

	// create a trampoline function to call original CreateFileW
	void* origStub = MakeTrampolineStub(origTarget);
	if (!origStub)
		return 1;

	// pTrampolineCreateFileW is our trampoline pointer to call original CreateFileW
	pTrampolineCreateFileW = (PrototypeCreateFileW)origStub;

	// allocate memory for relay function
	void* relay = AllocatePageNearAddress((void*)pOriginalCreateFileW);
	if (!relay) {
		return 1;
	}

	// write stub to jump to our hook function from relay function
	uint8_t jump12[12] = {
		/*mov rax, 0xCCCCCCCCCCCCCCCC*/
		0x48, 0xB8, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,

		/*jmp rax*/
		0xFF, 0xE0
	};

	uint64_t hookAddr = (uint64_t)HookedCreateFileW;
	memcpy(&jump12[2], &hookAddr, sizeof(hookAddr));
	memcpy(relay, jump12, sizeof(jump12));
	FlushInstructionCache(GetCurrentProcess(), relay, sizeof(jump12));

	DWORD oldProtect;
	VirtualProtect(pOriginalCreateFileW, 5, PAGE_EXECUTE_READWRITE, &oldProtect);
	// write stub to jump to relay function
	uint8_t jmpInstruction[5] = { 0xE9, 0x0, 0x0, 0x0, 0x0 };

	// calculate the offset from the next instruction to the relay function
	int32_t relAddr = (int32_t)((uint8_t*)relay - ((uint8_t*)pOriginalCreateFileW + 5));

	memcpy(jmpInstruction + 1, &relAddr, 4);
	memcpy(pOriginalCreateFileW, jmpInstruction, sizeof(jmpInstruction));
	VirtualProtect(pOriginalCreateFileW, 5, oldProtect, &oldProtect);
	FlushInstructionCache(GetCurrentProcess(), pOriginalCreateFileW, 5);

	return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		DisableThreadLibraryCalls(hModule);
		{
			uintptr_t th = _beginthreadex(nullptr, 0, InstallHook, nullptr, 0, nullptr);
			if (th) CloseHandle(reinterpret_cast<HANDLE>(th));
		}
		break;
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

