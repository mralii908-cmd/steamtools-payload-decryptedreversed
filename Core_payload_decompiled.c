/*
 * Core.dll decompiled + commented
 * steamtools v1.8 official release
 * sha256: 91c6a8aada59fc0d65051bc3d37c5d4ab8780f49e5a038a0da205e439cacaebd
 * size: 2,056,704 bytes decompressed (2mb lol)
 *
 * gets downloaded encrypted from https://update.tnkjmec.com/Core
 * AES-256-CBC + zlib, 4 byte size header then 78da magic
 * the key for this is at 0x180083FD8 in the stager
 * stager is the small boi (1474 funcs), this is the big boi hehe (5388 funcs)
 *
 * arch: x64, statically links sqlite3 + libcurl + cjson (maybe more links but didn't saw more)
 */

// ====================================================================
// DllMain at 0x18013A08C
// ====================================================================
// steam calls this when it loads the dll. on DLL_PROCESS_ATTACH it
// just inits the stack cookie and calls crt startup. the real init
// happens in static constructors which run BEFORE DllMain returns lmao
// sneaky cuz steam thinks the dll is done loading but its already
// hooking everything in the background

BOOL __stdcall DllEntryPoint(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
{
    if (fdwReason == 1)
        sub_18013A634();            // init stack cookie
    return sub_180139F64(hinstDLL, fdwReason, lpReserved);  // crt init
}

// ====================================================================
// security cookie init at sub_18013A634
// ====================================================================
// standard /GS cookie setup, seeds from time + thread id + process id
// + perf counter, xors everything together. if the result matches the
// default VS cookie value it bumps it by 1 so its not predictable lol

__int64 sub_18013A634()
{
    uintptr_t cookie = _security_cookie;
    if (cookie == 0x2B992DDFA232LL)  // default, needs to change
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
            cookie = 0x2B992DDFA233LL;  // lmao imagine the odds
        _security_cookie = cookie;
    }
    qword_1801C2940 = ~cookie;
    return ~cookie;
}

// ====================================================================
// steamclient64 diversion at sub_18000C910
// ====================================================================
// this is the core redirect. copies steam's steamclient64.dll to
// bin\diversion64.dll and loads the copy with LOAD_WITH_ALTERED_SEARCH_PATH.
// when SteamUI calls CreateInterface later, it hits OUR copy first.
//
// it checks the path ends with "steamclient64.dll" so it doesnt trigger
// on random LoadLibrary calls inside steam. smart tbh

HMODULE __fastcall sub_18000C910(__int64 modulePath)
{
    HMODULE existingModule = (HMODULE)(int)qword_1801CAAC8();
    if (!modulePath)
        return existingModule;

    // make sure path is long enough and ends with steamclient64.dll
    uint64_t len = 0;
    while (*(char*)(modulePath + len)) len++;
    if (len < 17)
        return existingModule;
    if (sub_180171C50(len + modulePath - 17, "steamclient64.dll"))
        return existingModule;       // nah not the real one
    if (!existingModule)
        return existingModule;

    hModule = existingModule;

    // unlock thread tracking before we mess with it
    sub_1800DE020(qword_1801CAAE8);

    WCHAR cwd[MAX_PATH];
    GetCurrentDirectoryW(0x104, cwd);

    WCHAR srcPath[MAX_PATH], dstPath[MAX_PATH];
    sub_180008980(srcPath, 260, L"%s\\steamclient64.dll", cwd);
    sub_180008980(dstPath, 260, L"%s\\bin\\diversion64.dll", cwd);

    CopyFileW(srcPath, dstPath, 0);          // only copies if newer

    // LOAD_WITH_ALTERED_SEARCH_PATH = 8
    // makes the dll resolve its own imports from its own directory
    // this matters for steams bin folder structure
    HMODULE diversion = LoadLibraryExW(dstPath, 0, 8);
    if (!diversion)
        return existingModule;

    qword_1801CAB60 = (int64_t)diversion;    // stash handle
    sub_180012B30();                          // NOW install the hook
    return diversion;
}

// ====================================================================
// CreateInterface hook at sub_180012B30 -> sub_1801E4934
// ====================================================================
// ok this is where the actual magic is. this function is huge (like 90kb
// in the decompiler lol) and partially obfuscated with inline asm rcr/rcl
// that hex-rays cant fully resolve (but managed to get most of the function). but from the clean parts we can see:
//
// 1. grabs diversion64.dll handle (loaded above)
// 2. finds SteamUI.dll in the process
// 3. resolves V_URLCracker from vstdlib_s64.dll
// 4. saves original CreateInterface ptr
// 5. overwrites it with our detour
//
// when steam calls CreateInterface("STEAMAPPS_INTERFACE_VERSION006"...)
// our detour fires, gets the real interface from the original, copies
// its vtable, and replaces these methods:
//   vtable[1]  = BIsSubscribed     -> true (yes u own it lol)
//   vtable[2]  = BIsLowViolence    -> false
//   vtable[3]  = BIsCybercafe      -> false
//   vtable[4]  = BIsVACBanned      -> false (hopefully)
//   vtable[7]  = BIsSubscribedApp  -> checks our sqlite db
//   vtable[8]  = BIsDlcInstalled   -> checks our sqlite db too
//   vtable[11] = GetDLCCount       -> returns count from config

// our version of CreateInterface, called for every steam interface request
static void* DetouredCreateInterface(const char* pName, int* pReturnCode)
{
    // this is the one we care about
    if (strcmp(pName, "STEAMAPPS_INTERFACE_VERSION006") == 0 ||
        strcmp(pName, "STEAMAPPS_INTERFACE_VERSION007") == 0 ||
        strcmp(pName, "STEAMAPPS_INTERFACE_VERSION008") == 0)
    {
        void* realIface = original_CreateInterface(pName, pReturnCode);
        if (realIface)
        {
            void** realVtable = *(void***)realIface;
            void** patchedVtable = BuildPatchedVtable(realVtable);
            *(void***)realIface = patchedVtable;  // swap the vtable lmaoo
            if (pReturnCode) *pReturnCode = 1;
        }
        return realIface;
    }

    // SteamUser we just pass through, we dont fake the actual user
    if (strcmp(pName, "SteamUser021") == 0 ||
        strcmp(pName, "SteamUser020") == 0 ||
        strcmp(pName, "SteamUser019") == 0)
    {
        return original_CreateInterface(pName, pReturnCode);
    }

    // everything else straight to original
    return original_CreateInterface(pName, pReturnCode);
}

// BIsSubscribedApp - vtable index 7
// steam calls this asking "does this user own appId 730?" and we go
// check our sqlite db. if its in app_list we say yeah bro u own it
bool __fastcall Fake_BIsSubscribedApp(void* self, unsigned int appId)
{
    // SELECT 1 FROM app_list WHERE AppID = appId
    return CheckAppInDatabase(appId);
}

// ====================================================================
// url command parser at sub_1801E425A
// ====================================================================
// handles steamtools://run/tool/ urls from the steamtools gui app
// format: steamtools://run/tool/<command>/<param>/...
//
// commands it handles:
//   unlockmode/0 or /1  -> toggle everything on/off
//   clearsteamid/<id>   -> nuke cached steamid from registry
//   geteticket/<id>     -> force generate auth ticket right now
//
// the original has some rcr/rcl garbage mixed in (anti-debug? idk)
// but the logic underneath is basic string parsing

__int64 __fastcall sub_1801E425A(const char* url)
{
    if (!url) goto done;

    // lowercase everything
    char buf[256];
    sub_180171AD0(buf, url, 255);
    buf[255] = 0;
    for (char* p = buf; *p; p++)
        *p = tolower(*p);

    // split protocol from rest
    char* colon = strchr(buf, ':');
    if (!colon) goto done;
    *colon = 0;
    char* afterColon = colon + 1;

    // skip // if present
    int skip = 0;
    if (afterColon[0] == '/' && afterColon[1] == '/')
        skip = 2;
    char* hostPart = afterColon + skip;

    // split host from path
    char* slash = strchr(hostPart, '/');
    if (!slash) goto done;
    *slash = 0;
    char* pathPart = slash + 1;

    if (strcmp(hostPart, "run") == 0)
    {
        char* slash2 = strchr(pathPart, '/');
        if (!slash2) goto done;
        *slash2 = 0;
        char* toolPart = slash2 + 1;

        if (strcmp(toolPart, "tool") == 0)
        {
            char* cmd = toolPart + 1;

            while (cmd && *cmd)
            {
                char* nextSlash = strchr(cmd, '/');
                if (nextSlash) *nextSlash = 0;

                // unlockmode toggle
                if (strcmp(cmd, "unlockmode") == 0 && nextSlash)
                {
                    char* val = nextSlash + 1;
                    char* end = strchr(val, '/');
                    if (end) *end = 0;

                    if (val[0] == '1') {
                        byte_1801CAB40 = 1;
                        sub_1801E38C3(0);
                    }
                    else if (val[0] == '0') {
                        byte_1801CAB40 = 0;
                        sub_1801E38C3(0);
                    }
                    cmd = (end ? end + 1 : nullptr);
                }
                // clear steamid from registry
                else if (strcmp(cmd, "clearsteamid") == 0 && nextSlash)
                {
                    char* val = nextSlash + 1;
                    char* end = strchr(val, '/');
                    if (end) *end = 0;

                    int appId = atoi(val);
                    if (appId) {
                        char subKey[256];
                        sprintf(subKey, "Software\\Valve\\Steam\\Apps\\%d", appId);
                        HKEY hk;
                        if (RegOpenKeyExA(HKEY_CURRENT_USER, subKey, 0, KEY_SET_VALUE, &hk) == 0) {
                            RegDeleteValueA(hk, "SteamID");
                            RegCloseKey(hk);
                        }
                    }
                    cmd = (end ? end + 1 : nullptr);
                }
                // force generate ticket
                else if (strcmp(cmd, "geteticket") == 0 && nextSlash)
                {
                    char* val = nextSlash + 1;
                    char* end = strchr(val, '/');
                    if (end) *end = 0;

                    int ticketId = atoi(val);
                    if (ticketId)
                        sub_18000DAE0(ticketId);
                    cmd = (end ? end + 1 : nullptr);
                }
                else {
                    cmd = (nextSlash ? nextSlash + 1 : nullptr);
                }
            }
        }
    }

done:
    return qword_1801CAAF8(url);  // call original url handler
}

// ====================================================================
// auth ticket generator at sub_180001D90
// ====================================================================
// writes/reads nTicket in HKCU\Software\Valve\Steam\Apps\{AppID}\nTicket
// steam checks this to verify u "own" a game. no valid ticket = no install.
//
// ticket format: hex string of binary blob starting with magic byte 0x14
// the blob is 129 bytes: header(9) + body(120). header has magic, flags,
// appid, body length. body is PRNG seeded from appid + decrypt key.
//
// flow: try existing registry -> if missing/too short -> gen new via ipc
// -> parse json -> write hex to registry

char __fastcall sub_180001D90(int appId, unsigned __int8** outBuffer)
{
    char subKey[256];
    sprintf(subKey, "Software\\Valve\\Steam\\Apps\\%d", appId);

    HKEY hKey;
    if (RegOpenKeyExA(HKEY_CURRENT_USER, subKey, 0,
                      KEY_READ | KEY_WOW64_64KEY, &hKey) != 0)
        goto generateNew;

    // read existing ticket
    BYTE existingData[8192] = {};
    DWORD cbData = sizeof(existingData);

    if (RegQueryValueExA(hKey, "nTicket", 0, 0, existingData, &cbData) != 0)
    {
        RegCloseKey(hKey);
        goto generateNew;
    }
    RegCloseKey(hKey);

    // hex string -> binary bytes
    int hexLen = (int)strlen((char*)existingData);
    if (hexLen > 0)
    {
        for (int i = 0; i < hexLen; i += 2)
        {
            BYTE byteVal = (BYTE)(hexCharToNibble(existingData[i]) << 4
                                | hexCharToNibble(existingData[i + 1]));
            AppendByteToBuffer(outBuffer, byteVal);
        }
    }

    if (GetBufferSize(outBuffer) >= 16)  // valid enough
        return 1;

    RegCloseKey(hKey);

generateNew:
    // build ipc request
    cJSON* request = cJSON_CreateObject();
    cJSON_AddNumberToObject(request, "appid");

    const char* ipcTarget = GetIpcTargetString();
    cJSON* response = SendIpcRequest(ipcTarget, request);
    cJSON_Delete(request);

    if (!response)
        return 0;

    // parse ticket from response
    cJSON* ticketField = cJSON_GetObjectItem(response, "ticket");
    if (ticketField && ticketField->type == cJSON_String)
    {
        const char* ticketHex = ticketField->valuestring;
        int ticketHexLen = (int)strlen(ticketHex);

        for (int i = 0; i < ticketHexLen; i += 2)
        {
            char val = hexCharToNibble(ticketHex[i]) << 4
                     | hexCharToNibble(ticketHex[i + 1]);
            AppendByteToBuffer(outBuffer, &val);
        }
    }
    cJSON_Delete(response);

    // write to registry if we got enough
    if (GetBufferSize(outBuffer) >= 16)
    {
        char hexString[512] = {0};
        for (size_t i = 0; i < GetBufferSize(outBuffer); i++)
        {
            char byteHex[3];
            sprintf(byteHex, "%02X", (*outBuffer)[i]);
            strcat(hexString, byteHex);
        }

        HKEY hNewKey;
        if (RegCreateKeyExA(HKEY_CURRENT_USER, subKey, 0, 0, 0,
                            KEY_WRITE | KEY_WOW64_64KEY, 0, &hNewKey, 0) == 0)
        {
            RegSetValueExA(hNewKey, "nTicket", 0, REG_SZ,
                          (BYTE*)hexString, (DWORD)(strlen(hexString) + 1));
            RegCloseKey(hNewKey);
        }
        return 1;
    }

    return 0;
}

// ====================================================================
// sqlite database init at sub_18003C5C0
// ====================================================================
// opens localcache.db in %APPDATA%\appcache\
// creates 5 tables that steamtools needs to work:
//
//   manifest(DepotID, ManifestID, Save)
//     - maps depots to manifests, Save=1 means "dont delete on restart"
//
//   app_list(AppID)
//     - the games we "own", BIsSubscribedApp checks this
//
//   app_list2(AppID)
//     - mirror table, probably used by a different code path idk
//
//   token(AppID)
//     - apps that have decryption keys, the key is stored elsewhere
//
//   packages(PackageID)
//     - subscription packages for steam's licensing system
//
// the db path is built from obfuscated wide string constants stored
// as xmmword values because they didnt want googleable strings lmao

void sub_18003C5C0()
{
    PWSTR appDataPath = nullptr;
    WCHAR dbPath[MAX_PATH] = {0};

    if (SHGetKnownFolderPath(FOLDERID_LocalAppData, 0, 0, &appDataPath) >= 0)
    {
        BuildWideString(dbPath, appDataPath, L"\\appcache\\localcache.db");
        CoTaskMemFree(appDataPath);
    }
    else
    {
        // fallback btw
        BuildWideString(dbPath, L"C:\\Users\\Default\\appcache\\localcache.db", 0);
    }

    qword_1801CAB68 = sqlite3_open(dbPath);
    sqlite3_stmt* stmt = nullptr;

    sqlite3_prepare(db, "CREATE TABLE IF NOT EXISTS manifest "
        "(DepotID INTEGER NOT NULL, ManifestID UNSIGNED BIG INT NOT NULL, "
        "Save INTEGER, PRIMARY KEY (DepotID, ManifestID), "
        "UNIQUE(DepotID, ManifestID));", -1, &stmt, 0);
    sqlite3_step(stmt); sqlite3_finalize(stmt);

    sqlite3_prepare(db, "CREATE TABLE IF NOT EXISTS app_list "
        "(AppID INTEGER PRIMARY KEY NOT NULL);", -1, &stmt, 0);
    sqlite3_step(stmt); sqlite3_finalize(stmt);

    sqlite3_prepare(db, "CREATE TABLE IF NOT EXISTS app_list2 "
        "(AppID INTEGER PRIMARY KEY NOT NULL);", -1, &stmt, 0);
    sqlite3_step(stmt); sqlite3_finalize(stmt);

    sqlite3_prepare(db, "CREATE TABLE IF NOT EXISTS token "
        "(AppID INTEGER PRIMARY KEY NOT NULL);", -1, &stmt, 0);
    sqlite3_step(stmt); sqlite3_finalize(stmt);

    sqlite3_prepare(db, "CREATE TABLE IF NOT EXISTS packages "
        "(PackageID INTEGER PRIMARY KEY NOT NULL);", -1, &stmt, 0);
    sqlite3_step(stmt); sqlite3_finalize(stmt);

    sqlite3_close(db);

    // after init it checks config bits:
    // lpMem[1] == '1' -> refresh app list from server
    // lpMem[3] == '1' -> start bg manifest download thread
    // lpMem[5] == '1' -> run token/package sync
}

// ====================================================================
// thread pool manager at sub_1800DE020
// ====================================================================
// manages suspended threads used for hot-patching steam modules
// spinlock + backoff, finds target in array, resumes threads if active,
// compacts the array, maybe shrinks allocation.
// returns 0 on success, error code if something broke

__int64 __fastcall sub_1800DE020(__int64 targetAddr)
{
    unsigned int result = 0;

    // spinlock with exponential-ish backoff
    for (uint64_t i = 0; InterlockedCompareExchange(&lock, 1, 0); i++)
        Sleep(i >= 32);

    if (!g_heapHandle) { result = 2; goto unlock; }

    unsigned int idx;
    for (idx = 0; idx < trackedCount; idx++)
        if (trackedEntries[idx].target == targetAddr) break;

    if (idx == trackedCount) { result = 4; goto unlock; }

    uint64_t entryOffset = 56 * idx;  // 56 bytes per entry for some reason lol
    if ((trackedEntries[idx].flags & 2) == 0)
        goto compact;  // not active yet

    // resume all threads for this entry
    SuspendResumeTrackingEntry(idx, 0);
    result = ResumeTrackedThreads(idx, 0);

    if (threadIdList && threadIdCount)
    {
        DWORD* tid = (DWORD*)threadIdList;
        for (size_t j = 0; j < threadIdCount; j++)
        {
            HANDLE hThread = OpenThread(
                THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT
                | THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION, 0, tid[j]);
            if (hThread) { ResumeThread(hThread); CloseHandle(hThread); }
        }
        HeapFree(g_heapHandle, 0, threadIdList);
        threadIdList = nullptr;
        threadIdCount = 0;
    }

    if (result) goto unlock;

compact:
    sub_1800DE4A0(trackedEntries[idx].module);

    // move last entry to fill the gap
    if (idx < trackedCount - 1)
    {
        size_t lastOff = 56 * (trackedCount - 1);
        trackedEntries[idx] = trackedEntries[lastOff];
    }

    trackedCount--;

    // halve allocation if capacity/2 >= 32 and >= count
    if ((trackedCapacity >> 1) >= 32 && (trackedCapacity >> 1) >= trackedCount)
    {
        void* newMem = HeapReAlloc(g_heapHandle, 0, trackedEntries,
                                   56 * (trackedCapacity >> 1));
        if (newMem) { trackedCapacity >>= 1; trackedEntries = newMem; }
    }

unlock:
    InterlockedExchange(&lock, 0);
    return result;
}

// ====================================================================
// unlock state change at sub_1801E38C3
// ====================================================================
// called when unlockmode toggles. refreshes cached app data
// and tells steam to redraw the library.
// iterates every tracked appid, fetches fresh data, uses RDTSC for
// timing each request (extra af but ok)

__int64 __fastcall sub_1801E38C3(int mode)
{
    sub_1801E4934(mode);

    if (byte_1801CAAE2)
    {
        for (auto* entry = qword_1801CAD10; entry != (void*)xmmword_1801CAD18; entry += 88)
        {
            sub_180006C20(entry + 56);
            sub_180006C20(entry + 24);
        }
        xmmword_1801CAD18 = qword_1801CAD10;

        void* appList = sub_1800418A0();
        if (appList != &xmmword_1801CAD60)
        {
            if (xmmword_1801CAD60) HeapFree(xmmword_1801CAD60);
            xmmword_1801CAD60 = 0;
            qword_1801CAD70 = 0;
            xmmword_1801CAD60 = appList[0];
            qword_1801CAD70 = appList[1];
            appList[0] = appList[1] = 0;
        }

        DWORD* end   = *(&xmmword_1801CAD60 + 1);
        DWORD* start = xmmword_1801CAD60;

        if (start == end) { sub_18003FE40(); return; }

        while (1)
        {
            sub_18000C4D0(*start, 1, mode, &queryResult, &timing);
            if (++start == end) { sub_18003FE40(); break; }
        }
    }
}

// ====================================================================
// ipc request at sub_18003ECB0
// ====================================================================
// sends json-rpc to steams local ipc endpoint
// request: {"method":"GetTicket","params":{"appid":123},"id":1}
// response: {"result":{"ticket":"14..."}}

void sub_18003ECB0(__int64* out, const char* method, cJSON* params, const char* ipcAddr)
{
    cJSON* request = cJSON_CreateObject();
    cJSON_AddStringToObject(request, "method", method);
    cJSON_AddItemToObject(request, "params", params);
    cJSON_AddNumberToObject(request, "id");
    cJSON_AddStringToObject(request, "jsonrpc", "2.0");

    char* requestStr = cJSON_PrintUnformatted(request);
    cJSON_Delete(request);
    // transport via sub_18003D920 (set up from CreateInterface hook)
    cJSON_free(requestStr);
}

// ====================================================================
// manifest downloader at sub_18003A7D0
// ====================================================================
// bg thread, downloads manifests from steam cdn for all tracked depots
// uses libcurl. replaces <mCode> in urls with hash of appid + cpuid
// fingerprint from stager. caches in appcache/httpcache/3b/

void sub_18003A7D0(void* dbPath)
{
    // for each depot without cached manifest:
    //   build cdn url with GetManifestRequestCode
    //   http get via libcurl
    //   parse response -> depot id + manifest id + file list
    //   write to sqlite manifest table
    //   cache in appcache/httpcache/3b/<hash>
}

// ====================================================================
// app list sync at sub_18003C320
// ====================================================================
// syncs local sqlite with steamtools server config
// called as bg thread from db init. fetches json list of "available"
// appids from server, inserts each into app_list + app_list2,
// writes nTicket per app, pings ui to refresh

void sub_18003C320(void* arg)
{
    // query steamtools api for app list
    // parse json
    // INSERT OR IGNORE into app_list + app_list2
    // sub_180001D90 per app -> nTicket
    // refresh ui
}

// ====================================================================
// config commands implementation
// ====================================================================
// these are the actual implementations behind the config.lua commands
// its not real lua, just a simple parser that matches function names

void addappid_impl(uint32_t appId, uint32_t dlcFlag, const char* decryptKey)
{
    // INSERT OR IGNORE INTO app_list (AppID) VALUES (appId)
    // INSERT OR IGNORE INTO app_list2 (AppID) VALUES (appId)
    // if dlc: INSERT OR IGNORE INTO token (AppID) VALUES (appId)
    // sub_180001D90(appId, &buf) -> writes nTicket to registry
}

void setManifestid_impl(uint32_t appId, uint64_t manifestId)
{
    // INSERT OR REPLACE INTO manifest (DepotID, ManifestID, Save)
    // VALUES (appId, manifestId, 1)
    // append to packageinfo.vdf
}

void adddownloadManifest_impl(uint32_t depotId, uint64_t manifestId)
{
    // same as above but depotId separate from appId
    // INSERT OR REPLACE INTO manifest (DepotID, ManifestID, Save)
    // VALUES (depotId, manifestId, 1)
}

void addpackage_impl(uint32_t packageId)
{
    // INSERT OR IGNORE INTO packages (PackageID) VALUES (packageId)
    // append to packageinfo.vdf
}

// ====================================================================
// packageinfo.vdf writer
// ====================================================================
// steam reads appcache\packageinfo.vdf at startup to figure out what
// packages and depots u own. we append entries for our injected stuff.
// format is valve's keyvalues text vdf. touches appinfo.vdf timestamp
// after writing so steam knows to reload

void WritePackageInfoVdf(const char* steamPath, uint32_t packageId,
                         uint32_t appId, uint32_t depotId, uint64_t manifestId)
{
    char path[MAX_PATH];
    sprintf(path, "%s\\appcache\\packageinfo.vdf", steamPath);

    FILE* f = fopen(path, "r");
    char* existing = NULL;
    size_t existingLen = 0;
    if (f) {
        fseek(f, 0, SEEK_END); existingLen = ftell(f); fseek(f, 0, SEEK_SET);
        existing = malloc(existingLen + 1);
        fread(existing, 1, existingLen, f); existing[existingLen] = 0;
        fclose(f);
    }

    f = fopen(path, "w");
    if (existing) { fwrite(existing, 1, existingLen, f); free(existing); }
    else fprintf(f, "\"packageinfo\"\n{\n");

    fprintf(f, "\t\"%u\"\n\t{\n", packageId);
    fprintf(f, "\t\t\"packageid\"\t\t\"%u\"\n", packageId);
    fprintf(f, "\t\t\"appid\"\t\t\"%u\"\n", appId);
    fprintf(f, "\t\t\"depotids\"\n\t\t{\n");
    fprintf(f, "\t\t\t\"%u\"\t\t\"%llu\"\n", depotId, manifestId);
    fprintf(f, "\t\t}\n\t}\n");
    if (!existing) fprintf(f, "}\n");
    fclose(f);

    // touch appinfo.vdf so steam re-reads the whole appcache
    char appInfoPath[MAX_PATH];
    sprintf(appInfoPath, "%s\\appcache\\appinfo.vdf", steamPath);
    HANDLE h = CreateFileA(appInfoPath, FILE_WRITE_ATTRIBUTES,
                           FILE_SHARE_READ | FILE_SHARE_WRITE,
                           NULL, OPEN_EXISTING, 0, NULL);
    if (h != INVALID_HANDLE_VALUE) {
        FILETIME ft; GetSystemTimeAsFileTime(&ft);
        SetFileTime(h, NULL, NULL, &ft); CloseHandle(h);
    }
}

// ====================================================================
// string deobfuscator at sub_180001080
// ====================================================================
// decodes obfuscated wide strings from pairs of 64-bit constants.
// each qword: unshuffle bit pairs -> unshuffle nibbles -> unshuffle bytes
// -> byteswap -> each byte becomes a wide char.
//
// decoded strings from this binary:
//   steamclient64.dll, SteamUI.dll, crashhandler.dll, ntdll.dll
//   plus internal paths they wanted hidden

__int64 __fastcall sub_180001080(unsigned int count, uint64_t qw1, uint64_t qw2, uint64_t qw3)
{
    uint64_t values[4] = {count, qw1, qw2, qw3};
    size_t charCount = 8 * count;
    wchar_t* result = (wchar_t*)malloc((charCount + 1) * sizeof(WCHAR));
    if (!result) return 0;

    wchar_t* out = result;
    for (unsigned int i = 0; i < count; i++)
    {
        uint64_t v = values[i + 1];
        v = (v >> 1) ^ (((v >> 1) ^ (v << 1)) & 0xAAAAAAAAAAAAAAAAULL);
        v = (v >> 2) ^ (((v >> 2) ^ (v << 2)) & 0xCCCCCCCCCCCCCCCCULL);
        v = (v >> 4) ^ (((v >> 4) ^ (v << 4)) & 0xF0F0F0F0F0F0F0F0ULL);
        v = _byteswap_uint64(v);
        for (int j = 0; j < 8; j++)
            *out++ = (wchar_t)((v >> (j * 8)) & 0xFF);
    }
    *out = 0;
    return (__int64)result;
}

// ====================================================================
// the full startup sequence (reconstructed from xrefs)
// ====================================================================
//
// 1. DllMain fires
//    -> sub_18013A634() cookie init
//    -> sub_180139F64() crt init (which runs static constructors!)
//
// 2. static ctors kick off the real shit:
//    -> find steam path from HKCU\Software\Valve\Steam\SteamPath
//    -> sub_18003C5C0() opens/creates localcache.db + 5 tables
//    -> load config (from stored settings, not a file)
//    -> if unlockmode on:
//       loop all appids: sub_180001D90() per app -> nTicket
//       loop all depots: write packageinfo.vdf
//    -> clear all cached SteamIDs from registry
//    -> sub_18000C910() copy steamclient64 to bin\diversion64
//    -> sub_180012B30() install CreateInterface detour
//    -> start bg manifest download thread
//    -> register steamtools:// protocol handler
//
// 3. at steady state:
//    -> every CreateInterface call hits our detour
//    -> ISteamApps checks our sqlite database
//    -> games show up in library as owned
//    -> downloads work cuz steam trusts nTicket + packageinfo
//    -> depot decryption uses keys from token table
//
// 4. runtime url commands work without restart:
//    unlockmode/1 or /0     -> toggle
//    clearsteamid/<id>      -> bye bye steamid
//    geteticket/<id>        -> fresh ticket right now
//    addappid/<id>          -> add game without restart
//    setManifestid/<id>/<mid> -> link manifest

// ====================================================================
// strings from the binary
// ====================================================================
// registry stuff:
//   Software\Valve\Steam\Apps\%d
//   SteamID, SteamPath, SteamExe, nTicket
//
// steam interfaces:
//   STEAMAPPS_INTERFACE_VERSION006 (the one we patch)
//   SteamUser021/020/019 (passthrough)
//   CreateInterface (the export we detour)
//
// files it touches:
//   appcache\packageinfo.vdf, packcode.vdf, appinfo.vdf
//   appcache\httpcache\3b\<mCode>
//   config/config.vdf
//   steamclient64.dll -> bin\diversion64.dll
//
// sql tables:
//   manifest, app_list, app_list2, token, packages
//
// url scheme:
//   run, tool, unlockmode, clearsteamid, geteticket
//   addappid, adddownloadManifest, setManifestid
//
// cdn stuff:
//   ContentServerDirectory.GetManifestRequestCode#1
//   Cloud.GetAppFileChangelist#1
//   CCMInterface::RecvPkt

// ====================================================================
// network endpoints (from decrypted version.json, you can also see this on the version_decrypted file :b)
// ====================================================================
// cdn mirrors: cdn-api-sg6.tnkjmec.com, cdn-api.tnkjmec.com,
//              cdn-api.steamox.com
// payload: update.tnkjmec.com/Core, update.steamox.com/CoreBeta
// site: steamtools.net
// installer (yes, it's a pdf mostly for av bypassing): https://cdn.wmpvp.com/steamWeb/B330D5F2F85F4FA784DD92B4D452BBD1-1731878923362.pdf

// ====================================================================
// build info
// ====================================================================
// pdb: I:\sTCode\x64\Release\update.pdb
// project: sTCode (steamtools code)
// output: update.dll -> renamed to Core.dll or xinput1_4.dll
// compiler: msvc 19.x, /MT (static crt), /O2
// static links: sqlite3, libcurl, cjson
// obfuscation: manual asm + bit shuffle strings
// some funcs have /GS- (no stack cookie, intentional for hook code)
//
// hashes:
//   payload (decompressed):
//     md5:  ebc72e5b01cbad65363fd77b50a8210a
//     sha256: 91c6a8aada59fc0d65051bc3d37c5d4ab8780f49e5a038a0da205e439cacaebd
//   stager (xinput1_4.dll):
//     md5:  7008ba0fdc713742028a610bd2a9c750
//     sha256: 84b0245b11cb7ae8508be634d8dde8e163e9ca834a52f4f252163636414ccee1
//
// btw the stager and this share the exact same skeleton (same func count,
// same segments, same entry points). stager just downloads+injects,
// this is the actual unlock logic. two stage design.
