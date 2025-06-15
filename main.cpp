// dll_injector_gui.cpp
// 带有基本GUI的DLL注入工具，允许通过点击窗口选择目标进程。
// 适配32位和64位目标进程，自动选择对应架构的DLL。

#include <windows.h>         // 包含大部分Windows API函数和定义
#include <string>            // 用于字符串操作 (std::string, std::wstring)
#include <vector>            // 用于存储进程信息 (std::vector)
#include <tlhelp32.h>        // 用于进程快照功能, 查找进程 (PROCESSENTRY32, CreateToolhelp32Snapshot等)
#include <algorithm>         // 包含了 std::transform
#include <cctype>            // 包含了 ::tolower
#include <cstdio>            // For snprintf (用于调试输出)
#include <psapi.h>           // 包含 psapi.h 头文件，用于 GetModuleFileNameExW
#include <shellscalingapi.h> // 包含 shellscalingapi.h 头文件，用于 DPI 感知函数
#include <winnt.h>           // For IMAGE_DOS_HEADER, IMAGE_NT_HEADERS, etc. (PE structure parsing)
#include <dbghelp.h>
#pragma comment(lib, "dbghelp.lib")
// 全局句柄和变量
HWND hMainWindow = NULL;
HWND hProcessNameStatic = NULL; // 用于显示进程名称的静态文本控件
HWND hProcessIdStatic = NULL;   // 用于显示进程ID的静态文本控件
HWND hStatusStatic = NULL;      // 用于显示操作状态的静态文本控件
DWORD g_selectedProcessId = 0;
std::wstring g_selectedProcessNameW;
HHOOK g_hMouseHook = NULL; // 全局鼠标钩子句柄

// 新增全局变量：用于优化预览时的进程信息获取
DWORD g_lastPreviewedPid = 0; // 上次预览的进程ID

// --- DLL注入和进程检测相关函数定义 ---

// 定义DLL中导出的函数所需的结构体 (保持不变)
typedef struct _REMOTE_CALL_PARAMS
{
    HWND hWnd;
    BOOL excludeFromCapture;
} REMOTE_CALL_PARAMS, *PREMOTE_CALL_PARAMS;

// 定义 DLL 中导出的 CallAntiScreenshotAffinity 函数指针类型 (保持不变)
typedef DWORD(WINAPI *PFN_CALLANTISCREENSHOTAFFINITY)(LPVOID);

// 用于动态加载 IsWow64Process 函数指针 (保持不变)
typedef BOOL(WINAPI *LPFN_ISWOW64PROCESS)(HANDLE, PBOOL);

/**
 * @brief 查找指定进程名称的进程ID。
 * @param processName 要查找的进程名称 (例如 "notepad.exe")。
 * @return DWORD 找到的进程ID；如果未找到, 返回0。
 */
DWORD FindProcessId(const std::string &processName)
{
    DWORD processId = 0;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE)
    {
        return 0;
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(pe32);

    if (!Process32First(hSnapshot, &pe32))
    {
        CloseHandle(hSnapshot);
        return 0;
    }

    do
    {
        std::string currentProcessName = pe32.szExeFile;
        std::transform(currentProcessName.begin(), currentProcessName.end(), currentProcessName.begin(), ::tolower);
        std::string targetProcessNameLower = processName;
        std::transform(targetProcessNameLower.begin(), targetProcessNameLower.end(), targetProcessNameLower.begin(), ::tolower);

        if (currentProcessName == targetProcessNameLower)
        {
            processId = pe32.th32ProcessID;
            break;
        }
    } while (Process32Next(hSnapshot, &pe32));

    CloseHandle(hSnapshot);

    if (processId == 0)
    {
        // No debug output needed here as MessageBox is used for errors.
    }
    return processId;
}

/**
 * @brief 获取目标进程的架构 (x86 或 x64)。
 * @param processId 目标进程的PID。
 * @return std::wstring 返回 L"x86" 或 L"x64"。如果无法确定，可能返回 L"未知" 或默认 L"x64"。
 */
std::wstring GetProcessArchitecture(DWORD processId)
{
    HANDLE hProcess = NULL;
    BOOL bIsWow64 = FALSE;
    std::wstring arch = L"x64"; // 默认假设为64位

    SYSTEM_INFO sysInfo;
    GetNativeSystemInfo(&sysInfo);
    bool currentOSIs64Bit = (sysInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 ||
                             sysInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_IA64);

    if (!currentOSIs64Bit)
    {
        // Current OS is 32-bit, so any process is 32-bit.
        return L"x86";
    }

    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, processId);
    if (hProcess == NULL)
    {
        return L"x64";
    }

    LPFN_ISWOW64PROCESS fnIsWow64Process = (LPFN_ISWOW64PROCESS)GetProcAddress(
        GetModuleHandleW(L"kernel32.dll"), "IsWow64Process");

    if (fnIsWow64Process != NULL)
    {
        if (fnIsWow64Process(hProcess, &bIsWow64))
        {
            arch = bIsWow64 ? L"x86" : L"x64";
        }
        else
        {
            // Error handling or logging for IsWow64Process call failure
        }
    }
    else
    {
        // Error handling or logging for GetProcAddress failure
    }

    CloseHandle(hProcess);
    return arch;
}

/**
 * @brief 获取目标进程中指定模块的基地址。
 * @param pid 目标进程的PID。
 * @param moduleName 要查找的模块名称 (例如 L"kernel32.dll")。
 * @return DWORD_PTR 模块的基地址；如果未找到, 返回0。
 */
DWORD_PTR GetRemoteModuleBase(DWORD pid, const wchar_t *moduleName)
{
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (hSnapshot == INVALID_HANDLE_VALUE)
    {
        char debug_msg[256];
        snprintf(debug_msg, sizeof(debug_msg), "Injector: CreateToolhelp32Snapshot failed for PID %lu. Error: %lu\n", pid, GetLastError());
        OutputDebugStringA(debug_msg);
        return 0;
    }

    MODULEENTRY32W me;
    me.dwSize = sizeof(me);
    if (!Module32FirstW(hSnapshot, &me))
    {
        char debug_msg[256];
        snprintf(debug_msg, sizeof(debug_msg), "Injector: Module32FirstW failed for PID %lu. Error: %lu\n", pid, GetLastError());
        OutputDebugStringA(debug_msg);
        CloseHandle(hSnapshot);
        return 0;
    }

    DWORD_PTR baseAddr = 0;
    do
    {
        if (_wcsicmp(me.szModule, moduleName) == 0)
        {
            baseAddr = (DWORD_PTR)me.modBaseAddr;
            break;
        }
    } while (Module32NextW(hSnapshot, &me));

    CloseHandle(hSnapshot);

    char debug_msg[256];
    snprintf(debug_msg, sizeof(debug_msg), "Injector: GetRemoteModuleBase for %ls in PID %lu: 0x%p\n", moduleName, pid, (void *)baseAddr);
    OutputDebugStringA(debug_msg);

    return baseAddr;
}

#include <Psapi.h>
#include <string>
#include <cctype>
#include <algorithm>

/**
 * @brief 在目标进程中注入DLL
 * @param processId 目标进程ID
 * @param dllPath DLL完整路径
 * @return DWORD_PTR 注入的DLL基地址
 */
DWORD_PTR InjectDll(DWORD processId, const std::wstring &dllPath)
{
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    if (!hProcess)
    {
        char debugMsg[256];
        snprintf(debugMsg, sizeof(debugMsg), "Injector: OpenProcess failed. Error: %lu", GetLastError());
        OutputDebugStringA(debugMsg);
        return 0;
    }

    // 在目标进程中分配内存
    SIZE_T pathSize = (dllPath.size() + 1) * sizeof(wchar_t);
    LPVOID remotePath = VirtualAllocEx(hProcess, NULL, pathSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remotePath)
    {
        char debugMsg[256];
        snprintf(debugMsg, sizeof(debugMsg), "Injector: VirtualAllocEx failed. Error: %lu", GetLastError());
        OutputDebugStringA(debugMsg);
        CloseHandle(hProcess);
        return 0;
    }

    // 写入DLL路径
    if (!WriteProcessMemory(hProcess, remotePath, dllPath.c_str(), pathSize, NULL))
    {
        char debugMsg[256];
        snprintf(debugMsg, sizeof(debugMsg), "Injector: WriteProcessMemory failed. Error: %lu", GetLastError());
        OutputDebugStringA(debugMsg);
        VirtualFreeEx(hProcess, remotePath, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 0;
    }

    // 获取LoadLibraryW地址
    LPTHREAD_START_ROUTINE pLoadLibraryRemote = NULL;
    std::wstring targetArch = GetProcessArchitecture(processId);

    if (targetArch == L"x64")
    {
        HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
        if (hKernel32)
        {
            pLoadLibraryRemote = (LPTHREAD_START_ROUTINE)GetProcAddress(hKernel32, "LoadLibraryW");
        }
    }
    else
    {
        // 对于x86目标，使用远程线程执行LoadLibraryW
        // 使用硬编码的RVA作为后备方案
        DWORD_PTR kernel32BaseRemote = GetRemoteModuleBase(processId, L"kernel32.dll");
        DWORD loadLibRVA = 0x1D8A0; // 根据您的日志使用实际值
        if (kernel32BaseRemote != 0)
        {
            DWORD_PTR loadLibAddrRemote = kernel32BaseRemote + loadLibRVA;
            if (loadLibAddrRemote > 0xFFFFFFFF)
            {
                loadLibAddrRemote &= 0xFFFFFFFF;
            }
            pLoadLibraryRemote = (LPTHREAD_START_ROUTINE)loadLibAddrRemote;
        }
    }

    if (!pLoadLibraryRemote)
    {
        // 错误处理
        return 0;
    }
    // 创建远程线程加载DLL
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, pLoadLibraryRemote, remotePath, 0, NULL);
    // 等待线程完成
    WaitForSingleObject(hThread, INFINITE);

    // 获取模块基址
    DWORD_PTR hInjectedDll = 0;
    GetExitCodeThread(hThread, (LPDWORD)&hInjectedDll);

    // 对于32位目标，确保只保留32位
    if (targetArch == L"x86")
    {
        hInjectedDll &= 0xFFFFFFFF;
    }

    // 清理资源
    CloseHandle(hThread);
    VirtualFreeEx(hProcess, remotePath, 0, MEM_RELEASE);
    CloseHandle(hProcess);

    if (hInjectedDll == 0)
    {
        OutputDebugStringA("Injector: DLL injection failed (LoadLibraryW returned NULL)");
    }
    else
    {
        char debugMsg[256];
        snprintf(debugMsg, sizeof(debugMsg), "Injector: DLL injected at base: 0x%p", (void *)hInjectedDll);
        OutputDebugStringA(debugMsg);
    }

    return hInjectedDll;
}
// 辅助函数：使用 Windows API 检查宽字符文件是否存在 (保持不变)
bool DoesFileExistW(const std::wstring &filePath)
{
    DWORD fileAttributes = GetFileAttributesW(filePath.c_str());
    return (fileAttributes != INVALID_FILE_ATTRIBUTES && !(fileAttributes & FILE_ATTRIBUTE_DIRECTORY));
}

// **** 新增： EnumWindows 的静态回调函数 ****
// 此函数必须是静态的，且符合 WNDENUMPROC 签名，以便与 EnumWindows API 兼容
static BOOL CALLBACK EnumWindowsCallbackForInjection(HWND hwnd, LPARAM lParam)
{
    DWORD currentPid;
    // 获取当前窗口所属的进程 ID
    GetWindowThreadProcessId(hwnd, &currentPid);

    // 从 lParam 获取我们传递的目标进程 ID 和指向 HWND 的指针
    // 我们将把目标进程 ID 和一个 HWND* 封装在一个自定义结构体中传递
    // 或者，在当前简单场景下，如果只传递一个 HWND*，lParam 就可以直接是 HWND*
    // 在这里，lParam 预期是 (LPARAM)&selectedHwnd

    // Check if this window belongs to the target process AND is visible
    if (currentPid == (DWORD)g_selectedProcessId && IsWindowVisible(hwnd))
    {
        // Assign the found window handle to the pointer passed via lParam
        *((HWND *)lParam) = hwnd;
        return FALSE; // Stop enumeration (found a suitable window)
    }
    return TRUE; // Continue enumeration (this window is not what we're looking for)
}

// --- GUI 相关代码 ---

#define ID_BTN_SELECT_WINDOW 1001
#define ID_BTN_INJECT_DLL 1002
#define ID_STATIC_PROCESS_NAME 1003
#define ID_STATIC_PROCESS_ID 1004
#define ID_STATIC_STATUS 1005

// 自定义消息：用于鼠标钩子回调函数向主窗口发送选定的进程信息
#define WM_USER_PROCESS_SELECTED (WM_USER + 1)
// 新增自定义消息：用于鼠标移动时发送预览进程信息
#define WM_USER_PREVIEW_PROCESS_INFO (WM_USER + 2)

// 鼠标钩子回调函数
LRESULT CALLBACK LowLevelMouseProc(int nCode, WPARAM wParam, LPARAM lParam)
{
    if (nCode == HC_ACTION)
    {
        MSLLHOOKSTRUCT *pMouseStruct = (MSLLHOOKSTRUCT *)lParam;
        POINT pt = pMouseStruct->pt; // 逻辑坐标

        HWND hClickedWindow = WindowFromPoint(pt); // 直接点击位置的窗口
        HWND hTopLevelWindow = NULL;               // 顶层窗口

        if (hClickedWindow)
        {
            hTopLevelWindow = GetAncestor(hClickedWindow, GA_ROOT);
            // 过滤掉我们自己的注入器窗口，避免鼠标在注入器上移动时显示自身信息
            if (hTopLevelWindow == hMainWindow)
            {
                hTopLevelWindow = NULL; // 忽略自身窗口
            }
        }

        DWORD currentProcessId = 0;
        if (hTopLevelWindow)
        {
            GetWindowThreadProcessId(hTopLevelWindow, &currentProcessId);
        }

        // 处理鼠标移动事件：实时更新预览
        if (wParam == WM_MOUSEMOVE)
        {
            // 只有当进程ID变化时才发送消息，避免频繁刷新
            // 并且确保不是我们自己的进程ID (如果自注入检查失败，这里是第二层过滤)
            if (currentProcessId != g_lastPreviewedPid && currentProcessId != GetCurrentProcessId())
            {
                // 发送消息，wParam为PID，lParam为NULL，因为进程名称将在主线程中查询
                PostMessageW(hMainWindow, WM_USER_PREVIEW_PROCESS_INFO, (WPARAM)currentProcessId, 0);
                g_lastPreviewedPid = currentProcessId;
            }
            else if (currentProcessId == 0 && g_lastPreviewedPid != 0)
            {
                // 从一个有效窗口移动到无有效窗口区域时清空显示
                PostMessageW(hMainWindow, WM_USER_PREVIEW_PROCESS_INFO, (WPARAM)0, 0);
                g_lastPreviewedPid = 0;
            }
        }
        // 处理左键单击事件：确认选择
        else if (wParam == WM_LBUTTONDOWN)
        {
            // 如果点击的是我们自己的窗口，也视为无效选择
            if (currentProcessId == GetCurrentProcessId())
            {
                MessageBoxW(hMainWindow, L"不能选择注入工具自身的窗口。请点击其他应用程序的窗口。", L"无效选择", MB_OK | MB_ICONWARNING);
                currentProcessId = 0; // 重置为无效选择
            }

            // 首先发送最终选择的消息，无论 PID 是否有效，然后解除钩子
            if (currentProcessId != 0)
            {
                // 获取进程名称 (根据PID)
                HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, currentProcessId);
                if (hProcess)
                {
                    wchar_t processNameBuffer[MAX_PATH];
                    if (GetModuleFileNameExW(hProcess, NULL, processNameBuffer, MAX_PATH))
                    {
                        std::wstring fullPath(processNameBuffer);
                        size_t lastSlash = fullPath.find_last_of(L'\\');
                        std::wstring exeName = (lastSlash == std::wstring::npos) ? fullPath : fullPath.substr(lastSlash + 1);
                        PostMessageW(hMainWindow, WM_USER_PROCESS_SELECTED, (WPARAM)currentProcessId, (LPARAM) new std::wstring(exeName));
                    }
                    else
                    {
                        // 无法获取名称时也发送消息
                        PostMessageW(hMainWindow, WM_USER_PROCESS_SELECTED, (WPARAM)currentProcessId, (LPARAM) new std::wstring(L"无法获取名称"));
                    }
                    CloseHandle(hProcess);
                }
                else
                {
                    // 无法打开进程时也发送消息
                    PostMessageW(hMainWindow, WM_USER_PROCESS_SELECTED, (WPARAM)currentProcessId, (LPARAM) new std::wstring(L"无法打开进程"));
                }
            }
            else
            {
                // 如果没有有效的窗口或进程ID，发送一个空选择消息
                PostMessageW(hMainWindow, WM_USER_PROCESS_SELECTED, (WPARAM)0, (LPARAM) new std::wstring(L"无效窗口/进程"));
            }

            // 无论是否找到有效进程，都取消钩子
            if (g_hMouseHook)
            {
                UnhookWindowsHookEx(g_hMouseHook);
                g_hMouseHook = NULL;
                // 恢复默认光标
                SetCursor(LoadCursor(NULL, IDC_ARROW));
                SetWindowTextW(hStatusStatic, L"选择模式结束。");
                g_lastPreviewedPid = 0; // 重置预览PID
            }
            return 1; // 阻止事件传递给应用程序
        }
    }
    return CallNextHookEx(g_hMouseHook, nCode, wParam, lParam);
}

// 窗口过程函数
LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    switch (uMsg)
    {
    case WM_CREATE:
    {
        hMainWindow = hwnd; // 存储主窗口句柄
        // 创建控件
        CreateWindowW(L"STATIC", L"目标进程名称:",
                      WS_VISIBLE | WS_CHILD,
                      20, 20, 150, 20, hwnd, NULL, NULL, NULL);
        hProcessNameStatic = CreateWindowW(L"STATIC", L"",
                                           WS_VISIBLE | WS_CHILD | WS_BORDER,
                                           170, 20, 250, 20, hwnd, (HMENU)ID_STATIC_PROCESS_NAME, NULL, NULL);

        CreateWindowW(L"STATIC", L"目标进程ID:",
                      WS_VISIBLE | WS_CHILD,
                      20, 50, 150, 20, hwnd, NULL, NULL, NULL);
        hProcessIdStatic = CreateWindowW(L"STATIC", L"",
                                         WS_VISIBLE | WS_CHILD | WS_BORDER,
                                         170, 50, 250, 20, hwnd, (HMENU)ID_STATIC_PROCESS_ID, NULL, NULL);

        CreateWindowW(L"BUTTON", L"选择窗口",
                      WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
                      20, 90, 100, 30, hwnd, (HMENU)ID_BTN_SELECT_WINDOW, NULL, NULL);

        CreateWindowW(L"BUTTON", L"注入 DLL",
                      WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
                      130, 90, 100, 30, hwnd, (HMENU)ID_BTN_INJECT_DLL, NULL, NULL);

        hStatusStatic = CreateWindowW(L"STATIC", L"状态: 待命",
                                      WS_VISIBLE | WS_CHILD,
                                      20, 140, 400, 20, hwnd, (HMENU)ID_STATIC_STATUS, NULL, NULL);
        break;
    }

    case WM_COMMAND:
    {
        int wmId = LOWORD(wParam);
        switch (wmId)
        {
        case ID_BTN_SELECT_WINDOW:
        {
            if (g_hMouseHook)
            {
                MessageBoxW(hwnd, L"选择模式已激活。请先点击一个窗口。", L"提示", MB_OK | MB_ICONINFORMATION);
                break;
            }
            SetWindowTextW(hStatusStatic, L"状态: 点击任意窗口以选择进程...");
            SetCursor(LoadCursor(NULL, IDC_CROSS)); // 将光标改为十字
            // 设置全局低级鼠标钩子
            g_hMouseHook = SetWindowsHookEx(WH_MOUSE_LL, LowLevelMouseProc, GetModuleHandle(NULL), 0);
            if (!g_hMouseHook)
            {
                MessageBoxW(hwnd, (L"无法设置鼠标钩子。错误码: " + std::to_wstring(GetLastError())).c_str(), L"错误", MB_OK | MB_ICONERROR);
                SetWindowTextW(hStatusStatic, L"状态: 错误，无法设置钩子。");
            }
            break;
        }
        case ID_BTN_INJECT_DLL:
        {
            if (g_selectedProcessId == 0)
            {
                MessageBoxW(hwnd, L"请先选择一个目标进程。", L"提示", MB_OK | MB_ICONINFORMATION);
                break;
            }

            // **** 新增：检查是否尝试注入自身进程 ****
            DWORD currentInjectorPid = GetCurrentProcessId();
            if (g_selectedProcessId == currentInjectorPid)
            {
                MessageBoxW(hwnd, L"错误: 无法将DLL注入到自身进程中。请选择其他进程。", L"注入失败", MB_OK | MB_ICONERROR);
                SetWindowTextW(hStatusStatic, L"状态: 注入失败 (禁止自注入)。");
                break;
            }
            // **** 结束自注入检查 ****

            SetWindowTextW(hStatusStatic, L"状态: 正在注入 DLL...");

            // 获取当前注入器自身的完整路径
            wchar_t injectorPath[MAX_PATH];
            GetModuleFileNameW(NULL, injectorPath, MAX_PATH);

            // 提取注入器所在的目录
            std::wstring injectorDir = injectorPath;
            size_t lastSlashPos = injectorDir.find_last_of(L'\\');
            if (lastSlashPos != std::wstring::npos)
            {
                injectorDir = injectorDir.substr(0, lastSlashPos);
            }
            else
            {
                injectorDir = L"."; // 如果没有斜杠，表示在当前目录
            }

            std::wstring dllToInjectPath;
            std::wstring targetArch = GetProcessArchitecture(g_selectedProcessId);

            if (targetArch == L"x86")
            {
                dllToInjectPath = injectorDir + L"\\anti_screenshot_32.dll";
            }
            else if (targetArch == L"x64")
            {
                dllToInjectPath = injectorDir + L"\\anti_screenshot_64.dll";
            }
            else
            {
                MessageBoxW(hwnd, L"无法确定目标进程架构，无法选择合适的DLL。", L"注入失败", MB_OK | MB_ICONERROR);
                SetWindowTextW(hStatusStatic, L"状态: 注入失败 (架构未知)。");
                break;
            }

            // 检查DLL文件是否存在
            if (!DoesFileExistW(dllToInjectPath))
            {
                MessageBoxW(hwnd, (L"对应的DLL文件不存在: " + dllToInjectPath + L". 请将编译好的DLL文件放到注入器所在的目录。").c_str(), L"注入失败", MB_OK | MB_ICONERROR);
                SetWindowTextW(hStatusStatic, L"状态: 注入失败 (DLL不存在)。");
                break;
            }
            // 执行注入
            DWORD_PTR hInjectedDllModule = InjectDll(g_selectedProcessId, dllToInjectPath);
            if (hInjectedDllModule != 0)
            {
                // 成功注入后的处理 - 不再调用任何DLL函数
                char debugMsg[256];
                snprintf(debugMsg, sizeof(debugMsg),
                         "Injector: DLL injected successfully at base: 0x%p",
                         (void *)hInjectedDllModule);
                OutputDebugStringA(debugMsg);

                MessageBoxW(hwnd, L"DLL 已成功注入。防截屏功能已自动激活。", L"注入成功", MB_OK | MB_ICONINFORMATION);
                SetWindowTextW(hStatusStatic, L"状态: 防截屏已激活。");
            }
            else
            {
                char debugMsg[256];
                snprintf(debugMsg, sizeof(debugMsg),
                         "Injector: DLL injection failed for PID %lu",
                         g_selectedProcessId);
                OutputDebugStringA(debugMsg);

                MessageBoxW(hwnd, L"DLL注入失败", L"错误", MB_OK | MB_ICONERROR);
                SetWindowTextW(hStatusStatic, L"状态: 注入失败。");
            }
            break;
        }
        }
        break;
    }
    // 处理鼠标移动时发送的预览信息
    case WM_USER_PREVIEW_PROCESS_INFO:
    {
        DWORD previewPid = (DWORD)wParam;
        std::wstring previewExeName;
        if (previewPid == 0)
        {
            previewExeName = L"无有效窗口";
            SetWindowTextW(hProcessNameStatic, previewExeName.c_str());
            SetWindowTextW(hProcessIdStatic, L"");
            SetWindowTextW(hStatusStatic, L"状态: 悬停于无效区域。"); // 更明确的提示
        }
        else
        {
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, previewPid);
            if (hProcess)
            {
                wchar_t processNameBuffer[MAX_PATH];
                if (GetModuleFileNameExW(hProcess, NULL, processNameBuffer, MAX_PATH))
                {
                    std::wstring fullPath(processNameBuffer);
                    size_t lastSlash = fullPath.find_last_of(L'\\');
                    previewExeName = (lastSlash == std::wstring::npos) ? fullPath : fullPath.substr(lastSlash + 1);
                }
                else
                {
                    previewExeName = L"无法获取名称";
                }
                CloseHandle(hProcess);
            }
            else
            {
                previewExeName = L"无法获取名称";
            }
            SetWindowTextW(hProcessNameStatic, previewExeName.c_str());
            SetWindowTextW(hProcessIdStatic, std::to_wstring(previewPid).c_str());
            SetWindowTextW(hStatusStatic, (L"状态: 悬停于 " + previewExeName + L", PID: " + std::to_wstring(previewPid)).c_str());
        }
        break;
    }

    case WM_USER_PROCESS_SELECTED:
    {
        // 从钩子回调接收选定的进程信息
        g_selectedProcessId = (DWORD)wParam;
        std::wstring *pExeName = reinterpret_cast<std::wstring *>(lParam); // 注意：这里需要清理
        g_selectedProcessNameW = *pExeName;
        delete pExeName; // 清理内存

        SetWindowTextW(hProcessNameStatic, g_selectedProcessNameW.c_str());
        SetWindowTextW(hProcessIdStatic, std::to_wstring(g_selectedProcessId).c_str());
        SetWindowTextW(hStatusStatic, L"状态: 已选择进程。");

        // 重新设置默认光标，钩子已经在回调函数中移除
        SetCursor(LoadCursor(NULL, IDC_ARROW));
        break;
    }

    case WM_CLOSE:
    {
        if (g_hMouseHook)
        { // 确保在关闭前取消钩子
            UnhookWindowsHookEx(g_hMouseHook);
            g_hMouseHook = NULL;
        }
        DestroyWindow(hwnd);
        break;
    }
    case WM_DESTROY:
    {
        PostQuitMessage(0);
        break;
    }
    // 处理WM_SETCURSOR消息，以在选择模式下显示十字光标
    case WM_SETCURSOR:
    {
        if (g_hMouseHook && LOWORD(lParam) == HTCLIENT)
        {
            SetCursor(LoadCursor(NULL, IDC_CROSS));
            return TRUE; // 已处理此消息
        }
        break;
    }
    }
    return DefWindowProcW(hwnd, uMsg, wParam, lParam);
}

// WinMain 是 GUI 应用程序的入口点
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
    // 关键修正：设置进程的 DPI 感知模式
    // 这是在 WinMain 的最开始执行，确保整个进程都正确处理 DPI 缩放
    // 优先使用 SetProcessDpiAwarenessContext (Windows 10, version 1607 及更高版本)
    // 如果该函数不可用 (旧版本Windows)，则回退到 SetProcessDpiAwareness
    HMODULE hUser32 = LoadLibraryW(L"user32.dll");
    if (hUser32)
    {
        typedef HRESULT(WINAPI * SetProcessDpiAwarenessContextFunc)(DPI_AWARENESS_CONTEXT);
        SetProcessDpiAwarenessContextFunc pSetProcessDpiAwarenessContext =
            (SetProcessDpiAwarenessContextFunc)GetProcAddress(hUser32, "SetProcessDpiAwarenessContext");

        if (pSetProcessDpiAwarenessContext)
        {
            // 推荐：Per-Monitor V2 DPI Aware，应用程序会根据显示器 DPI 变化调整
            pSetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
        }
        else
        {
            typedef HRESULT(WINAPI * SetProcessDpiAwarenessFunc)(PROCESS_DPI_AWARENESS);
            SetProcessDpiAwarenessFunc pSetProcessDpiAwareness =
                (SetProcessDpiAwarenessFunc)GetProcAddress(hUser32, "SetProcessDpiAwareness");
            if (pSetProcessDpiAwareness)
            {
                // 回退：System DPI Aware 或 Per-Monitor DPI Aware
                pSetProcessDpiAwareness(PROCESS_PER_MONITOR_DPI_AWARE); // 或者 PROCESS_SYSTEM_DPI_AWARE
            }
            else
            {
                // 如果以上函数都不可用 (非常旧的系统)，可能需要设置 SetProcessDPIAware()
                // 但通常不推荐混合使用旧 API
            }
        }
        FreeLibrary(hUser32); // 释放user32.dll的句柄
    }
    else
    {
        // No debug output needed here.
    }

    WNDCLASSEXW wc = {0}; // 初始化窗口类结构
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = WindowProc; // 窗口过程函数
    wc.hInstance = hInstance;
    wc.lpszClassName = L"InjectorWindowClass";     // 窗口类名称
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1); // 背景刷
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);      // 默认光标
    wc.hIcon = LoadIcon(NULL, IDI_APPLICATION);    // 默认图标
    wc.hIconSm = LoadIcon(NULL, IDI_APPLICATION);  // 小图标

    if (!RegisterClassExW(&wc))
    {
        MessageBoxW(NULL, L"无法注册窗口类!", L"错误", MB_OK | MB_ICONERROR);
        return 1;
    }

    // 创建主窗口
    HWND hwnd = CreateWindowExW(0, L"InjectorWindowClass", L"DLL 注入工具 (GUI)",
                                WS_OVERLAPPEDWINDOW | WS_VISIBLE,
                                CW_USEDEFAULT, CW_USEDEFAULT, 450, 220, // 窗口大小
                                NULL, NULL, hInstance, NULL);

    if (!hwnd)
    {
        MessageBoxW(NULL, L"无法创建窗口!", L"错误", MB_OK | MB_ICONERROR);
        return 1;
    }

    // 显示窗口
    ShowWindow(hwnd, nCmdShow);
    UpdateWindow(hwnd);

    // 消息循环
    MSG msg = {0};
    while (GetMessage(&msg, NULL, 0, 0))
    {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    return (int)msg.wParam;
}
