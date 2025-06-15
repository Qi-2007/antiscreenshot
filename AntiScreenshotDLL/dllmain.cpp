// dllmain.cpp
// 注入的DLL，用于设置目标进程窗口的防截屏属性，并在完成功能后自动卸载。

#include <windows.h>
#include <cstdio> // 用于 snprintf 和 OutputDebugStringA

#define DLLEXPORT __declspec(dllexport)

// 定义SetWindowDisplayAffinity函数的类型指针
typedef BOOL (WINAPI *PFN_SETWINDOWDISPLAYAFFINITY)(HWND, DWORD);

// 定义窗口显示亲和性标志 (如果未在头文件中定义)
#ifndef WDA_NONE
#define WDA_NONE                0x00000000
#endif
#ifndef WDA_EXCLUDEFROMCAPTURE
#define WDA_EXCLUDEFROMCAPTURE  0x00000011 // 排除在捕获之外的标志
#endif

// 全局变量用于窗口查找 (在EnumWindowsProc中使用)
static HWND g_foundHwnd = NULL;

/**
 * @brief EnumWindows的回调函数。
 * 用于查找属于当前进程的可见窗口。
 * @param hwnd 当前枚举到的窗口句柄。
 * @param lParam 用户定义参数 (在此例中未使用)。
 * @return BOOL 如果找到目标窗口，返回FALSE停止枚举；否则返回TRUE继续枚举。
 */
static BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam) {
    DWORD processId;
    // 获取当前窗口所属的进程 ID
    GetWindowThreadProcessId(hwnd, &processId);
    
    // 检查是否属于当前进程并且是可见窗口
    // 注意：被注入的DLL在目标进程的上下文中运行，所以GetCurrentProcessId()会返回目标进程的ID
    if (processId == GetCurrentProcessId() && IsWindowVisible(hwnd)) {
        // 找到符合条件的窗口，存储句柄并停止枚举
        g_foundHwnd = hwnd;
        return FALSE; // 返回FALSE停止枚举
    }
    return TRUE; // 返回TRUE继续枚举
}

/**
 * @brief 查找当前进程的主窗口或其他可见窗口。
 * @return HWND 找到的窗口句柄；如果未找到，返回NULL。
 */
HWND FindTargetWindow() {
    g_foundHwnd = NULL; // 重置全局变量
    EnumWindows(EnumWindowsProc, 0); // 枚举所有顶层窗口
    return g_foundHwnd;
}

/**
 * @brief 设置目标窗口的防截屏属性。
 * 调用SetWindowDisplayAffinity来防止窗口内容被屏幕截图或录制。
 */
void SetAntiScreenshot() {
    // 1. 尝试获取user32.dll的模块句柄
    // GetModuleHandleA 不会增加DLL的引用计数，所以不需要FreeLibrary
    HMODULE hUser32 = GetModuleHandleA("user32.dll");
    if (!hUser32) {
        OutputDebugStringA("SetAntiScreenshot: Failed to get handle for user32.dll");
        return;
    }
    
    // 2. 获取SetWindowDisplayAffinity函数的地址
    auto pSetWindowDisplayAffinity = reinterpret_cast<PFN_SETWINDOWDISPLAYAFFINITY>(
        GetProcAddress(hUser32, "SetWindowDisplayAffinity"));
    
    if (!pSetWindowDisplayAffinity) {
        OutputDebugStringA("SetAntiScreenshot: Failed to get SetWindowDisplayAffinity address");
        return;
    }
    
    // 3. 查找目标窗口
    HWND targetHwnd = FindTargetWindow();
    if (!targetHwnd) {
        OutputDebugStringA("SetAntiScreenshot: Failed to find target window in SetAntiScreenshot");
        return;
    }
    
    // 4. 设置防截屏属性
    // WDA_EXCLUDEFROMCAPTURE 标志将窗口内容标记为不应被截屏工具捕获
    if (!pSetWindowDisplayAffinity(targetHwnd, WDA_EXCLUDEFROMCAPTURE)) {
        char errorMsg[256];
        snprintf(errorMsg, sizeof(errorMsg), "SetAntiScreenshot: Failed to set affinity for HWND 0x%p. Error: %lu", targetHwnd, GetLastError());
        OutputDebugStringA(errorMsg);
    } else {
        char successMsg[256];
        snprintf(successMsg, sizeof(successMsg), "SetAntiScreenshot: Successfully set anti-screenshot affinity for HWND 0x%p", targetHwnd);
        OutputDebugStringA(successMsg);
    }
}

/**
 * @brief 独立线程函数，用于执行防截屏设置并随后卸载DLL。
 * @param lpParam 传入的参数，预期为当前DLL的HMODULE句柄。
 * @return DWORD 线程退出码。
 */
static DWORD WINAPI AntiScreenshotThread(LPVOID lpParam) {
    HMODULE hModule = static_cast<HMODULE>(lpParam); // 获取DLL自身的句柄

    // 循环尝试设置防截屏属性，以应对窗口可能尚未完全初始化的情况
    // 循环50次，每次间隔100毫秒，总共5秒
    OutputDebugStringA("AntiScreenshotThread: Starting anti-screenshot attempts.");
    for (int i = 0; i < 50; i++) {
        SetAntiScreenshot();
        Sleep(100); // 等待100毫秒
    }
    OutputDebugStringA("AntiScreenshotThread: Finished anti-screenshot attempts.");

    // 重要：在完成所有操作后，卸载DLL并退出线程。
    // FreeLibraryAndExitThread 是一个原子操作，确保在线程退出前DLL被安全卸载。
    OutputDebugStringA("AntiScreenshotThread: Unloading DLL and exiting thread.");
    FreeLibraryAndExitThread(hModule, 0); 
    
    return 0; // 此行代码实际上不会被执行，因为FreeLibraryAndExitThread已经处理了线程退出
}

/**
 * @brief DLL的入口点函数。
 * 当DLL被加载或卸载，或者进程/线程创建/终止时被调用。
 * @param hModule DLL模块的句柄。
 * @param ul_reason_for_call 调用原因。
 * @param lpReserved 保留参数。
 * @return BOOL 成功返回TRUE，失败返回FALSE。
 */
BOOL APIENTRY DllMain(HMODULE hModule,
                      DWORD ul_reason_for_call,
                      LPVOID lpReserved) {
    switch (ul_reason_for_call) {
        case DLL_PROCESS_ATTACH:
            // DLL被加载到进程时执行
            // 禁用线程通知，提高性能并避免不必要的DllMain调用
            DisableThreadLibraryCalls(hModule);
            
            // 创建一个新线程来执行防截屏设置。
            // 这样做是为了避免阻塞DLL_PROCESS_ATTACH，并允许DLL在后台执行其功能。
            // 将DLL自身的hModule传递给线程，以便线程可以安全地卸载它。
            CreateThread(NULL, 0, AntiScreenshotThread, hModule, 0, NULL);
            break;
        case DLL_PROCESS_DETACH:
            // DLL从进程中卸载时执行
            OutputDebugStringA("DllMain: DLL_PROCESS_DETACH received.");
            // 在此处理任何必要的清理工作，但由于DLL会自我卸载，这里的代码可能不会被执行
            break;
    }
    return TRUE; // 返回TRUE表示DllMain成功处理了调用
}

