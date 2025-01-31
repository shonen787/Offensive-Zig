const std = @import("std");
const print = std.debug.print;
const windows = std.os.windows;
const WH_MOUSE_LL = 14;
const WM_LBUTTONDOWN = 0x0201;
const WM_RBUTTONDOWN = 0x0204;
const WM_MBUTTONDOWN = 0x0207;
const MONITOR_TIME: usize = 20000;
const HANDLE = *anyopaque;
const HWND = *anyopaque;
const HINSTANCE = *anyopaque;
const HHOOK = *anyopaque;
const DWORD = u32;
const WPARAM = usize;
const LPARAM = isize;
const LRESULT = isize;
const BOOL = i32;
const UINT = u32;
const LONG = i32;
const HOOKPROC = *const fn (code: i32, wParam: WPARAM, lParam: LPARAM) callconv(WINAPI) LRESULT;
const WINAPI = std.os.windows.WINAPI;

const MSLLHOOKSTRUCT = struct {
    pt: windows.POINT,
    mouseData: windows.DWORD,
    flags: windows.DWORD,
    time: windows.DWORD,
    dwExtraInfo: windows.ULONG_PTR,
};

var g_hMouseHook: HHOOK = undefined;
const MSG = struct {
    hwnd: windows.HWND,
    message: windows.UINT,
    wParam: WPARAM,
    lParam: LPARAM,
    time: windows.DWORD,
    pt: windows.POINT,
    lPrivate: windows.DWORD,
};
// External Windows functions
extern "user32" fn SetWindowsHookExW(
    idHook: i32,
    lpfn: HOOKPROC,
    hmod: ?HINSTANCE,
    dwThreadId: DWORD,
) ?HHOOK;
extern "user32" fn GetMessageW(
    lpMsg: *MSG,
    hWnd: ?HWND,
    wMsgFilterMin: UINT,
    wMsgFilterMax: UINT,
) BOOL;
extern "user32" fn DefWindowProcW(
    hWnd: ?HWND,
    Msg: UINT,
    wParam: WPARAM,
    lParam: LPARAM,
) LRESULT;

extern "user32" fn CallNextHookEx(hhk: ?HHOOK, nCode: i32, wParam: WPARAM, lParam: LPARAM) windows.LRESULT;
extern "user32" fn UnhookWindowsHookEx(hhk: HHOOK) BOOL;
extern "user32" fn GetCursorPos(lpPoint: *windows.POINT) BOOL;

fn HookCallBack(nCode: i32, wParam: windows.WPARAM, lParam: windows.LPARAM) callconv(WINAPI) windows.LRESULT {
    var point: windows.POINT = undefined;
    _ = GetCursorPos(&point);
    switch (wParam) {
        WM_RBUTTONDOWN => print("[ # ] Right Mouse Click {any}\n", .{point}),
        WM_MBUTTONDOWN => print("[ # ] Middle Mouse Click {any} \n", .{point}),
        WM_LBUTTONDOWN => print("[ # ] Left Mouse Click {any}\n", .{point}),
        else => {},
    }

    return CallNextHookEx(null, nCode, wParam, lParam);
}

fn MouseClicksLogger(lpParam: ?*anyopaque) callconv(WINAPI) u32 {
    var Msg: MSG = undefined;
    _ = lpParam;

    g_hMouseHook = SetWindowsHookExW(WH_MOUSE_LL, HookCallBack, null, 0).?;

    while (GetMessageW(&Msg, null, 0, 0) != 0) {
        _ = DefWindowProcW(Msg.hwnd, Msg.message, Msg.wParam, Msg.lParam);
    }

    return 0;
}

pub fn main() !void {
    var hThread: windows.HANDLE = undefined;
    var dwThreadID: windows.DWORD = undefined;
    hThread = windows.kernel32.CreateThread(null, 0, MouseClicksLogger, null, 0, &dwThreadID).?;
    print("\t\t<<>> Thread {d} Is Created to monitor mouse clicks for {d} seconds <<>>\n\n", .{ dwThreadID, (MONITOR_TIME / 1000) });
    _ = windows.WaitForSingleObject(hThread, MONITOR_TIME) catch {};

    if (UnhookWindowsHookEx(g_hMouseHook) == 0) {
        print("[!] UnhookWindwsHookEx Failed with Error: {any}", .{windows.GetLastError()});
    }
}
