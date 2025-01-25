const std = @import("std");
const windows = std.os.windows;
const TRAMPOLINE_SIZE: usize = 13;
const MB_OK = 0x00000000;
const MB_ICONQUESTION = 0x00000020;
const MB_IFONINFORMATION = 0x00000040;

pub extern "User32" fn MessageBoxA(
    hWnd: ?windows.HWND,
    lpText: ?windows.LPCSTR,
    lpCaption: ?windows.LPCSTR,
    uType: windows.UINT,
) callconv(windows.WINAPI) i32;

pub extern "user32" fn MessageBoxW(
    hWnd: ?windows.HWND,
    lpText: [*:0]const u16,
    lpCaption: [*:0]const u16,
    uType: windows.UINT,
) callconv(windows.WINAPI) i32;

const HookSt = struct {
    pFunctionToHook: ?*anyopaque = null,
    pFunctionToRun: ?*anyopaque = null,
    pOriginalBytes: [TRAMPOLINE_SIZE]u8 = undefined,
    dwOldProtection: windows.DWORD = 0,
};

fn InitializeHookStruct(pFunctionToHook: *anyopaque, pFunctionToRun: *anyopaque, Hook: *HookSt) !bool {
    Hook.pFunctionToHook = pFunctionToHook;
    Hook.pFunctionToRun = pFunctionToRun;

    @memcpy(&Hook.pOriginalBytes, @as([*]const u8, @ptrCast(pFunctionToHook))[0..TRAMPOLINE_SIZE]);

    _ = try windows.VirtualProtect(pFunctionToHook, TRAMPOLINE_SIZE, windows.PAGE_EXECUTE_READWRITE, &Hook.dwOldProtection);
    return true;
}

fn InstallHook(Hook: *HookSt) bool {
    var uTrampoline = [_]u8{ 0x49, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x41, 0xFF, 0xE2 };
    var uPatch: u64 = @intFromPtr(Hook.pFunctionToRun.?);

    @memcpy(uTrampoline[2..10], std.mem.asBytes(&uPatch));
    @memcpy(@as([*]u8, @ptrCast(Hook.pFunctionToHook.?))[0..TRAMPOLINE_SIZE], &uTrampoline);

    return true;
}

fn RemoveHook(Hook: *HookSt) !bool {
    if (Hook.dwOldProtection == 0 or Hook.pFunctionToHook == null) {
        return false;
    }

    var dwOldProtection: windows.DWORD = 0;

    @memcpy(@as([*]u8, @ptrCast(Hook.pFunctionToHook.?))[0..TRAMPOLINE_SIZE], &Hook.pOriginalBytes);

    //    @memset(Hook.pOriginalBytes, "\\0");
    Hook.pOriginalBytes = undefined;
    _ = try windows.VirtualProtect(Hook.pFunctionToHook.?, TRAMPOLINE_SIZE, Hook.dwOldProtection, &dwOldProtection);

    Hook.pFunctionToHook = null;
    Hook.pFunctionToRun = null;
    Hook.dwOldProtection = 0;
    return true;
}

fn MyMessageBoxA(hWnd: ?windows.HWND, lpText: ?windows.LPCSTR, lpCation: ?windows.LPCSTR, uType: windows.UINT) callconv(windows.WINAPI) i32 {
    _ = lpText;
    _ = lpCation;

    const allocator = std.heap.page_allocator;

    const title_utf16 = std.unicode.utf8ToUtf16LeAllocZ(allocator, "Messge C") catch return 0;
    defer allocator.free(title_utf16);

    const message_utf16 = std.unicode.utf8ToUtf16LeAllocZ(allocator, "Hooked MsgBox") catch return 0;
    defer allocator.free(message_utf16);

    return MessageBoxW(hWnd, title_utf16, message_utf16, uType);
}

pub fn main() !void {
    var st: HookSt = .{};
    const message_box_ptr: *anyopaque = @ptrCast(@constCast(&MessageBoxA));
    const my_message_box_ptr: *anyopaque = @ptrCast(@constCast(&MyMessageBoxA));
    _ = try InitializeHookStruct(message_box_ptr, my_message_box_ptr, &st);
    _ = MessageBoxA(null, "Message A", "Original MsgBox", MB_OK | MB_ICONQUESTION);

    _ = InstallHook(&st);

    _ = MessageBoxA(null, "Message B", "Original MsgBox", MB_OK | MB_ICONQUESTION);
    _ = try RemoveHook(&st);
    _ = MessageBoxA(null, "Message D", "Original MsgBox", MB_OK | MB_ICONQUESTION);
}
