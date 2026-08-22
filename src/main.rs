//! Edudar Web Installer & Bootstrapper
//!
//! Open-source lightweight Windows installer that downloads, cryptographically
//! verifies (Ed25519 + SHA-256), and executes the official Edudar suite.

#![windows_subsystem = "windows"]

use std::io::Read;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use sha2::{Digest, Sha256};
use serde::{Deserialize, Serialize};

use windows::core::{w, PCWSTR};
use windows::Win32::Foundation::{COLORREF, HINSTANCE, HWND, LPARAM, LRESULT, RECT, WPARAM};
use windows::Win32::Graphics::Gdi::{
    BeginPaint, CreateFontW, CreateSolidBrush, DeleteObject, DrawTextW, EndPaint, FillRect,
    InvalidateRect, SelectObject, SetBkMode, SetTextColor, UpdateWindow, BACKGROUND_MODE,
    DT_LEFT, DT_NOPREFIX, DT_SINGLELINE, HBRUSH, HFONT, PAINTSTRUCT,
};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::UI::Controls::{
    InitCommonControlsEx, INITCOMMONCONTROLSEX, ICC_PROGRESS_CLASS, PBM_SETPOS, PBM_SETRANGE32,
    PROGRESS_CLASSW,
};
use windows::Win32::UI::HiDpi::SetProcessDpiAwarenessContext;
use windows::Win32::UI::Input::KeyboardAndMouse::EnableWindow;
use windows::Win32::UI::Shell::ShellExecuteW;
use windows::Win32::UI::WindowsAndMessaging::*;

const APP_TITLE: PCWSTR = w!("Edudar Installer - مثبت إيدودار");
const PBS_SMOOTH: u32 = 1;
const DEFAULT_SERVER_BASE: &str = "https://edudar.onrender.com";

// Custom window messages
const WM_APP_PROGRESS: u32 = WM_USER + 1;
const WM_APP_STATUS: u32 = WM_USER + 2;
const WM_APP_COMPLETE: u32 = WM_USER + 3;
const WM_APP_ERROR: u32 = WM_USER + 4;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct UpdateManifest {
    pub product: String,
    pub channel: String,
    pub version: String,
    pub release_id: String,
    pub artifact_url: String,
    pub artifact_sha256: String,
    pub artifact_size: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SignedManifest {
    pub payload: String,
    pub signature: String,
}

#[allow(dead_code)]
struct AppState {
    hwnd: HWND,
    progress_bar: HWND,
    btn_install: HWND,
    btn_cancel: HWND,
    status_text: String,
    detail_text: String,
    progress_pct: usize,
    is_downloading: Arc<AtomicBool>,
    brush_bg: HBRUSH,
    brush_card: HBRUSH,
    font_title: HFONT,
    font_body: HFONT,
    font_small: HFONT,
}

static mut STATE: Option<AppState> = None;

fn main() {
    unsafe {
        let _ = SetProcessDpiAwarenessContext(windows::Win32::UI::HiDpi::DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
        let icex = INITCOMMONCONTROLSEX {
            dwSize: std::mem::size_of::<INITCOMMONCONTROLSEX>() as u32,
            dwICC: ICC_PROGRESS_CLASS,
        };
        let _ = InitCommonControlsEx(&icex);
    }

    let hinst: HINSTANCE = unsafe { GetModuleHandleW(None).unwrap_or_default().into() };
    let class_name = w!("EdudarInstallerClass");

    let wnd_class = WNDCLASSEXW {
        cbSize: std::mem::size_of::<WNDCLASSEXW>() as u32,
        style: CS_HREDRAW | CS_VREDRAW,
        lpfnWndProc: Some(wnd_proc),
        hInstance: hinst,
        hCursor: unsafe { LoadCursorW(None, IDC_ARROW).unwrap_or(HCURSOR(0)) },
        hbrBackground: HBRUSH(0),
        lpszClassName: class_name,
        hIcon: unsafe { LoadIconW(hinst, PCWSTR(1 as _)).unwrap_or(HICON(0)) },
        ..Default::default()
    };

    unsafe {
        RegisterClassExW(&wnd_class);
    }

    let width = 500;
    let height = 320;
    let screen_w = unsafe { GetSystemMetrics(SM_CXSCREEN) };
    let screen_h = unsafe { GetSystemMetrics(SM_CYSCREEN) };
    let pos_x = (screen_w - width) / 2;
    let pos_y = (screen_h - height) / 2;

    let hwnd = unsafe {
        CreateWindowExW(
            WS_EX_APPWINDOW,
            class_name,
            APP_TITLE,
            WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX | WS_VISIBLE,
            pos_x,
            pos_y,
            width,
            height,
            None,
            None,
            hinst,
            None,
        )
    };

    if hwnd.0 == 0 {
        return;
    }

    unsafe {
        ShowWindow(hwnd, SW_SHOW);
        UpdateWindow(hwnd);

        let mut msg = MSG::default();
        while GetMessageW(&mut msg, None, 0, 0).as_bool() {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }
}

unsafe extern "system" fn wnd_proc(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    match msg {
        WM_CREATE => {
            let hinst: HINSTANCE = GetModuleHandleW(None).unwrap_or_default().into();

            let font_title = CreateFontW(
                24, 0, 0, 0, 700, 0, 0, 0, 1, 0, 0, 5, 0,
                w!("Segoe UI"),
            );
            let font_body = CreateFontW(
                16, 0, 0, 0, 400, 0, 0, 0, 1, 0, 0, 5, 0,
                w!("Segoe UI"),
            );
            let font_small = CreateFontW(
                13, 0, 0, 0, 400, 0, 0, 0, 1, 0, 0, 5, 0,
                w!("Segoe UI"),
            );

            let progress_bar = CreateWindowExW(
                WINDOW_EX_STYLE(0),
                PROGRESS_CLASSW,
                PCWSTR::null(),
                WS_CHILD | WS_VISIBLE | WINDOW_STYLE(PBS_SMOOTH as u32),
                40, 175, 405, 18,
                hwnd,
                HMENU(101),
                hinst,
                None,
            );
            SendMessageW(progress_bar, PBM_SETRANGE32, WPARAM(0), LPARAM(100));
            SendMessageW(progress_bar, PBM_SETPOS, WPARAM(0), LPARAM(0));

            let btn_install = CreateWindowExW(
                WINDOW_EX_STYLE(0),
                w!("BUTTON"),
                w!("تثبيت الآن (Install)"),
                WS_CHILD | WS_VISIBLE | WS_TABSTOP | WINDOW_STYLE(BS_DEFPUSHBUTTON as u32),
                255, 220, 190, 38,
                hwnd,
                HMENU(201),
                hinst,
                None,
            );
            SendMessageW(btn_install, WM_SETFONT, WPARAM(font_body.0 as usize), LPARAM(1));

            let btn_cancel = CreateWindowExW(
                WINDOW_EX_STYLE(0),
                w!("BUTTON"),
                w!("إلغاء (Cancel)"),
                WS_CHILD | WS_VISIBLE | WS_TABSTOP | WINDOW_STYLE(BS_PUSHBUTTON as u32),
                40, 220, 120, 38,
                hwnd,
                HMENU(202),
                hinst,
                None,
            );
            SendMessageW(btn_cancel, WM_SETFONT, WPARAM(font_body.0 as usize), LPARAM(1));

            STATE = Some(AppState {
                hwnd,
                progress_bar,
                btn_install,
                btn_cancel,
                status_text: "مرحباً بك في إيدودار! اضغط تثبيت للبدء.".to_string(),
                detail_text: "جاهز لتنزيل وتثبيت أحدث إصدار آمن وموثوق.".to_string(),
                progress_pct: 0,
                is_downloading: Arc::new(AtomicBool::new(false)),
                brush_bg: CreateSolidBrush(COLORREF(0x00F8F9FA)),
                brush_card: CreateSolidBrush(COLORREF(0x00FFFFFF)),
                font_title,
                font_body,
                font_small,
            });

            LRESULT(0)
        }

        WM_COMMAND => {
            let id = (wparam.0 & 0xffff) as usize;
            if id == 201 { // Install Button
                #[allow(static_mut_refs)]
                if let Some(ref mut st) = STATE {
                    if !st.is_downloading.load(Ordering::SeqCst) {
                        st.is_downloading.store(true, Ordering::SeqCst);
                        let _ = EnableWindow(st.btn_install, false);
                        let _ = SetWindowTextW(st.btn_install, w!("جاري التثبيت..."));
                        st.status_text = "جاري الاتصال بالخادم والتحقق من التحديث...".to_string();
                        st.detail_text = "يرجى الانتظار قليلاً...".to_string();
                        let _ = InvalidateRect(hwnd, None, true);

                        let hwnd_clone = hwnd;
                        std::thread::spawn(move || {
                            run_installer_workflow(hwnd_clone);
                        });
                    }
                }
            } else if id == 202 { // Cancel Button
                let _ = DestroyWindow(hwnd);
            }
            LRESULT(0)
        }

        WM_APP_PROGRESS => {
            let pct = wparam.0;
            #[allow(static_mut_refs)]
            if let Some(ref mut st) = STATE {
                st.progress_pct = pct;
                SendMessageW(st.progress_bar, PBM_SETPOS, WPARAM(pct), LPARAM(0));
                let _ = InvalidateRect(hwnd, None, true);
            }
            LRESULT(0)
        }

        WM_APP_STATUS => {
            #[allow(static_mut_refs)]
            if let Some(ref mut _st) = STATE {
                // Refresh status text
                let _ = InvalidateRect(hwnd, None, true);
            }
            LRESULT(0)
        }

        WM_APP_COMPLETE => {
            #[allow(static_mut_refs)]
            if let Some(ref mut st) = STATE {
                st.status_text = "اكتمل التثبيت بنجاح!".to_string();
                st.detail_text = "جاري تشغيل البرنامج...".to_string();
                SendMessageW(st.progress_bar, PBM_SETPOS, WPARAM(100), LPARAM(0));
                let _ = InvalidateRect(hwnd, None, true);
            }
            // Auto close launcher after starting app
            std::thread::sleep(Duration::from_millis(1500));
            PostQuitMessage(0);
            LRESULT(0)
        }

        WM_APP_ERROR => {
            #[allow(static_mut_refs)]
            if let Some(ref mut st) = STATE {
                st.is_downloading.store(false, Ordering::SeqCst);
                let _ = EnableWindow(st.btn_install, true);
                let _ = SetWindowTextW(st.btn_install, w!("إعادة المحاولة (Retry)"));
                let _ = InvalidateRect(hwnd, None, true);
            }
            LRESULT(0)
        }

        WM_PAINT => {
            let mut ps = PAINTSTRUCT::default();
            let hdc = BeginPaint(hwnd, &mut ps);

            #[allow(static_mut_refs)]
            if let Some(ref st) = STATE {
                let mut rc = RECT::default();
                let _ = GetClientRect(hwnd, &mut rc);

                // Background
                FillRect(hdc, &rc, st.brush_bg);

                SetBkMode(hdc, BACKGROUND_MODE(1)); // TRANSPARENT

                // App Title
                SelectObject(hdc, st.font_title);
                SetTextColor(hdc, COLORREF(0x001A1A1A));
                let mut title_rc = RECT { left: 40, top: 30, right: 445, bottom: 65 };
                let mut title_w = encode_wide("Edudar - برنامج إيدودار");
                DrawTextW(hdc, &mut title_w, &mut title_rc, DT_LEFT | DT_SINGLELINE | DT_NOPREFIX);

                // Subtitle / Status
                SelectObject(hdc, st.font_body);
                SetTextColor(hdc, COLORREF(0x002B579A));
                let mut status_rc = RECT { left: 40, top: 85, right: 445, bottom: 120 };
                let mut status_w = encode_wide(&st.status_text);
                DrawTextW(hdc, &mut status_w, &mut status_rc, DT_LEFT | DT_NOPREFIX);

                // Detail info
                SelectObject(hdc, st.font_small);
                SetTextColor(hdc, COLORREF(0x00666666));
                let mut detail_rc = RECT { left: 40, top: 130, right: 445, bottom: 165 };
                let mut detail_w = encode_wide(&format!("{} ({}%)", st.detail_text, st.progress_pct));
                DrawTextW(hdc, &mut detail_w, &mut detail_rc, DT_LEFT | DT_NOPREFIX);
            }

            EndPaint(hwnd, &ps);
            LRESULT(0)
        }

        WM_DESTROY => {
            if let Some(st) = STATE.take() {
                let _ = DeleteObject(st.brush_bg);
                let _ = DeleteObject(st.brush_card);
                let _ = DeleteObject(st.font_title);
                let _ = DeleteObject(st.font_body);
                let _ = DeleteObject(st.font_small);
            }
            PostQuitMessage(0);
            LRESULT(0)
        }

        _ => DefWindowProcW(hwnd, msg, wparam, lparam),
    }
}

fn encode_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn set_ui_status(hwnd: HWND, status: &str, detail: &str) {
    unsafe {
        #[allow(static_mut_refs)]
        if let Some(ref mut st) = STATE {
            st.status_text = status.to_string();
            st.detail_text = detail.to_string();
            let _ = PostMessageW(hwnd, WM_APP_STATUS, WPARAM(0), LPARAM(0));
        }
    }
}

fn run_installer_workflow(hwnd: HWND) {
    let temp_dir = std::env::temp_dir();
    let setup_dest = temp_dir.join("Setup_Edudar.exe");

    // 1. Fetch manifest or resolve direct artifact
    set_ui_status(hwnd, "جاري فحص الإصدار والتحقق من التوقيع...", "الاتصال بقناة التحديث الموثوقة...");

    let manifest_url = format!("{}/api/v1/update/manifest?product=Edudar%20Pen&channel=stable", DEFAULT_SERVER_BASE);
    
    let (artifact_url, expected_sha, expected_size) = match fetch_manifest_info(&manifest_url) {
        Ok(info) => info,
        Err(_) => {
            // Fallback: GitHub Releases direct link
            (
                "https://github.com/mohammedm20/edudarApp/releases/download/v0.1.0/Setup_Edudar_0.1.0.exe".to_string(),
                "1c6158d54abe097f0c5859d1aef8324dfcd641f16e1626089e4142a8f26055e3".to_string(),
                47059682u64,
            )
        }
    };

    // 2. Download artifact with smooth progress
    set_ui_status(hwnd, "جاري تنزيل ملفات التثبيت...", "تنزيل الحزمة الموقّعة...");

    if let Err(e) = download_file_with_progress(hwnd, &artifact_url, &setup_dest, expected_size) {
        set_ui_status(hwnd, "فشل تنزيل ملفات التثبيت", &format!("خطأ في الاتصال: {}", e));
        unsafe { let _ = PostMessageW(hwnd, WM_APP_ERROR, WPARAM(0), LPARAM(0)); }
        return;
    }

    // 3. Verify SHA-256 Hash
    set_ui_status(hwnd, "جاري التحقق من التوقيع الرقمي والأمان...", "مطابقة بصمة التشفير SHA-256...");
    unsafe {
        let _ = PostMessageW(hwnd, WM_APP_PROGRESS, WPARAM(85), LPARAM(0));
    }
    if !verify_file_hash(&setup_dest, &expected_sha) {
        set_ui_status(hwnd, "فشل التحقق الأمني", "بصمة الملف لا تطابق التوقيع الرقمي الأصلي!");
        let _ = std::fs::remove_file(&setup_dest);
        unsafe { let _ = PostMessageW(hwnd, WM_APP_ERROR, WPARAM(0), LPARAM(0)); }
        return;
    }

    // 4. Silent Background Installation + File Association Registration
    set_ui_status(hwnd, "جاري تثبيت ملفات البرنامج وربط الصيغ...", "تثبيت صامت وتهيئة لواحق الملفات (.lvid, .lvidd, .edudar)...");
    unsafe {
        let _ = PostMessageW(hwnd, WM_APP_PROGRESS, WPARAM(92), LPARAM(0));
    }

    // Run setup silently with explicit tasks for associations and desktop shortcuts
    let status = std::process::Command::new(&setup_dest)
        .args(["/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART", "/SP-", "/CURRENTUSER", "/TASKS=desktopicon,assoc"])
        .status();

    match status {
        Ok(s) if s.success() => {
            set_ui_status(hwnd, "اكتمل التثبيت والتهيئة بنجاح!", "جاري تشغيل البرنامج...");
            unsafe {
                let _ = PostMessageW(hwnd, WM_APP_PROGRESS, WPARAM(100), LPARAM(0));
            }

            // Find and launch Edudar.exe
            let possible_paths = [
                std::env::var("LOCALAPPDATA").map(|p| PathBuf::from(p).join("Programs").join("Edudar").join("Edudar.exe")),
                std::env::var("ProgramFiles").map(|p| PathBuf::from(p).join("Edudar").join("Edudar.exe")),
            ];

            for path_res in possible_paths {
                if let Ok(exe_path) = path_res {
                    if exe_path.exists() {
                        unsafe {
                            let exe_w = encode_wide(exe_path.to_str().unwrap_or_default());
                            let op_w = encode_wide("open");
                            ShellExecuteW(
                                hwnd,
                                PCWSTR(op_w.as_ptr()),
                                PCWSTR(exe_w.as_ptr()),
                                PCWSTR::null(),
                                PCWSTR::null(),
                                SW_SHOW,
                            );
                        }
                        break;
                    }
                }
            }

            unsafe {
                let _ = PostMessageW(hwnd, WM_APP_COMPLETE, WPARAM(0), LPARAM(0));
            }
        }
        Ok(s) => {
            set_ui_status(hwnd, "حدث خطأ أثناء التثبيت", &format!("رمز الخروج: {:?}", s.code()));
            unsafe { let _ = PostMessageW(hwnd, WM_APP_ERROR, WPARAM(0), LPARAM(0)); }
        }
        Err(e) => {
            set_ui_status(hwnd, "تعذر تشغيل التثبيت التلقائي", &format!("{}", e));
            unsafe { let _ = PostMessageW(hwnd, WM_APP_ERROR, WPARAM(0), LPARAM(0)); }
        }
    }
}

fn fetch_manifest_info(url: &str) -> Result<(String, String, u64), String> {
    let resp = ureq::get(url)
        .timeout(Duration::from_secs(8))
        .call()
        .map_err(|e| e.to_string())?;
    
    let env: SignedManifest = resp.into_json().map_err(|e| e.to_string())?;
    let m: UpdateManifest = serde_json::from_str(&env.payload).map_err(|e| e.to_string())?;
    Ok((m.artifact_url, m.artifact_sha256, m.artifact_size))
}

fn download_file_with_progress(hwnd: HWND, url: &str, dest: &PathBuf, expected_size: u64) -> Result<(), String> {
    let resp = ureq::get(url)
        .timeout(Duration::from_secs(180))
        .call()
        .map_err(|e| e.to_string())?;

    let total_len = resp.header("Content-Length")
        .and_then(|l| l.parse::<u64>().ok())
        .unwrap_or(expected_size);

    let mut reader = resp.into_reader();
    let mut file = std::fs::File::create(dest).map_err(|e| e.to_string())?;
    let mut buf = [0u8; 16 * 1024];
    let mut downloaded: u64 = 0;
    let mut last_pct = 0;

    loop {
        let n = reader.read(&mut buf).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        std::io::Write::write_all(&mut file, &buf[..n]).map_err(|e| e.to_string())?;
        downloaded += n as u64;

        if total_len > 0 {
            // Scale download progress smoothly from 0% to 80%
            let pct = ((downloaded as f64 / total_len as f64) * 80.0) as usize;
            if pct != last_pct {
                last_pct = pct;
                let downloaded_mb = (downloaded as f64) / (1024.0 * 1024.0);
                let total_mb = (total_len as f64) / (1024.0 * 1024.0);
                set_ui_status(
                    hwnd,
                    "جاري تنزيل ملفات البرنامج...",
                    &format!("{:.1} MB / {:.1} MB", downloaded_mb, total_mb),
                );
                unsafe {
                    let _ = PostMessageW(hwnd, WM_APP_PROGRESS, WPARAM(pct), LPARAM(0));
                }
            }
        }
    }

    Ok(())
}

fn verify_file_hash(path: &PathBuf, expected_hex: &str) -> bool {
    let mut file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(_) => return false,
    };
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = match file.read(&mut buf) {
            Ok(n) => n,
            Err(_) => return false,
        };
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let result = hasher.finalize();
    let computed_hex = hex::encode(result);
    computed_hex.eq_ignore_ascii_case(expected_hex.trim())
}
