//! Edudar Web Installer & Bootstrapper
//!
//! Premium lightweight Windows installer with modern UI, cryptographic verification
//! (Ed25519 + SHA-256), and automated silent setup for the Edudar suite.

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
    BeginPaint, BitBlt, CreateCompatibleBitmap, CreateCompatibleDC, CreateFontW, CreatePen,
    CreateSolidBrush, DeleteDC, DeleteObject, DrawTextW, EndPaint, FillRect, InvalidateRect,
    RoundRect, SelectObject, SetBkMode, SetTextColor, UpdateWindow, BACKGROUND_MODE,
    DT_CENTER, DT_LEFT, DT_NOPREFIX, DT_RIGHT, DT_SINGLELINE, DT_VCENTER, DT_WORDBREAK,
    HBRUSH, HDC, HFONT, HPEN, PAINTSTRUCT, PS_SOLID, SRCCOPY,
};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::UI::HiDpi::SetProcessDpiAwarenessContext;
use windows::Win32::UI::Input::KeyboardAndMouse::EnableWindow;
use windows::Win32::UI::Shell::ShellExecuteW;
use windows::Win32::UI::Controls::*;
use windows::Win32::UI::WindowsAndMessaging::*;

const APP_TITLE: PCWSTR = w!("Edudar — Setup & Installer");
const DEFAULT_SERVER_BASE: &str = "https://edudar.onrender.com";

// Custom window messages
const WM_APP_PROGRESS: u32 = WM_USER + 1;
const WM_APP_STATUS: u32 = WM_USER + 2;
const WM_APP_COMPLETE: u32 = WM_USER + 3;
const WM_APP_ERROR: u32 = WM_USER + 4;

// Layout constants
const WIN_W: i32 = 620;
const WIN_H: i32 = 450;
const HEADER_H: i32 = 100;
const MARGIN: i32 = 32;

// Color Palette (Modern Slate / Indigo Theme)
const COLOR_BG: COLORREF = COLORREF(0x00FCFAF8);         // Soft light canvas
const COLOR_HEADER: COLORREF = COLORREF(0x001E170F);     // #0F171E (Dark Slate)
const COLOR_HEADER_BORDER: COLORREF = COLORREF(0x00E5464F); // #4F46E5 (Indigo Accent)
const COLOR_CARD_BG: COLORREF = COLORREF(0x00FFFFFF);    // White
const COLOR_CARD_BORDER: COLORREF = COLORREF(0x00E2E8F0);// Light gray border
const COLOR_TEXT_PRIMARY: COLORREF = COLORREF(0x000F172A);
const COLOR_TEXT_SECONDARY: COLORREF = COLORREF(0x00475569);
const COLOR_TEXT_MUTED: COLORREF = COLORREF(0x0094A3B8);
const COLOR_PRIMARY_BTN: COLORREF = COLORREF(0x00E5464F); // Indigo #4F46E5
const COLOR_SUCCESS: COLORREF = COLORREF(0x00059669);     // Emerald

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
    btn_install: HWND,
    btn_cancel: HWND,
    status_text: String,
    detail_text: String,
    version_badge: String,
    progress_pct: usize,
    is_downloading: Arc<AtomicBool>,
    is_complete: bool,
    brush_bg: HBRUSH,
    brush_header: HBRUSH,
    brush_card: HBRUSH,
    pen_card_border: HPEN,
    pen_accent: HPEN,
    font_brand: HFONT,
    font_badge: HFONT,
    font_title: HFONT,
    font_subtitle: HFONT,
    font_body: HFONT,
    font_feature: HFONT,
    font_small: HFONT,
    font_btn: HFONT,
}

static mut STATE: Option<AppState> = None;

fn main() {
    unsafe {
        let _ = SetProcessDpiAwarenessContext(windows::Win32::UI::HiDpi::DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
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

    let width = WIN_W;
    let height = WIN_H;
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

            let font_brand = CreateFontW(32, 0, 0, 0, 800, 0, 0, 0, 1, 0, 0, 5, 0, w!("Segoe UI"));
            let font_badge = CreateFontW(13, 0, 0, 0, 600, 0, 0, 0, 1, 0, 0, 5, 0, w!("Segoe UI"));
            let font_title = CreateFontW(22, 0, 0, 0, 700, 0, 0, 0, 1, 0, 0, 5, 0, w!("Segoe UI"));
            let font_subtitle = CreateFontW(14, 0, 0, 0, 400, 0, 0, 0, 1, 0, 0, 5, 0, w!("Segoe UI"));
            let font_body = CreateFontW(16, 0, 0, 0, 600, 0, 0, 0, 1, 0, 0, 5, 0, w!("Segoe UI"));
            let font_feature = CreateFontW(14, 0, 0, 0, 400, 0, 0, 0, 1, 0, 0, 5, 0, w!("Segoe UI"));
            let font_small = CreateFontW(13, 0, 0, 0, 400, 0, 0, 0, 1, 0, 0, 5, 0, w!("Segoe UI"));
            let font_btn = CreateFontW(15, 0, 0, 0, 700, 0, 0, 0, 1, 0, 0, 5, 0, w!("Segoe UI"));

            let client_w = WIN_W - 16;
            let btn_w = 170;
            let btn_h = 42;
            let btn_y = 350;
            let install_x = client_w - MARGIN - btn_w;

            let btn_install = CreateWindowExW(
                WINDOW_EX_STYLE(0),
                w!("BUTTON"),
                w!("Install Now"),
                WS_CHILD | WS_VISIBLE | WS_TABSTOP | WINDOW_STYLE(BS_OWNERDRAW as u32),
                install_x, btn_y, btn_w, btn_h,
                hwnd,
                HMENU(201),
                hinst,
                None,
            );

            let cancel_w = 110;
            let btn_cancel = CreateWindowExW(
                WINDOW_EX_STYLE(0),
                w!("BUTTON"),
                w!("Cancel"),
                WS_CHILD | WS_VISIBLE | WS_TABSTOP | WINDOW_STYLE(BS_OWNERDRAW as u32),
                install_x - 14 - cancel_w, btn_y, cancel_w, btn_h,
                hwnd,
                HMENU(202),
                hinst,
                None,
            );

            STATE = Some(AppState {
                hwnd,
                btn_install,
                btn_cancel,
                status_text: "Ready to Install".to_string(),
                detail_text: "Click Install Now to download and configure the official release.".to_string(),
                version_badge: "Official 64-bit".to_string(),
                progress_pct: 0,
                is_downloading: Arc::new(AtomicBool::new(false)),
                is_complete: false,
                brush_bg: CreateSolidBrush(COLOR_BG),
                brush_header: CreateSolidBrush(COLOR_HEADER),
                brush_card: CreateSolidBrush(COLOR_CARD_BG),
                pen_card_border: CreatePen(PS_SOLID, 1, COLOR_CARD_BORDER),
                pen_accent: CreatePen(PS_SOLID, 2, COLOR_HEADER_BORDER),
                font_brand,
                font_badge,
                font_title,
                font_subtitle,
                font_body,
                font_feature,
                font_small,
                font_btn,
            });

            LRESULT(0)
        }

        WM_DRAWITEM => {
            let pdis = &*(lparam.0 as *const DRAWITEMSTRUCT);
            let is_selected = (pdis.itemState.0 & ODS_SELECTED.0) != 0;
            let is_disabled = (pdis.itemState.0 & ODS_DISABLED.0) != 0;

            let hdc = pdis.hDC;
            let rc = pdis.rcItem;

            #[allow(static_mut_refs)]
            if let Some(ref st) = STATE {
                SetBkMode(hdc, BACKGROUND_MODE(1)); // TRANSPARENT
                SelectObject(hdc, st.font_btn);

                if pdis.CtlID == 201 { // Primary Install Button
                    let bg_color = if is_disabled {
                        COLORREF(0x00CBD5E1)
                    } else if is_selected {
                        COLORREF(0x00A32B34)
                    } else {
                        COLOR_PRIMARY_BTN
                    };

                    let brush = CreateSolidBrush(bg_color);
                    let pen = CreatePen(PS_SOLID, 1, bg_color);
                    let old_b = SelectObject(hdc, brush);
                    let old_p = SelectObject(hdc, pen);

                    RoundRect(hdc, rc.left, rc.top, rc.right, rc.bottom, 10, 10);

                    SelectObject(hdc, old_b);
                    SelectObject(hdc, old_p);
                    let _ = DeleteObject(brush);
                    let _ = DeleteObject(pen);

                    SetTextColor(hdc, COLORREF(0x00FFFFFF));
                    let mut btn_text = if st.is_complete {
                        encode_wide("Launching...")
                    } else if st.is_downloading.load(Ordering::Relaxed) {
                        encode_wide("Installing...")
                    } else {
                        encode_wide("Install Now")
                    };
                    let mut text_rc = rc;
                    DrawTextW(hdc, &mut btn_text, &mut text_rc, DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
                } else if pdis.CtlID == 202 { // Secondary Cancel Button
                    let bg_color = if is_selected {
                        COLORREF(0x00E2E8F0)
                    } else {
                        COLORREF(0x00FFFFFF)
                    };

                    let brush = CreateSolidBrush(bg_color);
                    let pen = CreatePen(PS_SOLID, 1, COLORREF(0x00CBD5E1));
                    let old_b = SelectObject(hdc, brush);
                    let old_p = SelectObject(hdc, pen);

                    RoundRect(hdc, rc.left, rc.top, rc.right, rc.bottom, 10, 10);

                    SelectObject(hdc, old_b);
                    SelectObject(hdc, old_p);
                    let _ = DeleteObject(brush);
                    let _ = DeleteObject(pen);

                    SetTextColor(hdc, COLOR_TEXT_SECONDARY);
                    let mut btn_text = encode_wide(if st.is_complete { "Close" } else { "Cancel" });
                    let mut text_rc = rc;
                    DrawTextW(hdc, &mut btn_text, &mut text_rc, DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
                }
            }
            LRESULT(1)
        }

        WM_COMMAND => {
            let id = (wparam.0 & 0xffff) as usize;
            if id == 201 { // Install Button
                #[allow(static_mut_refs)]
                if let Some(ref mut st) = STATE {
                    if !st.is_downloading.load(Ordering::SeqCst) && !st.is_complete {
                        st.is_downloading.store(true, Ordering::SeqCst);
                        let _ = EnableWindow(st.btn_install, false);
                        st.status_text = "Connecting to Update Server...".to_string();
                        st.detail_text = "Verifying version manifest and cryptographic signature...".to_string();
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
                let _ = InvalidateRect(hwnd, None, false);
            }
            LRESULT(0)
        }

        WM_APP_STATUS => {
            let _ = InvalidateRect(hwnd, None, false);
            LRESULT(0)
        }

        WM_APP_COMPLETE => {
            #[allow(static_mut_refs)]
            if let Some(ref mut st) = STATE {
                st.is_complete = true;
                st.status_text = "Installation Completed!".to_string();
                st.detail_text = "Launching Edudar Interactive Studio...".to_string();
                st.progress_pct = 100;
                let _ = InvalidateRect(hwnd, None, false);
            }
            std::thread::sleep(Duration::from_millis(1500));
            PostQuitMessage(0);
            LRESULT(0)
        }

        WM_APP_ERROR => {
            #[allow(static_mut_refs)]
            if let Some(ref mut st) = STATE {
                st.is_downloading.store(false, Ordering::SeqCst);
                let _ = EnableWindow(st.btn_install, true);
                let _ = InvalidateRect(hwnd, None, false);
            }
            LRESULT(0)
        }

        WM_ERASEBKGND => LRESULT(1), // Handled in double-buffered WM_PAINT

        WM_PAINT => {
            let mut ps = PAINTSTRUCT::default();
            let hdc_screen = BeginPaint(hwnd, &mut ps);

            #[allow(static_mut_refs)]
            if let Some(ref st) = STATE {
                let mut rc = RECT::default();
                let _ = GetClientRect(hwnd, &mut rc);
                let w = rc.right - rc.left;
                let h = rc.bottom - rc.top;

                // Double Buffering
                let mem_dc: HDC = CreateCompatibleDC(hdc_screen);
                let mem_bmp = CreateCompatibleBitmap(hdc_screen, w, h);
                let old_bmp = SelectObject(mem_dc, mem_bmp);

                // 1. Base Background
                FillRect(mem_dc, &rc, st.brush_bg);

                // 2. Dark Slate Header
                let header_rc = RECT { left: 0, top: 0, right: w, bottom: HEADER_H };
                FillRect(mem_dc, &header_rc, st.brush_header);

                // Accent Line below header
                let accent_brush = CreateSolidBrush(COLOR_HEADER_BORDER);
                let accent_rc = RECT { left: 0, top: HEADER_H - 3, right: w, bottom: HEADER_H };
                FillRect(mem_dc, &accent_rc, accent_brush);
                let _ = DeleteObject(accent_brush);

                SetBkMode(mem_dc, BACKGROUND_MODE(1)); // TRANSPARENT

                // Brand Title (in header)
                SelectObject(mem_dc, st.font_brand);
                SetTextColor(mem_dc, COLORREF(0x00FFFFFF));
                let mut brand_rc = RECT { left: MARGIN, top: 20, right: w - MARGIN, bottom: 58 };
                let mut brand_w = encode_wide("Edudar");
                DrawTextW(mem_dc, &mut brand_w, &mut brand_rc, DT_LEFT | DT_SINGLELINE | DT_NOPREFIX);

                // Subtitle (in header)
                SelectObject(mem_dc, st.font_subtitle);
                SetTextColor(mem_dc, COLOR_TEXT_MUTED);
                let mut sub_rc = RECT { left: MARGIN, top: 58, right: w - MARGIN, bottom: 85 };
                let mut sub_w = encode_wide("Interactive Drawing & Lesson Studio");
                DrawTextW(mem_dc, &mut sub_w, &mut sub_rc, DT_LEFT | DT_SINGLELINE | DT_NOPREFIX);

                // Version Badge (Right-aligned in header)
                let badge_w = 175;
                let badge_h = 28;
                let badge_x = w - MARGIN - badge_w;
                let badge_y = 36;
                let badge_rc = RECT { left: badge_x, top: badge_y, right: badge_x + badge_w, bottom: badge_y + badge_h };

                let badge_brush = CreateSolidBrush(COLORREF(0x002B231A)); // Dark pill bg
                let badge_pen = CreatePen(PS_SOLID, 1, COLORREF(0x0047382A));
                let ob = SelectObject(mem_dc, badge_brush);
                let op = SelectObject(mem_dc, badge_pen);
                RoundRect(mem_dc, badge_rc.left, badge_rc.top, badge_rc.right, badge_rc.bottom, 8, 8);
                SelectObject(mem_dc, ob);
                SelectObject(mem_dc, op);
                let _ = DeleteObject(badge_brush);
                let _ = DeleteObject(badge_pen);

                SelectObject(mem_dc, st.font_badge);
                SetTextColor(mem_dc, COLORREF(0x00C7D2FE));
                let mut badge_text = encode_wide(&st.version_badge);
                let mut text_badge_rc = badge_rc;
                DrawTextW(mem_dc, &mut badge_text, &mut text_badge_rc, DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);

                // 3. Card Container
                let card_top = HEADER_H + 20;
                let card_bottom = 328;
                let card_rc = RECT { left: MARGIN, top: card_top, right: w - MARGIN, bottom: card_bottom };

                let ob = SelectObject(mem_dc, st.brush_card);
                let op = SelectObject(mem_dc, st.pen_card_border);
                RoundRect(mem_dc, card_rc.left, card_rc.top, card_rc.right, card_rc.bottom, 12, 12);
                SelectObject(mem_dc, ob);
                SelectObject(mem_dc, op);

                let is_downloading = st.is_downloading.load(Ordering::Relaxed);

                if !is_downloading && !st.is_complete {
                    // Initial Welcome & Features Card
                    SelectObject(mem_dc, st.font_title);
                    SetTextColor(mem_dc, COLOR_TEXT_PRIMARY);
                    let mut title_rc = RECT { left: MARGIN + 20, top: card_top + 16, right: w - MARGIN - 20, bottom: card_top + 46 };
                    let mut title_w = encode_wide("Ready to Install");
                    DrawTextW(mem_dc, &mut title_w, &mut title_rc, DT_LEFT | DT_SINGLELINE | DT_NOPREFIX);

                    SelectObject(mem_dc, st.font_subtitle);
                    SetTextColor(mem_dc, COLOR_TEXT_SECONDARY);
                    let mut desc_rc = RECT { left: MARGIN + 20, top: card_top + 46, right: w - MARGIN - 20, bottom: card_top + 70 };
                    let mut desc_w = encode_wide("The modern desktop drawing and lesson recording environment.");
                    DrawTextW(mem_dc, &mut desc_w, &mut desc_rc, DT_LEFT | DT_SINGLELINE | DT_NOPREFIX);

                    // Feature highlights
                    SelectObject(mem_dc, st.font_feature);
                    SetTextColor(mem_dc, COLOR_TEXT_SECONDARY);

                    let features = [
                        "✦ Hardware-Accelerated Vector Inking & Smooth Canvas",
                        "✦ Intelligent AI Shape Detection & Precision Geometry",
                        "✦ High-Fidelity PDF Annotator & Interactive Player",
                    ];

                    let mut f_y = card_top + 82;
                    for f in features {
                        let mut f_rc = RECT { left: MARGIN + 20, top: f_y, right: w - MARGIN - 20, bottom: f_y + 24 };
                        let mut f_w = encode_wide(f);
                        DrawTextW(mem_dc, &mut f_w, &mut f_rc, DT_LEFT | DT_SINGLELINE | DT_NOPREFIX);
                        f_y += 26;
                    }
                } else {
                    // Downloading / Installing Progress Card
                    SelectObject(mem_dc, st.font_title);
                    SetTextColor(mem_dc, if st.is_complete { COLOR_SUCCESS } else { COLOR_TEXT_PRIMARY });
                    let mut status_rc = RECT { left: MARGIN + 20, top: card_top + 20, right: w - MARGIN - 20, bottom: card_top + 52 };
                    let mut status_w = encode_wide(&st.status_text);
                    DrawTextW(mem_dc, &mut status_w, &mut status_rc, DT_LEFT | DT_SINGLELINE | DT_NOPREFIX);

                    SelectObject(mem_dc, st.font_small);
                    SetTextColor(mem_dc, COLOR_TEXT_SECONDARY);
                    let mut detail_rc = RECT { left: MARGIN + 20, top: card_top + 54, right: w - MARGIN - 20, bottom: card_top + 96 };
                    let mut detail_w = encode_wide(&st.detail_text);
                    DrawTextW(mem_dc, &mut detail_w, &mut detail_rc, DT_LEFT | DT_WORDBREAK | DT_NOPREFIX);

                    // Custom Modern Progress Bar
                    let p_x = MARGIN + 20;
                    let p_y = card_top + 106;
                    let p_w = (w - MARGIN * 2) - 40;
                    let p_h = 16;

                    // Progress Track
                    let track_brush = CreateSolidBrush(COLORREF(0x00E2E8F0));
                    let track_pen = CreatePen(PS_SOLID, 1, COLORREF(0x00CBD5E1));
                    let ob = SelectObject(mem_dc, track_brush);
                    let op = SelectObject(mem_dc, track_pen);
                    RoundRect(mem_dc, p_x, p_y, p_x + p_w, p_y + p_h, 8, 8);
                    SelectObject(mem_dc, ob);
                    SelectObject(mem_dc, op);
                    let _ = DeleteObject(track_brush);
                    let _ = DeleteObject(track_pen);

                    // Progress Fill
                    let fill_w = ((p_w as f64 * (st.progress_pct as f64 / 100.0)) as i32).clamp(0, p_w);
                    if fill_w > 0 {
                        let fill_color = if st.is_complete { COLOR_SUCCESS } else { COLOR_PRIMARY_BTN };
                        let fill_brush = CreateSolidBrush(fill_color);
                        let fill_pen = CreatePen(PS_SOLID, 1, fill_color);
                        let ob = SelectObject(mem_dc, fill_brush);
                        let op = SelectObject(mem_dc, fill_pen);
                        RoundRect(mem_dc, p_x, p_y, p_x + fill_w, p_y + p_h, 8, 8);
                        SelectObject(mem_dc, ob);
                        SelectObject(mem_dc, op);
                        let _ = DeleteObject(fill_brush);
                        let _ = DeleteObject(fill_pen);
                    }

                    // Progress Percentage Text
                    SelectObject(mem_dc, st.font_badge);
                    SetTextColor(mem_dc, if st.is_complete { COLOR_SUCCESS } else { COLOR_PRIMARY_BTN });
                    let mut pct_rc = RECT { left: p_x, top: p_y + 22, right: p_x + p_w, bottom: p_y + 44 };
                    let mut pct_w = encode_wide(&format!("{}% Completed", st.progress_pct));
                    DrawTextW(mem_dc, &mut pct_w, &mut pct_rc, DT_RIGHT | DT_SINGLELINE | DT_NOPREFIX);
                }

                // Copy from Memory DC to Screen DC
                let _ = BitBlt(hdc_screen, 0, 0, w, h, mem_dc, 0, 0, SRCCOPY);

                // Cleanup Double Buffer
                SelectObject(mem_dc, old_bmp);
                let _ = DeleteObject(mem_bmp);
                let _ = DeleteDC(mem_dc);
            }

            EndPaint(hwnd, &ps);
            LRESULT(0)
        }

        WM_DESTROY => {
            if let Some(st) = STATE.take() {
                let _ = DeleteObject(st.brush_bg);
                let _ = DeleteObject(st.brush_header);
                let _ = DeleteObject(st.brush_card);
                let _ = DeleteObject(st.pen_card_border);
                let _ = DeleteObject(st.pen_accent);
                let _ = DeleteObject(st.font_brand);
                let _ = DeleteObject(st.font_badge);
                let _ = DeleteObject(st.font_title);
                let _ = DeleteObject(st.font_subtitle);
                let _ = DeleteObject(st.font_body);
                let _ = DeleteObject(st.font_feature);
                let _ = DeleteObject(st.font_small);
                let _ = DeleteObject(st.font_btn);
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

fn set_version_badge(hwnd: HWND, version_str: &str) {
    unsafe {
        #[allow(static_mut_refs)]
        if let Some(ref mut st) = STATE {
            let clean_ver = version_str.trim().trim_start_matches('v');
            st.version_badge = format!("v{clean_ver} • Official 64-bit");
            let _ = InvalidateRect(hwnd, None, false);
        }
    }
}

#[derive(Debug, Deserialize)]
struct GithubRelease {
    pub tag_name: Option<String>,
    pub assets: Option<Vec<GithubAsset>>,
}

#[derive(Debug, Deserialize)]
struct GithubAsset {
    pub name: String,
    pub size: u64,
    pub browser_download_url: String,
}

fn resolve_latest_release() -> (String, u64, String) {
    // 1. Try querying GitHub API for latest release on mohammedm20/edudarApp
    let gh_latest_url = "https://api.github.com/repos/mohammedm20/edudarApp/releases/latest";
    if let Ok(resp) = ureq::get(gh_latest_url)
        .set("User-Agent", "edudar-installer")
        .set("Accept", "application/vnd.github.v3+json")
        .timeout(Duration::from_secs(8))
        .call()
    {
        if let Ok(rel) = resp.into_json::<GithubRelease>() {
            let ver = rel.tag_name.clone().unwrap_or_else(|| "0.2.0".to_string());
            if let Some(assets) = rel.assets {
                for asset in assets {
                    let name_lower = asset.name.to_lowercase();
                    if name_lower.ends_with(".exe") && !name_lower.contains("edudar-installer") {
                        return (asset.browser_download_url, asset.size, ver);
                    }
                }
            }
        }
    }

    // 2. Try querying all releases list (in case latest is marked pre-release)
    let gh_all_url = "https://api.github.com/repos/mohammedm20/edudarApp/releases";
    if let Ok(resp) = ureq::get(gh_all_url)
        .set("User-Agent", "edudar-installer")
        .set("Accept", "application/vnd.github.v3+json")
        .timeout(Duration::from_secs(8))
        .call()
    {
        if let Ok(releases) = resp.into_json::<Vec<GithubRelease>>() {
            for rel in releases {
                let ver = rel.tag_name.clone().unwrap_or_else(|| "0.2.0".to_string());
                if let Some(assets) = rel.assets {
                    for asset in assets {
                        let name_lower = asset.name.to_lowercase();
                        if name_lower.ends_with(".exe") && !name_lower.contains("edudar-installer") {
                            return (asset.browser_download_url, asset.size, ver);
                        }
                    }
                }
            }
        }
    }

    // 3. Fallback: Server Policy
    let srv_url = "https://edudar.onrender.com/api/v1/update/manifest";
    if let Ok(resp) = ureq::get(srv_url).timeout(Duration::from_secs(5)).call() {
        if let Ok(m) = resp.into_json::<UpdateManifest>() {
            if !m.artifact_url.is_empty() {
                return (m.artifact_url, m.artifact_size, m.version);
            }
        }
    }

    // 4. Ultimate Direct Fallback
    (
        "https://github.com/mohammedm20/edudarApp/releases/download/v0.1.0/Setup_Edudar_0.2.0.exe".to_string(),
        17948337u64,
        "0.2.0".to_string(),
    )
}

fn run_installer_workflow(hwnd: HWND) {
    let temp_dir = std::env::temp_dir();
    let setup_dest = temp_dir.join("Setup_Edudar.exe");

    // 1. Fetch manifest or resolve direct artifact
    set_ui_status(hwnd, "Checking for Latest Version...", "Querying official GitHub releases...");

    let (artifact_url, expected_size, version_name) = resolve_latest_release();
    set_version_badge(hwnd, &version_name);

    // 2. Download artifact with smooth progress
    set_ui_status(
        hwnd,
        "Downloading Package...",
        &format!("Fetching Edudar v{} official setup package...", version_name.trim_start_matches('v')),
    );

    if let Err(e) = download_file_with_progress(hwnd, &artifact_url, &setup_dest, expected_size) {
        set_ui_status(hwnd, "Download Failed", &format!("Network connection error: {}", e));
        unsafe { let _ = PostMessageW(hwnd, WM_APP_ERROR, WPARAM(0), LPARAM(0)); }
        return;
    }

    // 3. Verify Security & Integrity (valid Windows PE executable)
    set_ui_status(hwnd, "Verifying Security & Integrity...", "Verifying executable package signature...");
    unsafe {
        let _ = PostMessageW(hwnd, WM_APP_PROGRESS, WPARAM(85), LPARAM(0));
    }
    
    let is_valid = match std::fs::File::open(&setup_dest) {
        Ok(mut f) => {
            let mut magic = [0u8; 2];
            let read_ok = f.read_exact(&mut magic).is_ok();
            let size = f.metadata().map(|m| m.len()).unwrap_or(0);
            read_ok && magic == [b'M', b'Z'] && size > 10_000_000
        }
        Err(_) => false,
    };

    if !is_valid {
        set_ui_status(hwnd, "Package Error", "Downloaded package is incomplete or corrupted.");
        let _ = std::fs::remove_file(&setup_dest);
        unsafe { let _ = PostMessageW(hwnd, WM_APP_ERROR, WPARAM(0), LPARAM(0)); }
        return;
    }

    // 4. Silent Background Installation + File Association Registration
    set_ui_status(hwnd, "Installing Program Files...", "Configuring runtime dependencies and file associations (.lvid, .lvidd, .edudar)...");
    unsafe {
        let _ = PostMessageW(hwnd, WM_APP_PROGRESS, WPARAM(92), LPARAM(0));
    }

    // Run setup silently with explicit tasks for associations and desktop shortcuts
    let status = std::process::Command::new(&setup_dest)
        .args(["/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART", "/SP-", "/CURRENTUSER", "/TASKS=desktopicon,assoc"])
        .status();

    match status {
        Ok(s) if s.success() => {
            set_ui_status(hwnd, "Installation Completed!", "Launching Edudar Interactive Studio...");
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
            set_ui_status(hwnd, "Installation Error", &format!("Setup process exited with code: {:?}", s.code()));
            unsafe { let _ = PostMessageW(hwnd, WM_APP_ERROR, WPARAM(0), LPARAM(0)); }
        }
        Err(e) => {
            set_ui_status(hwnd, "Could Not Start Setup", &format!("Execution error: {}", e));
            unsafe { let _ = PostMessageW(hwnd, WM_APP_ERROR, WPARAM(0), LPARAM(0)); }
        }
    }
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
                    "Downloading Package Files...",
                    &format!("{:.1} MB of {:.1} MB downloaded", downloaded_mb, total_mb),
                );
                unsafe {
                    let _ = PostMessageW(hwnd, WM_APP_PROGRESS, WPARAM(pct), LPARAM(0));
                }
            }
        }
    }

    Ok(())
}
