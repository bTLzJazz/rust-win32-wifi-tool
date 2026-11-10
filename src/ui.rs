use crate::{
    charts::{self, Chart, SAMPLES},
    diagnostics,
    network::{self, Ping, Scan, Snapshot},
};
use std::{
    cell::RefCell,
    collections::VecDeque,
    fs,
    mem::size_of,
    os::windows::{ffi::OsStringExt, process::CommandExt},
    path::PathBuf,
    process::{Command, Stdio},
    ptr::{null, null_mut},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, Sender},
    },
    thread,
};
use windows_sys::{
    Win32::{
        Foundation::*,
        Graphics::Gdi::*,
        System::{LibraryLoader::GetModuleHandleW, SystemInformation::GetLocalTime},
        UI::{
            Controls::{Dialogs::*, *},
            HiDpi::GetDpiForWindow,
            Input::KeyboardAndMouse::{EnableWindow, SetFocus},
            Shell::ShellExecuteW,
            WindowsAndMessaging::*,
        },
    },
    core::{PCWSTR, w},
};

const WINDOW_CLASS: PCWSTR = w!("WifiToolMainWindow");
const WINDOW_TITLE: PCWSTR = w!("WiFi 检测优化助手");
const RESCAN: usize = 101;
const EXPORT: usize = 102;
const PING: usize = 103;
const FLUSH: usize = 104;
const ROUTER: usize = 105;
const WIFI: usize = 106;
const LOCATION: usize = 107;
const SIGNAL_CHART: usize = 108;
const CHANNEL_CHART: usize = 109;
const TAB: usize = 110;
const OWNER_DRAW_STATIC: u32 = 0x000d;
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

pub fn run() {
    unsafe {
        let instance = GetModuleHandleW(null());
        let common = INITCOMMONCONTROLSEX {
            dwSize: size_of::<INITCOMMONCONTROLSEX>() as u32,
            dwICC: ICC_TAB_CLASSES | ICC_LISTVIEW_CLASSES,
        };
        InitCommonControlsEx(&common);
        let class = WNDCLASSW {
            lpfnWndProc: Some(window_proc),
            hInstance: instance,
            hCursor: LoadCursorW(null_mut(), IDC_ARROW),
            hIcon: LoadIconW(null_mut(), IDI_APPLICATION),
            hbrBackground: GetSysColorBrush(COLOR_BTNFACE),
            lpszClassName: WINDOW_CLASS,
            ..Default::default()
        };
        if RegisterClassW(&class) == 0 {
            message(
                null_mut(),
                "启动失败",
                &std::io::Error::last_os_error().to_string(),
                MB_ICONERROR,
            );
            return;
        }
        let hwnd = CreateWindowExW(
            0,
            WINDOW_CLASS,
            WINDOW_TITLE,
            WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            null_mut(),
            null_mut(),
            instance,
            null(),
        );
        if hwnd.is_null() {
            message(
                null_mut(),
                "启动失败",
                &std::io::Error::last_os_error().to_string(),
                MB_ICONERROR,
            );
            return;
        }
        let dpi = GetDpiForWindow(hwnd).max(96) as i32;
        let app = Box::new(RefCell::new(App::new(hwnd, instance, dpi)));
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, (&*app as *const RefCell<App>) as isize);
        let mut work = RECT::default();
        SystemParametersInfoW(SPI_GETWORKAREA, 0, (&mut work as *mut RECT).cast(), 0);
        let width = px(1010, dpi).min((work.right - work.left).max(px(900, dpi)));
        let height = px(745, dpi).min((work.bottom - work.top).max(px(630, dpi)));
        SetWindowPos(
            hwnd,
            null_mut(),
            0,
            0,
            width,
            height,
            SWP_NOMOVE | SWP_NOZORDER,
        );
        {
            let mut app = app.borrow_mut();
            for control in [app.title, app.status, app.tabs] {
                ShowWindow(control, SW_SHOW);
            }
            app.select_page(0);
        }
        SetTimer(hwnd, 1, 150, None);
        ShowWindow(hwnd, SW_SHOW);
        UpdateWindow(hwnd);
        SetFocus(app.borrow().tabs);
        let mut msg = MSG::default();
        while GetMessageW(&mut msg, null_mut(), 0, 0) > 0 {
            if IsDialogMessageW(hwnd, &msg) == 0 {
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
        }
    }
}

unsafe extern "system" fn window_proc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    unsafe {
        if msg == WM_DESTROY {
            KillTimer(hwnd, 1);
            SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
            PostQuitMessage(0);
            return 0;
        }
        let state = GetWindowLongPtrW(hwnd, GWLP_USERDATA) as *const RefCell<App>;
        if let Some(state) = state.as_ref() {
            // Native controls may synchronously send messages during an update.
            if let Ok(mut app) = state.try_borrow_mut() {
                match msg {
                    WM_SIZE => app.layout(),
                    WM_GETMINMAXINFO => {
                        let min = &mut *(lparam as *mut MINMAXINFO);
                        min.ptMinTrackSize.x = app.px(900);
                        min.ptMinTrackSize.y = app.px(630);
                    }
                    WM_TIMER if wparam == 1 => app.update(),
                    WM_COMMAND if (wparam >> 16) & 0xffff == 0 && lparam != 0 => {
                        app.command(wparam & 0xffff);
                    }
                    WM_NOTIFY if lparam != 0 => {
                        let header = &*(lparam as *const NMHDR);
                        if header.hwndFrom == app.tabs && header.code == TCN_SELCHANGE {
                            let tab = SendMessageW(app.tabs, TCM_GETCURSEL, 0, 0);
                            if (0..4).contains(&tab) {
                                app.select_page(tab as usize);
                            }
                        } else {
                            return DefWindowProcW(hwnd, msg, wparam, lparam);
                        }
                    }
                    WM_DRAWITEM if lparam != 0 => {
                        let item = &*(lparam as *const DRAWITEMSTRUCT);
                        let chart = match wparam {
                            SIGNAL_CHART => Chart::Signal(&app.history, &app.snapshot),
                            CHANNEL_CHART => Chart::Channels(&app.snapshot),
                            _ => return DefWindowProcW(hwnd, msg, wparam, lparam),
                        };
                        charts::draw(item, app.small_font, app.dpi, chart);
                        return 1;
                    }
                    _ => return DefWindowProcW(hwnd, msg, wparam, lparam),
                }
                return 0;
            }
        }
        DefWindowProcW(hwnd, msg, wparam, lparam)
    }
}

#[derive(Clone, Copy)]
struct Overview {
    connection_title: HWND,
    rows: HWND,
    score_title: HWND,
    score: HWND,
    score_note: HWND,
    chart_title: HWND,
    chart: HWND,
}

#[derive(Clone, Copy)]
struct Networks {
    title: HWND,
    list: HWND,
    chart_title: HWND,
    chart: HWND,
    summary: HWND,
}

#[derive(Clone, Copy)]
struct Latency {
    start: HWND,
    status: HWND,
    list: HWND,
    help: HWND,
}

#[derive(Clone, Copy)]
struct Recommendations {
    title: HWND,
    body: HWND,
    buttons: [HWND; 4],
}

enum TaskResult {
    Ping(Vec<Ping>, Option<f64>),
    Flush(Result<(), String>),
}

struct App {
    hwnd: HWND,
    dpi: i32,
    font: HFONT,
    title_font: HFONT,
    heading_font: HFONT,
    small_font: HFONT,
    title: HWND,
    status: HWND,
    scan: HWND,
    export: HWND,
    tabs: HWND,
    overview: Overview,
    networks: Networks,
    latency: Latency,
    recommendations: Recommendations,
    pages: [Vec<HWND>; 4],
    snapshot: Snapshot,
    history: VecDeque<Option<u32>>,
    pings: Vec<Ping>,
    dns_ms: Option<f64>,
    ping_active: Arc<AtomicBool>,
    rescan_requested: bool,
    advice_text: String,
    monitor: Receiver<Snapshot>,
    refresh: Sender<()>,
    tasks: Receiver<TaskResult>,
    task_sender: Sender<TaskResult>,
}

impl App {
    fn new(hwnd: HWND, instance: HINSTANCE, dpi: i32) -> Self {
        let font = font(15, FW_NORMAL, dpi);
        let title_font = self::font(25, FW_BOLD, dpi);
        let heading_font = self::font(16, FW_SEMIBOLD, dpi);
        let small_font = self::font(12, FW_NORMAL, dpi);
        let factory = Controls {
            hwnd,
            instance,
            font,
        };

        let title = factory.label("WiFi 检测优化助手", title_font);
        let status = factory.label("正在读取网络信息…", font);
        let scan = factory.button("重新检测", RESCAN);
        let export = factory.button("导出报告", EXPORT);
        let tabs = factory.create(WC_TABCONTROLW, "", WS_TABSTOP | WS_CLIPSIBLINGS, 0, TAB);
        let padding = (px(5, dpi) << 16) | px(10, dpi);
        unsafe { SendMessageW(tabs, TCM_SETPADDING, 0, padding as isize) };
        for (index, title) in ["概览", "周边网络与信道", "延迟测试", "优化建议"]
            .into_iter()
            .enumerate()
        {
            let mut title = wide(title);
            let tab = TCITEMW {
                mask: TCIF_TEXT,
                pszText: title.as_mut_ptr(),
                ..Default::default()
            };
            send(tabs, TCM_INSERTITEMW, index, &tab);
        }
        let overview = Overview {
            connection_title: factory.label("当前连接与 IPv4 路由", heading_font),
            rows: factory.list(&["项目", "值"], true),
            score_title: factory.label("网络健康评分", heading_font),
            score: factory.label("—", title_font),
            score_note: factory.label("数据不足，等待检测结果", font),
            chart_title: factory.label("实时信号 · 最近 120 次采样", heading_font),
            chart: factory.create(
                w!("STATIC"),
                "",
                OWNER_DRAW_STATIC,
                WS_EX_CLIENTEDGE,
                SIGNAL_CHART,
            ),
        };
        let networks = Networks {
            title: factory.label("周边接入点 · 按信号强度排列", heading_font),
            list: factory.list(
                &[
                    "网络名称",
                    "信号 / RSSI",
                    "频段",
                    "信道",
                    "协议",
                    "安全模式",
                    "接入点 MAC",
                ],
                false,
            ),
            chart_title: factory.label(
                "信道拥挤度 · 蓝色为当前信道，绿色为建议 · 柱上数字为接入点数量",
                heading_font,
            ),
            chart: factory.create(
                w!("STATIC"),
                "",
                OWNER_DRAW_STATIC,
                WS_EX_CLIENTEDGE,
                CHANNEL_CHART,
            ),
            summary: factory.label("等待扫描结果…", font),
        };
        let latency = Latency {
            start: factory.button("开始延迟测试", PING),
            status: factory.label(
                "并行测试多个目标，每个目标发送 8 个 IPv4 ICMP 探测包，约需 8–12 秒。",
                font,
            ),
            list: factory.list(
                &[
                    "目标", "地址", "平均", "最低", "最高", "抖动", "丢包", "评价",
                ],
                false,
            ),
            help: factory.label(
                concat!(
                    "网关延迟反映本机到网关的链路情况。\r\n",
                    "网关稳定而外网延迟偏高时，可检查宽带线路。部分目标会屏蔽 ICMP。\r\n",
                    "抖动是相邻两次成功应答的延迟差的平均值。域名解析计时可能包含缓存命中。"
                ),
                font,
            ),
        };
        let recommendations = Recommendations {
            title: factory.label("诊断结果与优化建议", heading_font),
            body: factory.create(
                w!("EDIT"),
                "正在收集数据…",
                WS_TABSTOP
                    | WS_VSCROLL
                    | ES_MULTILINE as u32
                    | ES_AUTOVSCROLL as u32
                    | ES_READONLY as u32,
                WS_EX_CLIENTEDGE,
                0,
            ),
            buttons: [
                factory.button("刷新 DNS 缓存", FLUSH),
                factory.button("打开路由器管理页", ROUTER),
                factory.button("打开 WiFi 设置", WIFI),
                factory.button("打开位置权限设置", LOCATION),
            ],
        };
        let pages = [
            vec![
                overview.connection_title,
                overview.rows,
                overview.score_title,
                overview.score,
                overview.score_note,
                overview.chart_title,
                overview.chart,
            ],
            vec![
                networks.title,
                networks.list,
                networks.chart_title,
                networks.chart,
                networks.summary,
            ],
            vec![latency.start, latency.status, latency.list, latency.help],
            [
                vec![recommendations.title, recommendations.body],
                recommendations.buttons.to_vec(),
            ]
            .concat(),
        ];
        // Page controls are siblings of the tab and must paint above its background.
        unsafe { SetWindowPos(tabs, HWND_BOTTOM, 0, 0, 0, 0, SWP_NOSIZE | SWP_NOMOVE) };
        let (refresh, requests) = mpsc::channel();
        let (output, monitor) = mpsc::channel();
        let (task_sender, tasks) = mpsc::channel();
        let ping_active = Arc::new(AtomicBool::new(false));
        let testing = ping_active.clone();
        thread::spawn(move || network::monitor(requests, output, testing));
        Self {
            hwnd,
            dpi,
            font,
            title_font,
            heading_font,
            small_font,
            title,
            status,
            scan,
            export,
            tabs,
            overview,
            networks,
            latency,
            recommendations,
            pages,
            snapshot: Snapshot::default(),
            history: VecDeque::with_capacity(SAMPLES),
            pings: Vec::new(),
            dns_ms: None,
            ping_active,
            rescan_requested: false,
            advice_text: String::new(),
            monitor,
            refresh,
            tasks,
            task_sender,
        }
    }

    fn px(&self, value: i32) -> i32 {
        px(value, self.dpi)
    }

    fn select_page(&mut self, index: usize) {
        for (page, controls) in self.pages.iter().enumerate() {
            for &control in controls {
                unsafe { ShowWindow(control, if page == index { SW_SHOW } else { SW_HIDE }) };
            }
        }
        self.layout();
        self.invalidate_charts();
    }

    fn layout(&self) {
        let mut rect = RECT::default();
        unsafe { GetClientRect(self.hwnd, &mut rect) };
        let w = rect.right * 96 / self.dpi;
        let h = rect.bottom * 96 / self.dpi;
        if w < 600 || h < 490 {
            return;
        }
        let place = |handle, x, y, width, height| unsafe {
            MoveWindow(
                handle,
                self.px(x),
                self.px(y),
                self.px(width),
                self.px(height),
                1,
            );
        };
        place(self.title, 18, 14, w - 264, 35);
        place(self.status, 19, 50, w - 38, 23);
        place(self.scan, w - 234, 19, 102, 32);
        place(self.export, w - 122, 19, 104, 32);
        place(self.tabs, 16, 76, w - 32, h - 92);
        let mut body = RECT {
            left: 0,
            top: 0,
            right: self.px(w - 32),
            bottom: self.px(h - 92),
        };
        unsafe {
            SendMessageW(
                self.tabs,
                TCM_ADJUSTRECT,
                0,
                (&mut body as *mut RECT) as isize,
            )
        };
        let x = 27 + body.left * 96 / self.dpi;
        let y = 86 + body.top * 96 / self.dpi;
        let width = w - 2 * x;
        let height = 65 + body.bottom * 96 / self.dpi - y;
        let put = |handle, dx, dy, width, height| place(handle, x + dx, y + dy, width, height);

        let left = width - 244;
        let rows_h = 258;
        let o = self.overview;
        put(o.connection_title, 0, 0, left, 22);
        put(o.rows, 0, 25, left, rows_h);
        column_widths(o.rows, left, &[32, 68], self.dpi);
        put(o.score_title, left + 23, 0, 221, 22);
        put(o.score, left + 23, 35, 221, 42);
        put(o.score_note, left + 23, 79, 221, 65);
        put(o.chart_title, 0, rows_h + 38, width, 22);
        put(o.chart, 0, rows_h + 64, width, height - rows_h - 66);

        let n = self.networks;
        let chart_y = height - 206;
        put(n.title, 0, 0, width, 23);
        put(n.list, 0, 25, width, chart_y - 35);
        column_widths(n.list, width, &[25, 15, 10, 7, 10, 16, 17], self.dpi);
        put(n.chart_title, 0, chart_y, width, 24);
        put(n.chart, 0, chart_y + 26, width, 142);
        put(n.summary, 0, chart_y + 174, width, 32);

        let p = self.latency;
        put(p.start, 0, 0, 138, 32);
        put(p.status, 152, 7, width - 152, 25);
        put(p.list, 0, 44, width, 160);
        column_widths(p.list, width, &[15, 18, 10, 10, 10, 10, 9, 18], self.dpi);
        put(p.help, 1, 221, width - 2, 100);

        let a = self.recommendations;
        put(a.title, 0, 0, width, 22);
        put(a.body, 0, 25, width, height - 72);
        let mut dx = 0;
        for (button, bw) in a.buttons.into_iter().zip([132, 156, 132, 156]) {
            put(button, dx, height - 35, bw, 32);
            dx += bw + 9;
        }
    }

    fn update(&mut self) {
        while let Ok(snapshot) = self.monitor.try_recv() {
            let first = self.history.is_empty();
            let connection_changed = first
                || self.snapshot.connection != snapshot.connection
                || self.snapshot.connection_error != snapshot.connection_error
                || self.snapshot.denied() != snapshot.denied();
            let route_changed = self.snapshot.route != snapshot.route;
            let ap_changed = !Arc::ptr_eq(&self.snapshot.aps, &snapshot.aps)
                && self.snapshot.aps != snapshot.aps;
            let scan_changed = self.snapshot.scan != snapshot.scan;
            let old_bssid = self.snapshot.connection.as_ref().map(|c| c.bssid);
            self.snapshot = snapshot;
            if self.history.len() == SAMPLES {
                self.history.pop_front();
            }
            self.history
                .push_back(self.snapshot.connection.as_ref().map(|c| c.signal));

            let status = if self.snapshot.denied() {
                self.snapshot.scan.note()
            } else if let Some(code) = self.snapshot.connection_error {
                format!("当前连接读取失败（Windows 错误 {code}）")
            } else if let Some(connection) = &self.snapshot.connection {
                format!(
                    "已连接 {}  ·  {}  ·  {}",
                    network::ssid_label(&connection.ssid),
                    self.snapshot.scan.note(),
                    clock(false)
                )
            } else {
                format!("未连接 WiFi  ·  {}", self.snapshot.scan.note())
            };
            text(self.status, &status);
            if self.rescan_requested && self.snapshot.scan != Scan::Running {
                self.rescan_requested = false;
                enable(self.scan, true);
            }
            if connection_changed || route_changed {
                let rows = diagnostics::connection_rows(&self.snapshot);
                set_rows(
                    self.overview.rows,
                    rows.iter().map(|(key, val)| [*key, val.as_str()]),
                );
            }
            if ap_changed || old_bssid != self.snapshot.connection.as_ref().map(|c| c.bssid) {
                let own = self.snapshot.connection.as_ref().map(|c| c.bssid);
                set_rows(
                    self.networks.list,
                    self.snapshot.aps.iter().map(|ap| {
                        let label = network::ssid_label(&ap.ssid);
                        [
                            if Some(ap.bssid) == own {
                                format!("● {label}")
                            } else {
                                label.into()
                            },
                            format!("{}% / {} dBm", ap.signal, ap.rssi),
                            ap.band.name().into(),
                            ap.channel.map_or_else(|| "—".into(), |ch| ch.to_string()),
                            ap.phy.into(),
                            ap.security.into(),
                            network::mac(&ap.bssid),
                        ]
                    }),
                );
            }
            unsafe { InvalidateRect(self.overview.chart, null(), 0) };
            if ap_changed || connection_changed || scan_changed {
                text(
                    self.networks.summary,
                    &diagnostics::channel_summary(&self.snapshot),
                );
                unsafe { InvalidateRect(self.networks.chart, null(), 0) };
            }
            if ap_changed || connection_changed || route_changed || scan_changed {
                self.refresh_advice();
            }
        }
        while let Ok(result) = self.tasks.try_recv() {
            match result {
                TaskResult::Ping(pings, dns) => {
                    self.ping_active.store(false, Ordering::Relaxed);
                    self.pings = pings;
                    self.dns_ms = dns;
                    set_rows(
                        self.latency.list,
                        self.pings.iter().map(diagnostics::ping_row),
                    );
                    let dns = dns.map_or_else(
                        || "域名解析失败".into(),
                        |ms| format!("域名解析 {ms:.0} ms"),
                    );
                    text(
                        self.latency.status,
                        &format!("测试完成于 {}  ·  {dns}", clock(false)),
                    );
                    text(self.latency.start, "重新测试");
                    enable(self.latency.start, true);
                    self.refresh_advice();
                }
                TaskResult::Flush(result) => {
                    enable(self.recommendations.buttons[0], true);
                    match result {
                        Ok(()) => message(
                            self.hwnd,
                            "刷新 DNS 缓存",
                            "DNS 缓存已刷新。",
                            MB_ICONINFORMATION,
                        ),
                        Err(error) => message(self.hwnd, "刷新 DNS 缓存", &error, MB_ICONWARNING),
                    }
                }
            }
        }
    }

    fn invalidate_charts(&self) {
        unsafe {
            InvalidateRect(self.overview.chart, null(), 0);
            InvalidateRect(self.networks.chart, null(), 0);
        }
    }

    fn refresh_advice(&mut self) {
        let result = diagnostics::advice(&self.snapshot, &self.pings, self.dns_ms);
        if let Some(score) = result.score {
            text(self.overview.score, &format!("{score} / 100"));
            let summary = result.summary();
            text(
                self.overview.score_note,
                summary.split_once("  ").map_or("", |(_, note)| note),
            );
        } else {
            text(self.overview.score, "—");
            text(self.overview.score_note, "数据不足，等待检测结果");
        }
        let advice = result.text();
        if advice != self.advice_text {
            let scroll =
                unsafe { SendMessageW(self.recommendations.body, EM_GETFIRSTVISIBLELINE, 0, 0) };
            text(self.recommendations.body, &advice);
            unsafe { SendMessageW(self.recommendations.body, EM_LINESCROLL, 0, scroll) };
            self.advice_text = advice;
        }
    }

    fn command(&mut self, id: usize) {
        match id {
            RESCAN if self.refresh.send(()).is_ok() => {
                self.rescan_requested = true;
                enable(self.scan, false);
                text(self.status, "正在重新检测…");
            }
            EXPORT => self.export_report(),
            PING => self.start_ping(),
            FLUSH => self.flush_dns(),
            ROUTER => {
                if let Some(gateway) = self.snapshot.route.gateway {
                    self.open(&format!("http://{gateway}"));
                } else {
                    message(
                        self.hwnd,
                        "打开路由器管理页",
                        "暂未获取到 IPv4 网关地址。",
                        MB_ICONWARNING,
                    );
                }
            }
            WIFI => self.open("ms-settings:network-wifi"),
            LOCATION => self.open("ms-settings:privacy-location"),
            _ => (),
        }
    }

    fn open(&self, target: &str) {
        let target = wide(target);
        let result = unsafe {
            ShellExecuteW(
                self.hwnd,
                w!("open"),
                target.as_ptr(),
                null(),
                null(),
                SW_SHOWNORMAL,
            )
        };
        if result as isize <= 32 {
            message(
                self.hwnd,
                "打开失败",
                "Windows 无法打开此地址。",
                MB_ICONWARNING,
            );
        }
    }

    fn start_ping(&mut self) {
        if self.ping_active.swap(true, Ordering::Relaxed) {
            return;
        }
        self.pings.clear();
        self.dns_ms = None;
        set_rows::<String, 8>(self.latency.list, std::iter::empty());
        self.refresh_advice();
        enable(self.latency.start, false);
        text(self.latency.start, "测试中…");
        text(
            self.latency.status,
            "正在测试网关、外网延迟和域名解析，请稍候…",
        );
        let sender = self.task_sender.clone();
        let gateway = self.snapshot.route.gateway;
        thread::spawn(move || {
            let (results, dns) = network::latency(gateway);
            let _ = sender.send(TaskResult::Ping(results, dns));
        });
    }

    fn flush_dns(&self) {
        enable(self.recommendations.buttons[0], false);
        let sender = self.task_sender.clone();
        thread::spawn(move || {
            let result = Command::new("ipconfig.exe")
                .arg("/flushdns")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .creation_flags(CREATE_NO_WINDOW)
                .status()
                .map_err(|error| format!("无法启动 Windows DNS 缓存刷新命令。\r\n{error}"))
                .and_then(|status| {
                    if status.success() {
                        Ok(())
                    } else {
                        Err(format!(
                            "刷新失败（{status}）。请检查当前账户是否有权限刷新 DNS 缓存。"
                        ))
                    }
                });
            let _ = sender.send(TaskResult::Flush(result));
        });
    }

    fn export_report(&self) {
        let mut file = wide(&format!("WiFi检测报告_{}.txt", clock(true)));
        file.resize(32768, 0);
        let filter = wide("文本文件 (*.txt)\0*.txt\0");
        let mut dialog = OPENFILENAMEW {
            lStructSize: size_of::<OPENFILENAMEW>() as u32,
            hwndOwner: self.hwnd,
            lpstrFilter: filter.as_ptr(),
            nFilterIndex: 1,
            lpstrFile: file.as_mut_ptr(),
            nMaxFile: file.len() as u32,
            lpstrDefExt: w!("txt"),
            lpstrTitle: w!("导出 WiFi 检测报告"),
            Flags: OFN_EXPLORER | OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR,
            ..Default::default()
        };
        if unsafe { GetSaveFileNameW(&mut dialog) } == 0 {
            let error = unsafe { CommDlgExtendedError() };
            if error != 0 {
                message(
                    self.hwnd,
                    "导出失败",
                    &format!("保存窗口错误（{error}）。"),
                    MB_ICONERROR,
                );
            }
            return;
        }
        let len = file.iter().position(|&ch| ch == 0).unwrap_or(file.len());
        let path = PathBuf::from(std::ffi::OsString::from_wide(&file[..len]));
        let report = diagnostics::report(&self.snapshot, &self.pings, self.dns_ms, &clock(false));
        match fs::write(&path, report) {
            Ok(()) => message(
                self.hwnd,
                "导出报告",
                &format!("报告已保存到\r\n{}", path.display()),
                MB_ICONINFORMATION,
            ),
            Err(error) => message(self.hwnd, "导出失败", &error.to_string(), MB_ICONERROR),
        }
    }
}

impl Drop for App {
    fn drop(&mut self) {
        for font in [
            self.font,
            self.title_font,
            self.heading_font,
            self.small_font,
        ] {
            if !font.is_null() {
                unsafe { DeleteObject(font) };
            }
        }
    }
}

struct Controls {
    hwnd: HWND,
    instance: HINSTANCE,
    font: HFONT,
}

impl Controls {
    fn create(&self, class: PCWSTR, title: &str, style: u32, ex: u32, id: usize) -> HWND {
        let title = wide(title);
        unsafe {
            let control = CreateWindowExW(
                ex,
                class,
                title.as_ptr(),
                WS_CHILD | WS_CLIPSIBLINGS | style,
                0,
                0,
                0,
                0,
                self.hwnd,
                id as HMENU,
                self.instance,
                null(),
            );
            SendMessageW(control, WM_SETFONT, self.font as usize, 0);
            control
        }
    }

    fn label(&self, title: &str, font: HFONT) -> HWND {
        const NO_PREFIX: u32 = 0x0080;
        let hwnd = self.create(w!("STATIC"), title, NO_PREFIX, 0, 0);
        unsafe { SendMessageW(hwnd, WM_SETFONT, font as usize, 0) };
        hwnd
    }

    fn button(&self, title: &str, id: usize) -> HWND {
        self.create(w!("BUTTON"), title, WS_TABSTOP | WS_VISIBLE, 0, id)
    }

    fn list(&self, headers: &[&str], hide_headers: bool) -> HWND {
        let style = LVS_REPORT
            | LVS_SHOWSELALWAYS
            | LVS_SINGLESEL
            | if hide_headers { LVS_NOCOLUMNHEADER } else { 0 };
        let hwnd = self.create(WC_LISTVIEWW, "", WS_TABSTOP | style, WS_EX_CLIENTEDGE, 0);
        unsafe {
            SendMessageW(hwnd, LVM_SETUNICODEFORMAT, 1, 0);
            SendMessageW(
                hwnd,
                LVM_SETEXTENDEDLISTVIEWSTYLE,
                0,
                (LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_LABELTIP) as isize,
            );
        }
        for (index, header) in headers.iter().enumerate() {
            let mut label = wide(header);
            let column = LVCOLUMNW {
                mask: LVCF_TEXT | LVCF_WIDTH,
                cx: 80,
                pszText: label.as_mut_ptr(),
                ..Default::default()
            };
            send(hwnd, LVM_INSERTCOLUMNW, index, &column);
        }
        hwnd
    }
}

fn px(value: i32, dpi: i32) -> i32 {
    (value * dpi + 48) / 96
}

fn font(size: i32, weight: u32, dpi: i32) -> HFONT {
    unsafe {
        CreateFontW(
            -px(size, dpi),
            0,
            0,
            0,
            weight as i32,
            0,
            0,
            0,
            DEFAULT_CHARSET.into(),
            OUT_DEFAULT_PRECIS.into(),
            CLIP_DEFAULT_PRECIS.into(),
            CLEARTYPE_QUALITY.into(),
            DEFAULT_PITCH.into(),
            w!("Microsoft YaHei UI"),
        )
    }
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain([0]).collect()
}

fn send<T>(hwnd: HWND, msg: u32, index: usize, item: &T) -> LRESULT {
    unsafe { SendMessageW(hwnd, msg, index, (item as *const T) as isize) }
}

fn text(hwnd: HWND, value: &str) {
    let value = wide(value);
    unsafe { SetWindowTextW(hwnd, value.as_ptr()) };
}

fn enable(hwnd: HWND, enabled: bool) {
    unsafe { EnableWindow(hwnd, enabled.into()) };
}

fn message(hwnd: HWND, title: &str, body: &str, icon: MESSAGEBOX_STYLE) {
    let title = wide(title);
    let body = wide(body);
    unsafe { MessageBoxW(hwnd, body.as_ptr(), title.as_ptr(), MB_OK | icon) };
}

fn column_widths(hwnd: HWND, width: i32, weights: &[i32], dpi: i32) {
    let width = px(width, dpi) - px(22, dpi);
    for (index, weight) in weights.iter().enumerate() {
        unsafe {
            SendMessageW(
                hwnd,
                LVM_SETCOLUMNWIDTH,
                index,
                (width * weight / 100) as isize,
            )
        };
    }
}

fn set_rows<T: AsRef<str>, const N: usize>(hwnd: HWND, rows: impl Iterator<Item = [T; N]>) {
    let visible = unsafe { IsWindowVisible(hwnd) != 0 };
    if visible {
        unsafe { SendMessageW(hwnd, WM_SETREDRAW, 0, 0) };
    }
    unsafe { SendMessageW(hwnd, LVM_DELETEALLITEMS, 0, 0) };
    for (index, row) in rows.enumerate() {
        for (column, value) in row.into_iter().enumerate() {
            let mut value = wide(value.as_ref());
            let item = LVITEMW {
                mask: LVIF_TEXT,
                iItem: index as i32,
                iSubItem: column as i32,
                pszText: value.as_mut_ptr(),
                ..Default::default()
            };
            if column == 0 {
                send(hwnd, LVM_INSERTITEMW, 0, &item);
            } else {
                send(hwnd, LVM_SETITEMTEXTW, index, &item);
            }
        }
    }
    if visible {
        unsafe {
            SendMessageW(hwnd, WM_SETREDRAW, 1, 0);
            InvalidateRect(hwnd, null(), 1);
        }
    }
}

fn clock(filename: bool) -> String {
    let mut now = SYSTEMTIME::default();
    unsafe { GetLocalTime(&mut now) };
    let SYSTEMTIME {
        wYear: year,
        wMonth: month,
        wDay: day,
        wHour: hour,
        wMinute: min,
        wSecond: sec,
        ..
    } = now;
    if filename {
        format!("{year:04}{month:02}{day:02}_{hour:02}{min:02}")
    } else {
        format!("{year:04}-{month:02}-{day:02} {hour:02}:{min:02}:{sec:02}")
    }
}
