use crate::{
    diagnostics::{CHANNELS_5, CHANNELS_24, best_channel, channel_score},
    network::{Band, Snapshot},
};
use std::{collections::VecDeque, ptr::null_mut};
use windows_sys::Win32::{
    Foundation::{COLORREF, RECT},
    Graphics::Gdi::*,
    UI::Controls::DRAWITEMSTRUCT,
};

pub const SAMPLES: usize = 120;
const BLUE: COLORREF = 0xD76121;
const GREEN: COLORREF = 0x57911D;
const GRAY: COLORREF = 0xCBBBAE;

pub enum Chart<'a> {
    Signal(&'a VecDeque<Option<u32>>, &'a Snapshot),
    Channels(&'a Snapshot),
}

pub fn draw(item: &DRAWITEMSTRUCT, font: HFONT, dpi: i32, chart: Chart<'_>) {
    let width = item.rcItem.right - item.rcItem.left;
    let height = item.rcItem.bottom - item.rcItem.top;
    if width <= 0 || height <= 0 {
        return;
    }
    unsafe {
        let memory = CreateCompatibleDC(item.hDC);
        if memory.is_null() {
            return;
        }
        let bitmap = CreateCompatibleBitmap(item.hDC, width, height);
        if !bitmap.is_null() {
            let previous = SelectObject(memory, bitmap);
            let previous_font = SelectObject(memory, font);
            SetBkMode(memory, TRANSPARENT as i32);
            let canvas = Canvas {
                dc: memory,
                w: width,
                h: height,
                dpi,
            };
            FillRect(
                memory,
                &RECT {
                    left: 0,
                    top: 0,
                    right: width,
                    bottom: height,
                },
                GetSysColorBrush(COLOR_WINDOW),
            );
            match chart {
                Chart::Signal(history, snapshot) => canvas.signal(history, snapshot),
                Chart::Channels(snapshot) => canvas.channels(snapshot),
            }
            BitBlt(
                item.hDC,
                item.rcItem.left,
                item.rcItem.top,
                width,
                height,
                memory,
                0,
                0,
                SRCCOPY,
            );
            SelectObject(memory, previous_font);
            SelectObject(memory, previous);
            DeleteObject(bitmap);
        }
        DeleteDC(memory);
    }
}

struct Canvas {
    dc: HDC,
    w: i32,
    h: i32,
    dpi: i32,
}

impl Canvas {
    fn px(&self, value: i32) -> i32 {
        (value * self.dpi + 48) / 96
    }

    fn label(&self, x: i32, y: i32, align: u32, text: &str) {
        let wide: Vec<_> = text.encode_utf16().collect();
        unsafe {
            SetTextColor(self.dc, GetSysColor(COLOR_WINDOWTEXT));
            SetTextAlign(self.dc, align);
            TextOutW(self.dc, x, y, wide.as_ptr(), wide.len() as i32);
        }
    }

    fn rect(&self, left: i32, top: i32, right: i32, bottom: i32, color: COLORREF) {
        unsafe {
            let brush = CreateSolidBrush(color);
            if !brush.is_null() {
                FillRect(
                    self.dc,
                    &RECT {
                        left,
                        top,
                        right,
                        bottom,
                    },
                    brush,
                );
                DeleteObject(brush);
            }
        }
    }

    fn signal(&self, history: &VecDeque<Option<u32>>, snapshot: &Snapshot) {
        let left = self.px(56);
        let right = self.w - self.px(22);
        let top = self.px(18);
        let bottom = self.h - self.px(30);
        if left >= right || top >= bottom {
            return;
        }
        for pct in [0, 25, 50, 75, 100] {
            let y = bottom - (bottom - top) * pct / 100;
            self.rect(left, y, right + 1, y + 1, unsafe {
                GetSysColor(COLOR_3DLIGHT)
            });
            self.label(
                left - self.px(8),
                y - self.px(8),
                TA_RIGHT,
                &format!("{pct}%"),
            );
        }
        self.label(left, bottom + self.px(7), TA_LEFT, "约 4 分钟前");
        self.label(right, bottom + self.px(7), TA_RIGHT, "现在");
        if snapshot.denied() || !history.iter().any(Option::is_some) {
            let text = if snapshot.denied() {
                "请检查 Windows 位置权限"
            } else {
                "等待无线信号数据…"
            };
            self.label(self.w / 2, self.h / 2 - self.px(8), TA_CENTER, text);
            return;
        }
        unsafe {
            let pen = CreatePen(PS_SOLID, self.px(2), BLUE);
            if pen.is_null() {
                return;
            }
            let old_pen = SelectObject(self.dc, pen);
            let mut previous = false;
            for (index, value) in history.iter().enumerate() {
                if let Some(pct) = value {
                    let x = right
                        - (right - left) * (history.len() - index - 1) as i32
                            / (SAMPLES - 1) as i32;
                    let y = bottom - (bottom - top) * *pct as i32 / 100;
                    if previous {
                        LineTo(self.dc, x, y);
                    } else {
                        MoveToEx(self.dc, x, y, null_mut());
                    }
                    if index + 1 == history.len() {
                        let dot = self.px(3);
                        self.rect(x - dot, y - dot, x + dot, y + dot, BLUE);
                        self.label(x - self.px(7), y + self.px(3), TA_RIGHT, &format!("{pct}%"));
                    }
                }
                previous = value.is_some();
            }
            SelectObject(self.dc, old_pen);
            DeleteObject(pen);
        }
    }

    fn channels(&self, snapshot: &Snapshot) {
        if snapshot.aps.is_empty() {
            self.label(
                self.w / 2,
                self.h / 2 - self.px(8),
                TA_CENTER,
                &crate::diagnostics::channel_summary(snapshot),
            );
            return;
        }
        let own = snapshot
            .connection
            .as_ref()
            .map(|connection| connection.bssid);
        let score = |band, channel| channel_score(&snapshot.aps, own, band, channel);
        let groups = [(Band::G24, CHANNELS_24), (Band::G5, CHANNELS_5)].map(|(band, base)| {
            let current = snapshot
                .connection
                .as_ref()
                .filter(|c| c.band == band)
                .and_then(|c| c.channel);
            let mut channels = base.to_vec();
            if let Some(ch) = current.filter(|ch| !base.contains(ch)) {
                channels.push(ch);
                channels.sort_unstable();
            }
            (band, channels, current, best_channel(snapshot, band))
        });
        let scale = groups
            .iter()
            .flat_map(|(band, channels, _, _)| {
                channels.iter().map(|&channel| score(*band, channel))
            })
            .fold(1.0_f64, f64::max);
        let bottom = self.h - self.px(27);
        let bar_space = (bottom - self.px(42)).max(1);
        let half = self.w / 2;
        for (group, (band, channels, current, best)) in groups.into_iter().enumerate() {
            let start = group as i32 * half + self.px(10);
            let slot = (half - self.px(20)) / channels.len() as i32;
            if slot <= self.px(6) {
                continue;
            }
            self.label(start, self.px(5), TA_LEFT, band.name());
            for (index, channel) in channels.into_iter().enumerate() {
                let x = start + slot * index as i32;
                let height = (f64::from(bar_space) * score(band, channel) / scale) as i32;
                let top = bottom - height.max(self.px(2));
                let color = if Some(channel) == current {
                    BLUE
                } else if Some(channel) == best {
                    GREEN
                } else {
                    GRAY
                };
                self.rect(x + self.px(3), top, x + slot - self.px(3), bottom, color);
                let count = snapshot
                    .aps
                    .iter()
                    .filter(|ap| ap.band == band && ap.channel == Some(channel))
                    .count();
                if count > 0 {
                    self.label(
                        x + slot / 2,
                        top - self.px(17),
                        TA_CENTER,
                        &count.to_string(),
                    );
                }
                self.label(
                    x + slot / 2,
                    bottom + self.px(3),
                    TA_CENTER,
                    &channel.to_string(),
                );
            }
        }
    }
}
