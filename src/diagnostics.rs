use crate::network::{AccessPoint, Band, Ping, Snapshot, mac, mac_masked, same_device, ssid_label};
use std::fmt::Write;
use windows_sys::Win32::NetworkManagement::IpHelper::IF_TYPE_ETHERNET_CSMACD;

pub const CHANNELS_24: &[u32] = &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14];
pub const CHANNELS_5: &[u32] = &[36, 40, 44, 48, 52, 56, 60, 64, 149, 153, 157, 161, 165];
const PICKS_24: &[u32] = &[1, 6, 11];
const PICKS_5: &[u32] = &[36, 40, 44, 48, 149, 153, 157, 161];

pub fn channel_score(aps: &[AccessPoint], own: Option<[u8; 6]>, band: Band, channel: u32) -> f64 {
    aps.iter()
        .filter(|ap| ap.band == band && !own.is_some_and(|own| same_device(&own, &ap.bssid)))
        .filter_map(|ap| ap.channel.map(|other| (ap.signal, other.abs_diff(channel))))
        .map(|(signal, diff)| {
            let weight = match band {
                Band::G24 => (1.0 - f64::from(diff) / 5.0).max(0.0),
                Band::G5 if diff == 0 => 1.0,
                Band::G5 if diff <= 4 => 0.4,
                _ => 0.0,
            };
            f64::from(signal) / 100.0 * weight
        })
        .sum()
}

pub fn best_channel(snapshot: &Snapshot, band: Band) -> Option<u32> {
    let candidates = match band {
        Band::G24 => PICKS_24,
        Band::G5 => PICKS_5,
        _ => return None,
    };
    if !snapshot
        .aps
        .iter()
        .any(|ap| ap.band == band && ap.channel.is_some())
    {
        return None;
    }
    let own = snapshot
        .connection
        .as_ref()
        .map(|connection| connection.bssid);
    let current = snapshot
        .connection
        .as_ref()
        .filter(|c| c.band == band)
        .and_then(|c| c.channel);
    candidates.iter().copied().min_by(|&a, &b| {
        let score = |channel| channel_score(&snapshot.aps, own, band, channel);
        score(a)
            .total_cmp(&score(b))
            .then_with(|| (Some(b) == current).cmp(&(Some(a) == current)))
    })
}

pub fn channel_summary(snapshot: &Snapshot) -> String {
    if snapshot.aps.is_empty() {
        return if snapshot.scan == crate::network::Scan::Ready {
            "扫描完成，未发现接入点。".into()
        } else {
            snapshot.scan.note()
        };
    }
    let count = |band| snapshot.aps.iter().filter(|ap| ap.band == band).count();
    let pick = |band| best_channel(snapshot, band).map_or_else(|| "—".into(), |c| c.to_string());
    format!(
        "发现 {} 个接入点（2.4 GHz {} 个，5 GHz {} 个，6 GHz {} 个）。推荐信道  2.4 GHz {}  /  5 GHz {}",
        snapshot.aps.len(),
        count(Band::G24),
        count(Band::G5),
        count(Band::G6),
        pick(Band::G24),
        pick(Band::G5),
    )
}

pub struct Stats {
    pub average: f64,
    pub minimum: u32,
    pub maximum: u32,
    pub jitter: f64,
}

impl Ping {
    pub fn stats(&self) -> Option<Stats> {
        let minimum = *self.times.iter().min()?;
        let maximum = *self.times.iter().max()?;
        let average =
            self.times.iter().map(|&ms| f64::from(ms)).sum::<f64>() / self.times.len() as f64;
        let jitter = self
            .times
            .windows(2)
            .map(|pair| f64::from(pair[0].abs_diff(pair[1])))
            .sum::<f64>()
            / (self.times.len() - 1).max(1) as f64;
        Some(Stats {
            average,
            minimum,
            maximum,
            jitter,
        })
    }

    pub fn loss(&self) -> Option<f64> {
        (self.sent != 0).then(|| (self.sent - self.times.len()) as f64 * 100.0 / self.sent as f64)
    }

    pub fn gateway(&self) -> bool {
        self.name == "路由器网关"
    }

    pub fn verdict(&self) -> &str {
        if let Some(error) = &self.error {
            return error;
        }
        let Some(stats) = self.stats() else {
            return "无响应";
        };
        let limit = if self.gateway() { 20.0 } else { 80.0 };
        let loss = self.loss().unwrap_or_default();
        if loss >= 10.0 {
            "较差"
        } else if loss > 0.0 || stats.average > limit || stats.jitter > 20.0 {
            "一般"
        } else {
            "良好"
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Level {
    Bad,
    Warn,
    Info,
    Good,
}

impl Level {
    fn label(self) -> &'static str {
        match self {
            Self::Bad => "异常",
            Self::Warn => "注意",
            Self::Info => "提示",
            Self::Good => "良好",
        }
    }
}

pub struct Advice {
    pub score: Option<u32>,
    pub partial: bool,
    notes: Vec<(Level, String, String)>,
}

impl Advice {
    pub fn text(&self) -> String {
        self.notes
            .iter()
            .map(|(level, title, detail)| format!("【{}】{title}\r\n{detail}", level.label()))
            .collect::<Vec<_>>()
            .join("\r\n\r\n")
    }

    pub fn summary(&self) -> String {
        match self.score {
            None => "数据不足，等待检测结果".into(),
            Some(score) => {
                let label = match score {
                    90.. => "优秀",
                    80..=89 => "良好",
                    60..=79 => "一般",
                    _ => "较差",
                };
                let partial = if self.partial {
                    "（部分数据）"
                } else {
                    ""
                };
                format!("{score} / 100  {label}{partial}")
            }
        }
    }
}

pub fn advice(snapshot: &Snapshot, pings: &[Ping], dns_ms: Option<f64>) -> Advice {
    let mut notes = Vec::new();
    let mut score: f64 = 100.0;
    let mut add =
        |level, title: String, detail: &str| notes.push((level, title, detail.to_string()));
    if snapshot.denied() {
        add(
            Level::Warn,
            "Windows 拒绝读取 WLAN 信息".into(),
            "点击「打开位置权限设置」，检查「定位服务」和「允许桌面应用访问你的位置」，再回来重新检测。延迟测试可以独立运行。",
        );
    } else if let Some(code) = snapshot.connection_error {
        add(
            Level::Warn,
            format!("无法读取当前连接（Windows 错误 {code}）"),
            "请确认无线网卡已启用，然后点击「重新检测」。",
        );
    } else if snapshot.connection.is_none() {
        if snapshot.route.kind == IF_TYPE_ETHERNET_CSMACD {
            add(
                Level::Info,
                "当前 IPv4 路由使用以太网适配器".into(),
                "连接 Wi‑Fi 后可以查看无线信号和当前信道。",
            );
        } else {
            add(
                Level::Info,
                "未检测到已连接的 Wi‑Fi".into(),
                "连接无线网络后即可查看信号和当前信道。",
            );
        }
    }
    if let Some(c) = &snapshot.connection {
        match c.signal {
            0..=39 => {
                score -= 35.0;
                add(
                    Level::Bad,
                    format!("信号较弱（{}%）", c.signal),
                    "试着靠近路由器，或把路由器挪到较高、开阔的位置。",
                );
            }
            40..=64 => {
                score -= 15.0;
                add(
                    Level::Warn,
                    format!("信号一般（{}%）", c.signal),
                    "可缩短与路由器的距离，并避开金属柜等遮挡。",
                );
            }
            _ => add(
                Level::Good,
                format!("信号良好（{}%）", c.signal),
                "当前位置的无线信号强度较好。",
            ),
        }
        if c.band == Band::G24 {
            score -= 8.0;
            if let Some(ap) = snapshot.aps.iter().find(|ap| {
                !c.ssid.is_empty()
                    && ap.ssid == c.ssid
                    && matches!(ap.band, Band::G5 | Band::G6)
                    && ap.signal >= 50
            }) {
                add(
                    Level::Info,
                    format!("同名 {} 网络的信号为 {}%", ap.band.name(), ap.signal),
                    "如果设备和路由器支持，可试用这个频段，并比较延迟和稳定性。",
                );
            } else {
                add(
                    Level::Info,
                    "当前连接在 2.4 GHz".into(),
                    "如果路由器支持 5 GHz 且距离不远，可以试用该频段。",
                );
            }
        }
        if c.legacy_phy {
            score -= 6.0;
            add(
                Level::Warn,
                format!("当前使用 {} 协议", c.phy),
                "如果网卡与路由器支持更高版本的协议，可检查路由器的无线模式设置。",
            );
        }
        if c.weak_security {
            add(
                Level::Bad,
                format!("无线安全模式较弱（{} / {}）", c.security, c.cipher),
                "建议在路由器中改用 WPA2-Personal（AES）或 WPA3。",
            );
        }
        if let (Some(channel), Some(best)) = (c.channel, best_channel(snapshot, c.band)) {
            let same = snapshot
                .aps
                .iter()
                .filter(|ap| {
                    ap.band == c.band
                        && ap.channel == Some(channel)
                        && !same_device(&ap.bssid, &c.bssid)
                        && ap.signal >= 30
                })
                .count();
            score -= (same * 3).min(15) as f64;
            let interference = |ch| channel_score(&snapshot.aps, Some(c.bssid), c.band, ch);
            let change = interference(channel) - interference(best);
            if channel != best && change >= 0.5 {
                add(
                    Level::Warn,
                    format!("可尝试把 {} 信道从 {channel} 改为 {best}", c.band.name()),
                    &format!(
                        "当前同信道有 {same} 个信号达 30% 的其他接入点。根据扫描估算，切换后干扰分可下降 {change:.1}。请以路由器允许的信道及调整后的实测为准。"
                    ),
                );
            } else if c.band == Band::G24 && !PICKS_24.contains(&channel) {
                add(
                    Level::Info,
                    format!("当前使用 2.4 GHz 信道 {channel}"),
                    "如果遇到干扰，可以在路由器支持的 1、6、11 信道中比较实际表现。",
                );
            } else {
                add(
                    Level::Good,
                    format!("当前信道 {channel} 未见明显更低干扰的候选信道"),
                    &format!("扫描发现 {same} 个信号达 30% 的同信道接入点。"),
                );
            }
        }
    }

    let gateway = pings.iter().find(|p| p.gateway());
    let gateway_stable = gateway.and_then(|ping| {
        let loss = ping.loss()?;
        let stats = ping.stats()?;
        Some(loss == 0.0 && stats.average <= 20.0 && stats.jitter <= 15.0)
    });
    if let Some(g) = gateway {
        if let (Some(stats), Some(loss)) = (g.stats(), g.loss()) {
            if gateway_stable == Some(false) {
                score -= (loss * 0.6 + (stats.average - 10.0).max(0.0) * 0.5).min(25.0);
                add(
                    Level::Warn,
                    format!(
                        "到网关的链路波动（平均 {:.0} ms，丢包 {loss:.0}%）",
                        stats.average
                    ),
                    "可对照信号曲线，检查本地链路和路由器负载。",
                );
            } else {
                add(
                    Level::Good,
                    format!("到网关的延迟较稳定（平均 {:.0} ms）", stats.average),
                    "本次对网关的探测均收到应答。",
                );
            }
        } else if g.sent != 0 {
            add(
                Level::Info,
                "网关未回复 ICMP 探测".into(),
                "部分路由器会屏蔽 ICMP，请结合外网探测和实际访问情况判断。",
            );
        }
    }
    let outside: Vec<_> = pings
        .iter()
        .filter(|p| !p.gateway() && p.sent != 0)
        .collect();
    if !outside.is_empty() {
        // A target that never answers usually filters ICMP. Judge loss from the ones that answer.
        let replies: Vec<_> = outside
            .iter()
            .filter_map(|p| Some((p, p.stats()?)))
            .collect();
        if replies.is_empty() {
            score -= 30.0;
            add(
                Level::Bad,
                "外网目标未回复 ICMP 探测".into(),
                "请结合网页访问情况判断是否断网。部分网络或目标会屏蔽 ICMP。",
            );
        } else {
            let avg = replies.iter().map(|(_, s)| s.average).sum::<f64>() / replies.len() as f64;
            let loss =
                replies.iter().filter_map(|(p, _)| p.loss()).sum::<f64>() / replies.len() as f64;
            if loss >= 5.0 || avg > 80.0 {
                score -= (loss * 0.5 + (avg - 60.0).max(0.0) * 0.1).min(15.0);
                let detail = if gateway_stable == Some(true) {
                    "网关探测稳定，可再检查路由器外网口和运营商线路。"
                } else {
                    "可对照网关探测结果，判断问题更接近本地链路还是外网。"
                };
                add(
                    Level::Warn,
                    format!("外网探测波动（平均 {avg:.0} ms，丢包 {loss:.0}%）"),
                    detail,
                );
            } else {
                add(
                    Level::Good,
                    format!("外网探测延迟较低（平均 {avg:.0} ms）"),
                    "本次探测的延迟与丢包处于较低水平。",
                );
            }
            let silent: Vec<_> = outside
                .iter()
                .filter(|p| p.times.is_empty())
                .map(|p| p.name)
                .collect();
            if !silent.is_empty() {
                add(
                    Level::Info,
                    format!("{} 未回复 ICMP 探测", silent.join("、")),
                    "其他外网目标均有应答，该目标可能屏蔽 ICMP，未计入外网延迟与丢包统计。",
                );
            }
        }
    }
    if let Some(ms) = dns_ms.filter(|&ms| ms > 300.0) {
        add(
            Level::Warn,
            format!("本次域名解析较慢（{ms:.0} ms）"),
            "可多测几次比较，持续偏慢时可检查网卡或路由器的 DNS 设置。",
        );
    }
    notes.sort_by_key(|note| note.0);
    let has_ping = pings.iter().any(|p| p.sent != 0);
    Advice {
        score: (snapshot.connection.is_some() || has_ping)
            .then(|| score.clamp(0.0, 100.0).round() as u32),
        partial: snapshot.connection.is_none() || !has_ping,
        notes,
    }
}

pub fn connection_rows(snapshot: &Snapshot, mask_mac: bool) -> Vec<(&'static str, String)> {
    let blank = "—";
    let show_mac: fn(&[u8; 6]) -> String = if mask_mac { mac_masked } else { mac };
    let mut rows = if let Some(c) = &snapshot.connection {
        let rate = |value| {
            if value == 0 {
                blank.into()
            } else {
                format!("{:.1} Mbps", f64::from(value) / 1000.0)
            }
        };
        // Prefer the RSSI measured in the scan; otherwise estimate it from link quality.
        let rssi = c.rssi.map_or_else(
            || format!("约 {:.0} dBm", f64::from(c.signal) / 2.0 - 100.0),
            |rssi| format!("{rssi} dBm"),
        );
        vec![
            ("网络名称", ssid_label(&c.ssid).into()),
            ("无线信号", format!("{}%（{rssi}）", c.signal)),
            (
                "频段 / 信道",
                format!(
                    "{} / {}",
                    c.band.name(),
                    c.channel.map_or_else(|| blank.into(), |ch| ch.to_string())
                ),
            ),
            ("无线协议", c.phy.into()),
            (
                "协商速率（收 / 发）",
                format!("{} / {}", rate(c.rx), rate(c.tx)),
            ),
            ("认证 / 加密", format!("{} / {}", c.security, c.cipher)),
            ("接入点 MAC", show_mac(&c.bssid)),
        ]
    } else {
        let status = if snapshot.denied() {
            "请检查 Windows 位置权限"
        } else {
            blank
        };
        vec![
            ("网络名称", status.into()),
            ("无线信号", blank.into()),
            ("频段 / 信道", blank.into()),
            ("无线协议", blank.into()),
            ("协商速率（收 / 发）", blank.into()),
            ("认证 / 加密", blank.into()),
            ("接入点 MAC", blank.into()),
        ]
    };
    let r = &snapshot.route;
    let address =
        |ip: Option<std::net::Ipv4Addr>| ip.map_or_else(|| blank.into(), |ip| ip.to_string());
    let dns = r
        .dns
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    rows.extend([
        ("本机 IPv4", address(r.ip)),
        ("IPv4 网关", address(r.gateway)),
        (
            "DNS 服务器",
            if dns.is_empty() { blank.into() } else { dns },
        ),
        (
            "IPv4 路由网卡",
            if r.adapter.is_empty() {
                blank.into()
            } else {
                r.adapter.clone()
            },
        ),
        (
            "网卡接收链路速率",
            if r.speed == 0 || r.speed == u64::MAX {
                blank.into()
            } else {
                format!("{:.1} Mbps", r.speed as f64 / 1_000_000.0)
            },
        ),
    ]);
    rows
}

pub fn ping_row(ping: &Ping) -> [String; 8] {
    let ms = |value: Option<f64>, decimals| {
        value.map_or_else(|| "—".into(), |value| format!("{value:.decimals$} ms"))
    };
    let stats = ping.stats();
    [
        ping.name.into(),
        ping.host.clone(),
        ms(stats.as_ref().map(|s| s.average), 0),
        ms(stats.as_ref().map(|s| f64::from(s.minimum)), 0),
        ms(stats.as_ref().map(|s| f64::from(s.maximum)), 0),
        ms(stats.as_ref().map(|s| s.jitter), 1),
        ping.loss()
            .map_or_else(|| "—".into(), |loss| format!("{loss:.0}%")),
        ping.verdict().into(),
    ]
}

/// With `mask_mac`, the device-specific half of every MAC address is hidden, because
/// BSSIDs in a shared report can be used to look up where the scan was taken.
pub fn report(
    snapshot: &Snapshot,
    pings: &[Ping],
    dns_ms: Option<f64>,
    stamp: &str,
    mask_mac: bool,
) -> String {
    let advice = advice(snapshot, pings, dns_ms);
    let show_mac: fn(&[u8; 6]) -> String = if mask_mac { mac_masked } else { mac };
    let note = if mask_mac {
        "\r\n（为保护隐私，MAC 地址仅保留厂商前缀）"
    } else {
        ""
    };
    let mut report = format!(
        "\u{feff}WiFi 检测报告  {stamp}{note}\r\n健康评分  {}\r\n\r\n[当前连接]\r\n",
        advice.summary()
    );
    for (key, value) in connection_rows(snapshot, mask_mac) {
        let _ = write!(report, "{key}  {value}\r\n");
    }
    let _ = write!(
        report,
        "\r\n[周边网络与信道]\r\n{}\r\n",
        channel_summary(snapshot)
    );
    for ap in snapshot.aps.iter() {
        let _ = write!(
            report,
            "  {}% / {} dBm  {}  信道 {}  {}  {}  {}  {}\r\n",
            ap.signal,
            ap.rssi,
            ap.band.name(),
            ap.channel.map_or_else(|| "—".into(), |c| c.to_string()),
            show_mac(&ap.bssid),
            ap.phy,
            ap.security,
            ssid_label(&ap.ssid)
        );
    }
    report.push_str("\r\n[延迟测试]\r\n");
    if pings.is_empty() {
        report.push_str("  尚未完成测试\r\n");
    }
    for ping in pings {
        let [name, host, avg, min, max, jitter, loss, verdict] = ping_row(ping);
        let _ = write!(
            report,
            "  {name}（{host}）  平均 {avg}  最低 {min}  最高 {max}  抖动 {jitter}  丢包 {loss}  {verdict}\r\n"
        );
    }
    if let Some(ms) = dns_ms {
        let _ = write!(report, "  域名解析耗时 {ms:.0} ms\r\n");
    } else if !pings.is_empty() {
        report.push_str("  域名解析失败\r\n");
    }
    let _ = write!(report, "\r\n[诊断与建议]\r\n{}\r\n", advice.text());
    report
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interference_excludes_own_bssid_and_other_bands() {
        let ap = |bssid, band, channel| AccessPoint {
            ssid: String::new(),
            bssid: [bssid; 6],
            signal: 80,
            rssi: -60,
            band,
            channel: Some(channel),
            phy: "—",
            security: "—",
        };
        let aps = [ap(1, Band::G24, 1), ap(2, Band::G6, 1), ap(3, Band::G24, 3)];
        assert!((channel_score(&aps, Some([1; 6]), Band::G24, 1) - 0.48).abs() < 1e-9);
        assert_eq!(channel_score(&aps, Some([1; 6]), Band::G24, 11), 0.0);
    }

    #[test]
    fn ping_stats_count_loss_and_jitter() {
        let ping = Ping {
            name: "测试",
            host: String::new(),
            times: vec![5, 10, 30],
            sent: 8,
            error: None,
        };
        let stats = ping.stats().unwrap();
        assert_eq!(
            (stats.average, stats.minimum, stats.maximum, stats.jitter),
            (15.0, 5, 30, 12.5)
        );
        assert_eq!(ping.loss(), Some(62.5));
    }

    fn ap(bssid: [u8; 6], channel: u32) -> AccessPoint {
        AccessPoint {
            ssid: String::new(),
            bssid,
            signal: 100,
            rssi: -40,
            band: Band::G24,
            channel: Some(channel),
            phy: "—",
            security: "—",
        }
    }

    #[test]
    fn interference_ignores_virtual_bssids_of_own_router() {
        let own = [0x10, 0x20, 0x30, 0x40, 0x50, 0x60];
        let guest = [0x12, 0x20, 0x30, 0x40, 0x50, 0x61];
        let neighbor = [0x30, 0x20, 0x30, 0x40, 0x50, 0x60];
        let aps = [ap(own, 6), ap(guest, 6), ap(neighbor, 6)];
        assert!((channel_score(&aps, Some(own), Band::G24, 6) - 1.0).abs() < 1e-9);
    }

    fn ping(name: &'static str, times: Vec<u32>) -> Ping {
        Ping {
            name,
            host: String::new(),
            times,
            sent: 8,
            error: None,
        }
    }

    #[test]
    fn silent_target_is_not_counted_as_packet_loss() {
        let pings = [
            ping("阿里 DNS", vec![10; 8]),
            ping("腾讯 DNS", vec![12; 8]),
            ping("百度", Vec::new()),
        ];
        let advice = advice(&Snapshot::default(), &pings, Some(20.0));
        assert_eq!(advice.score, Some(100));
        assert!(advice.text().contains("百度 未回复 ICMP 探测"));
        assert!(!advice.text().contains("外网探测波动"));
    }

    #[test]
    fn all_targets_silent_is_reported() {
        let pings = [ping("阿里 DNS", Vec::new()), ping("百度", Vec::new())];
        let advice = advice(&Snapshot::default(), &pings, None);
        assert_eq!(advice.score, Some(70));
        assert!(advice.text().contains("外网目标未回复 ICMP 探测"));
    }

    #[test]
    fn report_masks_mac_addresses() {
        let snapshot = Snapshot {
            aps: std::sync::Arc::new(vec![ap([0xAA, 0xBB, 0xCC, 1, 2, 3], 1)]),
            ..Snapshot::default()
        };
        let masked = report(&snapshot, &[], None, "now", true);
        assert!(masked.contains("AA:BB:CC:**:**:**"));
        assert!(!masked.contains("AA:BB:CC:01:02:03"));
        assert!(report(&snapshot, &[], None, "now", false).contains("AA:BB:CC:01:02:03"));
    }
}
