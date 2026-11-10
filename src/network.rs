use std::{
    ffi::c_void,
    mem::{offset_of, size_of},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs},
    ptr::{null, null_mut},
    slice,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc::{Receiver, RecvTimeoutError, Sender},
    },
    thread,
    time::{Duration, Instant},
};
use windows_sys::{
    Win32::{
        Foundation::{ERROR_ACCESS_DENIED, ERROR_BUFFER_OVERFLOW, HANDLE, INVALID_HANDLE_VALUE},
        Globalization::{MB_ERR_INVALID_CHARS, MultiByteToWideChar},
        NetworkManagement::{IpHelper::*, WiFi::*},
        Networking::WinSock::{AF_INET, AF_INET6, SOCKADDR_IN, SOCKADDR_IN6, SOCKET_ADDRESS},
    },
    core::GUID,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Band {
    G24,
    G5,
    G6,
    Other,
}

impl Band {
    pub fn name(self) -> &'static str {
        match self {
            Self::G24 => "2.4 GHz",
            Self::G5 => "5 GHz",
            Self::G6 => "6 GHz",
            Self::Other => "未知频段",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccessPoint {
    pub ssid: String,
    pub bssid: [u8; 6],
    pub signal: u32,
    pub rssi: i32,
    pub band: Band,
    pub channel: Option<u32>,
    pub phy: &'static str,
    pub security: &'static str,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Connection {
    pub ssid: String,
    pub bssid: [u8; 6],
    pub signal: u32,
    /// Measured RSSI from the latest scan entry for this BSSID, when available.
    pub rssi: Option<i32>,
    pub band: Band,
    pub channel: Option<u32>,
    pub phy: &'static str,
    pub security: &'static str,
    pub cipher: &'static str,
    pub legacy_phy: bool,
    pub weak_security: bool,
    pub rx: u32,
    pub tx: u32,
}

#[derive(Default, Debug, PartialEq, Eq)]
pub struct Route {
    pub adapter: String,
    pub kind: u32,
    pub gateway: Option<Ipv4Addr>,
    pub ip: Option<Ipv4Addr>,
    pub dns: Vec<IpAddr>,
    pub speed: u64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Scan {
    #[default]
    Waiting,
    Running,
    Ready,
    NoAdapter,
    Denied,
    Failed(u32),
}

impl Scan {
    pub fn note(self) -> String {
        match self {
            Self::Waiting => "等待扫描结果…".into(),
            Self::Running => "正在扫描周边网络…".into(),
            Self::Ready => "扫描完成".into(),
            Self::NoAdapter => "未检测到启用的无线网卡".into(),
            Self::Denied => "Windows 拒绝读取 WLAN 数据，请检查位置权限".into(),
            Self::Failed(code) => format!("无线扫描失败（Windows 错误 {code}）"),
        }
    }
}

#[derive(Default)]
pub struct Snapshot {
    pub connection: Option<Connection>,
    pub connection_error: Option<u32>,
    pub aps: Arc<Vec<AccessPoint>>,
    pub scan: Scan,
    pub route: Arc<Route>,
    /// Number of the latest user rescan request whose scan has finished or failed.
    pub rescan_done: u64,
}

impl Snapshot {
    pub fn denied(&self) -> bool {
        self.connection_error == Some(ERROR_ACCESS_DENIED) || self.scan == Scan::Denied
    }
}

pub fn mac(bytes: &[u8; 6]) -> String {
    bytes.map(|byte| format!("{byte:02X}")).join(":")
}

/// Keeps the vendor prefix but hides the device-specific half, so a shared report
/// cannot be used to look up the location of nearby access points.
pub fn mac_masked(bytes: &[u8; 6]) -> String {
    format!(
        "{:02X}:{:02X}:{:02X}:**:**:**",
        bytes[0], bytes[1], bytes[2]
    )
}

/// Routers commonly derive guest, mesh and other virtual BSSIDs from the same base
/// address: the locally administered bit or the last byte changes, the rest does not.
pub fn same_device(a: &[u8; 6], b: &[u8; 6]) -> bool {
    a == b || ((a[0] | 0x02) == (b[0] | 0x02) && a[1..5] == b[1..5])
}

pub fn ssid_label(ssid: &str) -> &str {
    if ssid.is_empty() {
        "（隐藏网络）"
    } else {
        ssid
    }
}

fn ssid(raw: &DOT11_SSID) -> String {
    let len = (raw.uSSIDLength as usize).min(raw.ucSSID.len());
    decode_ssid(&raw.ucSSID[..len])
        .chars()
        .map(|ch| if ch.is_control() { '�' } else { ch })
        .collect()
}

/// Many routers sold in China broadcast Chinese SSIDs as GBK rather than UTF-8.
fn decode_ssid(bytes: &[u8]) -> String {
    match std::str::from_utf8(bytes) {
        Ok(text) => text.to_owned(),
        Err(_) => gbk(bytes).unwrap_or_else(|| String::from_utf8_lossy(bytes).into_owned()),
    }
}

fn gbk(bytes: &[u8]) -> Option<String> {
    const CP_GBK: u32 = 936;
    // An SSID is at most 32 bytes, which never decodes to more than 32 UTF-16 units.
    let mut wide = [0u16; 64];
    let len = unsafe {
        MultiByteToWideChar(
            CP_GBK,
            MB_ERR_INVALID_CHARS,
            bytes.as_ptr(),
            bytes.len() as i32,
            wide.as_mut_ptr(),
            wide.len() as i32,
        )
    };
    (len > 0).then(|| String::from_utf16_lossy(&wide[..len as usize]))
}

fn frequency(khz: u32) -> (Band, Option<u32>) {
    let mhz = khz / 1000;
    let (band, channel) = match mhz {
        2484 => (Band::G24, 14),
        2412..=2472 if (mhz - 2407).is_multiple_of(5) => (Band::G24, (mhz - 2407) / 5),
        4910..=4980 if (mhz - 4000).is_multiple_of(5) => (Band::G5, (mhz - 4000) / 5),
        5005..=5895 if mhz.is_multiple_of(5) => (Band::G5, (mhz - 5000) / 5),
        5935 => (Band::G6, 2),
        5955..=7115 if (mhz - 5950).is_multiple_of(5) => (Band::G6, (mhz - 5950) / 5),
        _ => return (Band::Other, None),
    };
    (band, Some(channel))
}

/// Used when the scan list has no entry for the connected BSSID yet.
#[allow(non_upper_case_globals)]
fn infer_band(channel: u32, phy: DOT11_PHY_TYPE) -> Band {
    // 802.11ax/be radios may be on 6 GHz, where channel numbers start again at 1.
    if matches!(phy, dot11_phy_type_he | dot11_phy_type_eht) {
        return Band::Other;
    }
    match channel {
        1..=14 => Band::G24,
        32..=196 => Band::G5,
        _ => Band::Other,
    }
}

#[allow(non_upper_case_globals)]
fn phy_name(phy: DOT11_PHY_TYPE) -> &'static str {
    match phy {
        dot11_phy_type_hrdsss | dot11_phy_type_dsss => "802.11b",
        dot11_phy_type_ofdm => "802.11a",
        dot11_phy_type_erp => "802.11g",
        dot11_phy_type_ht => "802.11n",
        dot11_phy_type_vht => "802.11ac",
        dot11_phy_type_he => "802.11ax",
        dot11_phy_type_eht => "802.11be",
        dot11_phy_type_dmg => "802.11ad",
        _ => "—",
    }
}

fn auth_name(auth: DOT11_AUTH_ALGORITHM) -> &'static str {
    match auth {
        DOT11_AUTH_ALGO_80211_OPEN => "开放",
        DOT11_AUTH_ALGO_80211_SHARED_KEY => "共享密钥",
        DOT11_AUTH_ALGO_WPA | DOT11_AUTH_ALGO_WPA_NONE => "WPA",
        DOT11_AUTH_ALGO_WPA_PSK => "WPA-Personal",
        DOT11_AUTH_ALGO_RSNA => "WPA2-Enterprise",
        DOT11_AUTH_ALGO_RSNA_PSK => "WPA2-Personal",
        DOT11_AUTH_ALGO_WPA3_ENT | DOT11_AUTH_ALGO_WPA3_ENT_192 => "WPA3-Enterprise",
        DOT11_AUTH_ALGO_WPA3_SAE => "WPA3-Personal",
        DOT11_AUTH_ALGO_OWE => "OWE",
        _ => "—",
    }
}

fn cipher_name(cipher: DOT11_CIPHER_ALGORITHM) -> &'static str {
    match cipher {
        DOT11_CIPHER_ALGO_NONE => "无",
        DOT11_CIPHER_ALGO_WEP | DOT11_CIPHER_ALGO_WEP40 | DOT11_CIPHER_ALGO_WEP104 => "WEP",
        DOT11_CIPHER_ALGO_TKIP => "TKIP",
        DOT11_CIPHER_ALGO_CCMP => "AES-CCMP",
        DOT11_CIPHER_ALGO_CCMP_256 => "CCMP-256",
        DOT11_CIPHER_ALGO_GCMP => "AES-GCMP",
        DOT11_CIPHER_ALGO_GCMP_256 => "GCMP-256",
        _ => "—",
    }
}

fn rsn_security(rsn: &[u8]) -> Option<&'static str> {
    let pairwise_count = u16::from_le_bytes(rsn.get(6..8)?.try_into().ok()?) as usize;
    let akms = rsn.get(8 + pairwise_count * 4..)?;
    let count = u16::from_le_bytes(akms.get(..2)?.try_into().ok()?) as usize;
    let suites = akms.get(2..2 + count * 4)?;
    let has = |types: &[u8]| {
        suites
            .chunks_exact(4)
            .any(|suite| suite[..3] == [0, 0x0f, 0xac] && types.contains(&suite[3]))
    };
    Some(match (has(&[2, 4, 6]), has(&[8, 9, 24, 25])) {
        (true, true) => "WPA2/WPA3",
        (false, true) => "WPA3-Personal",
        (true, false) => "WPA2-Personal",
        _ if has(&[18]) => "OWE",
        _ if has(&[12, 13]) => "WPA3-Enterprise",
        _ if has(&[1, 3, 5]) => "WPA2-Enterprise",
        _ => "RSN",
    })
}

fn ap_security(mut ies: &[u8], privacy: bool) -> &'static str {
    let mut wpa = false;
    while let [id, len, rest @ ..] = ies {
        let Some((data, tail)) = rest.split_at_checked(*len as usize) else {
            break;
        };
        if *id == 48 {
            return rsn_security(data).unwrap_or("RSN");
        }
        if *id == 221 && data.starts_with(&[0, 0x50, 0xf2, 1]) {
            wpa = true;
        }
        ies = tail;
    }
    if wpa {
        "WPA"
    } else if privacy {
        // The privacy bit without RSN or WPA information elements means WEP.
        "WEP"
    } else {
        "开放"
    }
}

struct WlanBuffer<T>(*mut T);

impl<T> Drop for WlanBuffer<T> {
    fn drop(&mut self) {
        unsafe { WlanFreeMemory(self.0.cast()) };
    }
}

struct Wlan(HANDLE);

impl Drop for Wlan {
    fn drop(&mut self) {
        unsafe { WlanCloseHandle(self.0, null()) };
    }
}

fn check(code: u32) -> Result<(), u32> {
    if code == 0 { Ok(()) } else { Err(code) }
}

impl Wlan {
    fn open() -> Result<Self, u32> {
        let mut handle = null_mut();
        unsafe { check(WlanOpenHandle(2, null(), &mut 0, &mut handle))? };
        Ok(Self(handle))
    }

    fn interfaces(&self) -> Result<Vec<WLAN_INTERFACE_INFO>, u32> {
        let mut list = null_mut();
        unsafe {
            check(WlanEnumInterfaces(self.0, null(), &mut list))?;
            let buffer = WlanBuffer(list);
            // WLAN supplies a trailing array, which can contain zero entries.
            let count = (*buffer.0).dwNumberOfItems as usize;
            let entries = buffer
                .0
                .cast::<u8>()
                .add(offset_of!(WLAN_INTERFACE_INFO_LIST, InterfaceInfo))
                .cast::<WLAN_INTERFACE_INFO>();
            Ok(slice::from_raw_parts(entries, count).to_vec())
        }
    }

    // The caller selects the type paired with the documented WLAN opcode.
    unsafe fn query<T: Copy>(&self, guid: &GUID, opcode: WLAN_INTF_OPCODE) -> Result<T, u32> {
        let mut data = null_mut();
        let mut len = 0;
        unsafe {
            check(WlanQueryInterface(
                self.0,
                guid,
                opcode,
                null(),
                &mut len,
                &mut data,
                null_mut(),
            ))?;
            let buffer = WlanBuffer(data);
            if (len as usize) < size_of::<T>() || buffer.0.is_null() {
                return Err(windows_sys::Win32::Foundation::ERROR_INVALID_DATA);
            }
            Ok(buffer.0.cast::<T>().read())
        }
    }

    #[allow(non_upper_case_globals)]
    fn current(&self, guid: &GUID, aps: &[AccessPoint]) -> Result<Connection, u32> {
        let attributes: WLAN_CONNECTION_ATTRIBUTES =
            unsafe { self.query(guid, wlan_intf_opcode_current_connection)? };
        let assoc = attributes.wlanAssociationAttributes;
        let security = attributes.wlanSecurityAttributes;
        let ap = aps.iter().find(|ap| ap.bssid == assoc.dot11Bssid);
        let channel: Option<u32> = unsafe { self.query(guid, wlan_intf_opcode_channel_number) }
            .ok()
            .filter(|channel| *channel != 0);
        let matching_ap = ap.filter(|ap| channel.is_none() || ap.channel == channel);
        let channel = channel.or_else(|| matching_ap.and_then(|ap| ap.channel));
        let band = match (matching_ap, channel) {
            (Some(ap), _) => ap.band,
            (None, Some(channel)) => infer_band(channel, assoc.dot11PhyType),
            (None, None) => Band::Other,
        };
        Ok(Connection {
            ssid: ssid(&assoc.dot11Ssid),
            bssid: assoc.dot11Bssid,
            signal: assoc.wlanSignalQuality.min(100),
            rssi: matching_ap.map(|ap| ap.rssi),
            band,
            channel,
            phy: phy_name(assoc.dot11PhyType),
            security: auth_name(security.dot11AuthAlgorithm),
            cipher: cipher_name(security.dot11CipherAlgorithm),
            legacy_phy: matches!(
                assoc.dot11PhyType,
                dot11_phy_type_hrdsss
                    | dot11_phy_type_dsss
                    | dot11_phy_type_ofdm
                    | dot11_phy_type_erp
                    | dot11_phy_type_ht
            ),
            weak_security: matches!(
                security.dot11CipherAlgorithm,
                DOT11_CIPHER_ALGO_WEP
                    | DOT11_CIPHER_ALGO_WEP40
                    | DOT11_CIPHER_ALGO_WEP104
                    | DOT11_CIPHER_ALGO_TKIP
            ) || matches!(
                security.dot11AuthAlgorithm,
                DOT11_AUTH_ALGO_WPA | DOT11_AUTH_ALGO_WPA_NONE | DOT11_AUTH_ALGO_WPA_PSK
            ) || security.bSecurityEnabled == 0,
            rx: assoc.ulRxRate,
            tx: assoc.ulTxRate,
        })
    }

    fn start_scan(&self, guid: &GUID) -> Result<(), u32> {
        unsafe { check(WlanScan(self.0, guid, null(), null(), null())) }
    }

    fn nearby(&self, guid: &GUID) -> Result<Vec<AccessPoint>, u32> {
        let mut list = null_mut();
        unsafe {
            check(WlanGetNetworkBssList(
                self.0,
                guid,
                null(),
                dot11_BSS_type_any,
                0,
                null(),
                &mut list,
            ))?;
            let buffer = WlanBuffer(list);
            let size = (*buffer.0).dwTotalSize as usize;
            let count = (*buffer.0).dwNumberOfItems as usize;
            let base = buffer.0.cast::<u8>();
            let first = offset_of!(WLAN_BSS_LIST, wlanBssEntries);
            if count > size.saturating_sub(first) / size_of::<WLAN_BSS_ENTRY>() {
                return Err(windows_sys::Win32::Foundation::ERROR_INVALID_DATA);
            }
            let mut aps = Vec::with_capacity(count);
            for index in 0..count {
                let offset = first + index * size_of::<WLAN_BSS_ENTRY>();
                let entry = &*base.add(offset).cast::<WLAN_BSS_ENTRY>();
                let start = offset + entry.ulIeOffset as usize;
                // Offsets are relative to this entry. Validate them before reading radio data.
                let ies = if entry.ulIeOffset as usize >= size_of::<WLAN_BSS_ENTRY>()
                    && start <= size
                    && entry.ulIeSize as usize <= size - start
                {
                    slice::from_raw_parts(base.add(start), entry.ulIeSize as usize)
                } else {
                    &[]
                };
                let (band, channel) = frequency(entry.ulChCenterFrequency);
                aps.push(AccessPoint {
                    ssid: ssid(&entry.dot11Ssid),
                    bssid: entry.dot11Bssid,
                    signal: entry.uLinkQuality.min(100),
                    rssi: entry.lRssi,
                    band,
                    channel,
                    phy: phy_name(entry.dot11BssPhyType),
                    security: ap_security(ies, entry.usCapabilityInformation & 0x10 != 0),
                });
            }
            Ok(aps)
        }
    }
}

unsafe fn socket_ip(address: SOCKET_ADDRESS) -> Option<IpAddr> {
    if address.lpSockaddr.is_null() {
        return None;
    }
    unsafe {
        match (*address.lpSockaddr).sa_family {
            AF_INET if address.iSockaddrLength >= size_of::<SOCKADDR_IN>() as i32 => {
                let addr = &*address.lpSockaddr.cast::<SOCKADDR_IN>();
                Some(Ipv4Addr::from(addr.sin_addr.S_un.S_addr.to_ne_bytes()).into())
            }
            AF_INET6 if address.iSockaddrLength >= size_of::<SOCKADDR_IN6>() as i32 => {
                let addr = &*address.lpSockaddr.cast::<SOCKADDR_IN6>();
                Some(Ipv6Addr::from(addr.sin6_addr.u.Byte).into())
            }
            _ => None,
        }
    }
}

unsafe fn wide_string(value: *const u16) -> String {
    if value.is_null() {
        return String::new();
    }
    unsafe {
        let len = (0..).take_while(|index| *value.add(*index) != 0).count();
        String::from_utf16_lossy(slice::from_raw_parts(value, len))
    }
}

pub fn route() -> Route {
    let mut row = MIB_IPFORWARDROW::default();
    // Match Windows' route for the same public IPv4 target used by the probe.
    if unsafe { GetBestRoute(u32::from_ne_bytes([223, 5, 5, 5]), 0, &mut row) } != 0 {
        return Route::default();
    }
    let gateway = Ipv4Addr::from(row.dwForwardNextHop.to_ne_bytes());
    let mut route = Route {
        gateway: (!gateway.is_unspecified()).then_some(gateway),
        ..Route::default()
    };
    let mut bytes = 15 * 1024;
    for _ in 0..3 {
        let mut buffer = vec![0u64; (bytes as usize).div_ceil(size_of::<u64>())];
        let mut ptr = buffer.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
        let flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST;
        unsafe {
            match GetAdaptersAddresses(AF_INET.into(), flags, null(), ptr, &mut bytes) {
                0 => (),
                ERROR_BUFFER_OVERFLOW => continue,
                _ => break,
            }
            while let Some(adapter) = ptr.as_ref() {
                if adapter.Anonymous1.Anonymous.IfIndex == row.dwForwardIfIndex {
                    route.adapter = wide_string(adapter.Description);
                    route.kind = adapter.IfType;
                    route.speed = adapter.ReceiveLinkSpeed;
                    let mut ip = adapter.FirstUnicastAddress;
                    while let Some(entry) = ip.as_ref() {
                        if let Some(IpAddr::V4(addr)) = socket_ip(entry.Address) {
                            route.ip = Some(addr);
                            break;
                        }
                        ip = entry.Next;
                    }
                    let mut dns = adapter.FirstDnsServerAddress;
                    while let Some(entry) = dns.as_ref() {
                        if let Some(addr) = socket_ip(entry.Address) {
                            route.dns.push(addr);
                        }
                        dns = entry.Next;
                    }
                    break;
                }
                ptr = adapter.Next;
            }
        }
        break;
    }
    route
}

/// Background scans make many drivers leave the channel briefly, which shows up as
/// latency spikes. Scan rarely on a timer; the user can still request a rescan.
const SCAN_INTERVAL: Duration = Duration::from_secs(60);

fn settle(pending: &mut Option<u64>, done: &mut u64) {
    if let Some(request) = pending.take() {
        *done = request;
    }
}

pub fn monitor(refresh: Receiver<()>, output: Sender<Snapshot>, testing: Arc<AtomicBool>) {
    let mut requests = 0;
    let mut pending = None;
    let mut done = 0;
    let mut wlan = None;
    let mut aps = Arc::new(Vec::new());
    let mut current_route = Arc::new(route());
    let mut scan = Scan::Waiting;
    let mut scan_due = Instant::now();
    let mut scan_read = None;
    loop {
        let now = Instant::now();
        let mut connection = None;
        let mut connection_error = None;
        let should_scan = now >= scan_due && !testing.load(Ordering::Relaxed);
        let handle = match &wlan {
            Some(_) => Ok(()),
            None => Wlan::open().map(|opened| wlan = Some(opened)),
        };
        match handle.and_then(|()| wlan.as_ref().unwrap().interfaces()) {
            Ok(interfaces) if !interfaces.is_empty() => {
                let wlan = wlan.as_ref().unwrap();
                if scan_read.is_some_and(|time| now >= time) {
                    scan_read = None;
                    let mut found = Vec::new();
                    let mut result = None;
                    for interface in &interfaces {
                        match wlan.nearby(&interface.InterfaceGuid) {
                            Ok(mut entries) => {
                                found.append(&mut entries);
                                result = Some(Scan::Ready);
                            }
                            Err(code) if result != Some(Scan::Ready) => {
                                result = Some(scan_error(code));
                            }
                            Err(_) => (),
                        }
                    }
                    found.sort_by_key(|ap| (std::cmp::Reverse(ap.signal), ap.bssid));
                    let mut seen = std::collections::HashSet::new();
                    found.retain(|ap| seen.insert((ap.bssid, ap.band as u8, ap.channel)));
                    aps = Arc::new(found);
                    scan = result.unwrap_or(Scan::NoAdapter);
                    settle(&mut pending, &mut done);
                }
                #[allow(non_upper_case_globals)]
                for interface in interfaces
                    .iter()
                    .filter(|i| i.isState == wlan_interface_state_connected)
                {
                    match wlan.current(&interface.InterfaceGuid, &aps) {
                        Ok(value) => {
                            connection = Some(value);
                            connection_error = None;
                            break;
                        }
                        Err(code) => connection_error = Some(code),
                    }
                }
                if connection_error == Some(ERROR_ACCESS_DENIED) {
                    aps = Arc::default();
                    scan = Scan::Denied;
                    settle(&mut pending, &mut done);
                } else if should_scan && scan_read.is_none() {
                    let mut requested = false;
                    for interface in &interfaces {
                        match wlan.start_scan(&interface.InterfaceGuid) {
                            Ok(()) => requested = true,
                            Err(code) if !requested => scan = scan_error(code),
                            Err(_) => (),
                        }
                    }
                    if requested {
                        // WlanScan returns immediately. Allow the driver time to finish.
                        scan_read = Some(Instant::now() + Duration::from_secs(4));
                        scan = Scan::Running;
                    } else {
                        aps = Arc::default();
                        settle(&mut pending, &mut done);
                    }
                }
            }
            result => {
                scan_read = None;
                settle(&mut pending, &mut done);
                aps = Arc::default();
                scan = match result {
                    Err(code) => {
                        wlan = None;
                        scan_error(code)
                    }
                    Ok(_) => Scan::NoAdapter,
                };
            }
        }
        if should_scan {
            scan_due = now + SCAN_INTERVAL;
            current_route = Arc::new(route());
        }
        if output
            .send(Snapshot {
                connection,
                connection_error,
                aps: aps.clone(),
                scan,
                route: current_route.clone(),
                rescan_done: done,
            })
            .is_err()
        {
            break;
        }
        match refresh.recv_timeout(Duration::from_secs(2)) {
            Ok(()) => {
                requests += 1;
                while refresh.try_recv().is_ok() {
                    requests += 1;
                }
                pending = Some(requests);
                current_route = Arc::new(route());
                scan_due = Instant::now();
            }
            Err(RecvTimeoutError::Timeout) => (),
            Err(RecvTimeoutError::Disconnected) => break,
        }
    }
}

fn scan_error(code: u32) -> Scan {
    if code == ERROR_ACCESS_DENIED {
        Scan::Denied
    } else {
        Scan::Failed(code)
    }
}

pub const PROBES: usize = 8;
pub const DNS_NAME: &str = "www.baidu.com";

pub struct Ping {
    pub name: &'static str,
    pub host: String,
    pub times: Vec<u32>,
    pub sent: usize,
    pub error: Option<String>,
}

struct Icmp(HANDLE);

impl Drop for Icmp {
    fn drop(&mut self) {
        unsafe { IcmpCloseHandle(self.0) };
    }
}

fn probe(name: &'static str, host: String) -> Ping {
    let mut result = Ping {
        name,
        host,
        times: Vec::new(),
        sent: 0,
        error: None,
    };
    let addr = match (result.host.as_str(), 0).to_socket_addrs() {
        Ok(mut addrs) => addrs.find_map(|addr| match addr.ip() {
            IpAddr::V4(ip) => Some(ip),
            IpAddr::V6(_) => None,
        }),
        Err(_) => None,
    };
    let Some(addr) = addr else {
        result.error = Some("无法解析 IPv4 地址".into());
        return result;
    };
    let handle = unsafe { IcmpCreateFile() };
    if handle == INVALID_HANDLE_VALUE {
        result.error = Some(format!(
            "无法启动 ICMP（{}）",
            std::io::Error::last_os_error()
        ));
        return result;
    }
    let icmp = Icmp(handle);
    let payload = [0u8; 32];
    let mut reply = [0u64; 16];
    for index in 0..PROBES {
        let start = Instant::now();
        let count = unsafe {
            IcmpSendEcho(
                icmp.0,
                u32::from_ne_bytes(addr.octets()),
                payload.as_ptr().cast::<c_void>(),
                payload.len() as u16,
                null(),
                reply.as_mut_ptr().cast(),
                size_of_val(&reply) as u32,
                1500,
            )
        };
        result.sent += 1;
        let reply = unsafe { &*reply.as_ptr().cast::<ICMP_ECHO_REPLY>() };
        if count != 0 && reply.Status == IP_SUCCESS {
            result.times.push(reply.RoundTripTime);
        }
        if index + 1 < PROBES {
            thread::sleep(Duration::from_secs(1).saturating_sub(start.elapsed()));
        }
    }
    result
}

pub fn latency(gateway: Option<Ipv4Addr>) -> (Vec<Ping>, Option<f64>) {
    let mut targets = Vec::new();
    if let Some(gateway) = gateway {
        targets.push(("路由器网关", gateway.to_string()));
    }
    targets.extend([
        ("阿里 DNS", "223.5.5.5".into()),
        ("腾讯 DNS", "119.29.29.29".into()),
        ("百度", DNS_NAME.into()),
    ]);
    thread::scope(|scope| {
        // Time name resolution alongside the probes so a slow resolver cannot delay them.
        let dns = scope.spawn(|| {
            let started = Instant::now();
            (DNS_NAME, 80)
                .to_socket_addrs()
                .ok()
                .and_then(|mut addrs| addrs.next())
                .map(|_| started.elapsed().as_secs_f64() * 1000.0)
        });
        let workers: Vec<_> = targets
            .into_iter()
            .map(|(name, host)| {
                let label = host.clone();
                (name, label, scope.spawn(move || probe(name, host)))
            })
            .collect();
        let pings = workers
            .into_iter()
            .map(|(name, host, worker)| {
                worker.join().unwrap_or_else(|_| Ping {
                    name,
                    host,
                    times: Vec::new(),
                    sent: 0,
                    error: Some("探测线程异常退出".into()),
                })
            })
            .collect();
        (pings, dns.join().ok().flatten())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frequency_distinguishes_overlapping_channel_numbers() {
        assert_eq!(frequency(2_412_000), (Band::G24, Some(1)));
        assert_eq!(frequency(2_484_000), (Band::G24, Some(14)));
        assert_eq!(frequency(5_180_000), (Band::G5, Some(36)));
        assert_eq!(frequency(5_955_000), (Band::G6, Some(1)));
    }

    #[test]
    fn rsn_transition_mode_and_truncated_information_elements() {
        let data = [
            48, 18, 1, 0, 0, 15, 172, 4, 0, 0, 2, 0, 0, 15, 172, 2, 0, 15, 172, 8,
        ];
        assert_eq!(ap_security(&data, true), "WPA2/WPA3");
        assert_eq!(ap_security(&data[..11], true), "WEP");
    }

    fn rsn(akm: u8) -> [u8; 20] {
        [
            48, 18, 1, 0, 0, 15, 172, 4, 1, 0, 0, 15, 172, 4, 1, 0, 0, 15, 172, akm,
        ]
    }

    #[test]
    fn rsn_akm_suites() {
        assert_eq!(ap_security(&rsn(1), true), "WPA2-Enterprise");
        assert_eq!(ap_security(&rsn(5), true), "WPA2-Enterprise");
        assert_eq!(ap_security(&rsn(2), true), "WPA2-Personal");
        assert_eq!(ap_security(&rsn(8), true), "WPA3-Personal");
        assert_eq!(ap_security(&rsn(18), true), "OWE");
        assert_eq!(ap_security(&rsn(12), true), "WPA3-Enterprise");
        assert_eq!(ap_security(&rsn(99), true), "RSN");
    }

    #[test]
    fn legacy_wpa_and_open_networks() {
        let wpa = [221, 4, 0, 0x50, 0xf2, 1];
        assert_eq!(ap_security(&wpa, true), "WPA");
        assert_eq!(ap_security(&[], false), "开放");
        // A length that runs past the buffer must not be read.
        assert_eq!(ap_security(&[48, 200, 1, 0], true), "WEP");
    }

    #[test]
    fn frequency_band_edges() {
        assert_eq!(frequency(2_472_000), (Band::G24, Some(13)));
        assert_eq!(frequency(5_825_000), (Band::G5, Some(165)));
        assert_eq!(frequency(5_935_000), (Band::G6, Some(2)));
        assert_eq!(frequency(7_115_000), (Band::G6, Some(233)));
        assert_eq!(frequency(2_400_000), (Band::Other, None));
        assert_eq!(frequency(5_182_000), (Band::Other, None));
    }

    #[test]
    fn band_inferred_from_channel_and_phy() {
        assert_eq!(infer_band(6, dot11_phy_type_ht), Band::G24);
        assert_eq!(infer_band(36, dot11_phy_type_vht), Band::G5);
        assert_eq!(infer_band(5, dot11_phy_type_he), Band::Other);
    }

    #[test]
    fn ssid_decoding_falls_back_to_gbk() {
        assert_eq!(decode_ssid("咖啡店".as_bytes()), "咖啡店");
        // "测试" encoded as GBK.
        assert_eq!(decode_ssid(&[0xb2, 0xe2, 0xca, 0xd4]), "测试");
    }

    #[test]
    fn related_bssids() {
        let base = [0x10, 0x20, 0x30, 0x40, 0x50, 0x60];
        assert!(same_device(&base, &[0x12, 0x20, 0x30, 0x40, 0x50, 0x61]));
        assert!(!same_device(&base, &[0x10, 0x20, 0x30, 0x41, 0x50, 0x60]));
        assert_eq!(mac_masked(&base), "10:20:30:**:**:**");
    }
}
