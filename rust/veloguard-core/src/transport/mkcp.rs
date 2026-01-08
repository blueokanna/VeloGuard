use crate::error::{Error, Result};
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::UdpSocket;
use tokio::sync::Mutex;

const KCP_RTO_NDL: u32 = 30;
const KCP_RTO_MIN: u32 = 100;
const KCP_RTO_DEF: u32 = 200;
const KCP_RTO_MAX: u32 = 60000;
const KCP_CMD_PUSH: u8 = 81;
const KCP_CMD_ACK: u8 = 82;
const KCP_CMD_WASK: u8 = 83;
const KCP_CMD_WINS: u8 = 84;
const KCP_ASK_SEND: u32 = 1;
const KCP_ASK_TELL: u32 = 2;
const KCP_WND_SND: u32 = 32;
const KCP_WND_RCV: u32 = 128;
const KCP_MTU_DEF: usize = 1350;
const KCP_INTERVAL: u32 = 100;
const KCP_OVERHEAD: usize = 24;
const KCP_DEADLINK: u32 = 20;
const KCP_THRESH_INIT: u32 = 2;
const KCP_THRESH_MIN: u32 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MkcpHeaderType {
    None,
    Srtp,
    Utp,
    Wechat,
    Dtls,
    Wireguard,
}

impl MkcpHeaderType {
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "srtp" => MkcpHeaderType::Srtp,
            "utp" => MkcpHeaderType::Utp,
            "wechat-video" | "wechat" => MkcpHeaderType::Wechat,
            "dtls" => MkcpHeaderType::Dtls,
            "wireguard" | "wg" => MkcpHeaderType::Wireguard,
            _ => MkcpHeaderType::None,
        }
    }

    pub fn header_bytes(&self) -> Vec<u8> {
        match self {
            MkcpHeaderType::None => vec![],
            MkcpHeaderType::Srtp => {
                let mut header = vec![0x80, 0x60];
                let mut seq = [0u8; 2];
                getrandom::fill(&mut seq).ok();
                header.extend_from_slice(&seq);
                let mut ts = [0u8; 4];
                getrandom::fill(&mut ts).ok();
                header.extend_from_slice(&ts);
                let mut ssrc = [0u8; 4];
                getrandom::fill(&mut ssrc).ok();
                header.extend_from_slice(&ssrc);
                header
            }
            MkcpHeaderType::Utp => {
                let mut header = vec![0x01, 0x00, 0x00, 0x00];
                let mut conn_id = [0u8; 2];
                getrandom::fill(&mut conn_id).ok();
                header.extend_from_slice(&conn_id);
                let mut ts = [0u8; 4];
                getrandom::fill(&mut ts).ok();
                header.extend_from_slice(&ts);
                header.extend_from_slice(&[0u8; 8]);
                header
            }
            MkcpHeaderType::Wechat => {
                let mut header = vec![0xa1, 0x08];
                let mut random = [0u8; 10];
                getrandom::fill(&mut random).ok();
                header.extend_from_slice(&random);
                header
            }
            MkcpHeaderType::Dtls => {
                let mut header = vec![0x17, 0xfe, 0xfd];
                let mut epoch = [0u8; 2];
                getrandom::fill(&mut epoch).ok();
                header.extend_from_slice(&epoch);
                let mut seq = [0u8; 6];
                getrandom::fill(&mut seq).ok();
                header.extend_from_slice(&seq);
                header
            }
            MkcpHeaderType::Wireguard => {
                let mut header = vec![0x04, 0x00, 0x00, 0x00];
                let mut receiver = [0u8; 4];
                getrandom::fill(&mut receiver).ok();
                header.extend_from_slice(&receiver);
                let mut counter = [0u8; 8];
                getrandom::fill(&mut counter).ok();
                header.extend_from_slice(&counter);
                header
            }
        }
    }

    pub fn header_len(&self) -> usize {
        match self {
            MkcpHeaderType::None => 0,
            MkcpHeaderType::Srtp => 12,
            MkcpHeaderType::Utp => 20,
            MkcpHeaderType::Wechat => 12,
            MkcpHeaderType::Dtls => 13,
            MkcpHeaderType::Wireguard => 16,
        }
    }
}

#[derive(Debug, Clone)]
pub struct MkcpConfig {
    pub mtu: usize,
    pub tti: u32,
    pub uplink_capacity: u32,
    pub downlink_capacity: u32,
    pub congestion: bool,
    pub read_buffer_size: usize,
    pub write_buffer_size: usize,
    pub header_type: MkcpHeaderType,
    pub seed: Option<String>,
}

impl Default for MkcpConfig {
    fn default() -> Self {
        Self {
            mtu: KCP_MTU_DEF,
            tti: 50,
            uplink_capacity: 5,
            downlink_capacity: 20,
            congestion: false,
            read_buffer_size: 4 * 1024 * 1024,
            write_buffer_size: 4 * 1024 * 1024,
            header_type: MkcpHeaderType::None,
            seed: None,
        }
    }
}

#[derive(Debug, Clone)]
struct KcpSegment {
    conv: u32,
    cmd: u8,
    frg: u8,
    wnd: u16,
    ts: u32,
    sn: u32,
    una: u32,
    resendts: u32,
    rto: u32,
    fastack: u32,
    xmit: u32,
    data: Vec<u8>,
}

impl KcpSegment {
    fn new(conv: u32) -> Self {
        Self {
            conv,
            cmd: KCP_CMD_PUSH,
            frg: 0,
            wnd: 0,
            ts: 0,
            sn: 0,
            una: 0,
            resendts: 0,
            rto: 0,
            fastack: 0,
            xmit: 0,
            data: Vec::new(),
        }
    }

    fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(KCP_OVERHEAD + self.data.len());
        buf.extend_from_slice(&self.conv.to_le_bytes());
        buf.push(self.cmd);
        buf.push(self.frg);
        buf.extend_from_slice(&self.wnd.to_le_bytes());
        buf.extend_from_slice(&self.ts.to_le_bytes());
        buf.extend_from_slice(&self.sn.to_le_bytes());
        buf.extend_from_slice(&self.una.to_le_bytes());
        buf.extend_from_slice(&(self.data.len() as u32).to_le_bytes());
        buf.extend_from_slice(&self.data);
        buf
    }

    fn decode(data: &[u8]) -> Option<(Self, usize)> {
        if data.len() < KCP_OVERHEAD {
            return None;
        }
        let conv = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let cmd = data[4];
        let frg = data[5];
        let wnd = u16::from_le_bytes([data[6], data[7]]);
        let ts = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
        let sn = u32::from_le_bytes([data[12], data[13], data[14], data[15]]);
        let una = u32::from_le_bytes([data[16], data[17], data[18], data[19]]);
        let len = u32::from_le_bytes([data[20], data[21], data[22], data[23]]) as usize;
        if data.len() < KCP_OVERHEAD + len {
            return None;
        }
        let seg_data = data[KCP_OVERHEAD..KCP_OVERHEAD + len].to_vec();
        Some((
            Self {
                conv, cmd, frg, wnd, ts, sn, una,
                resendts: 0, rto: 0, fastack: 0, xmit: 0,
                data: seg_data,
            },
            KCP_OVERHEAD + len,
        ))
    }
}

struct Kcp {
    conv: u32,
    mtu: usize,
    mss: usize,
    state: i32,
    snd_una: u32,
    snd_nxt: u32,
    rcv_nxt: u32,
    ssthresh: u32,
    rx_rttval: u32,
    rx_srtt: u32,
    rx_rto: u32,
    rx_minrto: u32,
    snd_wnd: u32,
    rcv_wnd: u32,
    rmt_wnd: u32,
    cwnd: u32,
    probe: u32,
    current: u32,
    interval: u32,
    ts_flush: u32,
    xmit: u32,
    nodelay: bool,
    updated: bool,
    dead_link: u32,
    incr: u32,
    snd_queue: VecDeque<KcpSegment>,
    rcv_queue: VecDeque<KcpSegment>,
    snd_buf: VecDeque<KcpSegment>,
    rcv_buf: VecDeque<KcpSegment>,
    acklist: Vec<(u32, u32)>,
    #[allow(dead_code)]
    buffer: Vec<u8>,
    fastresend: i32,
    fastlimit: i32,
    nocwnd: bool,
    stream: bool,
}

impl Kcp {
    fn new(conv: u32) -> Self {
        Self {
            conv,
            mtu: KCP_MTU_DEF,
            mss: KCP_MTU_DEF - KCP_OVERHEAD,
            state: 0,
            snd_una: 0,
            snd_nxt: 0,
            rcv_nxt: 0,
            ssthresh: KCP_THRESH_INIT,
            rx_rttval: 0,
            rx_srtt: 0,
            rx_rto: KCP_RTO_DEF,
            rx_minrto: KCP_RTO_MIN,
            snd_wnd: KCP_WND_SND,
            rcv_wnd: KCP_WND_RCV,
            rmt_wnd: KCP_WND_RCV,
            cwnd: 0,
            probe: 0,
            current: 0,
            interval: KCP_INTERVAL,
            ts_flush: KCP_INTERVAL,
            xmit: 0,
            nodelay: false,
            updated: false,
            dead_link: KCP_DEADLINK,
            incr: 0,
            snd_queue: VecDeque::new(),
            rcv_queue: VecDeque::new(),
            snd_buf: VecDeque::new(),
            rcv_buf: VecDeque::new(),
            acklist: Vec::new(),
            buffer: vec![0u8; (KCP_MTU_DEF + KCP_OVERHEAD) * 3],
            fastresend: 0,
            fastlimit: 5,
            nocwnd: false,
            stream: false,
        }
    }

    fn set_nodelay(&mut self, nodelay: bool, interval: u32, resend: i32, nc: bool) {
        self.nodelay = nodelay;
        self.rx_minrto = if nodelay { KCP_RTO_NDL } else { KCP_RTO_MIN };
        if interval > 0 {
            self.interval = interval.clamp(10, 5000);
        }
        self.fastresend = resend;
        self.nocwnd = nc;
    }

    fn set_wndsize(&mut self, sndwnd: u32, rcvwnd: u32) {
        if sndwnd > 0 {
            self.snd_wnd = sndwnd;
        }
        if rcvwnd > 0 {
            self.rcv_wnd = rcvwnd.max(KCP_WND_RCV);
        }
    }

    fn set_mtu(&mut self, mtu: usize) -> bool {
        if mtu < 50 || mtu < KCP_OVERHEAD {
            return false;
        }
        self.mtu = mtu;
        self.mss = mtu - KCP_OVERHEAD;
        self.buffer = vec![0u8; (mtu + KCP_OVERHEAD) * 3];
        true
    }

    fn send(&mut self, data: &[u8]) -> Result<usize> {
        if data.is_empty() {
            return Err(Error::protocol("Empty data"));
        }
        let mut sent = 0;
        let mut offset = 0;
        let count = if data.len() <= self.mss { 1 } else { data.len().div_ceil(self.mss) };
        if count > 255 {
            return Err(Error::protocol("Data too large"));
        }
        for i in 0..count {
            let size = std::cmp::min(self.mss, data.len() - offset);
            let mut seg = KcpSegment::new(self.conv);
            seg.data = data[offset..offset + size].to_vec();
            seg.frg = if self.stream { 0 } else { (count - i - 1) as u8 };
            self.snd_queue.push_back(seg);
            offset += size;
            sent += size;
        }
        Ok(sent)
    }

    fn recv(&mut self) -> Option<Vec<u8>> {
        if self.rcv_queue.is_empty() {
            return None;
        }
        let mut peeksize = 0;
        for seg in &self.rcv_queue {
            peeksize += seg.data.len();
            if seg.frg == 0 {
                break;
            }
        }
        if peeksize == 0 {
            return None;
        }
        let mut data = Vec::with_capacity(peeksize);
        while let Some(seg) = self.rcv_queue.pop_front() {
            data.extend_from_slice(&seg.data);
            if seg.frg == 0 {
                break;
            }
        }
        while !self.rcv_buf.is_empty() {
            if let Some(seg) = self.rcv_buf.front() {
                if seg.sn == self.rcv_nxt && self.rcv_queue.len() < self.rcv_wnd as usize {
                    let seg = self.rcv_buf.pop_front().unwrap();
                    self.rcv_nxt = self.rcv_nxt.wrapping_add(1);
                    self.rcv_queue.push_back(seg);
                } else {
                    break;
                }
            }
        }
        Some(data)
    }

    fn input(&mut self, data: &[u8]) -> Result<()> {
        if data.len() < KCP_OVERHEAD {
            return Err(Error::protocol("Data too short"));
        }
        let mut offset = 0;
        let mut flag = false;
        let mut maxack: u32 = 0;
        let mut latest_ts: u32 = 0;
        while offset + KCP_OVERHEAD <= data.len() {
            let (seg, consumed) = match KcpSegment::decode(&data[offset..]) {
                Some(s) => s,
                None => break,
            };
            if seg.conv != self.conv {
                return Err(Error::protocol("Invalid conversation ID"));
            }
            offset += consumed;
            self.rmt_wnd = seg.wnd as u32;
            self.parse_una(seg.una);
            self.shrink_buf();
            match seg.cmd {
                KCP_CMD_ACK => {
                    if self.current >= seg.ts {
                        self.update_ack(self.current - seg.ts);
                    }
                    self.parse_ack(seg.sn);
                    self.shrink_buf();
                    if !flag {
                        flag = true;
                        maxack = seg.sn;
                        latest_ts = seg.ts;
                    } else if seg.sn > maxack {
                        maxack = seg.sn;
                        latest_ts = seg.ts;
                    }
                }
                KCP_CMD_PUSH => {
                    if seg.sn < self.rcv_nxt.wrapping_add(self.rcv_wnd) {
                        self.acklist.push((seg.sn, seg.ts));
                        if seg.sn >= self.rcv_nxt {
                            self.parse_data(seg);
                        }
                    }
                }
                KCP_CMD_WASK => {
                    self.probe |= KCP_ASK_TELL;
                }
                KCP_CMD_WINS => {}
                _ => {
                    return Err(Error::protocol("Unknown command"));
                }
            }
        }
        if flag {
            self.parse_fastack(maxack, latest_ts);
        }
        if self.snd_una > self.cwnd {
            let mss = self.mss as u32;
            if self.cwnd < self.ssthresh {
                self.cwnd += 1;
                self.incr += mss;
            } else {
                if self.incr < mss {
                    self.incr = mss;
                }
                self.incr += (mss * mss) / self.incr + (mss / 16);
                if (self.cwnd + 1) * mss <= self.incr {
                    self.cwnd = if mss > 0 { self.incr.div_ceil(mss) } else { self.incr };
                }
            }
            if self.cwnd > self.rmt_wnd {
                self.cwnd = self.rmt_wnd;
                self.incr = self.rmt_wnd * mss;
            }
        }
        Ok(())
    }

    fn flush(&mut self) -> Vec<Vec<u8>> {
        if !self.updated {
            return Vec::new();
        }
        let mut output = Vec::new();
        let mut seg = KcpSegment::new(self.conv);
        seg.wnd = self.wnd_unused() as u16;
        seg.una = self.rcv_nxt;
        for (sn, ts) in self.acklist.drain(..) {
            if output.len() >= 3 {
                break;
            }
            seg.cmd = KCP_CMD_ACK;
            seg.sn = sn;
            seg.ts = ts;
            output.push(seg.encode());
        }
        if self.probe & KCP_ASK_SEND != 0 {
            seg.cmd = KCP_CMD_WASK;
            output.push(seg.encode());
        }
        if self.probe & KCP_ASK_TELL != 0 {
            seg.cmd = KCP_CMD_WINS;
            output.push(seg.encode());
        }
        self.probe = 0;
        let cwnd = std::cmp::min(self.snd_wnd, self.rmt_wnd);
        let cwnd = if self.nocwnd { cwnd } else { std::cmp::min(cwnd, self.cwnd) };
        while self.snd_nxt < self.snd_una.wrapping_add(cwnd) {
            if let Some(mut newseg) = self.snd_queue.pop_front() {
                newseg.conv = self.conv;
                newseg.cmd = KCP_CMD_PUSH;
                newseg.wnd = seg.wnd;
                newseg.ts = self.current;
                newseg.sn = self.snd_nxt;
                newseg.una = self.rcv_nxt;
                newseg.resendts = self.current;
                newseg.rto = self.rx_rto;
                newseg.fastack = 0;
                newseg.xmit = 0;
                self.snd_buf.push_back(newseg);
                self.snd_nxt = self.snd_nxt.wrapping_add(1);
            } else {
                break;
            }
        }
        let resent = if self.fastresend > 0 { self.fastresend as u32 } else { u32::MAX };
        let rtomin = if self.nodelay { 0 } else { self.rx_rto >> 3 };
        let mut change = 0;
        let mut lost = 0;
        let wnd_unused = self.wnd_unused() as u16;
        for seg in &mut self.snd_buf {
            let mut needsend = false;
            if seg.xmit == 0 {
                needsend = true;
                seg.xmit += 1;
                seg.rto = self.rx_rto;
                seg.resendts = self.current.wrapping_add(seg.rto).wrapping_add(rtomin);
            } else if self.current >= seg.resendts {
                needsend = true;
                seg.xmit += 1;
                self.xmit += 1;
                if !self.nodelay {
                    seg.rto += std::cmp::max(seg.rto, self.rx_rto);
                } else {
                    let step = if self.nodelay { seg.rto } else { self.rx_rto };
                    seg.rto += step / 2;
                }
                seg.resendts = self.current.wrapping_add(seg.rto);
                lost += 1;
            } else if seg.fastack >= resent
                && (seg.xmit <= self.fastlimit as u32 || self.fastlimit <= 0) {
                    needsend = true;
                    seg.xmit += 1;
                    seg.fastack = 0;
                    seg.resendts = self.current.wrapping_add(seg.rto);
                    change += 1;
                }
            if needsend {
                seg.ts = self.current;
                seg.wnd = wnd_unused;
                seg.una = self.rcv_nxt;
                output.push(seg.encode());
                if seg.xmit >= self.dead_link {
                    self.state = -1;
                }
            }
        }
        if change > 0 {
            let inflight = self.snd_nxt.wrapping_sub(self.snd_una);
            self.ssthresh = std::cmp::max(inflight / 2, KCP_THRESH_MIN);
            self.cwnd = self.ssthresh + resent;
            self.incr = self.cwnd * self.mss as u32;
        }
        if lost > 0 {
            self.ssthresh = std::cmp::max(cwnd / 2, KCP_THRESH_MIN);
            self.cwnd = 1;
            self.incr = self.mss as u32;
        }
        if self.cwnd < 1 {
            self.cwnd = 1;
            self.incr = self.mss as u32;
        }
        output
    }

    fn update(&mut self, current: u32) {
        self.current = current;
        if !self.updated {
            self.updated = true;
            self.ts_flush = self.current;
        }
        let mut slap = self.current as i32 - self.ts_flush as i32;
        if !(-10000..10000).contains(&slap) {
            self.ts_flush = self.current;
            slap = 0;
        }
        if slap >= 0 {
            self.ts_flush = self.ts_flush.wrapping_add(self.interval);
            if self.current >= self.ts_flush {
                self.ts_flush = self.current.wrapping_add(self.interval);
            }
        }
    }

    fn wnd_unused(&self) -> u32 {
        if self.rcv_queue.len() < self.rcv_wnd as usize {
            self.rcv_wnd - self.rcv_queue.len() as u32
        } else {
            0
        }
    }

    fn parse_una(&mut self, una: u32) {
        while let Some(seg) = self.snd_buf.front() {
            if una > seg.sn {
                self.snd_buf.pop_front();
            } else {
                break;
            }
        }
    }

    fn shrink_buf(&mut self) {
        self.snd_una = if let Some(seg) = self.snd_buf.front() { seg.sn } else { self.snd_nxt };
    }

    fn parse_ack(&mut self, sn: u32) {
        if sn < self.snd_una || sn >= self.snd_nxt {
            return;
        }
        self.snd_buf.retain(|seg| seg.sn != sn);
    }

    fn parse_fastack(&mut self, sn: u32, _ts: u32) {
        if sn < self.snd_una || sn >= self.snd_nxt {
            return;
        }
        for seg in &mut self.snd_buf {
            if sn < seg.sn {
                break;
            } else if sn != seg.sn {
                seg.fastack += 1;
            }
        }
    }

    fn parse_data(&mut self, newseg: KcpSegment) {
        let sn = newseg.sn;
        if sn >= self.rcv_nxt.wrapping_add(self.rcv_wnd) || sn < self.rcv_nxt {
            return;
        }
        let mut repeat = false;
        let mut insert_idx = self.rcv_buf.len();
        for (i, seg) in self.rcv_buf.iter().enumerate().rev() {
            if seg.sn == sn {
                repeat = true;
                break;
            }
            if seg.sn < sn {
                insert_idx = i + 1;
                break;
            }
            insert_idx = i;
        }
        if !repeat {
            self.rcv_buf.insert(insert_idx, newseg);
        }
        while !self.rcv_buf.is_empty() {
            if let Some(seg) = self.rcv_buf.front() {
                if seg.sn == self.rcv_nxt && self.rcv_queue.len() < self.rcv_wnd as usize {
                    let seg = self.rcv_buf.pop_front().unwrap();
                    self.rcv_nxt = self.rcv_nxt.wrapping_add(1);
                    self.rcv_queue.push_back(seg);
                } else {
                    break;
                }
            }
        }
    }

    fn update_ack(&mut self, rtt: u32) {
        if self.rx_srtt == 0 {
            self.rx_srtt = rtt;
            self.rx_rttval = rtt / 2;
        } else {
            let delta = rtt.abs_diff(self.rx_srtt);
            self.rx_rttval = (3 * self.rx_rttval + delta) / 4;
            self.rx_srtt = (7 * self.rx_srtt + rtt) / 8;
            if self.rx_srtt < 1 {
                self.rx_srtt = 1;
            }
        }
        let rto = self.rx_srtt + std::cmp::max(self.interval, 4 * self.rx_rttval);
        self.rx_rto = rto.clamp(self.rx_minrto, KCP_RTO_MAX);
    }
}

pub struct MkcpTransport {
    #[allow(dead_code)]
    config: MkcpConfig,
    socket: Arc<UdpSocket>,
    #[allow(dead_code)]
    remote_addr: SocketAddr,
    kcp: Arc<Mutex<Kcp>>,
    #[allow(dead_code)]
    recv_buf: Arc<Mutex<VecDeque<Vec<u8>>>>,
    start_time: Instant,
    closed: Arc<std::sync::atomic::AtomicBool>,
}

impl MkcpTransport {
    pub async fn connect(remote_addr: SocketAddr, config: MkcpConfig) -> Result<Self> {
        let bind_addr: SocketAddr = if remote_addr.is_ipv6() {
            "[::]:0".parse().unwrap()
        } else {
            "0.0.0.0:0".parse().unwrap()
        };
        let socket = UdpSocket::bind(bind_addr)
            .await
            .map_err(|e| Error::network(format!("Failed to bind UDP socket: {}", e)))?;
        socket
            .connect(remote_addr)
            .await
            .map_err(|e| Error::network(format!("Failed to connect UDP socket: {}", e)))?;
        let mut conv_bytes = [0u8; 4];
        getrandom::fill(&mut conv_bytes).ok();
        let conv = u32::from_le_bytes(conv_bytes);
        let mut kcp = Kcp::new(conv);
        kcp.set_mtu(config.mtu);
        kcp.set_wndsize(
            config.write_buffer_size as u32 / config.mtu as u32,
            config.read_buffer_size as u32 / config.mtu as u32,
        );
        if config.congestion {
            kcp.set_nodelay(false, config.tti, 0, false);
        } else {
            kcp.set_nodelay(true, config.tti, 2, true);
        }
        let transport = Self {
            config,
            socket: Arc::new(socket),
            remote_addr,
            kcp: Arc::new(Mutex::new(kcp)),
            recv_buf: Arc::new(Mutex::new(VecDeque::new())),
            start_time: Instant::now(),
            closed: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        };
        transport.start_background_tasks();
        Ok(transport)
    }

    fn start_background_tasks(&self) {
        let socket = self.socket.clone();
        let kcp = self.kcp.clone();
        let closed = self.closed.clone();
        let header_len = self.config.header_type.header_len();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65536];
            while !closed.load(Ordering::Relaxed) {
                match tokio::time::timeout(Duration::from_millis(100), socket.recv(&mut buf)).await {
                    Ok(Ok(n)) => {
                        if n > header_len {
                            let data = &buf[header_len..n];
                            let mut kcp_guard = kcp.lock().await;
                            if let Err(e) = kcp_guard.input(data) {
                                tracing::debug!("mKCP input error: {}", e);
                            }
                        }
                    }
                    Ok(Err(e)) => {
                        tracing::debug!("mKCP recv error: {}", e);
                        break;
                    }
                    Err(_) => {}
                }
            }
        });
        let socket = self.socket.clone();
        let kcp = self.kcp.clone();
        let closed = self.closed.clone();
        let start_time = self.start_time;
        let header_type = self.config.header_type;
        let interval = self.config.tti;
        tokio::spawn(async move {
            while !closed.load(Ordering::Relaxed) {
                let current = start_time.elapsed().as_millis() as u32;
                let packets = {
                    let mut kcp_guard = kcp.lock().await;
                    kcp_guard.update(current);
                    kcp_guard.flush()
                };
                for packet in packets {
                    let mut data = header_type.header_bytes();
                    data.extend_from_slice(&packet);
                    if let Err(e) = socket.send(&data).await {
                        tracing::debug!("mKCP send error: {}", e);
                    }
                }
                tokio::time::sleep(Duration::from_millis(interval as u64)).await;
            }
        });
    }

    pub async fn send(&self, data: &[u8]) -> Result<usize> {
        let mut kcp = self.kcp.lock().await;
        kcp.send(data)
    }

    pub async fn recv(&self) -> Result<Vec<u8>> {
        loop {
            {
                let mut kcp = self.kcp.lock().await;
                if let Some(data) = kcp.recv() {
                    return Ok(data);
                }
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
            if self.closed.load(Ordering::Relaxed) {
                return Err(Error::network("Connection closed"));
            }
        }
    }

    pub fn close(&self) {
        self.closed.store(true, Ordering::Relaxed);
    }
}

impl Drop for MkcpTransport {
    fn drop(&mut self) {
        self.close();
    }
}

pub struct MkcpStream {
    transport: Arc<MkcpTransport>,
    read_buf: Vec<u8>,
    read_pos: usize,
}

impl MkcpStream {
    pub fn new(transport: MkcpTransport) -> Self {
        Self {
            transport: Arc::new(transport),
            read_buf: Vec::new(),
            read_pos: 0,
        }
    }

    pub async fn connect(remote_addr: SocketAddr, config: MkcpConfig) -> Result<Self> {
        let transport = MkcpTransport::connect(remote_addr, config).await?;
        Ok(Self::new(transport))
    }
}

impl AsyncRead for MkcpStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        use std::task::Poll;
        if self.read_pos < self.read_buf.len() {
            let remaining = &self.read_buf[self.read_pos..];
            let to_copy = std::cmp::min(remaining.len(), buf.remaining());
            buf.put_slice(&remaining[..to_copy]);
            self.read_pos += to_copy;
            if self.read_pos >= self.read_buf.len() {
                self.read_buf.clear();
                self.read_pos = 0;
            }
            return Poll::Ready(Ok(()));
        }
        let transport = self.transport.clone();
        let waker = cx.waker().clone();
        tokio::spawn(async move {
            if let Ok(_data) = transport.recv().await {
                waker.wake();
            }
        });
        Poll::Pending
    }
}

impl AsyncWrite for MkcpStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        use std::task::Poll;
        let transport = self.transport.clone();
        let data = buf.to_vec();
        let waker = cx.waker().clone();
        tokio::spawn(async move {
            match transport.send(&data).await {
                Ok(_) => waker.wake(),
                Err(_) => waker.wake(),
            }
        });
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        self.transport.close();
        std::task::Poll::Ready(Ok(()))
    }
}
