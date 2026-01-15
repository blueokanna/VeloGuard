use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Once;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rsntp::SntpClient;

static TIME_OFFSET_MS: AtomicI64 = AtomicI64::new(0);
static LAST_SYNC_TIME: AtomicI64 = AtomicI64::new(0);
static SYNC_INITIALIZED: Once = Once::new();
const NTP_SERVERS: &[&str] = &[
    "ntp.aliyun.com",
    "ntp1.aliyun.com",
    "ntp2.aliyun.com",
    "cn.ntp.org.cn",
    "time.windows.com",
    "time.google.com",
    "time.cloudflare.com",
    "pool.ntp.org",
    "cn.pool.ntp.org",
];

const SYNC_INTERVAL_SECS: i64 = 300;

/// 时间戳诊断信息，用于调试 VMess 连接问题
#[derive(Debug, Clone)]
pub struct TimestampDiagnostics {
    /// 本地系统时间戳（秒）
    pub local_timestamp_secs: i64,
    /// NTP 校正后的时间戳（秒）
    pub corrected_timestamp_secs: i64,
    /// NTP 偏移量（毫秒）
    pub ntp_offset_ms: i64,
    /// 最终用于 VMess 的时间戳（秒）
    pub vmess_timestamp_secs: i64,
    /// 随机抖动值（秒）
    pub jitter_secs: i64,
    /// 上次 NTP 同步时间（秒）
    pub last_sync_time_secs: i64,
    /// 是否需要重新同步
    pub needs_resync: bool,
    /// 疑似毫秒错误（时间戳看起来像毫秒而不是秒）
    pub suspected_milliseconds_error: bool,
    /// 诊断消息
    pub diagnostic_message: String,
}

impl TimestampDiagnostics {
    /// 生成诊断消息
    fn generate_diagnostic_message(&self) -> String {
        let mut issues = Vec::new();

        if self.suspected_milliseconds_error {
            issues.push(format!(
                "⚠️ CRITICAL: Timestamp {} looks like MILLISECONDS, not seconds! \
                This will cause VMess auth to fail. Check NTP offset unit conversion.",
                self.vmess_timestamp_secs
            ));
        }

        if self.needs_resync {
            issues.push(format!(
                "⚠️ NTP sync is stale (last sync: {}s ago, threshold: {}s)",
                self.local_timestamp_secs - self.last_sync_time_secs,
                SYNC_INTERVAL_SECS
            ));
        }

        if self.ntp_offset_ms.abs() > 60_000 {
            issues.push(format!(
                "⚠️ Large NTP offset: {}ms ({}s). Local clock may be significantly off.",
                self.ntp_offset_ms,
                self.ntp_offset_ms / 1000
            ));
        }

        let diff = (self.vmess_timestamp_secs - self.corrected_timestamp_secs).abs();
        if diff > 10 {
            issues.push(format!("⚠️ Jitter {} exceeds expected range ±10s", diff));
        }

        if issues.is_empty() {
            "✓ Timestamp diagnostics OK".to_string()
        } else {
            issues.join("\n")
        }
    }
}

#[derive(Debug, Clone)]
pub struct SyncResult {
    pub success: bool,
    pub server: Option<String>,
    pub offset_ms: i64,
    pub error: Option<String>,
}

pub fn sync_time_blocking() -> SyncResult {
    let client = SntpClient::new();

    for server in NTP_SERVERS {
        match sync_from_server(&client, server) {
            Ok(offset_ms) => {
                TIME_OFFSET_MS.store(offset_ms, Ordering::SeqCst);
                LAST_SYNC_TIME.store(get_local_timestamp(), Ordering::SeqCst);

                tracing::info!(
                    "NTP sync successful: server={}, offset={}ms ({}s)",
                    server,
                    offset_ms,
                    offset_ms / 1000
                );

                return SyncResult {
                    success: true,
                    server: Some(server.to_string()),
                    offset_ms,
                    error: None,
                };
            }
            Err(e) => {
                tracing::debug!("NTP sync failed for {}: {}", server, e);
                continue;
            }
        }
    }

    tracing::warn!("All NTP servers failed, using local time");
    SyncResult {
        success: false,
        server: None,
        offset_ms: 0,
        error: Some("All NTP servers failed".to_string()),
    }
}

fn sync_from_server(client: &SntpClient, server: &str) -> Result<i64, String> {
    let result = std::panic::catch_unwind(|| client.synchronize(server));

    match result {
        Ok(Ok(response)) => {
            let ntp_datetime = response.datetime();
            let ntp_chrono = ntp_datetime
                .into_chrono_datetime()
                .map_err(|e| format!("Failed to convert NTP time: {:?}", e))?;

            let ntp_timestamp_ms = ntp_chrono.timestamp_millis();
            let local_timestamp_ms = get_local_timestamp_ms();
            let offset_ms = ntp_timestamp_ms - local_timestamp_ms;

            Ok(offset_ms)
        }
        Ok(Err(e)) => Err(format!("NTP error: {:?}", e)),
        Err(_) => Err("NTP request panicked".to_string()),
    }
}

fn get_local_timestamp() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs() as i64
}

fn get_local_timestamp_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_millis() as i64
}

pub fn get_corrected_timestamp() -> i64 {
    let local_secs = get_local_timestamp(); // 直接用秒，避免毫秒转换精度问题
    let offset_ms = TIME_OFFSET_MS.load(Ordering::SeqCst);
    let offset_secs = offset_ms / 1000; // 毫秒转秒
    local_secs + offset_secs
}

pub fn get_vmess_timestamp() -> i64 {
    let corrected_ts = get_corrected_timestamp();
    if corrected_ts > 10_000_000_000 {
        tracing::error!(
            "CRITICAL: corrected_ts {} looks like milliseconds! Expected ~{} (seconds)",
            corrected_ts,
            get_local_timestamp()
        );
    }

    // 添加随机抖动 [-10, +10] 秒
    // 注意：VMess 协议允许 ±30s，但为了安全起见使用更小的范围
    // 避免因为服务器时间偏差导致请求被拒绝
    let jitter: i64 = (rand::random::<u8>() % 21) as i64 - 10; // Range: [-10, +10]
    let vmess_ts = corrected_ts.saturating_add(jitter);

    tracing::debug!(
        "VMess timestamp: corrected={}, jitter={}, final={}",
        corrected_ts,
        jitter,
        vmess_ts
    );

    vmess_ts
}

pub fn get_timestamp_diagnostics() -> TimestampDiagnostics {
    let local_timestamp_secs = get_local_timestamp();
    let ntp_offset_ms = TIME_OFFSET_MS.load(Ordering::SeqCst);
    let corrected_timestamp_secs = get_corrected_timestamp();
    let last_sync_time_secs = LAST_SYNC_TIME.load(Ordering::SeqCst);
    let needs_resync_flag = needs_resync();

    // 生成带抖动的时间戳：[-10, +10] 秒（与 get_vmess_timestamp 保持一致）
    let jitter_secs: i64 = (rand::random::<u8>() % 21) as i64 - 10;
    let vmess_timestamp_secs = corrected_timestamp_secs.saturating_add(jitter_secs);

    // 检查是否疑似毫秒错误（时间戳 > 10^10 说明可能是毫秒）
    let suspected_milliseconds_error =
        vmess_timestamp_secs > 10_000_000_000 || corrected_timestamp_secs > 10_000_000_000;

    let mut diag = TimestampDiagnostics {
        local_timestamp_secs,
        corrected_timestamp_secs,
        ntp_offset_ms,
        vmess_timestamp_secs,
        jitter_secs,
        last_sync_time_secs,
        needs_resync: needs_resync_flag,
        suspected_milliseconds_error,
        diagnostic_message: String::new(),
    };
    diag.diagnostic_message = diag.generate_diagnostic_message();
    diag
}

pub fn get_vmess_timestamp_with_diagnostics() -> (i64, TimestampDiagnostics) {
    let local_timestamp_secs = get_local_timestamp();
    let ntp_offset_ms = TIME_OFFSET_MS.load(Ordering::SeqCst);
    let corrected_timestamp_secs = get_corrected_timestamp();
    let last_sync_time_secs = LAST_SYNC_TIME.load(Ordering::SeqCst);
    let needs_resync_flag = needs_resync();

    // 生成带抖动的时间戳：[-10, +10] 秒
    // 注意：VMess 协议允许 ±30s，但为了安全起见使用更小的范围
    // 避免因为服务器时间偏差导致请求被拒绝
    let jitter_secs: i64 = (rand::random::<u8>() % 21) as i64 - 10; // Range: [-10, +10]
    let vmess_timestamp_secs = corrected_timestamp_secs.saturating_add(jitter_secs);

    // 检查是否疑似毫秒错误（时间戳 > 10^10 说明可能是毫秒）
    // 2025年的秒级时间戳约为 1.7 * 10^9
    let suspected_milliseconds_error =
        vmess_timestamp_secs > 10_000_000_000 || corrected_timestamp_secs > 10_000_000_000;

    let mut diag = TimestampDiagnostics {
        local_timestamp_secs,
        corrected_timestamp_secs,
        ntp_offset_ms,
        vmess_timestamp_secs,
        jitter_secs,
        last_sync_time_secs,
        needs_resync: needs_resync_flag,
        suspected_milliseconds_error,
        diagnostic_message: String::new(),
    };
    diag.diagnostic_message = diag.generate_diagnostic_message();

    // 返回的时间戳和诊断信息中的是同一个值
    (vmess_timestamp_secs, diag)
}

pub fn get_vmess_timestamp_bytes() -> [u8; 8] {
    get_vmess_timestamp().to_be_bytes()
}

pub fn get_corrected_timestamp_ms() -> i64 {
    let local_ms = get_local_timestamp_ms();
    let offset_ms = TIME_OFFSET_MS.load(Ordering::SeqCst);
    local_ms + offset_ms
}

pub fn needs_resync() -> bool {
    let last_sync = LAST_SYNC_TIME.load(Ordering::SeqCst);
    if last_sync == 0 {
        return true;
    }

    let now = get_local_timestamp();
    (now - last_sync) > SYNC_INTERVAL_SECS
}

pub fn init_time_sync() {
    SYNC_INITIALIZED.call_once(|| {
        tracing::info!("Initializing NTP time sync...");
        let result = sync_time_blocking();
        if result.success {
            tracing::info!("Initial NTP sync completed: offset={}ms", result.offset_ms);
        } else {
            tracing::warn!("Initial NTP sync failed, will retry later");
        }
    });
}

pub async fn sync_time_async() -> SyncResult {
    tokio::task::spawn_blocking(sync_time_blocking)
        .await
        .unwrap_or_else(|e| SyncResult {
            success: false,
            server: None,
            offset_ms: 0,
            error: Some(format!("Task join error: {}", e)),
        })
}

pub async fn ensure_time_synced() -> SyncResult {
    if needs_resync() {
        sync_time_async().await
    } else {
        SyncResult {
            success: true,
            server: None,
            offset_ms: TIME_OFFSET_MS.load(Ordering::SeqCst),
            error: None,
        }
    }
}

pub fn get_time_offset_ms() -> i64 {
    TIME_OFFSET_MS.load(Ordering::SeqCst)
}

pub fn get_last_sync_time() -> i64 {
    LAST_SYNC_TIME.load(Ordering::SeqCst)
}

#[cfg(test)]
pub fn set_time_offset_ms(offset: i64) {
    TIME_OFFSET_MS.store(offset, Ordering::SeqCst);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_local_timestamp() {
        let ts = get_local_timestamp();
        assert!(ts > 0);
        assert!(ts > 1577836800);
    }

    #[test]
    fn test_get_corrected_timestamp() {
        TIME_OFFSET_MS.store(0, Ordering::SeqCst);

        let local = get_local_timestamp();
        let corrected = get_corrected_timestamp();

        assert!((local - corrected).abs() <= 1);
    }

    #[test]
    fn test_get_vmess_timestamp() {
        TIME_OFFSET_MS.store(0, Ordering::SeqCst);

        let corrected = get_corrected_timestamp();
        let vmess_ts = get_vmess_timestamp();

        let diff = (vmess_ts - corrected).abs();
        assert!(diff <= 10, "Jitter should be within ±10s, got {}", diff);
    }

    #[test]
    fn test_vmess_timestamp_bytes() {
        // 测试 get_vmess_timestamp_bytes 返回的字节是否是有效的大端序时间戳
        let bytes = get_vmess_timestamp_bytes();
        let reconstructed = i64::from_be_bytes(bytes);

        // 验证重建的时间戳在合理范围内（当前时间 ±60 秒）
        let now = get_corrected_timestamp();
        let diff = (reconstructed - now).abs();
        assert!(
            diff <= 60,
            "Timestamp should be within 60 seconds of current time"
        );
    }

    #[test]
    fn test_needs_resync() {
        LAST_SYNC_TIME.store(0, Ordering::SeqCst);
        assert!(needs_resync());

        LAST_SYNC_TIME.store(get_local_timestamp(), Ordering::SeqCst);
        assert!(!needs_resync());
    }
}
