use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Once;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rand::Rng;
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
    let local_ms = get_local_timestamp_ms();
    let offset_ms = TIME_OFFSET_MS.load(Ordering::SeqCst);
    let corrected_ms = local_ms + offset_ms;
    corrected_ms / 1000
}

pub fn get_vmess_timestamp() -> i64 {
    let corrected_ts = get_corrected_timestamp();

    // VMess 协议要求时间戳在服务器时间的 ±30 秒范围内
    // 为了安全起见，我们只使用 ±15 秒的随机偏移，留出一些余量
    let mut rng = rand::rng();
    let random_offset: i64 = rng.random_range(-15..=15);

    let vmess_ts = corrected_ts + random_offset;

    tracing::debug!(
        "VMess timestamp: corrected={}, random_offset={}, final={}",
        corrected_ts,
        random_offset,
        vmess_ts
    );

    vmess_ts
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
        assert!(diff <= VMESS_TIME_RANDOM_RANGE);
    }

    #[test]
    fn test_vmess_timestamp_bytes() {
        // 测试 get_vmess_timestamp_bytes 返回的字节是否是有效的大端序时间戳
        let bytes = get_vmess_timestamp_bytes();
        let reconstructed = i64::from_be_bytes(bytes);
        
        // 验证重建的时间戳在合理范围内（当前时间 ±60 秒）
        let now = get_corrected_timestamp();
        let diff = (reconstructed - now).abs();
        assert!(diff <= 60, "Timestamp should be within 60 seconds of current time");
    }

    #[test]
    fn test_needs_resync() {
        LAST_SYNC_TIME.store(0, Ordering::SeqCst);
        assert!(needs_resync());

        LAST_SYNC_TIME.store(get_local_timestamp(), Ordering::SeqCst);
        assert!(!needs_resync());
    }
}
