use bytes::{Buf, BufMut, Bytes, BytesMut};
use futures::ready;
use h2::{RecvStream, SendStream};
use http::{Request, Uri, Version};
use prost::encoding::{decode_varint, encode_varint};
use std::fmt::Debug;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{mpsc, Mutex};

use crate::error::{Error, Result};

/// gRPC 客户端配置
#[derive(Debug, Clone)]
pub struct GrpcConfig {
    pub host: String,
    pub service_name: String,
}

impl Default for GrpcConfig {
    fn default() -> Self {
        Self {
            host: String::new(),
            service_name: "GunService".to_string(),
        }
    }
}

/// gRPC 客户端
#[derive(Clone)]
pub struct GrpcClient {
    pub host: String,
    pub path: http::uri::PathAndQuery,
}

impl GrpcClient {
    pub fn new(config: GrpcConfig) -> Result<Self> {
        let path_str = format!("/{}/Tun", config.service_name);
        let path = path_str.parse::<http::uri::PathAndQuery>()
            .map_err(|e| Error::config(format!("Invalid gRPC path: {}", e)))?;
        
        Ok(Self {
            host: config.host,
            path,
        })
    }

    fn build_request(&self) -> io::Result<Request<()>> {
        let uri = Uri::builder()
            .scheme("https")
            .authority(self.host.as_str())
            .path_and_query(self.path.clone())
            .build()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        let request = Request::builder()
            .method("POST")
            .uri(uri)
            .version(Version::HTTP_2)
            .header("content-type", "application/grpc")
            .header("user-agent", "grpc-go/1.48.0");

        Ok(request.body(()).unwrap())
    }

    /// 将底层流包装为 gRPC 流
    pub async fn proxy_stream<S>(&self, stream: S) -> Result<GrpcStream>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (client, h2) = h2::client::Builder::new()
            .initial_connection_window_size(0x7FFFFFFF)
            .initial_window_size(0x7FFFFFFF)
            .initial_max_send_streams(1024)
            .enable_push(false)
            .handshake(stream)
            .await
            .map_err(|e| Error::network(format!("gRPC handshake failed: {}", e)))?;

        let mut client = client
            .ready()
            .await
            .map_err(|e| Error::network(format!("gRPC client not ready: {}", e)))?;

        let req = self.build_request()
            .map_err(|e| Error::network(format!("Failed to build gRPC request: {}", e)))?;

        let (resp, send_stream) = client
            .send_request(req, false)
            .map_err(|e| Error::network(format!("gRPC send request failed: {}", e)))?;

        // 在后台运行 H2 连接
        tokio::spawn(async move {
            if let Err(e) = h2.await {
                tracing::debug!("gRPC H2 connection error: {}", e);
            }
        });

        // 创建初始化通道
        let (init_sender, init_ready) = mpsc::channel(1);
        let recv_stream = Arc::new(Mutex::new(None));

        // 异步等待响应
        {
            let recv_stream = recv_stream.clone();
            tokio::spawn(async move {
                match resp.await {
                    Ok(resp) => {
                        match resp.status() {
                            http::StatusCode::OK => {}
                            status => {
                                tracing::warn!(
                                    "gRPC handshake resp status: {:?}",
                                    status
                                );
                                return;
                            }
                        }
                        let stream = resp.into_body();
                        recv_stream.lock().await.replace(stream);
                    }
                    Err(e) => {
                        tracing::warn!("gRPC resp error: {:?}", e);
                    }
                }
                let _ = init_sender.send(()).await;
            });
        }

        Ok(GrpcStream::new(init_ready, recv_stream, send_stream))
    }
}

/// gRPC 双向流
pub struct GrpcStream {
    init_ready: mpsc::Receiver<()>,
    recv: Arc<Mutex<Option<RecvStream>>>,
    send: SendStream<Bytes>,
    buffer: BytesMut,
    payload_len: usize,
}

impl Debug for GrpcStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GrpcStream")
            .field("send", &self.send)
            .field("buffer_len", &self.buffer.len())
            .field("payload_len", &self.payload_len)
            .finish()
    }
}

impl GrpcStream {
    pub fn new(
        init_ready: mpsc::Receiver<()>,
        recv: Arc<Mutex<Option<RecvStream>>>,
        send: SendStream<Bytes>,
    ) -> Self {
        Self {
            init_ready,
            recv,
            send,
            buffer: BytesMut::with_capacity(4 * 1024),
            payload_len: 0,
        }
    }

    /// 将数据编码为 gRPC + protobuf 格式
    fn encode_buf(&self, data: &[u8]) -> Bytes {
        // Protobuf 头部: field tag (0x0a = field 1, wire type 2) + varint length
        let mut protobuf_header = BytesMut::with_capacity(10 + 1);
        protobuf_header.put_u8(0x0a);
        encode_varint(data.len() as u64, &mut protobuf_header);

        // gRPC 头部: 5 字节 (1 字节压缩标志 + 4 字节长度)
        let mut grpc_header = [0u8; 5];
        let grpc_payload_len = (protobuf_header.len() + data.len()) as u32;
        grpc_header[1..5].copy_from_slice(&grpc_payload_len.to_be_bytes());

        // 组装完整帧
        let mut buf = BytesMut::with_capacity(
            grpc_header.len() + protobuf_header.len() + data.len(),
        );
        buf.put_slice(&grpc_header[..]);
        buf.put_slice(&protobuf_header.freeze()[..]);
        buf.put_slice(data);
        buf.freeze()
    }
}

impl AsyncRead for GrpcStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // 等待初始化完成
        ready!(self.init_ready.poll_recv(cx));

        let recv = self.recv.clone();
        let mut recv = match recv.try_lock() {
            Ok(guard) => guard,
            Err(_) => return Poll::Pending,
        };

        if recv.is_none() {
            tracing::warn!("gRPC initialization error");
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "initialization error",
            )));
        }

        // 处理缓冲区中的数据
        if (self.payload_len > 0 && !self.buffer.is_empty())
            || (self.payload_len == 0 && self.buffer.len() > 6)
        {
            if self.payload_len == 0 {
                // 跳过 gRPC 头部 (5 字节) + protobuf field tag (1 字节)
                self.buffer.advance(6);
                let payload_len = decode_varint(&mut self.buffer)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                self.payload_len = payload_len as usize;
            }

            let to_read = std::cmp::min(buf.remaining(), self.payload_len);
            let to_read = std::cmp::min(to_read, self.buffer.len());

            if to_read == 0 {
                return Poll::Pending;
            }

            let data = self.buffer.split_to(to_read);
            self.payload_len -= to_read;
            buf.put_slice(&data[..]);
            return Poll::Ready(Ok(()));
        }

        // 从 H2 流读取数据
        match ready!(Pin::new(&mut recv.as_mut().unwrap()).poll_data(cx)) {
            Some(Ok(b)) => {
                self.buffer.reserve(b.len());
                self.buffer.extend_from_slice(&b[..]);

                // 处理接收到的数据
                while self.payload_len > 0 || self.buffer.len() > 6 {
                    if self.payload_len == 0 {
                        self.buffer.advance(6);
                        let payload_len = decode_varint(&mut self.buffer)
                            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                        self.payload_len = payload_len as usize;
                    }

                    let to_read = std::cmp::min(self.buffer.len(), self.payload_len);
                    let to_read = std::cmp::min(buf.remaining(), to_read);
                    if to_read == 0 {
                        break;
                    }

                    buf.put_slice(self.buffer.split_to(to_read).freeze().as_ref());
                    self.payload_len -= to_read;
                }

                // 释放流控制容量
                recv.as_mut()
                    .unwrap()
                    .flow_control()
                    .release_capacity(b.len())
                    .map_or_else(
                        |e| Poll::Ready(Err(io::Error::new(io::ErrorKind::ConnectionReset, e))),
                        |_| Poll::Ready(Ok(())),
                    )
            }
            Some(Err(e)) => Poll::Ready(Err(io::Error::other(e))),
            None => {
                if recv.as_mut().unwrap().is_end_stream() {
                    Poll::Ready(Ok(()))
                } else {
                    Poll::Pending
                }
            }
        }
    }
}

impl AsyncWrite for GrpcStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let encoded_buf = self.encode_buf(buf);
        self.send.reserve_capacity(encoded_buf.len());

        Poll::Ready(match ready!(self.send.poll_capacity(cx)) {
            Some(Ok(_)) => self.send.send_data(encoded_buf, false).map_or_else(
                |e| {
                    tracing::warn!("gRPC write error: {}", e);
                    Err(io::Error::new(io::ErrorKind::BrokenPipe, e))
                },
                |_| Ok(buf.len()),
            ),
            Some(Err(e)) => {
                tracing::warn!("gRPC poll_capacity error: {}", e);
                Err(io::Error::new(io::ErrorKind::BrokenPipe, e))
            }
            None => Err(io::Error::new(io::ErrorKind::BrokenPipe, "broken pipe")),
        })
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.send.send_reset(h2::Reason::NO_ERROR);
        self.send
            .poll_reset(cx)
            .map_err(io::Error::other)
            .map(|_| Ok(()))
    }
}
