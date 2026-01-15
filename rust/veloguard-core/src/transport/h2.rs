use bytes::{Bytes, BytesMut};
use futures::ready;
use h2::{RecvStream, SendStream};
use http::Request;
use rand::Rng;
use std::collections::HashMap;
use std::fmt::Debug;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::error::{Error, Result};

/// HTTP/2 客户端配置
#[derive(Debug, Clone)]
pub struct H2Config {
    pub hosts: Vec<String>,
    pub headers: HashMap<String, String>,
    pub method: http::Method,
    pub path: String,
}

impl Default for H2Config {
    fn default() -> Self {
        Self {
            hosts: Vec::new(),
            headers: HashMap::new(),
            method: http::Method::GET,
            path: "/".to_string(),
        }
    }
}

/// HTTP/2 客户端
pub struct H2Client {
    pub hosts: Vec<String>,
    pub headers: HashMap<String, String>,
    pub method: http::Method,
    pub path: http::uri::PathAndQuery,
}

impl H2Client {
    pub fn new(config: H2Config) -> Result<Self> {
        let path = config.path.parse::<http::uri::PathAndQuery>()
            .map_err(|e| Error::config(format!("Invalid H2 path: {}", e)))?;
        
        Ok(Self {
            hosts: config.hosts,
            headers: config.headers,
            method: config.method,
            path,
        })
    }

    fn build_request(&self) -> io::Result<Request<()>> {
        let uri_idx = rand::rng().random_range(0..self.hosts.len());
        let uri = http::Uri::builder()
            .scheme("https")
            .authority(self.hosts[uri_idx].as_str())
            .path_and_query(self.path.clone())
            .build()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        let mut request = Request::builder()
            .uri(uri)
            .method(self.method.clone())
            .version(http::Version::HTTP_2);

        for (k, v) in self.headers.iter() {
            if k.to_lowercase() != "host" {
                request = request.header(k, v);
            }
        }

        Ok(request.body(()).expect("build request"))
    }

    /// 将底层流包装为 HTTP/2 流
    pub async fn proxy_stream<S>(&self, stream: S) -> Result<H2Stream>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (mut client, h2) = h2::client::handshake(stream)
            .await
            .map_err(|e| Error::network(format!("H2 handshake failed: {}", e)))?;

        let req = self.build_request()
            .map_err(|e| Error::network(format!("Failed to build H2 request: {}", e)))?;

        let (resp, send_stream) = client
            .send_request(req, false)
            .map_err(|e| Error::network(format!("H2 send request failed: {}", e)))?;

        // 在后台运行 H2 连接
        tokio::spawn(async move {
            if let Err(e) = h2.await {
                tracing::debug!("H2 connection error: {}", e);
            }
        });

        let recv_stream = resp
            .await
            .map_err(|e| Error::network(format!("H2 response failed: {}", e)))?
            .into_body();

        Ok(H2Stream::new(recv_stream, send_stream))
    }
}

/// HTTP/2 双向流
pub struct H2Stream {
    recv: RecvStream,
    send: SendStream<Bytes>,
    buffer: BytesMut,
}

impl Debug for H2Stream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("H2Stream")
            .field("recv", &self.recv)
            .field("send", &self.send)
            .field("buffer_len", &self.buffer.len())
            .finish()
    }
}

impl H2Stream {
    pub fn new(recv: RecvStream, send: SendStream<Bytes>) -> Self {
        Self {
            recv,
            send,
            buffer: BytesMut::with_capacity(4 * 1024),
        }
    }
}

impl AsyncRead for H2Stream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // 先返回缓冲区中的数据
        if !self.buffer.is_empty() {
            let to_read = std::cmp::min(self.buffer.len(), buf.remaining());
            let data = self.buffer.split_to(to_read);
            buf.put_slice(&data[..to_read]);
            return Poll::Ready(Ok(()));
        }

        // 从 H2 流读取数据
        Poll::Ready(match ready!(self.recv.poll_data(cx)) {
            Some(Ok(data)) => {
                let to_read = std::cmp::min(data.len(), buf.remaining());
                buf.put_slice(&data[..to_read]);
                
                // 如果数据超过缓冲区容量，存储剩余部分
                if to_read < data.len() {
                    self.buffer.extend_from_slice(&data[to_read..]);
                }
                
                // 释放流控制容量
                self.recv
                    .flow_control()
                    .release_capacity(to_read)
                    .map_or_else(
                        |e| Err(io::Error::new(io::ErrorKind::ConnectionReset, e)),
                        |_| Ok(()),
                    )
            }
            Some(Err(e)) => Err(io::Error::other(e)),
            None => Ok(()), // 流结束
        })
    }
}

impl AsyncWrite for H2Stream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.send.reserve_capacity(buf.len());
        
        Poll::Ready(match ready!(self.send.poll_capacity(cx)) {
            Some(Ok(to_write)) => {
                let to_write = std::cmp::min(to_write, buf.len());
                self.send
                    .send_data(Bytes::from(buf[..to_write].to_owned()), false)
                    .map_or_else(
                        |e| Err(io::Error::new(io::ErrorKind::BrokenPipe, e)),
                        |_| Ok(to_write),
                    )
            }
            Some(Err(e)) => Err(io::Error::new(io::ErrorKind::BrokenPipe, e)),
            None => Err(io::Error::new(io::ErrorKind::BrokenPipe, "broken pipe")),
        })
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.send.reserve_capacity(0);
        Poll::Ready(ready!(self.send.poll_capacity(cx)).map_or(
            Err(io::Error::new(io::ErrorKind::BrokenPipe, "broken pipe")),
            |_| {
                self.send
                    .send_data(Bytes::new(), true)
                    .map_or_else(
                        |e| Err(io::Error::new(io::ErrorKind::BrokenPipe, e)),
                        |_| Ok(()),
                    )
            },
        ))
    }
}
