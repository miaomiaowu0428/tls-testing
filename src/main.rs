mod error;
#[allow(unused, unused_imports, unused_variables, dead_code)]
mod structs;

use colored::Colorize;
use rustls_acme::caches::DirCache;
use rustls_acme::AcmeConfig;
use std::{
    fs,
    net::Ipv6Addr,
    process::Command,
    net::Ipv4Addr
};
use humantime::format_duration;
use tokio_stream::StreamExt;
use tracing::{error, info, warn};

use crate::error::Error;
use crate::structs::ZinoToml;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    info!("Starting zli");

    let mut server = Command::new("cargo")
        .arg("run")
        .arg("-q")
        .spawn()
        .expect("Failed to start server");

    info!("Server started");

    info!("Loading configuration");
    let deploy_manager = Deploy::default();
    deploy_manager
        .do_acme_work_and_forward_connections()
        .await
        .unwrap();
    info!("Configuration loaded");

    let status = server.wait().expect("Failed to wait for server");

    println!("{}", "Finish".blue());
}

#[derive(Debug)]
struct Deploy {
    zino_toml: ZinoToml,
}

impl Default for Deploy {
    fn default() -> Self {
        let mut deploy_manager = Deploy {
            zino_toml: ZinoToml::default(),
        };
        if let Err(err) = deploy_manager.init_zino_toml() {
            error!("Failed to initialize zino.toml: {}", err);
        }
        println!("{}",format!("{:#?}",deploy_manager.zino_toml).blue());
        deploy_manager
    }
}

impl Deploy {
    fn init_zino_toml(&mut self) -> Result<(), Error> {
        self.zino_toml = match self.parse_zino_toml() {
            Ok(zino_toml) => {
                info!("zino.toml file found");
                zino_toml
            }
            Err(err) => {
                warn!(
                    "failed to parse zino.toml file: {}\n  using default config",
                    err
                );
                ZinoToml::default()
            }
        };

        info!(
            "zli will check for updates after {} ",
            format_duration(self.zino_toml.zli_config.refresh_interval)
        );

        Ok(())
    }

    fn parse_zino_toml(&self) -> Result<ZinoToml, Error> {
        let zino_toml = fs::read_to_string("zino.toml")
            .map_err(|err| Error::new(format!("failed to read zino.toml: {}", err)))?;
        let zino_toml: ZinoToml = toml::from_str(&zino_toml)
            .map_err(|err| Error::new(format!("failed to parse zino.toml: {}", err)))?;
        Ok(zino_toml)
    }

    async fn do_acme_work_and_forward_connections(&self) -> Result<(), Error> {
        info!(
            "Starting to bind TCP listener on port {}",
            self.zino_toml.acme.port
        );
        let tcp_listener =
            tokio::net::TcpListener::bind((Ipv4Addr::UNSPECIFIED, self.zino_toml.acme.port))
                .await
                .map_err(|err| Error::new(format!("failed to bind TCP listener: {}", err)))?;
        info!("TCP listener bound successfully");

        // let mut tls_incoming = tokio_stream::wrappers::TcpListenerStream::new(tcp_listener);
        // info!("TCP incoming stream created");

        let tcp_incoming = tokio_stream::wrappers::TcpListenerStream::new(tcp_listener);
        info!("TCP incoming stream created\n");

        let mut tls_incoming = AcmeConfig::new(self.zino_toml.acme.domain.clone())
            .contact(
                self.zino_toml
                    .acme
                    .email
                    .iter()
                    .map(|e| format!("mailto:{}", e)),
            )
            .cache_option(Some(self.zino_toml.acme.cache.clone()).map(DirCache::new))
            .directory_lets_encrypt(self.zino_toml.acme.product_mode)
            .tokio_incoming(tcp_incoming, Vec::new());
        info!("ACME configuration set up");


        while let Some(tls) = tls_incoming.next().await {
            info!("Waiting for a new TLS connection");
            let tls = tls.map_err(|err| {
                error!("Failed to get next TLS connection: {}", err);
                Error::new(format!("failed to accept TLS connection: {}", err))
            })?;
            info!("Received a new TLS connection: {:?}", tls);

            tokio::spawn(async move {
                if let Err(e) = Self::handle_tls_connection(tls).await {
                    error!("failed to handle tls connection: {}", e);
                } else {
                    info!("TLS connection handled successfully");
                }
            });
        }

        Ok(())
    }

    async fn handle_tls_connection<T>(mut tls: T) -> Result<(), Error>
    where
        T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        info!("Handling TLS connection at 127.0.0.1:6080");
        // 连接到本机的 6080 端口
        let mut target_stream = tokio::net::TcpStream::connect("127.0.0.1:6080")
            .await
            .map_err(|err| {
                error!("Failed to connect to target server: {}", err);
                Error::new(format!("failed to connect to target server: {}", err))
            })?;
        info!("Connected to target server");

        info!("Forwarding TLS connection to target server");
        // 将 TLS 连接直接转发给目标应用
        tokio::io::copy_bidirectional(&mut tls, &mut target_stream)
            .await
            .map_err(|err| {
                error!("Failed to forward connection: {}", err);
                Error::new(format!("failed to forward connection: {}", err))
            })?;
        info!("TLS connection forwarding finished");

        Ok(())
    }
}
