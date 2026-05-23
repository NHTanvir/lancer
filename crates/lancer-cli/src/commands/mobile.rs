//! `lancer mobile` — iOS / Android / Frida helpers.

use std::path::PathBuf;

use anyhow::Result;
use clap::{Args, Subcommand};
use lancer_mobile::{android::Adb, frida, ios};

#[derive(Debug, Args)]
pub struct MobileArgs {
    #[command(subcommand)]
    cmd: MobileCmd,
}

#[derive(Debug, Subcommand)]
enum MobileCmd {
    /// List ADB-attached Android devices.
    Devices,
    /// Push a DER CA to /sdcard and (if su available) into the user-trust store.
    AndroidCa {
        der: PathBuf,
        #[arg(long)]
        serial: Option<String>,
    },
    /// Set the global Android HTTP proxy.
    AndroidProxy {
        host: String,
        port: u16,
        #[arg(long)]
        serial: Option<String>,
    },
    /// Clear the Android HTTP proxy.
    AndroidProxyClear {
        #[arg(long)]
        serial: Option<String>,
    },
    /// Print iOS install instructions for a hosted CA PEM URL.
    IosSteps { ca_url: String },
    /// Render an iOS .mobileconfig profile from the CA PEM (base64-payload).
    IosProfile {
        ca_pem: PathBuf,
        #[arg(long, default_value = "Lancer")]
        name: String,
        #[arg(long, default_value = "io.lancer.ca")]
        identifier: String,
    },
    /// Print a Frida SSL-pinning bypass snippet.
    Frida {
        #[arg(long, value_parser = ["android", "ios", "flutter"])]
        platform: String,
    },
}

pub async fn run(args: MobileArgs) -> Result<()> {
    match args.cmd {
        MobileCmd::Devices => {
            let adb = Adb::new(None);
            for d in adb.devices().await? {
                println!("{d}");
            }
        }
        MobileCmd::AndroidCa { der, serial } => {
            let adb = Adb::new(serial);
            adb.install_user_ca(&der).await?;
            println!("pushed; rooted devices will accept it as a system CA.");
        }
        MobileCmd::AndroidProxy { host, port, serial } => {
            Adb::new(serial).set_proxy(&host, port).await?;
        }
        MobileCmd::AndroidProxyClear { serial } => {
            Adb::new(serial).clear_proxy().await?;
        }
        MobileCmd::IosSteps { ca_url } => print!("{}", ios::install_steps(&ca_url)),
        MobileCmd::IosProfile { ca_pem, name, identifier } => {
            use base64::Engine as _;
            let pem = std::fs::read(&ca_pem)?;
            let b64 = base64::engine::general_purpose::STANDARD.encode(pem);
            print!("{}", ios::make_profile(&b64, &name, &identifier));
        }
        MobileCmd::Frida { platform } => {
            let snippet = match platform.as_str() {
                "android" => frida::ANDROID_SSL_PIN_BYPASS,
                "ios" => frida::IOS_SSL_PIN_BYPASS,
                "flutter" => frida::FLUTTER_BYPASS,
                _ => unreachable!(),
            };
            print!("{snippet}");
        }
    }
    Ok(())
}
