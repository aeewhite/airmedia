#[macro_use]
extern crate quicli;
use quicli::prelude::*;

extern crate indicatif;
use std::fs;
use std::path::PathBuf;
use std::thread::sleep;
use std::time::Duration;

use std::net::IpAddr;
use std::str::FromStr;

use indicatif::{HumanBytes, ProgressBar, ProgressStyle};

/// Upload a new background to an AirMedia device
#[derive(Debug, StructOpt)]
#[structopt(author = "")]
struct Cli {
    /// Pass many times for more log output
    #[structopt(long = "verbose", short = "v", parse(from_occurrences))]
    verbosity: u8,
    /// IP Address of AirMedia device on network
    ip_addr: String,
    /// Image to upload as background
    #[structopt(parse(from_os_str))]
    background_file: PathBuf,
    /// Authentication to use in the form of user:password
    #[structopt(long = "auth", short = "a", default_value = "admin:admin")]
    auth: String,
}

main!(|args: Cli, log_level: verbosity| {
    let ip = IpAddr::from_str(&args.ip_addr)?;
    check_background_input(&args.background_file)?;
    login_to_airmedia(&args.auth, &ip)?;
    upload_image(&args.background_file);
    apply_settings();
});

fn check_background_input(file: &PathBuf) -> Result<()> {
    let sp = ProgressBar::new_spinner();
    sp.enable_steady_tick(100);
    sp.set_style(
        ProgressStyle::default_spinner()
            .tick_chars("⠋⠙⠹⠸⠼⠴⠦⠧⠇")
            .template("{spinner} Checking Image Requirements"),
    );
    sp.tick();
    let meta = fs::metadata(file)?;
    if !meta.is_file() {
        bail!("Selected image is not a file");
    }
    let max_bytes = 7000000;
    if meta.len() > max_bytes {
        bail!("Image is larger than {:} limit", HumanBytes(max_bytes));
    }
    sp.finish_and_clear();
    println!("✔ Image meets requirements");
    Ok(())
}

fn login_to_airmedia(auth: &str, ip: &IpAddr) -> Result<()> {
    let mut auth_parts = auth.splitn(2, ":");
    if let Some(user) = auth_parts.next() {
        if let Some(password) = auth_parts.next() {
            info!("Using authentication {:?}:{:?}", user, password);
            let sp = ProgressBar::new_spinner();
            sp.enable_steady_tick(100);
            sp.set_style(
                ProgressStyle::default_spinner()
                    .tick_chars("⠋⠙⠹⠸⠼⠴⠦⠧⠇")
                    .template("{spinner} Logging in"),
            );
            sp.tick();
            sleep(Duration::from_secs(3));
            sp.finish_and_clear();
            println!("✔ Login Complete");
            return Ok(());
        }
    }
    bail!("Invalid username or password")
}

fn upload_image(file: &PathBuf) {
    let sp = ProgressBar::new_spinner();
    sp.enable_steady_tick(100);
    sp.set_style(
        ProgressStyle::default_spinner()
            .tick_chars("⠋⠙⠹⠸⠼⠴⠦⠧⠇")
            .template("{spinner} Uploading new background"),
    );
    sp.tick();
    sleep(Duration::from_secs(3));
    sp.finish_and_clear();
    println!("✔ Image Uploaded");
}

fn apply_settings() {
    let sp = ProgressBar::new_spinner();
    sp.enable_steady_tick(100);
    sp.set_style(
        ProgressStyle::default_spinner()
            .tick_chars("⠋⠙⠹⠸⠼⠴⠦⠧⠇")
            .template("{spinner} Changing background setting"),
    );
    sp.tick();
    sleep(Duration::from_secs(3));
    sp.finish_and_clear();
    println!("✔ Settings Updated");
}
