#[macro_use]
extern crate quicli;
extern crate indicatif;
extern crate reqwest;

use quicli::prelude::*;

use std::fs;
use std::net::IpAddr;
use std::path::PathBuf;
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
    upload_image(&ip, &args.background_file)?;
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
    // Basic check
    if !meta.is_file() {
        bail!("Selected image is not a file");
    }
    // Size Check
    let max_bytes = 522240;
    if meta.len() > max_bytes {
        bail!("Image is larger than {:} limit", HumanBytes(max_bytes));
    }
    // File Type Check
    if let Some(extension) = file.extension() {
        let ext = extension.to_string_lossy().to_lowercase();
        if ext != "jpg" && ext != "jpg" {
            bail!("Background image must be of file type JPEG (.jpg or .jpeg)")
        }
    } else {
        bail!("Background image must be of file type JPEG (.jpg or .jpeg)")
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

            let url = format!("https://{}/cgi-bin/login.cgi", ip);
            debug!("Logging in with {:}", url);
            let sp = ProgressBar::new_spinner();
            sp.enable_steady_tick(100);
            sp.set_style(
                ProgressStyle::default_spinner()
                    .tick_chars("⠋⠙⠹⠸⠼⠴⠦⠧⠇")
                    .template("{spinner} Logging in"),
            );
            sp.tick();
            let client = reqwest::Client::builder()
                .danger_disable_hostname_verification()
                .build()?;
            let params = [
                ("login", "admin"),
                ("account", &user),
                ("password", &password),
            ];
            let _res = client
                .post(&url)
                .query(&[("lang", "en"), ("src", "AwLoginAdmin.html")])
                .form(&params)
                .send()?
                .error_for_status()?;

            sp.finish_and_clear();
            println!("✔ Login Complete");
            return Ok(());
        }
    }
    bail!("Invalid username or password")
}

fn upload_image(ip: &IpAddr, file: &PathBuf) -> Result<()> {
    let url = format!("https://{}/cgi-bin/web_index.cgi", ip);
    debug!("Posting image to {:}", url);
    let sp = ProgressBar::new_spinner();
    sp.enable_steady_tick(100);
    sp.set_style(
        ProgressStyle::default_spinner()
            .tick_chars("⠋⠙⠹⠸⠼⠴⠦⠧⠇")
            .template("{spinner} Uploading new background"),
    );
    sp.tick();
    let client = reqwest::Client::builder()
        .danger_disable_hostname_verification()
        .build()?;
    let form = reqwest::multipart::Form::new().file("filename", &file)?;
    let mut _result = client
        .post(&url)
        .query(&[("lang", "en"), ("src", "AwOsdTool.html")])
        .multipart(form)
        .send()?
        .error_for_status()?;

    sp.finish_and_clear();
    debug!("Response {:}", _result.text()?);
    println!("✔ Image Uploaded");
    Ok(())
}
