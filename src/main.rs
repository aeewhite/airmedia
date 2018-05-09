#[macro_use]
extern crate quicli;
extern crate indicatif;
extern crate regex;
extern crate reqwest;

use regex::Regex;

use quicli::prelude::*;

use std::fs;
use std::io::Read;
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
    let login_token = login_to_airmedia(&args.auth, &ip)?;
    upload_image(&ip, &args.background_file, &login_token)?;
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

fn login_to_airmedia(auth: &str, ip: &IpAddr) -> Result<String> {
    let mut auth_parts = auth.splitn(2, ":");
    if let Some(user) = auth_parts.next() {
        if let Some(password) = auth_parts.next() {
            info!("Using authentication {:?}:{:?}", user, password);

            let url = format!(
                "https://{}/cgi-bin/login.cgi?lang=en&src=AwLoginAdmin.html",
                ip
            );
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
                .danger_disable_certificate_validation_entirely()
                .build()?;
            let params = [
                ("login", "admin"),
                ("account", &user),
                ("password", &password),
            ];
            let mut res = client.post(&url).form(&params).send()?.error_for_status()?;
            let mut res_str = String::new();
            res.read_to_string(&mut res_str)?;
            sp.finish_and_clear();

            info!(
                "Login Response: {:?}",
                get_status_from_airmedia_response(&res_str)
            );

            let token = get_token_from_airmedia_response(&res_str)?;

            debug!("Login Token: {:?}", token);
            println!("✔ Login Complete");
            return Ok(token);
        }
    }
    bail!("Invalid username or password")
}

fn upload_image(ip: &IpAddr, file: &PathBuf, token: &str) -> Result<()> {
    let url = format!(
        "https://{}/cgi-bin/web_index.cgi?lang=en&src=AwOsdTool.html&{:}",
        ip, token
    );
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
        .danger_disable_certificate_validation_entirely()
        .build()?;
    let form = reqwest::multipart::Form::new().file("filename", &file)?;
    let mut result = client
        .post(&url)
        .multipart(form)
        .send()?
        .error_for_status()?;
    let mut res_str = String::new();
    result.read_to_string(&mut res_str)?;

    sp.finish_and_clear();
    info!(
        "Upload Response: {:?}",
        get_status_from_airmedia_response(&res_str)
    );
    // debug!("Response {:}", _result.text()?);
    println!("✔ Image Uploaded");
    Ok(())
}

fn get_status_from_airmedia_response(response: &str) -> Result<String> {
    let pattern = Regex::new(r#"switch\(\s*"(?P<msg>.*?)"\s*\)"#)?;
    let caps = pattern.captures(&response);
    match caps {
        Some(captures) => Ok(captures["msg"].into()),
        None => bail!("Failed to search response for status message"),
    }
}

fn get_token_from_airmedia_response(response: &str) -> Result<String> {
    let pattern = Regex::new(r#"location.replace\(".*&(?P<token>\w*)"\)"#)?;
    let caps = pattern.captures(&response);
    match caps {
        Some(captures) => Ok(captures["token"].into()),
        None => bail!("Failed to search response for login token"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_status_test() {
        let test_res = " switch( \"strAlertPasswordSuccess\" ) {";
        let status = get_status_from_airmedia_response(test_res).unwrap();
        assert_eq!("strAlertPasswordSuccess", status);
    }

    #[test]
    fn get_login_token_test() {
        let test_res = r#"location.replace("/cgi-bin/web_index.cgi?lang=en&src=AwSystem.html&7H5ncokWnQgaIdFW");"#;
        let status = get_token_from_airmedia_response(test_res).unwrap();
        assert_eq!("7H5ncokWnQgaIdFW", status);
    }
}
