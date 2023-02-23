use std::fs;
use std::io::Read;
use std::path::PathBuf;
use std::collections::HashMap;
use crypto::digest::Digest;
use crypto::md5::Md5;
// For sleep
use std::time::Duration;
use std::thread;
// For virustotal api / upload file
use reqwest::blocking::{multipart, Client};
use reqwest::header::{HeaderMap, HeaderValue};
use std::fs::File;
use serde_json::Value;
use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        println!("Usage: vt-scan <dir> <api_key>");
        std::process::exit(0);
    }
    
    let dir = &args[1];
    let api_key = &args[2];
    
    // Create a HashMap to store the results
    let mut init_md5_map: HashMap<String, String> = HashMap::new();
    scan_dir(PathBuf::from(dir), &mut init_md5_map);
    
    while true { // Scan every 5 minutes
        // Recursively scan the directory and calculate the MD5 hashes of each file
        let mut current_md5_map: HashMap<String, String> = HashMap::new();
        scan_dir(PathBuf::from(dir), &mut current_md5_map);
        println!("Waiting 5 minutes ... ");
        thread::sleep(Duration::from_secs(300));
        println!("Comparing scan results!!!");
        // Print the results
        for (filename, md5) in current_md5_map.iter() {
            println!("{}: {}", filename, md5);
            if current_md5_map.get(filename) != init_md5_map.get(filename) {
            let md5_c = current_md5_map.get(filename);
                if &md5_c  == &init_md5_map.get(filename){
                    // Scan file with Virustotal
                    upload_file(&api_key,&filename);
                    check_file(&api_key, md5_c.unwrap()).unwrap();
                }
            }
        }
    }
}

fn upload_file(api_key: &str, file_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    println!("Uploading new file!");
    let url = "https://www.virustotal.com/api/v3/files";

    let client = reqwest::blocking::Client::new();
    let mut headers = HeaderMap::new();
    headers.insert("accept", HeaderValue::from_static("application/json"));
    headers.insert("x-apikey", HeaderValue::from_str(api_key)?);
    let form = multipart::Form::new()
        .file("file", file_path)?;
    let response = client.post(url)
        .headers(headers)
        .multipart(form)
        .send()?;

    let status_code = response.status();
    println!("Status Code: {}", status_code);
    let rt = response.text()?;
    //println!("{}",&rt);
    //let json: Value = serde_json::from_str(&rt)?;
    //let id = json["data"]["id"].as_str().ok_or("id not found")?;
    //println!("ID: {}", id);
    //Ok(id.to_string())
    Ok(())
}

fn check_file(api_key: &str, file_id:&str) -> Result<(), Box<dyn std::error::Error>>  {
    println!("Checking file id...");
    let url = format!("https://www.virustotal.com/api/v3/files/{}",file_id);
    dbg!(&url);
    let client = reqwest::blocking::Client::new();
    let mut headers = HeaderMap::new();
    headers.insert("accept", HeaderValue::from_static("application/json"));
    headers.insert("content-length", HeaderValue::from_static("0"));
    headers.insert("x-apikey", HeaderValue::from_str(api_key)?);
    let response = client.get(url)
        .headers(headers)
        .send()?;

    let status_code = response.status();
    println!("Status Code: {}", status_code);
    let rt = response.text()?;
    let json: Value = serde_json::from_str(&rt)?;
    let undetected = json["data"]["attributes"]["last_analysis_stats"]["undetected"].as_u64().unwrap_or_default();
    let malicious = json["data"]["attributes"]["last_analysis_stats"]["malicious"].as_u64().unwrap_or_default();
    println!("Score: {}/{}", malicious,undetected);
    Ok(())
}

fn scan_dir(path: PathBuf, md5_map: &mut HashMap<String, String>) {
    // Check if the path is a file or a directory
    if path.is_file() {
        // Calculate the MD5 hash of the file and add it to the HashMap
        let md5 = md5_file(&path);
        md5_map.insert(path.to_string_lossy().to_string(), md5);
    } else if path.is_dir() {
        // Recursively scan the directory
        for entry in fs::read_dir(path).unwrap() {
            let entry_path = entry.unwrap().path();
            scan_dir(entry_path, md5_map);
        }
    }
}

fn md5_file(path: &PathBuf) -> String {
    let mut file = fs::File::open(path).unwrap();
    let mut buffer = [0u8; 1024];
    let mut hasher = Md5::new();

    loop {
        let bytes_read = file.read(&mut buffer).unwrap();
        if bytes_read == 0 {
            break;
        }
        hasher.input(&buffer[..bytes_read]);
    }
    hasher.result_str()
}

