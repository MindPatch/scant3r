extern crate scanners;
extern crate scant3r_utils;

use scanners::scan;
use scant3r_utils::{
    extract_headers_vec,
    requests::{Msg, Settings},
    valid_url
};
use std::fs::File;
use std::io::prelude::*;
use std::io::BufReader;
mod args;

fn main() {
    let arg = args::args();
    match arg.subcommand_name() {
        Some("urls") => {
            let sub = arg.subcommand_matches("urls").unwrap();
            let urls = {
                let read_file = File::open(sub.value_of("file").unwrap()).unwrap();
                let mut _urls = BufReader::new(read_file)
                    .lines()
                    .map(|x| x.unwrap())
                    .collect::<Vec<String>>();
                _urls.sort();
                _urls.dedup();
                _urls
            };

            let header = extract_headers_vec(
                sub.values_of("headers")
                    .unwrap()
                    .map(|x| x.to_string())
                    .collect::<Vec<String>>(),
            );
            let mut reqs: Vec<Msg> = Vec::new();
            urls.iter().for_each(|url| {
                if valid_url(url) {
                    let mut live_check = Msg::new()
                        .method(sub.value_of("method").unwrap().to_string())
                        .url(url.to_string())
                        .redirect(sub.value_of("redirect").unwrap().parse::<u32>().unwrap())
                        .headers(header.clone())
                        .body(sub.value_of("data").unwrap_or("").to_string())
                        .delay(sub.value_of("delay").unwrap_or("0").parse::<u64>().unwrap());
                    if sub.value_of("proxy").is_some() {
                        live_check.proxy(sub.value_of("proxy").unwrap().to_string());
                    }
                    reqs.push(live_check.clone());
                }
            });
            drop(urls);
            let mut scan_settings =
                scan::Scanner::new(vec!["xss".to_string()], reqs, sub.is_present("keep-value"));
            scan_settings.load_config();
            scan_settings.scan(
                sub.value_of("concurrency")
                    .unwrap()
                    .parse::<usize>()
                    .unwrap(),
            );
        }
        _ => println!("No subcommand was used"),
    }
}
