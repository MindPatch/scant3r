// Copyright 2020 Folyd
// Copyright 2019 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

/// Simple binary to assess whether a URL is accessible to a user-agent according
/// to records found in a local robots.txt file, based on Google's robots.txt
/// parsing and matching algorithms.
/// Usage:
///     cargo run <local_path_to_robotstxt> <user_agent> <url>
/// Arguments:
/// local_path_to_robotstxt: local path to a file containing robots.txt records.
///   For example: /home/users/username/robots.txt
/// user_agent: a token to be matched against records in the robots.txt.
///   For example: Googlebot
/// url: a url to be matched against records in the robots.txt. The URL must be
/// %-encoded according to RFC3986.
///   For example: https://example.com/accessible/url.html
/// Returns: Prints a sentence with verdict about whether 'user_agent' is allowed
/// to access 'url' based on records in 'local_path_to_robotstxt'.
use std::env;
use std::fs;

use robotstxt::DefaultMatcher;

fn show_help(name: &str) {
    eprintln!(
        "Shows whether the given user_agent and URI combination \
        is allowed or disallowed by the given robots.txt file. \n"
    );
    eprintln!(
        "Usage:\n {} <robots.txt filename> <user_agent> <URI> \n",
        name
    );
    eprintln!("The URI must be %-encoded according to RFC3986.\n");
    eprintln!(
        "Example:\n {} robots.txt FooBot http://example.com/foo\n",
        name
    );
}

fn main() {
    let mut args = env::args();
    match (args.next(), args.next(), args.next(), args.next()) {
        (Some(execute), Some(filename), ..)
            if &filename == "-h" || &filename == "-help" || &filename == "--help" =>
        {
            show_help(&execute);
        }
        (_, Some(filename), Some(user_agent), Some(url)) => {
            if let Ok(robots_content) = fs::read_to_string(filename.clone()) {
                let user_agents: Vec<&str> = vec![&user_agent];
                let mut matcher = DefaultMatcher::default();
                let allowed = matcher.allowed_by_robots(&robots_content, user_agents, &url);

                println!(
                    "user-agent '{}' with URI '{}': {}",
                    user_agent,
                    url,
                    if allowed { "ALLOWED" } else { "DISALLOWED" }
                );

                if robots_content.is_empty() {
                    println!("notice: robots file is empty so all user-agents are allowed");
                }
            } else {
                eprintln!("failed to read file \"{}\"", filename);
            }
        }
        (Some(execute), ..) => {
            eprintln!("Invalid amount of arguments. Showing help.\n");
            show_help(&execute);
        }
        _ => {}
    }
}
