<h3 align="center">
  <img src="https://github.com/knassar702/scant3r/blob/gh-pages/logo.png" width="170px">
</h3>



<h1 align="center">
  <br>
  <br>
  ScanT3r <br><h4 align="center">Fast &amp; flexible DAST CLI tool</h4>
  <br>  
</h1>

<p align="center">
  <a href="https://github.com//scant3r/releases">
    <img src="https://img.shields.io/github/release/knassar702/scant3r.svg">
  </a>
  <a href="https://github.com/knassar702/scant3r/issues?q=is%3Aissue+is%3Aclosed">
      <img src="https://img.shields.io/github/issues-closed-raw/knassar702/scant3r?color=dark-green&label=issues%20fixed">
  </a>
  <a href="https://img.shields.io/github/stars/knassar702/scant3r">
      <img src="https://img.shields.io/github/stars/knassar702/scant3r">
  </a>
  <a href="https://img.shields.io/github/forks/knassar702/scant3r">
      <img src="https://img.shields.io/github/forks/knassar702/scant3r">
  </a>
  <a href="https://img.shields.io/github/issues/knassar702/scant3r">
      <img src="https://img.shields.io/github/issues/knassar702/scant3r">
  </a>
  <a href="https://img.shields.io/github/license/knassar702/scant3r">
      <img src="https://img.shields.io/github/license/knassar702/scant3r">
  </a>
</p>

***



### What's this?
**ScanT3r** is a fast and flexible **DAST** (Dynamic Application Security Testing)
command-line tool written in **Rust**. It scans running web applications for
vulnerabilities from the outside — no source code needed: point it at a URL
(or a list of URLs) and its modules probe the target with real HTTP traffic,
analyze the responses, and report exploitable findings.

### Why ScanT3r?

- **Fast** — an async Rust engine (tokio + reqwest) fires hundreds of concurrent
  requests with connection reuse, bounded by a single `--workers` flag. Scans
  that took minutes in the old Python version finish in seconds.
- **Flexible** — a module-based architecture: enable only the checks you need
  (`-m xss,ssti`) or run everything (`-m all`). Custom headers, cookies, proxy
  (Burp-ready), HTTP methods, JSON bodies, rate-limiting delays and timeouts are
  all first-class CLI options.
- **OOB-ready** — built-in out-of-band (interact.sh / odiss.eu) callback support
  for detecting blind vulnerabilities like SSRF and out-of-band resource loads.
- **Pipeline-friendly** — reads targets from stdin, `-u` or `-l`, and writes
  structured JSON reports (`-o report.json`) that slot straight into your
  CI/CD or bug-bounty automation.

Adding a new check means implementing one Rust trait (`src/modules/mod.rs`) and
registering it — the engine takes care of concurrency, HTTP, logging, progress
and reporting. New CLI option? One clap attribute in `src/cli.rs`, resolved in
`src/opts.rs`.

### Modules

Built-in detection modules (need a new one? open an issue with the `Feature request` template)

| module         | Short description                                           |
| :------------- | :-------------                                               |
| **xss** | reflected XSS scanner — detects reflection context (ATTR_NAME, ATTR_VALUE, Comments, TAG_NAME, text) and confirms with context-aware payloads |
| **req_callback**     | finds out-of-band resource load parameters (blind SSRF-style) via interact.sh callbacks |
| **ssti**       | finds Server-Side Template Injection                                         |
| **firebase**   | checks for public firebase databases (write/read) permission  |

Official documentation: https://scant3r.knas.me 

#### Requirements
* Rust toolchain (cargo) >= 1.75
* Git

#### install
* Unix & MS-DOS

```bash
$ git clone https://github.com/knassar702/scant3r && cd scant3r
$ cargo build --release
$ ./target/release/scant3r --help
# or install it into your cargo bin directory:
$ cargo install --path .
$ scant3r --help
Usage: scant3r [OPTIONS]

Options:
  -u, --url <URL>                      Your target URL
  -e, --exit-after <EXIT_AFTER>        Exit after get this number of errors [default: 500]
      --callback-time <CALLBACK_TIME>  Callback timeout [default: 0.5]
  -c, --convert-body                   Change the url parameters into request body ( in non-GET methods )
  -o, --output <OUTPUT>                The output json file location
  -H, --header <HEADERS>               add custom header (ex:-H='Cookie: test=1; PHPSESSID=test')
  -C, --cookie <COOKIES>               add cookie to the header (ex: 'cookie1=1; cookie2=2')
  -v, --logger-mode <LOG_MODE>         change debug messages mode (1: info 2: debug 3: warning 4: error) [default: 2]
  -s, --sleep <DELAY>                  number of seconds to hold between each HTTP(S) requests.
  -M, --method <METHODS>               Methods Allowed on your target [default: GET]
  -m, --module <MODULES>               run scant3r module (ex: -m=example)
  -l, --list <TARGETLIST>              add targets list
  -j, --json                           JSON Request Body
  -p, --proxy <PROXY>                  Forward all requests to proxy
  -r, --follow-redirects               Follow redirects
  -R, --random-agents                  use random user agent
  -w, --workers <THREADS>              Number of workers [default: 50]
  -t, --timeout <TIMEOUT>              set connection timeout [default: 10]
  -h, --help                           Print help
  -V, --version                        Print version

for Questions/suggestions/Bugs : https://github.com/knassar702/scant3r/issues
wiki: https://github.com/knassar702/scant3r/wiki
```

With Docker:

```bash
$ docker build -t scant3r .
$ echo "http://testphp.vulnweb.com/listproducts.php?cat=1" | docker run -i scant3r -m all
```


### Start
```bash
# pipe a target and run every module
$ echo "http://testphp.vulnweb.com/listproducts.php?cat=1" | scant3r -m all

# scan a list of targets, JSON report out, 100 workers
$ scant3r -l targets.txt -m xss,ssti -w 100 -o report.json

# route traffic through Burp with a session cookie
$ scant3r -u "http://target.com/search?q=1" -m all -p http://127.0.0.1:8080 -C "session=abc123"
```

## TODO-Features
* [ ] Restful API
* [x] re-write in Rust
* [ ] Custom scanning map
* [ ] Selenium Modules

## Acknowledgments
![cont](CONTRIBUTORS.svg)


#### Join us 
* https://docs.google.com/forms/d/e/1FAIpQLSfb7-67XG5d1CU-zwqux6Kfx8nCHsM0SiFlZLj8VmXZL-vSwg/viewform

## License
* [GPL 3v](https://github.com/knassar702/scant3r/blob/master/LICENSE)


### Stars Rate
![stars](https://starchart.cc/knassar702/scant3r.svg)

***

## Media
some demo gifs from the old versions

* LorSrf
![](.src/output.gif)

#### Version: [0.6](https://github.com/knassar702/scant3r/releases/tag/0.6)

![](.src/all.gif)

**Nokia** https://www.nokia.com/responsible-disclosure/
![](.src/nokia.gif)

**IBM** https://hackerone.com/ibm

![](.src/ibm.png)
