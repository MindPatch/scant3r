<h1 align="center">
  <img src="https://github.com/knassar702/scant3r/blob/gh-pages/logo.png" width="150px"><br>
  ScanT3r
</h1>

<p align="center">
  Fast DAST CLI tool, written in Rust.<br>
  <a href="https://github.com/MindPatch/scant3r/stargazers"><img src="https://img.shields.io/github/stars/knassar702/scant3r"></a>
  <a href="https://github.com/MindPatch/scant3r/blob/master/LICENSE"><img src="https://img.shields.io/github/license/knassar702/scant3r"></a>
</p>

## Install

```bash
git clone https://github.com/MindPatch/scant3r && cd scant3r
cargo install --path .
```

## Usage

```bash
# pipe a target, run all modules
echo "http://testphp.vulnweb.com/listproducts.php?cat=1" | scant3r -m all

# targets list, JSON report, 100 workers
scant3r -l targets.txt -m xss,ssti -w 100 -o report.json

# through Burp, with cookies
scant3r -u "http://target.com/search?q=1" -m all -p http://127.0.0.1:8080 -C "session=abc123"
```

Run `scant3r --help` for all options.

## Modules

| module | description |
| :----- | :---------- |
| **xss** | reflected XSS with context-aware payloads |
| **ssti** | Server-Side Template Injection |
| **req_callback** | out-of-band resource load / blind SSRF (interact.sh) |
| **firebase** | public Firebase databases (read/write) |

New module = one trait in `src/modules/mod.rs`.

## Roadmap

- [ ] More modules: SQLi, path traversal, RCE, open redirect
- [ ] AI payload generation (context/WAF-aware, replaces static wordlists)
- [ ] AI triage of findings (fewer false positives)
- [ ] REST API mode
- [ ] Headless-browser module

## License

[GPL-3.0](LICENSE)
