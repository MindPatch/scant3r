# robotstxt

![Crates.io](https://img.shields.io/crates/v/robotstxt)
![Docs.rs](https://docs.rs/robotstxt/badge.svg)
[![Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

A native Rust port of [Google's robots.txt parser and matcher C++ library](https://github.com/google/robotstxt).

- Native Rust port, no third-part crate dependency
- Zero unsafe code
- Preserves all behavior of original library
- Consistent API with the original library
- 100% google original test passed

## Installation

```toml
[dependencies]
robotstxt = "0.3.0"
```

## Quick start

```rust
use robotstxt::DefaultMatcher;

let mut matcher = DefaultMatcher::default();
let robots_body = "user-agent: FooBot\n\
                   disallow: /\n";
assert_eq!(false, matcher.one_agent_allowed_by_robots(robots_body, "FooBot", "https://foo.com/"));
```

## About

Quoting the README from Google's robots.txt parser and matcher repo:

> The Robots Exclusion Protocol (REP) is a standard that enables website owners to control which URLs may be accessed by automated clients (i.e. crawlers) through a simple text file with a specific syntax. It's one of the basic building blocks of the internet as we know it and what allows search engines to operate.
>
> Because the REP was only a de-facto standard for the past 25 years, different implementers implement parsing of robots.txt slightly differently, leading to confusion. This project aims to fix that by releasing the parser that Google uses.
>
> The library is slightly modified (i.e. some internal headers and equivalent symbols) production code used by Googlebot, Google's crawler, to determine which URLs it may access based on rules provided by webmasters in robots.txt files. The library is released open-source to help developers build tools that better reflect Google's robots.txt parsing and matching.

Crate **robotstxt** aims to be a faithful conversion, from C++ to Rust, of Google's robots.txt parser and matcher.

## Testing

```
$ git clone https://github.com/Folyd/robotstxt
Cloning into 'robotstxt'...
$ cd robotstxt/tests 
...
$ mkdir c-build && cd c-build
...
$ cmake ..
...
$ make
...
$ make test
Running tests...
Test project ~/robotstxt/tests/c-build
    Start 1: robots-test
1/1 Test #1: robots-test ......................   Passed    0.33 sec
```

## License

The robotstxt parser and matcher Rust library is licensed under the terms of the
Apache license. See [LICENSE](LICENSE) for more information.
