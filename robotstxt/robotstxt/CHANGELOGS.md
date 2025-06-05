# Changelogs

## v0.3.0 2021-02-13

- Replace unnecessary assert statements to avoid panic in some corner cases. Fixes [#1](https://github.com/Folyd/robotstxt/issues/1), [#2](https://github.com/Folyd/robotstxt/issues/2).
- Improve performance by using `Cow<T>` to prevent redundant `clone()`.
- Convert to intra-doc links.

## v0.2.0  2020-05-24

The first implementation of the Rust port to Google Robotstxt C++ library.

## v0.1.0 (yanked)

