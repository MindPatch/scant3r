# ordered-multimap-rs

[![LICENSE](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Build Status](https://travis-ci.org/sgodwincs/ordered-multimap-rs.svg?branch=master)](https://travis-ci.org/sgodwincs/ordered-multimap-rs)

Currently, this crate contains a single type `ListOrderedMultimap`. This is a multimap meaning that
multiple values can be associated with a given key, but it also maintains insertion order across all
keys and values.

[Documentation](https://docs.rs/ordered-multimap/)

# Performance

Preliminary benchmarks show that performance is quite decent but more will be required to state
anything definitive.

# Features

 - `serde` for (de)serialization.

# TODO

It is planned that a corresponding `SetOrderedMultimap` will also be included in this crate which
will provide the same insertion order guarantees, but the set of values associated to a given key
will be an actual set instead of a list.
