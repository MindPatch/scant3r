# 0.4.3

 - Updated `hashbrown` dependency to `0.12.0`.

# 0.4.2

 - Updated `dlv-list` dependency to `0.3.0`. This is not a breaking change as it's not user visible.

# 0.4.1

 - Updated `dlv-list` dependency to `0.2.4`.
 - Updated `hashbrown` dependency to `0.11.0`.

# 0.4.0

 - Remove `drain_pairs` as it's unsafe.
 - Fix miri issues with `retain`.

# 0.3.1

 - Added crate feature `serde` for (de)serialization.
 - Implemented `IntoIterator` of owned key-value pairs for `ListOrderedMultimap`.

# 0.3.0

 - Updated `hashbrown` dependency to `0.9.0`.

# 0.2.4

 - Updated `dlv-list` dependency to `0.2.2`.
 - Updated `hashbrown` dependency to `0.7.0`.

# 0.2.3

 - Works on stable Rust.
 - Updated `hashbrown` dependency to `0.6.0`.

# 0.2.2

 - Fix crate as it was broken from std's migration to hashbrown.

# 0.2.1

 - Update dependency on `dlv-list` which will reduce memory size of `ListOrderedMultimap` by 48
   bytes.

# 0.2.0

 - Initial release.

# 0.1.0

 - Version was yanked due to critical design flaw.
