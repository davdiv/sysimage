//! Size arithmetic.
//!
//! Sizes in config may be bare integers (bytes) or strings with `M`/`G`
//! suffixes. [`compute_partition_sizes`] distributes available disk space
//! across partitions according to their `sizeMin`/`sizeMax`/`sizeWeight`,
//! aligning to a block size.

use crate::model::config::{ConfigPartitionSize, ConfigSize};
use crate::model::manifest::ManifestPartitionSize;

/// Extra bytes needed to round `size` *up* to a multiple of `block_size`.
pub fn extra_align_size(size: u64, block_size: u64) -> u64 {
    let diff = size % block_size;
    if diff > 0 { block_size - diff } else { 0 }
}

/// Round `size` *up* to the next multiple of `block_size`.
pub fn align_size(size: u64, block_size: u64) -> u64 {
    size + extra_align_size(size, block_size)
}

/// Round `size` *down* to the previous multiple of `block_size`.
pub fn align_size_floor(size: u64, block_size: u64) -> u64 {
    let diff = size % block_size;
    if diff > 0 { size - diff } else { size }
}

/// Parse a [`ConfigSize`] into a number of bytes.
///
/// Integers are bytes; strings accept an optional `M`/`G` unit (case
/// insensitive) and an optional trailing `B`, e.g. `"10M"`, `"2GB"`, `"500"`.
pub fn size_to_bytes(size: &ConfigSize) -> crate::error::Result<u64> {
    match size {
        ConfigSize::Number(n) => Ok(*n),
        ConfigSize::String(s) => {
            let bytes = s.as_bytes();
            let mut end = bytes.len();
            if end > 0 && (bytes[end - 1] == b'B' || bytes[end - 1] == b'b') {
                end -= 1;
            }
            let unit: u64 = if end > 0 {
                match bytes[end - 1] {
                    b'M' | b'm' => {
                        end -= 1;
                        1024 * 1024
                    }
                    b'G' | b'g' => {
                        end -= 1;
                        1024 * 1024 * 1024
                    }
                    _ => 1,
                }
            } else {
                1
            };
            let value_str = std::str::from_utf8(&bytes[..end])?;
            let value: f64 = value_str
                .parse()
                .map_err(|_| crate::error::Error::msg(format!("Invalid size format: {s}")))?;
            Ok((value * unit as f64).round() as u64)
        }
    }
}

/// Convert a config partition-size spec into a manifest partition-size.
///
/// `content_size` is a floor for `sizeMin`: a partition must be at least large
/// enough to hold its content.
pub fn to_manifest_partition_size(
    spec: &ConfigPartitionSize,
    content_size: u64,
) -> crate::error::Result<ManifestPartitionSize> {
    let size_min = match &spec.size_min {
        Some(min) => std::cmp::max(size_to_bytes(min)?, content_size),
        None => content_size,
    };
    let size_max = match &spec.size_max {
        Some(max) => Some(size_to_bytes(max)?),
        None => None,
    };
    Ok(ManifestPartitionSize {
        size_min,
        size_weight: spec.size_weight.unwrap_or(0.0),
        size_max,
    })
}

#[derive(Clone)]
struct PartState {
    min: u64,
    max_extra: u64,
    weight: f64,
    extra: u64,
}

/// Distribute `available_size` bytes across `partitions`, respecting each
/// partition's `sizeMin`/`sizeMax` and distributing surplus by `sizeWeight`.
///
/// All sizes are aligned up to `block_size`.
pub fn compute_partition_sizes(
    partitions: &[ManifestPartitionSize],
    available_size: u64,
    block_size: u64,
) -> crate::error::Result<Vec<u64>> {
    const INFINITY_EXTRA: u64 = u64::MAX;
    let mut total_current: i128 = 0;
    let mut total_weight: f64 = 0.0;
    let mut state: Vec<PartState> = Vec::with_capacity(partitions.len());

    for p in partitions {
        let max_extra = match p.size_max {
            Some(max) => {
                let max_aligned = align_size_floor(max, block_size);
                if max_aligned < p.size_min {
                    return Err(crate::error::Error::msg(format!(
                        "Cannot satisfy size requirements: sizeMin={}, sizeMax={}, blockSize={}",
                        p.size_min, max, block_size
                    )));
                }
                max_aligned - p.size_min
            }
            None => INFINITY_EXTRA,
        };
        if p.size_weight < 0.0 {
            return Err(crate::error::Error::msg(format!(
                "Invalid negative weight: {}",
                p.size_weight
            )));
        }
        let extra = extra_align_size(p.size_min, block_size);
        let weight = if extra == max_extra {
            0.0
        } else {
            p.size_weight
        };
        total_current += p.size_min as i128 + extra as i128;
        total_weight += weight;
        state.push(PartState {
            min: p.size_min,
            max_extra,
            weight,
            extra,
        });
    }

    let total_extra_size: i128 = available_size as i128 - total_current;
    if total_extra_size < 0 {
        return Err(crate::error::Error::msg(format!(
            "Insufficient space: {} bytes missing",
            -total_extra_size
        )));
    }

    // Distribute the surplus (space beyond every partition's aligned
    // `sizeMin`) to partitions proportionally to their `sizeWeight`. Each
    // allocation is aligned *down* to `block_size`, so a sub-`block_size`
    // remainder cannot be distributed and is left unused.
    //
    // The surplus is tracked decrementally (`remaining`): every time a
    // partition absorbs space (whether fully or capped at its `sizeMax`) the
    // amount it actually took is subtracted, so the next partition in the same
    // pass sees only the space that is genuinely still free. This guarantees
    // the distributed total never exceeds `available_size` (which the
    // previous stale-per-pass formulation could do when a partition hit its
    // cap mid-pass).
    //
    // Because allocations are aligned down to `block_size`, a pass can make
    // zero progress once the leftover surplus drops below `block_size`; the
    // loop must terminate then, otherwise it would spin forever on that
    // sub-block remainder.
    let mut remaining: i128 = total_extra_size;
    while remaining > 0 && total_weight > 0.0 {
        let prev_remaining = remaining;
        for s in state.iter_mut() {
            if s.weight == 0.0 {
                continue;
            }
            let share = align_size_floor(
                ((remaining as f64) * s.weight / total_weight).floor() as u64,
                block_size,
            );
            let new_extra = std::cmp::min(s.extra + share, s.max_extra);
            // `new_extra >= s.extra` because `share >= 0` and the cap only
            // lowers the upper bound, so this never underflows.
            let absorbed = new_extra - s.extra;
            if new_extra == s.max_extra {
                total_weight -= s.weight;
                s.weight = 0.0;
            }
            s.extra = new_extra;
            remaining -= absorbed as i128;
        }
        // No partition absorbed any space this pass: the remaining surplus is
        // smaller than `block_size` and cannot be allocated in whole blocks.
        if remaining == prev_remaining {
            break;
        }
    }

    Ok(state.iter().map(|s| s.min + s.extra).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::manifest::ManifestPartitionSize;

    fn part(min: u64, weight: f64, max: Option<u64>) -> ManifestPartitionSize {
        ManifestPartitionSize {
            size_min: min,
            size_weight: weight,
            size_max: max,
        }
    }

    /// Regression test: when the surplus left after distributing every
    /// partition's aligned `sizeMin` is smaller than `block_size`, the
    /// weighted-distribution loop used to spin forever (the per-partition
    /// allocation is aligned *down* to `block_size`, flooring a sub-block
    /// remainder to 0, so no partition ever grew). It must terminate and leave
    /// the sub-block remainder unused.
    #[test]
    fn compute_partition_sizes_terminates_on_sub_block_remainder() {
        // Mirrors the sample manifest: a fixed-size "efi" partition plus a
        // weighted "data" partition on a 2 GiB disk.
        let parts = [part(37832192, 0.0, None), part(655360000, 1.0, None)];
        // 2 GiB minus a small GPT overhead; leaves ~1.45 GiB surplus whose
        // final remainder (3072 bytes) is below block_size (4096).
        let available = 2 * 1024 * 1024 * 1024 - 66 * 512;
        let result = compute_partition_sizes(&parts, available, 4096).unwrap();
        assert_eq!(result.len(), 2);
        // efi is fixed (weight 0): aligned up to a block.
        assert_eq!(result[0], align_size(37832192, 4096));
        // data absorbs the bulk of the surplus; the total does not exceed the
        // available space and is aligned to a block.
        assert!(result[0] + result[1] <= available);
        assert_eq!(result[1] % 4096, 0);
        // The total must use as much as possible: only a sub-block remainder is
        // left unused (less than one block).
        assert!(available - (result[0] + result[1]) < 4096);
    }

    #[test]
    fn compute_partition_sizes_respects_size_max() {
        let parts = [part(1024, 1.0, Some(8192)), part(1024, 1.0, None)];
        let result = compute_partition_sizes(&parts, 1 << 20, 4096).unwrap();
        // First partition capped at its aligned max.
        assert_eq!(result[0], align_size_floor(8192, 4096));
        // Second absorbs the rest.
        assert!(result[0] + result[1] <= 1 << 20);
        assert_eq!(result[1] % 4096, 0);
    }
}
