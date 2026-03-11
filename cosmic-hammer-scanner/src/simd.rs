//! SIMD-accelerated scanning (placeholder).
//!
//! Future implementation: use SSE2/AVX2/NEON intrinsics to scan 2-4 u64 words
//! per iteration, comparing against expected sentinels in parallel. Fallback to
//! scalar scan on platforms without SIMD support.
//!
//! The public API will mirror `scan::scan_arena()` but with a `scan_arena_simd()`
//! entry point that the caller can select at runtime via feature detection.
