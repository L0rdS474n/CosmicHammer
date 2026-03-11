//! Cosmic Hammer Scanner — arena management, fill/scan with volatile reads,
//! lock-free FlipRing, and parallel scanning.

pub mod arena;
pub mod fill;
pub mod parallel;
pub mod ring;
pub mod scan;
pub mod simd;

pub use arena::Arena;
pub use ring::FlipRing;
