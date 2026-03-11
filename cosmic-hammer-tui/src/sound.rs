use std::io::Cursor;

use rodio::{Decoder, OutputStream, OutputStreamHandle, Sink};

/// Embedded 8-bit retro "level up" WAV.
const FLIP_WAV: &[u8] = include_bytes!("../assets/flip_levelup.wav");

/// Manages audio playback for flip detection alerts.
///
/// Wraps rodio's `OutputStream` so the stream stays alive for the lifetime of
/// the TUI. If the audio device is unavailable at construction time,
/// `FlipSounder::new()` returns `None` and the TUI runs silently.
pub struct FlipSounder {
    _stream: OutputStream,
    stream_handle: OutputStreamHandle,
}

impl FlipSounder {
    /// Try to open the default audio output device.
    /// Returns `None` if no device is available (logged as warning).
    pub fn new() -> Option<Self> {
        match OutputStream::try_default() {
            Ok((_stream, stream_handle)) => Some(Self {
                _stream,
                stream_handle,
            }),
            Err(e) => {
                tracing::warn!(
                    "Audio device unavailable, --flip-sound disabled: {}",
                    e
                );
                None
            }
        }
    }

    /// Play the flip sound once (non-blocking).
    /// Silently does nothing if playback fails.
    pub fn play(&self) {
        let cursor = Cursor::new(FLIP_WAV);
        match Decoder::new(cursor) {
            Ok(source) => {
                if let Ok(sink) = Sink::try_new(&self.stream_handle) {
                    sink.append(source);
                    sink.detach(); // fire-and-forget: plays to completion on background thread
                }
            }
            Err(e) => {
                tracing::debug!("Failed to decode flip sound: {}", e);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // T3: Given FlipSounder, when new() is called, then the constructor does not
    // panic regardless of whether an audio device is present.
    // CI environments may have no audio device, so None is a valid result.
    #[cfg(feature = "flip-sound")]
    #[test]
    fn given_flip_sounder_when_new_called_then_does_not_panic() {
        // The call itself must not panic. We accept both Some and None.
        let _result = FlipSounder::new();
        // No assertion on Some/None — audio device may be absent in CI.
    }

    // T4: Given FlipSounder::new() returns Some, when play() is called, then it
    // does not panic. If new() returns None (no audio device), the test is silently
    // skipped — do NOT unwrap() new().
    #[cfg(feature = "flip-sound")]
    #[test]
    fn given_flip_sounder_when_new_returns_some_then_play_does_not_panic() {
        if let Some(sounder) = FlipSounder::new() {
            // play() is fire-and-forget; it must not panic even if the sink
            // cannot be created or the WAV cannot be decoded at runtime.
            sounder.play();
        }
        // If new() returned None, no audio device is present; skip silently.
    }
}
