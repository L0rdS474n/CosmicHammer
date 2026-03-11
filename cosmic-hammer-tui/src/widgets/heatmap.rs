use cosmic_hammer_core::FlipEvent;
use ratatui::layout::Rect;
use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;

/// Number of row groups to divide the DRAM address space into.
const HEATMAP_ROWS: usize = 8;
/// Number of columns in the heatmap grid.
const HEATMAP_COLS: usize = 8;
/// Total number of cells in the heatmap.
const HEATMAP_CELLS: usize = HEATMAP_ROWS * HEATMAP_COLS;

/// Characters used to represent flip density, from lowest to highest.
const DENSITY_CHARS: [char; 5] = ['.', '+', '*', '#', '@'];

/// Renders a simplified DRAM heatmap showing flip density per row group.
///
/// The heatmap divides the DRAM row space into a grid, and each cell shows
/// a character representing the number of flips in that bucket.
pub fn render_heatmap(frame: &mut Frame, area: Rect, events: &[FlipEvent]) {
    // Build density buckets from events
    let mut buckets = [0u32; HEATMAP_CELLS];

    if !events.is_empty() {
        // Find max DRAM row to normalize
        let max_row = events.iter().map(|e| e.dram_row).max().unwrap_or(1).max(1) as usize;

        for event in events {
            let bucket = ((event.dram_row as usize) * HEATMAP_CELLS) / (max_row + 1);
            let bucket = bucket.min(HEATMAP_CELLS - 1);
            buckets[bucket] = buckets[bucket].saturating_add(1);
        }
    }

    // Find max density for color scaling
    let max_density = buckets.iter().copied().max().unwrap_or(0);

    // Build display lines
    let mut lines = Vec::with_capacity(HEATMAP_ROWS);
    for row in 0..HEATMAP_ROWS {
        let mut spans = vec![Span::raw("  ")];
        for col in 0..HEATMAP_COLS {
            let idx = row * HEATMAP_COLS + col;
            let count = buckets[idx];
            let ch = density_char(count, max_density);
            let color = density_color(count, max_density);
            spans.push(Span::styled(format!("{ch} "), Style::default().fg(color)));
        }
        lines.push(Line::from(spans));
    }

    let block = Block::default()
        .title(" DRAM Heatmap ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Blue));

    let paragraph = Paragraph::new(lines).block(block);
    frame.render_widget(paragraph, area);
}

/// Selects a density character based on the count relative to the maximum.
fn density_char(count: u32, max: u32) -> char {
    if max == 0 || count == 0 {
        return DENSITY_CHARS[0];
    }
    let ratio = (count as f64) / (max as f64);
    let idx = (ratio * (DENSITY_CHARS.len() - 1) as f64).round() as usize;
    DENSITY_CHARS[idx.min(DENSITY_CHARS.len() - 1)]
}

/// Selects a color based on the density ratio.
fn density_color(count: u32, max: u32) -> Color {
    if max == 0 || count == 0 {
        return Color::DarkGray;
    }
    let ratio = (count as f64) / (max as f64);
    if ratio < 0.33 {
        Color::Green
    } else if ratio < 0.66 {
        Color::Yellow
    } else {
        Color::Red
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn given_zero_count_when_density_char_then_dot() {
        assert_eq!(density_char(0, 10), '.');
    }

    #[test]
    fn given_max_count_when_density_char_then_at() {
        assert_eq!(density_char(10, 10), '@');
    }

    #[test]
    fn given_zero_max_when_density_char_then_dot() {
        assert_eq!(density_char(0, 0), '.');
    }

    #[test]
    fn given_zero_count_when_density_color_then_dark_gray() {
        assert_eq!(density_color(0, 10), Color::DarkGray);
    }

    #[test]
    fn given_max_count_when_density_color_then_red() {
        assert_eq!(density_color(10, 10), Color::Red);
    }

    #[test]
    fn given_low_count_when_density_color_then_green() {
        assert_eq!(density_color(1, 10), Color::Green);
    }
}
