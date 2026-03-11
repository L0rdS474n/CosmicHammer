use cosmic_hammer_core::RegionType;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;

use crate::theme::region_flip_color;

/// Region labels matching the dashboard display names.
const REGION_LABELS: [(&str, RegionType); RegionType::COUNT] = [
    ("PTR ", RegionType::Pointer),
    ("RET ", RegionType::RetAddr),
    ("PERM", RegionType::Permission),
    ("DATA", RegionType::Data),
    ("PTE ", RegionType::PteSim),
];

/// Renders the region map widget showing all 5 memory regions.
///
/// Each region is color-coded based on the number of flips detected:
/// - Green: 0 flips
/// - Yellow: 1-5 flips
/// - Red: 6+ flips
pub fn render_region_map(
    frame: &mut Frame,
    area: Rect,
    region_stats: &[u64; RegionType::COUNT],
    region_size_mb: u64,
) {
    let mut lines = Vec::with_capacity(RegionType::COUNT);

    for (label, region) in &REGION_LABELS {
        let count = region_stats[*region as usize];
        let color = region_flip_color(count);

        let line = Line::from(vec![
            Span::styled(
                format!("  {label}"),
                Style::default().fg(color).add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!("  {region_size_mb}M"),
                Style::default().fg(Color::White),
            ),
            Span::styled(format!("  ({count} flips)"), Style::default().fg(color)),
        ]);
        lines.push(line);
    }

    let block = Block::default()
        .title(" Region Map ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Blue));

    let paragraph = Paragraph::new(lines).block(block);
    frame.render_widget(paragraph, area);
}
