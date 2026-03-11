use cosmic_hammer_core::FlipClass;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;

use crate::theme::severity_color;

/// Renders the flip statistics panel showing count per FlipClass.
///
/// Each class is color-coded by severity:
/// - Green: benign
/// - Yellow: data corruption, PTE present clear
/// - Light Red: PTE write set, PTE NX clear
/// - Red: ptr hijack, priv esc, code page, PTE phys corrupt, PTE supervisor esc
pub fn render_stats(frame: &mut Frame, area: Rect, stats: &[u64; FlipClass::COUNT]) {
    let mut lines = Vec::with_capacity(FlipClass::COUNT);

    for (i, &count) in stats.iter().enumerate().take(FlipClass::COUNT) {
        if let Some(class) = FlipClass::from_index(i) {
            let color = severity_color(class);

            let style = if count > 0 {
                Style::default().fg(color).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::DarkGray)
            };

            let line = Line::from(vec![
                Span::styled(format!("  {:<20}", class.name()), style),
                Span::styled(format!("{count:>6}"), style),
            ]);
            lines.push(line);
        }
    }

    let block = Block::default()
        .title(" Flip Stats ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Magenta));

    let paragraph = Paragraph::new(lines).block(block);
    frame.render_widget(paragraph, area);
}
