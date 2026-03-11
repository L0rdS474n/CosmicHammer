use cosmic_hammer_core::VERSION;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;

/// Renders the header bar showing version, uptime, scan count, flip count, and quit hint.
pub fn render_header(
    frame: &mut Frame,
    area: Rect,
    uptime_str: &str,
    scan_count: u64,
    flip_count: usize,
) {
    let spans = vec![
        Span::styled(
            format!(" CosmicHammer v{VERSION} "),
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("| "),
        Span::styled(
            format!("Uptime: {uptime_str} "),
            Style::default().fg(Color::White),
        ),
        Span::raw("| "),
        Span::styled(
            format!("Scans: {scan_count} "),
            Style::default().fg(Color::White),
        ),
        Span::raw("| "),
        Span::styled(
            format!("Flips: {flip_count} "),
            Style::default().fg(if flip_count > 0 {
                Color::Yellow
            } else {
                Color::Green
            }),
        ),
        Span::raw("| "),
        Span::styled("q:quit ", Style::default().fg(Color::DarkGray)),
    ];

    let header = Paragraph::new(Line::from(spans)).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan))
            .title(" Dashboard "),
    );

    frame.render_widget(header, area);
}
