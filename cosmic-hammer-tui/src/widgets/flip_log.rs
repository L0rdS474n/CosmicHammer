use cosmic_hammer_core::FlipEvent;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::widgets::{
    Block, Borders, Cell, Row, Scrollbar, ScrollbarOrientation, ScrollbarState, Table,
};
use ratatui::Frame;

use crate::theme::severity_color;

/// Renders the flip event log as a scrollable table.
///
/// Columns: Time, Offset, Bit, Dir, Class
/// Most recent events appear at the top (caller provides events pre-sorted).
/// The selected row is highlighted.
pub fn render_flip_log(
    frame: &mut Frame,
    area: Rect,
    events: &[FlipEvent],
    selected: usize,
    scroll_offset: usize,
) {
    let header_cells = ["Time", "Offset", "Bit", "Dir", "Class"].iter().map(|h| {
        Cell::from(*h).style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )
    });
    let header = Row::new(header_cells).height(1);

    let rows: Vec<Row> = events
        .iter()
        .enumerate()
        .map(|(i, event)| {
            let color = severity_color(event.flip_class);
            let style = if i == selected {
                Style::default()
                    .fg(Color::Black)
                    .bg(color)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(color)
            };

            // Format timestamp as HH:MM:SS
            let secs = event.timestamp;
            let h = (secs / 3600) % 24;
            let m = (secs % 3600) / 60;
            let s = secs % 60;
            let time_str = format!("{h:02}:{m:02}:{s:02}");

            let cells = vec![
                Cell::from(time_str),
                Cell::from(format!("0x{:012x}", event.offset)),
                Cell::from(format!("{:3}", event.bit_position)),
                Cell::from(format!("{}", event.direction)),
                Cell::from(event.flip_class.name()),
            ];
            Row::new(cells).style(style)
        })
        .collect();

    let widths = [
        ratatui::layout::Constraint::Length(10),
        ratatui::layout::Constraint::Length(16),
        ratatui::layout::Constraint::Length(5),
        ratatui::layout::Constraint::Length(5),
        ratatui::layout::Constraint::Min(16),
    ];

    let table = Table::new(rows, widths)
        .header(header)
        .block(
            Block::default()
                .title(" Flip Event Log ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Yellow)),
        )
        .row_highlight_style(
            Style::default()
                .add_modifier(Modifier::BOLD)
                .bg(Color::DarkGray),
        )
        .highlight_symbol(">> ");

    frame.render_widget(table, area);

    // Render scrollbar
    if !events.is_empty() {
        let mut scrollbar_state = ScrollbarState::new(events.len()).position(scroll_offset);
        let scrollbar = Scrollbar::new(ScrollbarOrientation::VerticalRight)
            .begin_symbol(Some("^"))
            .end_symbol(Some("v"));
        frame.render_stateful_widget(scrollbar, area, &mut scrollbar_state);
    }
}
