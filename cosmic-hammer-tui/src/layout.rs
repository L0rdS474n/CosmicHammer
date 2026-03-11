use ratatui::layout::{Constraint, Direction, Layout, Rect};

/// Describes the layout rectangles for all dashboard panels.
pub struct DashboardLayout {
    pub header: Rect,
    pub left_top: Rect,     // region map
    pub left_bottom: Rect,  // DRAM heatmap
    pub right_top: Rect,    // flip log
    pub right_bottom: Rect, // stats
    pub footer: Rect,
}

/// Builds the dashboard layout from a given terminal area.
///
/// Layout structure:
/// - Header: 3 rows (full width)
/// - Body: remaining minus footer
///   - Left panel (30%): region map (70%) + heatmap (30%)
///   - Right panel (70%): flip log (60%) + stats (40%)
/// - Footer: 3 rows (full width)
pub fn build_layout(area: Rect) -> DashboardLayout {
    // Vertical split: header, body, footer
    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // header
            Constraint::Min(10),   // body
            Constraint::Length(3), // footer
        ])
        .split(area);

    let header = vertical[0];
    let body = vertical[1];
    let footer = vertical[2];

    // Horizontal split of body: left (30%) + right (70%)
    let horizontal = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(30), Constraint::Percentage(70)])
        .split(body);

    let left = horizontal[0];
    let right = horizontal[1];

    // Left panel: region map (70%) + heatmap (30%)
    let left_split = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(70), Constraint::Percentage(30)])
        .split(left);

    // Right panel: flip log (60%) + stats (40%)
    let right_split = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
        .split(right);

    DashboardLayout {
        header,
        left_top: left_split[0],
        left_bottom: left_split[1],
        right_top: right_split[0],
        right_bottom: right_split[1],
        footer,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::layout::Rect;

    #[test]
    fn given_80x24_area_when_build_layout_then_all_rects_nonzero() {
        let area = Rect::new(0, 0, 80, 24);
        let layout = build_layout(area);

        assert!(layout.header.width > 0);
        assert!(layout.header.height > 0);
        assert!(layout.left_top.width > 0);
        assert!(layout.left_top.height > 0);
        assert!(layout.left_bottom.width > 0);
        assert!(layout.right_top.width > 0);
        assert!(layout.right_top.height > 0);
        assert!(layout.right_bottom.width > 0);
        assert!(layout.footer.width > 0);
        assert!(layout.footer.height > 0);
    }

    #[test]
    fn given_80x24_area_when_build_layout_then_header_spans_full_width() {
        let area = Rect::new(0, 0, 80, 24);
        let layout = build_layout(area);
        assert_eq!(layout.header.width, area.width);
    }

    #[test]
    fn given_80x24_area_when_build_layout_then_footer_spans_full_width() {
        let area = Rect::new(0, 0, 80, 24);
        let layout = build_layout(area);
        assert_eq!(layout.footer.width, area.width);
    }

    #[test]
    fn given_80x24_area_when_build_layout_then_left_narrower_than_right() {
        let area = Rect::new(0, 0, 80, 24);
        let layout = build_layout(area);
        assert!(layout.left_top.width < layout.right_top.width);
    }
}
