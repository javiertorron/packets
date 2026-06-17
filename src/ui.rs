use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, List, ListItem, Paragraph, Wrap, Tabs, Table, Row, Cell},
    Frame,
};

use crate::app::App;

pub fn draw(f: &mut Frame, app: &mut App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Title
            Constraint::Length(3), // Tabs
            Constraint::Min(0),    // Content
        ].as_ref())
        .split(f.area());

    // Title / Stats
    let title = Paragraph::new(format!(
        " 🛡️  Analizador de Red Educativo  |  Paquetes analizados: {}  |  Alertas: {} ",
        app.packet_count,
        app.alerts.len()
    ))
    .style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))
    .block(Block::default().borders(Borders::ALL));
    f.render_widget(title, chunks[0]);

    // Tabs
    let titles = vec![
        Line::from(" 1. Seguridad (Alertas & Tráfico) "),
        Line::from(" 2. Perfilador de Actividad (Hosts) ")
    ];
    let tabs = Tabs::new(titles)
        .block(Block::default().borders(Borders::ALL))
        .select(app.active_tab)
        .style(Style::default().fg(Color::Gray))
        .highlight_style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD));
    f.render_widget(tabs, chunks[1]);

    if app.active_tab == 0 {
        // Main layout
        let main_chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(60), Constraint::Percentage(40)].as_ref())
            .split(chunks[2]);

        draw_packets(f, app, main_chunks[0]);
        draw_alerts(f, app, main_chunks[1]);

        if app.show_pedagogy {
            draw_pedagogy_popup(f, app);
        }
    } else {
        draw_profiler(f, app, chunks[2]);
    }
}

fn draw_profiler(f: &mut Frame, app: &App, area: Rect) {
    let mut local_ips: Vec<_> = app.profiler.hosts.keys().collect();
    local_ips.sort();

    let mut rows = Vec::new();
    
    for ip in local_ips {
        let conns = &app.profiler.hosts[ip];
        
        rows.push(Row::new(vec![
            Cell::from(ip.clone()).style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
            Cell::from(format!("{} conexiones", conns.len())),
            Cell::from(""),
            Cell::from(""),
            Cell::from(""),
        ]));
        
        let mut sorted_conns: Vec<_> = conns.values().collect();
        sorted_conns.sort_by(|a, b| b.bytes_transferred.cmp(&a.bytes_transferred));
        
        for (i, conn) in sorted_conns.iter().enumerate() {
            if i >= 15 { // Top 15 connections per IP
                break;
            }
            
            let mb = conn.bytes_transferred as f64 / 1024.0 / 1024.0;
            let target_display = if let Some(domain) = &conn.target_domain {
                format!("{} ({})", domain, conn.target_ip)
            } else {
                conn.target_ip.clone()
            };
            let proto_display = format!("{}/{}", conn.protocol, conn.port);

            rows.push(Row::new(vec![
                Cell::from("  └─"),
                Cell::from(target_display),
                Cell::from(proto_display),
                Cell::from(conn.category.clone()).style(Style::default().fg(Color::Green)),
                Cell::from(format!("{:.2} MB", mb)),
            ]));
        }
    }

    let table = Table::new(rows, [
        Constraint::Percentage(15),
        Constraint::Percentage(40),
        Constraint::Percentage(10),
        Constraint::Percentage(20),
        Constraint::Percentage(15),
    ])
    .header(Row::new(vec!["IP Local", "Destino", "Puerto", "Actividad", "Tráfico"])
        .style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))
        .bottom_margin(1))
    .block(Block::default().title(" Perfilador de Tráfico de Red Local (DPI) ").borders(Borders::ALL));

    f.render_widget(table, area);
}

fn draw_packets(f: &mut Frame, app: &App, area: Rect) {
    let items: Vec<ListItem> = app
        .packets
        .iter()
        .rev()
        .map(|p| {
            ListItem::new(Line::from(vec![
                Span::styled(
                    p.timestamp.format("%H:%M:%S").to_string(),
                    Style::default().fg(Color::DarkGray),
                ),
                Span::raw(" "),
                Span::styled(
                    format!("Len: {:<5}", p.length),
                    Style::default().fg(Color::Yellow),
                ),
                Span::raw(" | "),
                Span::raw(&p.summary),
            ]))
        })
        .collect();

    let packets_list = List::new(items).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Flujo de Red en Vivo "),
    );

    f.render_widget(packets_list, area);
}

fn draw_alerts(f: &mut Frame, app: &mut App, area: Rect) {
    let items: Vec<ListItem> = app
        .alerts
        .iter()
        .enumerate()
        .map(|(i, alert)| {
            let style = if Some(i) == app.selected_alert {
                Style::default().bg(Color::Red).fg(Color::White).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::Red)
            };
            ListItem::new(Line::from(alert.title.clone())).style(style)
        })
        .collect();

    let alerts_list = List::new(items).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Alertas Detectadas (Arriba/Abajo para navegar, Enter para aprender) "),
    );

    f.render_widget(alerts_list, area);
}

fn draw_pedagogy_popup(f: &mut Frame, app: &App) {
    if let Some(selected) = app.selected_alert {
        if let Some(alert) = app.alerts.get(selected) {
            let content = alert.attack_type.get_content();

            let block = Block::default()
                .title(format!(" Lección: {} ", content.title))
                .borders(Borders::ALL)
                .style(Style::default().bg(Color::Black).fg(Color::White));

            let text = vec![
                Line::from(Span::styled("¿QUÉ ES?", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))),
                Line::from(content.what_is_it),
                Line::from(""),
                Line::from(Span::styled("¿CÓMO FUNCIONA?", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))),
                Line::from(content.how_it_works),
                Line::from(""),
                Line::from(Span::styled("NIVEL DE PELIGRO", Style::default().fg(Color::Red).add_modifier(Modifier::BOLD))),
                Line::from(content.danger_level),
                Line::from(""),
                Line::from(Span::styled("MITIGACIÓN", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD))),
                Line::from(content.mitigation),
            ];

            let paragraph = Paragraph::new(text)
                .block(block)
                .wrap(Wrap { trim: true });

            let area = centered_rect(80, 80, f.area());
            f.render_widget(Clear, area); // clear background
            f.render_widget(paragraph, area);
        }
    }
}

// Helper to create a centered rect
fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints(
            [
                Constraint::Percentage((100 - percent_y) / 2),
                Constraint::Percentage(percent_y),
                Constraint::Percentage((100 - percent_y) / 2),
            ]
            .as_ref(),
        )
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints(
            [
                Constraint::Percentage((100 - percent_x) / 2),
                Constraint::Percentage(percent_x),
                Constraint::Percentage((100 - percent_x) / 2),
            ]
            .as_ref(),
        )
        .split(popup_layout[1])[1]
}
