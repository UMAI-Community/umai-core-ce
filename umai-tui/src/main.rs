//! UMAI Monitor TUI — SRE-facing dashboard.
//!
//! Standalone binary. Connects to the agent over gRPC (default
//! localhost:50051) and ticks `GetStats` + `ListSignatures` on a 500 ms
//! cadence, redrawing the screen between polls.
//!
//! Layout:
//!   ┌───────────────────────────────────────────────────────────┐
//!   │ UMAI Monitor                          uptime  00:01:23   │
//!   ├──────────────────┬────────────────────────────────────────┤
//!   │ Status           │ Counters                               │
//!   │  iface  veth-r   │  drops          1,204                  │
//!   │  attach yes      │  passes     18,932                     │
//!   │                  │  parse errs       0                    │
//!   ├──────────────────┴────────────────────────────────────────┤
//!   │ Signatures (12 in kernel intel map)                       │
//!   │   10.200.0.2      ipv4   sev   0                          │
//!   │   10.200.0.42     ipv4   sev   0                          │
//!   │   ...                                                     │
//!   └───────────────────────────────────────────────────────────┘
//!   q: quit | r: refresh now

use std::{io, time::Duration};

use anyhow::{Context, Result};
use clap::Parser;
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Row, Table},
    Frame, Terminal,
};
use tokio::time::Instant;
use umai_proto::monitor::{
    monitor_client::MonitorClient, signature::Kind, Empty, Signature, SignatureList, Stats,
};

#[derive(Debug, Parser)]
#[command(name = "umai-tui", version)]
struct Cli {
    /// gRPC endpoint of the umai-agent. Default works for the sandbox.
    #[arg(long, default_value = "http://127.0.0.1:50051")]
    grpc: String,

    /// Refresh interval in milliseconds. 500 ms by default — fast enough
    /// to watch a red-team script land drops in real time, slow enough to
    /// keep the agent's gRPC syscall load low.
    #[arg(long, default_value_t = 500)]
    tick_ms: u64,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let mut client = MonitorClient::connect(cli.grpc.clone())
        .await
        .with_context(|| format!("connecting to umai-agent at {}", cli.grpc))?;

    // Enter raw mode + alt screen. ratatui standard boilerplate.
    enable_raw_mode().context("enable_raw_mode")?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture).context("crossterm setup")?;
    let backend = CrosstermBackend::new(stdout);
    let mut term = Terminal::new(backend).context("ratatui terminal init")?;

    let result = run(&mut term, &mut client, &cli).await;

    // Best-effort restore. We don't propagate teardown errors over the
    // primary error — if a render failure already happened, we still want
    // to leave the terminal usable.
    disable_raw_mode().ok();
    execute!(term.backend_mut(), LeaveAlternateScreen, DisableMouseCapture).ok();
    term.show_cursor().ok();

    result
}

async fn run<B: ratatui::backend::Backend>(
    term: &mut Terminal<B>,
    client: &mut MonitorClient<tonic::transport::Channel>,
    cli: &Cli,
) -> Result<()> {
    let tick = Duration::from_millis(cli.tick_ms);
    let mut last_poll = Instant::now() - tick; // force immediate first poll
    let mut stats: Option<Stats> = None;
    let mut signatures: Vec<Signature> = Vec::new();
    let mut error: Option<String> = None;

    loop {
        // Poll the agent at the configured cadence.
        if last_poll.elapsed() >= tick {
            last_poll = Instant::now();
            match client.get_stats(Empty {}).await {
                Ok(r) => {
                    stats = Some(r.into_inner());
                    error = None;
                }
                Err(e) => error = Some(format!("GetStats: {e}")),
            }
            match client.list_signatures(Empty {}).await {
                Ok(r) => {
                    let SignatureList { entries } = r.into_inner();
                    signatures = entries;
                }
                Err(e) => error = Some(format!("ListSignatures: {e}")),
            }
        }

        // Render frame.
        term.draw(|f| draw(f, stats.as_ref(), &signatures, error.as_deref()))?;

        // Drain keyboard events with a short timeout so we stay responsive
        // to the next tick deadline.
        if event::poll(Duration::from_millis(50))? {
            if let Event::Key(key) = event::read()? {
                match key.code {
                    KeyCode::Char('q') | KeyCode::Esc => break,
                    KeyCode::Char('r') => last_poll = Instant::now() - tick, // force re-poll
                    _ => {}
                }
            }
        }
    }

    Ok(())
}

fn draw(f: &mut Frame, stats: Option<&Stats>, sigs: &[Signature], error: Option<&str>) {
    let area = f.area();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // header
            Constraint::Length(6), // status + counters
            Constraint::Min(5),    // signatures table
            Constraint::Length(1), // help line
        ])
        .split(area);

    draw_header(f, chunks[0], stats);
    draw_status(f, chunks[1], stats, error);
    draw_signatures(f, chunks[2], sigs);
    draw_help(f, chunks[3]);
}

fn draw_header(f: &mut Frame, rect: Rect, stats: Option<&Stats>) {
    let uptime = stats.map(|s| s.uptime_sec).unwrap_or(0);
    let h = uptime / 3600;
    let m = (uptime % 3600) / 60;
    let s = uptime % 60;
    let block = Block::default().borders(Borders::ALL).title(Span::styled(
        " UMAI Monitor ",
        Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
    ));
    let inner = block.inner(rect);
    f.render_widget(block, rect);

    let line = Line::from(vec![
        Span::styled(
            "kernel-resident threat enforcement",
            Style::default().fg(Color::Gray),
        ),
        Span::raw(" "),
        Span::raw(" ".repeat(inner.width.saturating_sub(56) as usize)),
        Span::styled("uptime ", Style::default().fg(Color::Gray)),
        Span::styled(
            format!("{h:02}:{m:02}:{s:02}"),
            Style::default().fg(Color::White).add_modifier(Modifier::BOLD),
        ),
    ]);
    f.render_widget(line, inner);
}

fn draw_status(f: &mut Frame, rect: Rect, stats: Option<&Stats>, error: Option<&str>) {
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(rect);

    let status_block = Block::default().borders(Borders::ALL).title(" Status ");
    let counters_block = Block::default().borders(Borders::ALL).title(" Counters ");

    if let Some(stats) = stats {
        let status_lines = vec![
            Line::from(vec![
                Span::raw(" iface   "),
                Span::styled(&stats.attached_iface, Style::default().fg(Color::Yellow)),
            ]),
            Line::from(vec![
                Span::raw(" attach  "),
                if stats.kernel_attached {
                    Span::styled("yes", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD))
                } else {
                    Span::styled("no", Style::default().fg(Color::Red).add_modifier(Modifier::BOLD))
                },
            ]),
            Line::from(vec![
                Span::raw(" sigs    "),
                Span::styled(
                    stats.signature_count.to_string(),
                    Style::default().fg(Color::White),
                ),
            ]),
        ];
        let para = ratatui::widgets::Paragraph::new(status_lines).block(status_block);
        f.render_widget(para, cols[0]);

        let counter_lines = vec![
            Line::from(vec![
                Span::raw(" drops        "),
                Span::styled(
                    fmt_num(stats.total_drops),
                    Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                ),
            ]),
            Line::from(vec![
                Span::raw(" passes       "),
                Span::styled(fmt_num(stats.total_passes), Style::default().fg(Color::Green)),
            ]),
            Line::from(vec![
                Span::raw(" parse errs   "),
                Span::styled(
                    fmt_num(stats.parse_errors),
                    if stats.parse_errors == 0 {
                        Style::default().fg(Color::Gray)
                    } else {
                        Style::default().fg(Color::Yellow)
                    },
                ),
            ]),
        ];
        let para = ratatui::widgets::Paragraph::new(counter_lines).block(counters_block);
        f.render_widget(para, cols[1]);
    } else {
        let msg = error.unwrap_or("connecting…");
        let para = ratatui::widgets::Paragraph::new(msg)
            .style(Style::default().fg(Color::Yellow))
            .block(status_block);
        f.render_widget(para, cols[0]);
        let _ = counters_block;
        f.render_widget(Block::default().borders(Borders::ALL).title(" Counters "), cols[1]);
    }
}

fn draw_signatures(f: &mut Frame, rect: Rect, sigs: &[Signature]) {
    let title = format!(" Signatures ({} in kernel intel map) ", sigs.len());
    let block = Block::default().borders(Borders::ALL).title(title);

    let rows: Vec<Row> = sigs
        .iter()
        .map(|s| {
            let (kind_label, value) = match s.kind.as_ref() {
                Some(Kind::Ipv4(ip)) => ("ipv4", ip.clone()),
                Some(Kind::Ja4Hash(_)) => ("ja4", "(opaque)".to_string()),
                Some(Kind::Sni(name)) => ("sni", name.clone()),
                Some(Kind::SpkiSha256(_)) => ("spki", "(opaque)".to_string()),
                None => ("?", String::new()),
            };
            Row::new(vec![
                Cell::from(value),
                Cell::from(kind_label),
                Cell::from(format!("sev {}", s.severity)),
            ])
        })
        .collect();

    let widths = [
        Constraint::Length(24),
        Constraint::Length(8),
        Constraint::Length(8),
    ];
    let table = Table::new(rows, widths)
        .block(block)
        .header(
            Row::new(vec!["value", "kind", "severity"])
                .style(Style::default().fg(Color::Gray).add_modifier(Modifier::DIM)),
        );

    f.render_widget(table, rect);
}

fn draw_help(f: &mut Frame, rect: Rect) {
    let line = Line::from(vec![
        Span::styled("q", Style::default().fg(Color::Yellow)),
        Span::raw(": quit  "),
        Span::styled("r", Style::default().fg(Color::Yellow)),
        Span::raw(": refresh now"),
    ]);
    f.render_widget(line, rect);
}

/// Compact "1,204" style number. Avoids pulling in num-format for one
/// thing — we're rendering at most ten digits.
fn fmt_num(n: u64) -> String {
    let s = n.to_string();
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len() + s.len() / 3);
    for (i, b) in bytes.iter().enumerate() {
        if i > 0 && (bytes.len() - i) % 3 == 0 {
            out.push(',');
        }
        out.push(*b as char);
    }
    out
}
