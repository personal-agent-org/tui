//! `pa conversations`: one page of `ListConversations`, with the stored session.
//!
//! The endpoint is the verified `api` endpoint plus the operation's published path; the
//! session is presented as the `pa_session` cookie plus the `pa-csrf` header, and the answer
//! must be the published `no-store` JSON page. Titles and instants are the instance's own
//! bytes, sanitized before they reach the terminal.

use super::session;
use super::*;
use reqwest::header::{ACCEPT, COOKIE};
use serde::Deserialize;

/// `ListConversations`' published default and maximum page size.
const DEFAULT_LIMIT: i64 = 50;
const MAX_LIMIT: i64 = 200;
/// The published ordering key this renderer relies on.
const ORDERING: &str = "callers_main_first,activity_at_desc,entity_key_desc";
/// A page of at most 200 rows with bounded fields.
const MAX_PAGE_BYTES: usize = 4 * 1024 * 1024;

#[derive(Deserialize)]
struct Page {
    ordering: String,
    conversations: Vec<Row>,
    next_cursor: Option<String>,
}

#[derive(Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum Lifecycle {
    Active,
    Archived,
}

#[derive(Deserialize)]
struct Row {
    branch_id: String,
    title: Option<String>,
    activity_at: String,
    lifecycle: Lifecycle,
    main: bool,
    pinned: bool,
    hidden: bool,
    live_run: Option<serde_json::Value>,
}

/// `^[mc]\.[0-9]+\.[0-9a-fA-F-]{36}$`, at most 64 bytes: the published cursor shape.
fn valid_cursor(cursor: &str) -> bool {
    let mut parts = cursor.splitn(3, '.');
    let (Some(kind), Some(position), Some(key)) = (parts.next(), parts.next(), parts.next()) else {
        return false;
    };
    cursor.len() <= 64
        && matches!(kind, "m" | "c")
        && !position.is_empty()
        && position.bytes().all(|byte| byte.is_ascii_digit())
        && key.len() == 36
        && key
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() || byte == b'-')
}

fn decode(bytes: &[u8], limit: i64) -> Result<Page, ReadError> {
    let page: Page = serde_json::from_slice(bytes).map_err(|_| ReadError::InvalidResponse)?;
    if page.ordering != ORDERING
        || page.conversations.len() > limit as usize
        || page
            .conversations
            .iter()
            .any(|row| !contract::canonical_uuid(&row.branch_id))
        || page
            .next_cursor
            .as_deref()
            .is_some_and(|cursor| !valid_cursor(cursor))
    {
        return Err(ReadError::InvalidResponse);
    }
    Ok(page)
}

fn render(page: &Page) -> String {
    use std::fmt::Write as _;
    let mut rendered = format!(
        "Conversations · {} on this page\n",
        page.conversations.len()
    );
    for row in &page.conversations {
        let mut title = String::new();
        push_sanitized(&mut title, row.title.as_deref().unwrap_or("(untitled)"));
        let mut activity = String::new();
        push_sanitized(&mut activity, &row.activity_at);
        let mut marks = Vec::new();
        if row.main {
            marks.push("main");
        }
        if row.pinned {
            marks.push("pinned");
        }
        if row.lifecycle == Lifecycle::Archived {
            marks.push("archived");
        }
        if row.hidden {
            marks.push("hidden");
        }
        if row.live_run.as_ref().is_some_and(|run| !run.is_null()) {
            marks.push("run live");
        }
        let marks = if marks.is_empty() {
            String::new()
        } else {
            format!("  [{}]", marks.join(", "))
        };
        let _ = writeln!(
            rendered,
            "\n  {title}{marks}\n    branch {} · activity {activity}",
            row.branch_id
        );
    }
    match &page.next_cursor {
        Some(cursor) => {
            let _ = writeln!(rendered, "\nNext page: --cursor {cursor}");
        }
        None => rendered.push_str("\nEnd of the list.\n"),
    }
    rendered
}

/// One page, fetched with an already presented session.
pub(super) async fn fetch(
    http: &reqwest::Client,
    trust: &session::Trust,
    session: &SessionToken,
    limit: i64,
    cursor: Option<&str>,
    include_hidden: bool,
) -> Result<String, ReadError> {
    let mut url = reqwest::Url::parse(&format!("{}/conversations", trust.api))
        .map_err(|_| ReadError::EndpointTrustUnverified)?;
    {
        let mut query = url.query_pairs_mut();
        query.append_pair("limit", &limit.to_string());
        if let Some(cursor) = cursor {
            query.append_pair("cursor", cursor);
        }
        if include_hidden {
            query.append_pair("include_hidden", "true");
        }
    }
    let response = http
        .get(url)
        .header(ACCEPT, "application/json")
        .header(COOKIE, session.header()?)
        .header(contract::CSRF_HEADER, "1")
        .send()
        .await
        .map_err(|error| session::transport(&error))?;
    match response.status().as_u16() {
        200 => {}
        401 => return Err(ReadError::AuthenticationRequired),
        403 | 404 => return Err(ReadError::NotAuthorized),
        _ => return Err(ReadError::Transport),
    }
    if !session::is_json(&response) || !session::no_store(&response) {
        return Err(ReadError::InvalidResponse);
    }
    let bytes = Zeroizing::new(session::bounded(response, MAX_PAGE_BYTES).await?);
    Ok(render(&decode(&bytes, limit)?))
}

/// `pa conversations`: the stored session's own list, for `server` or the stored origin.
pub async fn list(
    server: Option<String>,
    limit: Option<i64>,
    cursor: Option<String>,
    include_hidden: bool,
    allow_loopback_http: bool,
) -> Result<(), ReadError> {
    let server = match server {
        Some(server) => server,
        None => session::stored_origin()?,
    };
    let origin = origin(&server, allow_loopback_http)?;
    let limit = limit.unwrap_or(DEFAULT_LIMIT);
    if !(1..=MAX_LIMIT).contains(&limit) || cursor.as_deref().is_some_and(|c| !valid_cursor(c)) {
        return Err(ReadError::InvalidSelector);
    }
    let http = session::client()?;
    let (token, trust) = session::present_at(
        &http,
        &origin,
        &session::store_path()?,
        session::now_unix(),
        true,
    )
    .await?;
    let rendered = Zeroizing::new(
        fetch(
            &http,
            &trust,
            &token,
            limit,
            cursor.as_deref(),
            include_hidden,
        )
        .await?,
    );
    let mut output = std::io::stdout().lock();
    output
        .write_all(rendered.as_bytes())
        .and_then(|()| output.flush())
        .map_err(|_| ReadError::Output)
}
