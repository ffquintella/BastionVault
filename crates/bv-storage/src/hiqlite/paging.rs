//! Keyset pagination for [`HiqliteBackend::list`] and [`HiqliteBackend::scan`].
//!
//! # Why
//!
//! A consistent hiqlite query runs on the leader, and a follower receives the
//! result over one multiplexed WebSocket. That socket rejects any message of
//! 64 MiB or more (fastwebsockets' default max message size) and is then
//! closed, failing *every* request in flight on it — the node reports
//! "Cluster node is unhealthy" until it reconnects. `list` and `scan` used to
//! return a whole subtree in one query (`list` even shipped the values it then
//! discarded), so a prefix that grows without bound — an audit log reached
//! 184k rows / ~67 MiB on the wire — took the node's storage link down.
//!
//! # How
//!
//! Every query reads one *page*:
//!
//! - **Range.** Keys in `[prefix, prefix_upper_bound(prefix))`, which is
//!   exactly the set of keys starting with `prefix` in SQLite's `BINARY`
//!   order, so the primary-key index serves it as a range seek. The escaped
//!   `LIKE` pattern is kept as a second filter and `strip_prefix` /
//!   `starts_with` in Rust remains the authoritative membership test.
//! - **Cursor.** The next page starts strictly after the last key returned
//!   ([`PageStart::After`]) or, for `list`, at the first key past the child
//!   directory the previous page ended in ([`PageStart::AtOrAfter`]) — a
//!   directory is one child however many descendants it has, so there is no
//!   point shipping the rest of them.
//! - **Rows.** At most [`PAGE_MAX_ROWS`] candidate rows per page.
//! - **Bytes.** Among those candidates, rows are returned while the running
//!   total of `key bytes + value bytes + PAGE_ROW_OVERHEAD_BYTES` stays within
//!   [`PAGE_MAX_BYTES`]. The first row of a page is always returned, so a
//!   page carries at most `max(PAGE_MAX_BYTES, one row)` of payload: a scan
//!   never ships more than a `get` of its largest row would.
//! - **Cut marker.** When the budget cuts a page short, the query appends one
//!   row whose columns are all `NULL`. That is how the pager tells "the
//!   budget stopped this page" apart from "the range is exhausted" exactly,
//!   without recomputing SQLite's arithmetic in Rust — a silently truncated
//!   listing on an audit path would be worse than any slowness.
//!
//! # Consistency
//!
//! Each page is one consistent (leader, read-index) query, so each page is a
//! point-in-time view. **The pages together are not a snapshot**: a key
//! written behind the cursor while a multi-page `list`/`scan` is running is
//! not returned, a key written ahead of it is, and a key deleted ahead of it
//! is not. Before this change a single query was a snapshot. No caller relied
//! on that: the audit/history readers scan append-only logs (a row appended
//! mid-scan may or may not be included — a scan started a moment earlier
//! would have missed it anyway), recursive walks (`get_keys`, backup,
//! export, migrate) already issued one query per directory, and
//! check-then-write callers (resource-name resolution) were never atomic
//! with their write. Keys are never returned twice and every key present
//! for the whole duration of the call is returned exactly once, because the
//! cursor only moves forward.
//!
//! # Order
//!
//! Results come back in ascending key order (byte order). The single query
//! had no `ORDER BY` and returned SQLite's rowid (insertion) order; both
//! barriers already sorted `list`, and the order of `scan` was never part of
//! the contract — the default `Backend::scan` walks depth-first in yet
//! another order.
//!
//! [`HiqliteBackend::list`]: super::HiqliteBackend
//! [`HiqliteBackend::scan`]: super::HiqliteBackend

use bv_errors::RvError;

use crate::BackendEntry;

/// Most candidate rows one page query considers.
///
/// Bounds the leader's work per query (the window sums at most this many
/// index entries) and the row count on the wire independently of the byte
/// budget. A production access-audit row averages ~314 bytes (102 key +
/// 212 value), so a full page is ~4.4 MiB as charged and the row limit, not
/// the byte budget, ends it; 184k rows are ~19 pages. The sqlite3 3.54 CLI
/// takes ~10 ms for a 10k-row page of this query on a 400k-row table.
pub(super) const PAGE_MAX_ROWS: i64 = 10_000;

/// Byte budget of one page: key bytes + value bytes + per-row overhead.
///
/// 1/8 of the 64 MiB WebSocket max message size. A page never carries more
/// than `max(budget, its first row)`, so a scan never ships more than a `get`
/// of its largest row would: a page holding a file blob (`MAX_FILE_BYTES`,
/// 32 MiB plus the AEAD envelope) stays near half the cap. Rows themselves
/// are bounded only by the put cap (`MAX_PUT_VALUE_BYTES`, ~63 MiB), which is
/// a per-row limit this module cannot lower.
pub(super) const PAGE_MAX_BYTES: i64 = 8 * 1024 * 1024;

/// Wire overhead charged per row on top of its key and value bytes.
///
/// hiqlite serialises each row as a list of named columns; measured at about
/// 68 bytes per two-column row. Charged at roughly twice that so the budget
/// stays conservative if the encoding grows a field.
pub(super) const PAGE_ROW_OVERHEAD_BYTES: i64 = 128;

/// Per-page limits. A value rather than bare constants so tests can force
/// many small pages over a handful of rows.
#[derive(Clone, Copy, Debug)]
pub(super) struct PageLimits {
    pub max_rows: i64,
    pub max_bytes: i64,
}

impl PageLimits {
    pub(super) const DEFAULT: PageLimits = PageLimits { max_rows: PAGE_MAX_ROWS, max_bytes: PAGE_MAX_BYTES };
}

/// Lower bound of the next page.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum PageStart {
    /// Keys `>= key`.
    AtOrAfter(String),
    /// Keys `> key`.
    After(String),
}

impl PageStart {
    /// The `vault_key >= ?` bound and the `vault_key IS NOT ?` exclusion
    /// (`None` binds `NULL`, which excludes nothing) the page query takes.
    pub(super) fn sql_bounds(&self) -> (&str, Option<&str>) {
        match self {
            PageStart::AtOrAfter(key) => (key, None),
            PageStart::After(key) => (key, Some(key)),
        }
    }
}

/// The smallest string greater than every string that starts with `prefix`,
/// or `None` when no such string exists (`prefix` is empty or made only of
/// `char::MAX`), i.e. the range runs to the end of the keyspace.
///
/// Byte order of UTF-8 equals code-point order, and SQLite's `BINARY`
/// collation and Rust's `str` ordering are both byte order, so
/// `k.starts_with(prefix)` holds exactly when
/// `prefix <= k && upper.map_or(true, |u| k < u)`. Dropping the trailing
/// `char::MAX`s and incrementing the last remaining character (skipping the
/// surrogate gap, which UTF-8 cannot encode) yields that bound.
pub(super) fn prefix_upper_bound(prefix: &str) -> Option<String> {
    let mut chars: Vec<char> = prefix.chars().collect();
    while let Some(last) = chars.pop() {
        let next = match last {
            '\u{D7FF}' => Some('\u{E000}'),
            char::MAX => None,
            c => char::from_u32(c as u32 + 1),
        };
        if let Some(next) = next {
            chars.push(next);
            return Some(chars.into_iter().collect());
        }
    }
    None
}

/// Splits a page into its data rows and whether another page may follow.
///
/// `None` is the cut marker (see the module docs). It may only be the last
/// row, and a page that has one also has at least one data row — the query
/// always returns its first row — so a violation is reported instead of
/// risking a loop that never advances or a listing that silently stops.
fn split_page<T>(rows: Vec<Option<T>>, limits: PageLimits) -> Result<(Vec<T>, bool), RvError> {
    let row_count = rows.len();
    let mut data = Vec::with_capacity(row_count);
    let mut cut = false;
    for (i, row) in rows.into_iter().enumerate() {
        match row {
            Some(row) if !cut => data.push(row),
            None if i + 1 == row_count && i > 0 => cut = true,
            _ => {
                return Err(RvError::ErrString(format!(
                    "hiqlite paged read: malformed page (cut marker at row {} of {row_count})",
                    i + 1
                )))
            }
        }
    }
    // Without a marker, a full page may still be followed by more rows; a
    // short one ends the range. One extra empty query when a range holds an
    // exact multiple of `max_rows` keys is the price of not counting them.
    let more = cut || row_count as i64 >= limits.max_rows;
    Ok((data, more))
}

/// Folds `list` pages into the immediate children of `prefix`.
pub(super) struct ListPager {
    prefix: String,
    limits: PageLimits,
    next: Option<PageStart>,
    children: Vec<String>,
}

impl ListPager {
    pub(super) fn new(prefix: &str, limits: PageLimits) -> Self {
        Self {
            prefix: prefix.to_string(),
            limits,
            next: Some(PageStart::AtOrAfter(prefix.to_string())),
            children: Vec::new(),
        }
    }

    /// Where the next page starts, or `None` once the range is exhausted.
    pub(super) fn next_start(&self) -> Option<&PageStart> {
        self.next.as_ref()
    }

    /// Consume one page of full keys, in ascending order.
    pub(super) fn accept(&mut self, rows: Vec<Option<String>>) -> Result<(), RvError> {
        let (keys, more) = split_page(rows, self.limits)?;
        let mut last_dir_child: Option<String> = None;
        for key in &keys {
            last_dir_child = None;
            // Authoritative prefix test. The range and `LIKE` narrow the
            // query, `strip_prefix` decides (SQLite's `LIKE` is
            // ASCII-case-insensitive, and was once wildcard-widened). It is
            // `strip_prefix`, not `trim_start_matches`, so a key whose
            // remainder repeats the prefix keeps that remainder.
            let Some(rest) = key.strip_prefix(self.prefix.as_str()) else {
                continue;
            };
            let child = match rest.find('/') {
                Some(i) => &rest[..=i],
                None => rest,
            };
            if child.ends_with('/') {
                // Keys arrive sorted and every key under one child directory
                // is contiguous in byte order, so comparing with the last
                // child is a complete de-duplication.
                if self.children.last().map(String::as_str) != Some(child) {
                    self.children.push(child.to_string());
                }
                last_dir_child = Some(child.to_string());
            } else {
                self.children.push(child.to_string());
            }
        }

        self.next = match (more, keys.last()) {
            (false, _) | (true, None) => None,
            // Skip the rest of the directory the page ended in: every key
            // left in it maps to the child already recorded.
            (true, Some(last_key)) => match last_dir_child {
                Some(dir) => prefix_upper_bound(&format!("{}{dir}", self.prefix)).map(PageStart::AtOrAfter),
                None => Some(PageStart::After(last_key.clone())),
            },
        };
        Ok(())
    }

    pub(super) fn finish(self) -> Vec<String> {
        self.children
    }
}

/// Folds `scan` pages into the entries under `prefix`.
pub(super) struct ScanPager {
    prefix: String,
    limits: PageLimits,
    next: Option<PageStart>,
    entries: Vec<BackendEntry>,
}

impl ScanPager {
    /// `start_key` is the inclusive lower bound on the full key, as in
    /// `Backend::scan`.
    pub(super) fn new(prefix: &str, start_key: Option<&str>, limits: PageLimits) -> Self {
        let first = match start_key {
            Some(start) if start > prefix => start,
            _ => prefix,
        };
        Self {
            prefix: prefix.to_string(),
            limits,
            next: Some(PageStart::AtOrAfter(first.to_string())),
            entries: Vec::new(),
        }
    }

    pub(super) fn next_start(&self) -> Option<&PageStart> {
        self.next.as_ref()
    }

    /// Consume one page of `(full key, value)` rows, in ascending key order.
    pub(super) fn accept(&mut self, rows: Vec<Option<BackendEntry>>) -> Result<(), RvError> {
        let (page, more) = split_page(rows, self.limits)?;
        self.next = match (more, page.last()) {
            (true, Some(last)) => Some(PageStart::After(last.key.clone())),
            _ => None,
        };
        // Same authoritative prefix test as `list`: without it a subtree
        // read could hand the caller rows from a sibling subtree whose key
        // merely matched the pattern.
        self.entries.extend(page.into_iter().filter(|entry| entry.key.starts_with(self.prefix.as_str())));
        Ok(())
    }

    pub(super) fn finish(self) -> Vec<BackendEntry> {
        self.entries
    }
}

#[cfg(test)]
mod tests {
    //! The pagers driven against an in-memory model of the page query. The
    //! model is checked against real SQL by the hiqlite-backed tests in
    //! `super::super::test`; these run without a cluster.

    use std::collections::BTreeMap;

    use super::*;

    /// In-memory model of the page SQL in `super::super` (`LIST_PAGE_*` /
    /// `SCAN_PAGE_*`): range + cursor, `max_rows` candidates, running byte
    /// total, rows returned while the bytes before them fit, a `None` cut
    /// marker after the last row that fits.
    fn model_page(
        table: &BTreeMap<String, Vec<u8>>,
        prefix: &str,
        start: &PageStart,
        limits: PageLimits,
        with_values: bool,
    ) -> Vec<Option<BackendEntry>> {
        let upper = prefix_upper_bound(prefix);
        let (from, exclude) = start.sql_bounds();
        let candidates = table
            .iter()
            .filter(|(k, _)| k.as_str() >= from && Some(k.as_str()) != exclude)
            .filter(|(k, _)| upper.as_deref().map_or(true, |u| k.as_str() < u))
            .take(limits.max_rows as usize);
        let mut out = Vec::new();
        let mut page_bytes = 0i64;
        for (page_row, (k, v)) in candidates.enumerate().map(|(i, kv)| (i + 1, kv)) {
            let row_bytes = k.len() as i64 + if with_values { v.len() as i64 } else { 0 } + PAGE_ROW_OVERHEAD_BYTES;
            let before = page_bytes;
            page_bytes += row_bytes;
            if !(page_row <= 2 || before <= limits.max_bytes) {
                break;
            }
            if page_row == 1 || page_bytes <= limits.max_bytes {
                out.push(Some(BackendEntry { key: k.clone(), value: v.clone() }));
            } else {
                out.push(None);
            }
        }
        out
    }

    /// Run a full paged `list`, returning the children and the page count.
    fn paged_list(table: &BTreeMap<String, Vec<u8>>, prefix: &str, limits: PageLimits) -> (Vec<String>, usize) {
        let mut pager = ListPager::new(prefix, limits);
        let mut pages = 0;
        while let Some(start) = pager.next_start().cloned() {
            pages += 1;
            assert!(pages < 10_000, "list paging does not terminate");
            let rows = model_page(table, prefix, &start, limits, false);
            pager.accept(rows.into_iter().map(|r| r.map(|e| e.key)).collect()).unwrap();
        }
        (pager.finish(), pages)
    }

    fn paged_scan(
        table: &BTreeMap<String, Vec<u8>>,
        prefix: &str,
        start_key: Option<&str>,
        limits: PageLimits,
    ) -> (Vec<BackendEntry>, usize) {
        let mut pager = ScanPager::new(prefix, start_key, limits);
        let mut pages = 0;
        while let Some(start) = pager.next_start().cloned() {
            pages += 1;
            assert!(pages < 10_000, "scan paging does not terminate");
            pager.accept(model_page(table, prefix, &start, limits, true)).unwrap();
        }
        (pager.finish(), pages)
    }

    /// The pre-pagination `list`: every key under `prefix`, children
    /// de-duplicated in first-seen order.
    fn reference_list(table: &BTreeMap<String, Vec<u8>>, prefix: &str) -> Vec<String> {
        let mut keys: Vec<String> = Vec::new();
        for k in table.keys() {
            let Some(rest) = k.strip_prefix(prefix) else { continue };
            match rest.find('/') {
                Some(i) => {
                    let child = rest[..=i].to_string();
                    if !keys.contains(&child) {
                        keys.push(child);
                    }
                }
                None => keys.push(rest.to_string()),
            }
        }
        keys.sort();
        keys
    }

    fn reference_scan(table: &BTreeMap<String, Vec<u8>>, prefix: &str, start_key: Option<&str>) -> Vec<BackendEntry> {
        table
            .iter()
            .filter(|(k, _)| k.starts_with(prefix) && start_key.map_or(true, |s| k.as_str() >= s))
            .map(|(k, v)| BackendEntry { key: k.clone(), value: v.clone() })
            .collect()
    }

    fn fixture() -> BTreeMap<String, Vec<u8>> {
        let mut t = BTreeMap::new();
        for i in 0..50 {
            t.insert(format!("log/{i:020}"), vec![b'x'; 10 + (i % 7) * 40]);
        }
        for d in 0..5 {
            for i in 0..9 {
                t.insert(format!("tree/dir{d}/leaf{i}"), b"v".to_vec());
                t.insert(format!("tree/dir{d}/sub/deep{i}"), b"v".to_vec());
            }
            t.insert(format!("tree/leaf{d}"), b"v".to_vec());
        }
        // A key equal to a listed prefix, and a key ending in '/'.
        t.insert("tree/".to_string(), b"v".to_vec());
        t.insert("tree/dir0/".to_string(), b"v".to_vec());
        // LIKE wildcards and the escape character, plus their impostors.
        for k in
            ["w/my_app/a", "w/my_app/b/c", "w/myXapp/a", "w/my%app/a", "w/myZZapp/a", r"w/my\app/a", r"w/my\\app/a"]
        {
            t.insert(k.to_string(), b"v".to_vec());
        }
        // Siblings sorting just around the `tree/` range.
        t.insert("tree".to_string(), b"v".to_vec());
        t.insert("tree.".to_string(), b"v".to_vec());
        t.insert("tree0".to_string(), b"v".to_vec());
        // Non-ASCII, including the surrogate-gap neighbour.
        t.insert("u/\u{D7FF}/x".to_string(), b"v".to_vec());
        t.insert("u/\u{E000}/y".to_string(), b"v".to_vec());
        t.insert("u/é".to_string(), b"v".to_vec());
        t
    }

    const TINY: PageLimits = PageLimits { max_rows: 3, max_bytes: 4 * PAGE_ROW_OVERHEAD_BYTES };

    #[test]
    fn upper_bound_is_the_exact_end_of_the_prefix_range() {
        assert_eq!(prefix_upper_bound(""), None);
        assert_eq!(prefix_upper_bound("a/").as_deref(), Some("a0"));
        assert_eq!(prefix_upper_bound("sys/access-audit/").as_deref(), Some("sys/access-audit0"));
        assert_eq!(prefix_upper_bound("a\u{D7FF}").as_deref(), Some("a\u{E000}"));
        assert_eq!(prefix_upper_bound("ab\u{10FFFF}").as_deref(), Some("ac"));
        assert_eq!(prefix_upper_bound("\u{10FFFF}\u{10FFFF}"), None);

        let keys: Vec<String> = fixture().into_keys().chain(["a".into(), "a\u{10FFFF}z".into(), "".into()]).collect();
        for prefix in ["", "tree/", "tree", "w/my_app/", "u/", "u/\u{D7FF}", "a", "zzz"] {
            let upper = prefix_upper_bound(prefix);
            for k in &keys {
                let in_range = k.as_str() >= prefix && upper.as_deref().map_or(true, |u| k.as_str() < u);
                assert_eq!(in_range, k.starts_with(prefix), "prefix {prefix:?} key {k:?}");
            }
        }
    }

    #[test]
    fn paged_list_matches_unpaged_list_across_many_pages() {
        let t = fixture();
        for prefix in [
            "",
            "log/",
            "tree/",
            "tree/dir0/",
            "tree/dir3/sub/",
            "w/",
            "w/my_app/",
            "w/my%app/",
            r"w/my\app/",
            "u/",
            "nothing/",
        ] {
            let (paged, pages) = paged_list(&t, prefix, TINY);
            assert_eq!(paged, reference_list(&t, prefix), "prefix {prefix:?}");
            let (default, _) = paged_list(&t, prefix, PageLimits::DEFAULT);
            assert_eq!(default, paged, "prefix {prefix:?}");
            if prefix == "log/" {
                assert!(pages > 10, "50 leaves at 3 rows per page must take many pages, took {pages}");
            }
        }
    }

    #[test]
    fn paged_list_skips_the_rest_of_a_child_directory() {
        let mut t = BTreeMap::new();
        for d in 0..3 {
            for i in 0..1_000 {
                t.insert(format!("big/d{d}/{i:05}"), b"v".to_vec());
            }
        }
        let limits = PageLimits { max_rows: 10, max_bytes: PAGE_MAX_BYTES };
        let (children, pages) = paged_list(&t, "big/", limits);
        assert_eq!(children, vec!["d0/", "d1/", "d2/"]);
        assert!(pages <= 4, "each directory should cost one page, took {pages}");
    }

    #[test]
    fn paged_scan_splits_on_the_byte_budget() {
        let mut t = fixture();
        // One value larger than the whole budget: it must travel alone.
        t.insert("log/99999999999999999999".to_string(), vec![b'L'; 10 * TINY.max_bytes as usize]);
        let limits = PageLimits { max_rows: 1_000, max_bytes: TINY.max_bytes };
        let (paged, pages) = paged_scan(&t, "log/", None, limits);
        assert_eq!(paged, reference_scan(&t, "log/", None));
        assert!(pages > 10, "the byte budget, not the row limit, must split this scan; took {pages} pages");

        // No page carries more than max(budget, its first row).
        let mut start = Some(PageStart::AtOrAfter("log/".to_string()));
        while let Some(s) = start.take() {
            let rows = model_page(&t, "log/", &s, limits, true);
            let data: Vec<&BackendEntry> = rows.iter().flatten().collect();
            let bytes: i64 = data.iter().map(|e| (e.key.len() + e.value.len()) as i64 + PAGE_ROW_OVERHEAD_BYTES).sum();
            assert!(data.len() == 1 || bytes <= limits.max_bytes, "page of {} rows carries {bytes} bytes", data.len());
            let mut pager = ScanPager::new("log/", None, limits);
            pager.next = Some(s);
            pager.accept(rows).unwrap();
            start = pager.next;
        }
    }

    #[test]
    fn paged_scan_honours_start_key_and_prefix() {
        let t = fixture();
        let cases: &[(&str, Option<&str>)] = &[
            ("log/", None),
            ("log/", Some("log/00000000000000000017")),
            ("log/", Some("log/000000000000000000175")), // between two keys
            ("log/", Some("a")),                         // below the prefix
            ("log/", Some("log0")),                      // above the range
            ("tree/", Some("tree/dir2/")),
            ("w/my_app/", None),
            ("w/my%app/", None),
            (r"w/my\app/", None),
            ("", None),
            ("", Some("tree/dir4/")),
            ("nothing/", None),
        ];
        for (prefix, start) in cases {
            for limits in [TINY, PageLimits { max_rows: 1, max_bytes: 1 }, PageLimits::DEFAULT] {
                let (paged, _) = paged_scan(&t, prefix, *start, limits);
                assert_eq!(paged, reference_scan(&t, prefix, *start), "prefix {prefix:?} start {start:?} {limits:?}");
            }
        }
    }

    #[test]
    fn malformed_pages_are_errors_not_truncations() {
        let limits = PageLimits::DEFAULT;
        assert!(split_page::<u8>(vec![None], limits).is_err(), "a marker needs a data row before it");
        assert!(split_page(vec![Some(1u8), None, Some(2)], limits).is_err(), "a marker must be last");
        assert!(split_page(vec![Some(1u8), None, None], limits).is_err());
        assert_eq!(split_page(vec![Some(1u8), None], limits).unwrap(), (vec![1], true));
        assert_eq!(split_page(vec![Some(1u8)], limits).unwrap(), (vec![1], false));
        assert_eq!(split_page::<u8>(vec![], limits).unwrap(), (vec![], false));
        let full = PageLimits { max_rows: 2, max_bytes: PAGE_MAX_BYTES };
        assert_eq!(split_page(vec![Some(1u8), Some(2)], full).unwrap(), (vec![1, 2], true));
    }
}
