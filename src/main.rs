#![feature(iter_array_chunks)]
#![feature(iter_map_windows)]
use color_eyre::{
    eyre::{bail, eyre},
    Result,
};
use itertools::Itertools;
use std::{
    cmp,
    collections::BinaryHeap,
    ffi::OsString,
    fmt::Display,
    fs::File,
    io::{BufRead, BufReader},
    iter::once,
    path::PathBuf,
    time::Duration,
};
use time::{format_description::well_known::Iso8601, Date, PrimitiveDateTime, Time};

/// Relevant action a user might take on a host
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum Action {
    LogOn,
    LogOff,
}
/// Logged event of a user taking an action at a time and date
#[derive(Debug, Clone)]
struct Event {
    time: time::PrimitiveDateTime,
    user: String,
    action: Action,
}

impl Display for Event {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!(
            "{}, {}, {:?}",
            self.time, self.user, self.action
        ))
    }
}

/// Parse time as written in these log files, YYYYMMDDhhmm
fn parse_time(time: &str) -> Result<PrimitiveDateTime> {
    let year = time[..4].parse()?;
    let month: u8 = time[4..6].parse()?;
    let day = time[6..8].parse()?;
    let hour = time[8..10].parse()?;
    let minute = time[10..12].parse()?;
    let time = PrimitiveDateTime::new(
        Date::from_calendar_date(year, month.try_into()?, day)?,
        Time::from_hms(hour, minute, 0)?,
    );
    Ok(time)
}

/// For each path, parse all the logged events and output alongside the filename stem
fn read_from_paths(paths: &[PathBuf]) -> Result<Vec<(OsString, Vec<Event>)>> {
    let mut names_and_events = Vec::with_capacity(paths.len());
    for path in paths {
        let name_stem = path
            .file_stem()
            .ok_or_else(|| eyre!("file path {path:?} has no stem"))?
            .to_owned();
        let mut events = Vec::new();
        for (i, line) in BufReader::new(File::open(path)?).lines().enumerate() {
            let line = line?;
            let mut array_chunks = line.split(',').array_chunks::<6>();
            let Some(record) = array_chunks.next() else {
                // line had fewer than 6 comma separated fields
                if line.trim().is_empty() {
                    // ignore empty lines
                } else {
                    eprintln!("line {i} in {path:?} has too few fields: {line}");
                }
                continue;
            };
            let [user, action, _host, _ip, time, _domain] = record;
            if time.len() != 12 {
                eprintln!("malformed datetime on line {i} in {path:?}: {time}");
            }
            let time = parse_time(time)?;
            let action = match action {
                "on" => Action::LogOn,
                "off" => Action::LogOff,
                _ => bail!("invalid action field '{action}' in file {path:?}"),
            };
            events.push(Event {
                time,
                user: user.to_string(),
                action,
            });
        }
        names_and_events.push((name_stem, events));
    }
    Ok(names_and_events)
}

/// A well-formed user session with no missing events or time travel.
#[derive(Debug, Clone, Copy)]
struct ValidSessionTime {
    start: PrimitiveDateTime,
    duration: Duration,
}

/// A user session on a host, potentially malformed or missing start or end
#[allow(dead_code)]
#[derive(Debug, Clone, Copy)]
enum SessionTime {
    /// Start and end are logged, with start before end
    Valid(ValidSessionTime),
    /// Only an end event was logged for this session.
    /// The preceding event provides a lower bound for the start time.
    UnknownStart {
        preceded_by: PrimitiveDateTime,
        end: PrimitiveDateTime,
    },
    /// Only a start event was logged for this session.
    /// The following event provides an upper bound for the end time.
    UnknownEnd {
        start: PrimitiveDateTime,
        followed_by: PrimitiveDateTime,
    },
    /// The log-off for this session was recorded as happening at a point in time
    /// earlier than the recorded log-on time.
    TimeMachine {
        log_on: PrimitiveDateTime,
        log_off: PrimitiveDateTime,
    },
}

/// Whether a session appears in the log file in the correct order in time.
/// That is, while processing the log file from top to bottom, if this session
/// has log on and off times newer than all logs above it in the file, then it is
/// considered in-order, otherwise it is out-of-order because a "newer" (later in time)
/// session was encountered "earlier" (at smaller line number) in the file.
#[derive(Debug, Clone, Copy)]
enum OrderCorrectness {
    InOrder,
    OutOfOrder,
}

/// A period of time a user spent logged onto on a host
#[allow(dead_code)]
#[derive(Debug, Clone, Copy)]
struct Session<'u> {
    time: SessionTime,
    user: &'u str,
}

/// State kept while processing log events for a host into sessions.
enum CleaningState<'u> {
    /// Host is in use (most recent event was a log-on)
    InUse {
        /// Was the login event timestamp the newest timestamp so far?
        start_order: OrderCorrectness,
        /// User associated with login event
        user: &'u str,
        /// Timestamp associated with login event
        start: PrimitiveDateTime,
    },
    /// Host is not in use (most recent event was a log-off, or initial state)
    Unused,
}

/// Process list of log on and off events into list of user sessions, noting
/// order correctness.
fn sessionize(events: &[Event]) -> Vec<(Session<'_>, OrderCorrectness)> {
    use CleaningState::*;
    use OrderCorrectness::*;
    use SessionTime::*;
    // should be about half as many sessions as log events
    let mut sessions = Vec::with_capacity(events.len() / 2);
    // will assume that hosts are unused before the events in the log file
    let mut state = Unused;
    // the newest time witnessed so far
    let mut now = PrimitiveDateTime::MIN;
    // time of the previous event in the file, equal to `now` when events are in order
    let mut prev_time = PrimitiveDateTime::MIN;
    for event in events {
        let currentness = if event.time >= now {
            InOrder
        } else {
            OutOfOrder
        };
        match event.action {
            Action::LogOn => {
                if let InUse {
                    user,
                    start,
                    start_order,
                } = state
                {
                    // double log-in
                    sessions.push((
                        // first session, missing end
                        Session {
                            time: UnknownEnd {
                                start,
                                followed_by: event.time,
                            },
                            user,
                        },
                        start_order,
                    ));
                } else {
                    // normal log-in, nothing special to do
                }
                // start of new session
                state = InUse {
                    user: &event.user,
                    start: event.time,
                    start_order: currentness,
                }
            }
            Action::LogOff => {
                if let InUse {
                    user,
                    start,
                    start_order,
                } = state
                {
                    if event.user == user {
                        let time = if let Ok(duration) = (event.time - start).try_into() {
                            // normal log-off
                            Valid(ValidSessionTime { start, duration })
                        } else {
                            // log-off is chronologically before log-in
                            TimeMachine {
                                log_on: start,
                                log_off: event.time,
                            }
                        };
                        sessions.push((Session { time, user }, start_order));
                    } else {
                        // log-off of different user from last known
                        sessions.push((
                            Session {
                                // session for last known user
                                time: UnknownEnd {
                                    start,
                                    followed_by: event.time,
                                },
                                user,
                            },
                            currentness,
                        ));
                        sessions.push((
                            Session {
                                // session for new user
                                time: UnknownStart {
                                    preceded_by: prev_time,
                                    end: event.time,
                                },
                                user: &event.user,
                            },
                            currentness,
                        ));
                    }
                } else {
                    // double log-off (missed log-on?)
                    sessions.push((
                        Session {
                            time: UnknownStart {
                                preceded_by: prev_time,
                                end: event.time,
                            },
                            user: &event.user,
                        },
                        currentness,
                    ));
                }
                state = Unused;
            }
        }

        now = Ord::max(now, event.time);
        prev_time = event.time;
    }
    sessions
}

/// Here, we are in a sense turning our processed sessions back into log-on and
/// log-off events for counting concurrent users of a collection of hosts.
/// Processing into 'sessions' was useful for filtering, but now we need to consider
/// each event in order from a collection of sources.
/// For each host in the collection, we maintain a "cursor" into the conceptual timeline
/// of events from it. `next_transition()` yields the time of the next event, and
/// `advance()` moves the cursor forward one event.
/// The cursor `state` member keeps track of whether the cursor is 'before' the
/// `current` session, (meaning the next event is the log-on for `current`) or 'during'
/// the `current` session, (meaning the next event is the log-off for `current`).
struct HostTimelineCursor<It: Iterator<Item = ValidSessionTime>> {
    current: ValidSessionTime,
    /// just caching calculation of the end time
    end: PrimitiveDateTime,
    state: OverlapState,
    /// remaining future sessions
    rest: It,
}

/// Is the cursor before or during the current session?
/// That is, is the next event a log-on or a log-off?
enum OverlapState {
    Before,
    During,
}

/// Allow two cursors to be compared for equality.
impl<It: Iterator<Item = ValidSessionTime>> PartialEq for HostTimelineCursor<It> {
    /// Cursors are equal if their next events will be simultaneous.
    fn eq(&self, other: &Self) -> bool {
        self.next_transition() == other.next_transition()
    }
}

/// Equality of times is an equivalence relation.
impl<It: Iterator<Item = ValidSessionTime>> Eq for HostTimelineCursor<It> {}

/// Required for implementing `Ord`
impl<It: Iterator<Item = ValidSessionTime>> PartialOrd for HostTimelineCursor<It> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// Allow cursors to be compared for ordering.
impl<It: Iterator<Item = ValidSessionTime>> Ord for HostTimelineCursor<It> {
    /// Cursors are ordered by ordering their next events.
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.next_transition().cmp(&other.next_transition())
    }
}

impl<It: Iterator<Item = ValidSessionTime>> HostTimelineCursor<It> {
    fn new(mut it: It) -> Option<Self> {
        let current = it.next()?;
        Some(Self {
            current,
            end: current.start + current.duration,
            state: OverlapState::Before,
            rest: it,
        })
    }

    /// Move the cursor forward one event.
    fn advance(self) -> Option<Self> {
        match self.state {
            OverlapState::Before => Some(Self {
                state: OverlapState::During,
                ..self
            }),
            OverlapState::During => Self::new(self.rest),
        }
    }

    /// Get the time of the next event.
    fn next_transition(&self) -> PrimitiveDateTime {
        match self.state {
            OverlapState::Before => self.current.start,
            OverlapState::During => self.end,
        }
    }
}

type CountInstant = (PrimitiveDateTime, usize);

/// For the given collection of hosts, count the number of concurrent sessions,
/// recording the value and timestamp each time it changes. This is in some sense
/// looking at the 'overlaps' of sessions.
fn overlaps(hosts_sessions: &[(OsString, Vec<ValidSessionTime>)]) -> Vec<CountInstant> {
    let total_sessions: usize = hosts_sessions.iter().map(|(_, v)| v.len()).sum();
    // usage count should change exactly twice for each session.
    // record of changes
    let mut changes = Vec::with_capacity(total_sessions * 2);
    // running count of concurrent users
    let mut count = 0_usize;
    // heap of cursors, ordered by oldest un-processed event
    let mut fronts = hosts_sessions
        .iter()
        // we wrap the cursors in a std::cmp::Reverse because the std::collections::BinaryHeap
        // is a max heap, and we want to pop the cursor with the oldest next event.
        .filter_map(|(_, ss)| HostTimelineCursor::new(ss.iter().cloned()).map(cmp::Reverse))
        .collect::<BinaryHeap<_>>();
    loop {
        let Some(up_next) = fronts.pop() else {
            break;
        };
        match up_next.0.state {
            // state was off, so this event is a log-on
            OverlapState::Before => count += 1,
            // state was on, so this event is a log-off
            OverlapState::During => count -= 1,
        }
        // record time of transition, and new count
        changes.push((up_next.0.next_transition(), count));
        // re-insert cursor into heap if it is not finished
        if let Some(next) = up_next.0.advance() {
            fronts.push(cmp::Reverse(next));
        }
    }
    changes
}

/// Compute average user count for each chunk (or 'bucket') of time of
/// a given length. For example, the average number of users each hour.
pub fn bucketize<'a, T>(
    changes: &'a [CountInstant],
    bucket_size: Duration,
    start: PrimitiveDateTime,
    mut combine_operation: impl FnMut(Duration, CountInstant, &'a [CountInstant]) -> T,
) -> Vec<(PrimitiveDateTime, T)> {
    let end = changes.last().unwrap().0;
    let full_duration = end - start;
    let buckets = (full_duration / bucket_size).ceil() as usize;
    let mut bucketized = Vec::with_capacity(buckets);
    let mut current_bucket_start = start;
    let mut current_bucket_end = current_bucket_start + bucket_size;
    let mut value_before_current_bucket_start = 0;
    let mut most_recent_value = 0;
    let mut change_slice = changes;
    let mut current_bucket_changes = 0;
    while let Some(next_change) = change_slice.get(current_bucket_changes) {
        if next_change.0 < current_bucket_end {
            most_recent_value = next_change.1;
            current_bucket_changes += 1;
        } else {
            let (current_bucket_change_slice, future_changes) =
                change_slice.split_at(current_bucket_changes);

            let combined = combine_operation(
                bucket_size,
                (current_bucket_start, value_before_current_bucket_start),
                current_bucket_change_slice,
            );
            bucketized.push((current_bucket_start, combined));

            current_bucket_start = current_bucket_end;
            current_bucket_end += bucket_size;
            value_before_current_bucket_start = most_recent_value;
            change_slice = future_changes;
            current_bucket_changes = 0;
        }
    }
    bucketized
}

fn combine_and_display<T: Display + PartialEq, Combiner: ChunkCombiner<T>>(
    values: &[CountInstant],
    args: Args,
) {
    let start_date = args.start_date.unwrap_or_else(|| values[0].0.date());
    let start = PrimitiveDateTime::new(start_date, Time::MIDNIGHT);
    let bucket_size = args.granularity.into();
    let values = bucketize(values, bucket_size, start, Combiner::combine);
    values
        .into_iter()
        .dedup_by(|a, b| args.filter_repeats && a.1 == b.1)
        .for_each(|(time, count)| {
            let date = time.date();
            let hour = time.time().hour();
            let minute = time.time().minute();
            println!("{date} {hour:02}:{minute:02}, {count}")
        });
}
/// Combine all the above functionality to perform the specific filtering we want
/// on the provided set of paths, printing the result to standard output.
fn go(args: Args) -> Result<()> {
    let mut cleaned = read_from_paths(&args.paths)?;
    if let Some(start_date) = args.start_date {
        cleaned
            .iter_mut()
            .for_each(|(_, ref mut list)| list.retain(|e| e.time.date() >= start_date));
    };
    let cleaned: Vec<_> = if args.multi_user {
        cleaned
            .into_iter()
            .flat_map(|(name, list)| {
                let group_map = list
                    .into_iter()
                    .into_group_map_by(|event| event.user.clone()); // TODO: don't clone here
                group_map.into_iter().map(move |(username, events)| {
                    let mut new_name = OsString::with_capacity(name.len() + 1 + username.len());
                    new_name.push(&name);
                    new_name.push("-");
                    new_name.push(username);
                    (new_name, events)
                })
            })
            .collect()
    } else {
        cleaned
    };
    let cleaned = cleaned
        .into_iter()
        .map(|(name, list)| {
            let sessions = sessionize(&list)
                .into_iter()
                .filter_map(|sess| {
                    // keep only sessions with 'valid' times, that appear
                    // in correct time order in the log file, and that
                    // are longer than the minimum duration, and shorter
                    // than the maximum.
                    if let (
                        Session {
                            time: SessionTime::Valid(valid),
                            ..
                        },
                        OrderCorrectness::InOrder,
                    ) = sess
                    {
                        if valid.duration < *args.min_duration {
                            return None;
                        }
                        if valid.duration > *args.max_duration {
                            return None;
                        }
                        Some(valid)
                    } else {
                        if args.show_weird {
                            eprintln!("{name:?}: {sess:?}");
                        }
                        None
                    }
                })
                .collect::<Vec<_>>();
            (name, sessions)
        })
        .collect::<Vec<_>>();

    let values = overlaps(&cleaned);
    match &args.combine {
        CombiningOperationKind::Max => combine_and_display::<usize, MaxCombiner>(&values, args),
        CombiningOperationKind::Min => combine_and_display::<usize, MinCombiner>(&values, args),
        CombiningOperationKind::Avg => combine_and_display::<f32, AverageCombiner>(&values, args),
    }
    Ok(())
}

use clap::{Parser, ValueEnum};

#[derive(Debug, Clone, ValueEnum)]
enum CombiningOperationKind {
    /// take the maximum value observed within the chunk of time
    Max,
    /// take the minimum value observed within the chunk of time
    Min,
    /// compute the duration-weighted average value for the chunk of time
    Avg,
}

trait ChunkCombiner<T> {
    fn combine(bucket_size: Duration, initial: CountInstant, changes: &[CountInstant]) -> T;
}

trait PureReducer<A, B> {
    fn single(a: A) -> B;
    fn reduce(acc: B, next: A) -> B;
}

struct MinCombiner;
impl PureReducer<CountInstant, usize> for MinCombiner {
    fn reduce(acc: usize, (_, next): CountInstant) -> usize {
        cmp::min(acc, next)
    }

    fn single((_, value): CountInstant) -> usize {
        value
    }
}
struct MaxCombiner;
impl PureReducer<CountInstant, usize> for MaxCombiner {
    fn reduce(acc: usize, (_, next): CountInstant) -> usize {
        cmp::max(acc, next)
    }

    fn single((_, value): CountInstant) -> usize {
        value
    }
}
impl<T, Reducer: PureReducer<CountInstant, T>> ChunkCombiner<T> for Reducer {
    fn combine(
        _d: Duration,
        initial @ (bucket_start, _): CountInstant,
        changes: &[CountInstant],
    ) -> T {
        if let Some((first @ (first_change_time, _), following_changes)) = changes.split_first() {
            let (initial, rest) = if *first_change_time == bucket_start {
                (*first, following_changes)
            } else {
                (initial, changes)
            };
            rest.iter()
                .cloned()
                .fold(Self::single(initial), Self::reduce)
        } else {
            Self::single(initial)
        }
    }
}

struct AverageCombiner;
impl ChunkCombiner<f32> for AverageCombiner {
    fn combine(bucket_size: Duration, initial: CountInstant, changes: &[CountInstant]) -> f32 {
        let sum_user_seconds: usize = once(&initial)
            .chain(changes)
            .chain(once(&(initial.0 + bucket_size, 0)))
            .map_windows(|[(start_time, start_val), (end_time, _)]| {
                ((*end_time - *start_time).unsigned_abs(), start_val)
            })
            .map(|(duration, users)| duration.as_secs() as usize * users)
            .sum();
        sum_user_seconds as f32 / bucket_size.as_secs_f32()
    }
}

#[derive(Debug, Parser)]
struct Args {
    /// time granularity of output
    #[arg(short, long, default_value = "30m")]
    granularity: humantime::Duration,

    /// how to combine values within each chunk of time
    #[arg(short, long, default_value = "max")]
    combine: CombiningOperationKind,

    /// ISO8601 date (YYYY-MM-DD) to begin processing from, by default the first day mentioned in the provided logs
    #[arg(short, long, value_parser = |s: &_| Date::parse(s, &Iso8601::PARSING))]
    start_date: Option<Date>,

    /// output only the first of consecutive identical values
    #[arg(short, long)]
    filter_repeats: bool,

    /// count concurrent user sessions on individual machines
    #[arg(short, long)]
    multi_user: bool,

    /// the paths from which to pull logs
    #[arg(required = true)]
    paths: Vec<PathBuf>,

    /// sessions with durations shorter than this will be filtered out
    #[arg(long, default_value = "1m")]
    min_duration: humantime::Duration,

    /// sessions with durations longer than this will be filtered out
    #[arg(long, default_value = "1d")]
    max_duration: humantime::Duration,

    /// log to stderr all the sessions with missing starts/ends and timetravels
    #[arg(long)]
    show_weird: bool,
}

fn main() -> Result<()> {
    let args = Args::parse();
    go(args)
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use color_eyre::Result;
    use glob::glob;

    use crate::*;
    #[test]
    fn fab() -> Result<()> {
        let args = Args {
            paths: glob("machine/FAB??.csv")?
                .into_iter()
                .collect::<Result<Vec<PathBuf>, _>>()?,
            granularity: humantime::Duration::from_str("1m")?,
            combine: CombiningOperationKind::Max,
            start_date: None,
            filter_repeats: true,
            multi_user: true,
            min_duration: humantime::Duration::from_str("1m")?,
            max_duration: humantime::Duration::from_str("1d")?,
            show_weird: false,
        };

        go(args)
    }
}
