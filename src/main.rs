#![feature(iterator_try_collect)]
#![feature(iter_array_chunks)]
use color_eyre::{
    eyre::{bail, eyre},
    Result,
};
use std::{
    cmp,
    collections::BinaryHeap,
    env,
    ffi::OsString,
    fmt::Display,
    fs::File,
    io::{BufRead, BufReader},
    path::PathBuf,
    time::Duration,
};
use time::{Date, PrimitiveDateTime, Time};

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
    /// The log-off for this session was recorded as happening at point in time
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
fn sessionize<'u>(events: &'u [Event]) -> Vec<(Session<'u>, OrderCorrectness)> {
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
        self.next_transition().partial_cmp(&other.next_transition())
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

/// For the given collection of hosts, count the number of concurrent sessions,
/// recording the value and timestamp each time it changes. This is in some sense
/// looking at the 'overlaps' of sessions.
fn overlaps(
    hosts_sessions: &[(OsString, Vec<ValidSessionTime>)],
) -> Vec<(PrimitiveDateTime, usize)> {
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
pub fn bucketize(
    changes: &[(PrimitiveDateTime, usize)],
    bucket_size: Duration,
    start: PrimitiveDateTime,
) -> Vec<(PrimitiveDateTime, f64)> {
    let end = changes.last().unwrap().0;
    let full_duration = end - start;
    let buckets = (full_duration / bucket_size).ceil() as usize;
    let mut bucketized = Vec::with_capacity(buckets);
    let mut bucket_start = start;
    let mut bucket_end = bucket_start + bucket_size;
    let mut prev_change = (PrimitiveDateTime::MIN, 0_usize);
    let mut sum = 0_f64;
    for change in changes {
        while bucket_end <= change.0 {
            let chunk_start = PrimitiveDateTime::max(bucket_start, prev_change.0);
            let chunk_size = bucket_end - chunk_start;
            sum += (chunk_size * prev_change.1 as u32) / bucket_size;
            bucketized.push((bucket_start, sum));
            sum = 0_f64;
            bucket_start = bucket_end;
            bucket_end += bucket_size;
        }
        let chunk_start = PrimitiveDateTime::max(bucket_start, prev_change.0);
        let chunk_size = change.0 - chunk_start;
        sum += (chunk_size * prev_change.1 as u32) / bucket_size;
        prev_change = *change;
    }
    bucketized
}

// 1 day
const MAX_VALID_DURATION: Duration = Duration::from_secs(60 * 60 * 24);
// 1 min
const MIN_VALID_DURATION: Duration = Duration::from_secs(60);

/// Combine all the above functionality to perform the specific filtering we want
/// on the provided set of paths, printing the result to standard output.
fn go(paths: &[PathBuf]) -> Result<()> {
    let cleaned = read_from_paths(&paths)?
        .into_iter()
        .map(|(name, list)| {
            (
                name,
                sessionize(&list)
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
                            if valid.duration < MIN_VALID_DURATION {
                                return None;
                            }
                            if valid.duration > MAX_VALID_DURATION {
                                return None;
                            }
                            Some(valid)
                        } else {
                            None
                        }
                    })
                    .collect::<Vec<_>>(),
            )
        })
        .collect::<Vec<_>>();

    let changes = overlaps(&cleaned);
    // let changes = bucketize(
    //     &changes,
    //     Duration::from_secs(60 * 60),
    //     changes[0].0.replace_time(Time::MIDNIGHT),
    // );
    for (time, count) in changes {
        let date = time.date();
        let hour = time.time().hour();
        let minute = time.time().minute();
        println!("{date} {hour:02}:{minute:02}, {count}",)
    }
    Ok(())
}

fn main() -> Result<()> {
    let paths: Vec<_> = env::args().map(Into::into).skip(1).collect();
    go(&paths)
}

#[cfg(test)]
mod tests {
    use color_eyre::Result;
    use glob::glob;

    use crate::go;
    #[test]
    fn fab() -> Result<()> {
        let paths: Vec<_> = glob("machine/FAB??.csv")?.into_iter().try_collect()?;
        go(&paths)
    }
}
