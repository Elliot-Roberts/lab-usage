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

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum Action {
    LogOn,
    LogOff,
}
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

fn read_from_paths(paths: &[PathBuf]) -> Result<Vec<(OsString, Vec<Event>)>> {
    let mut data = Vec::with_capacity(paths.len());
    for path in paths {
        let name = path
            .file_stem()
            .ok_or_else(|| eyre!("file path {path:?} has no stem"))?
            .to_owned();
        let mut events = Vec::new();
        for (i, line) in BufReader::new(File::open(path)?).lines().enumerate() {
            let line = line?;
            let mut array_chunks = line.split(',').array_chunks();
            let Some(rec) = array_chunks.next() else {
                if !line.trim().is_empty() {
                    eprintln!("line {i} in {path:?} has too few fields: {line}");
                }
                continue;
            };
            let [user, action, _host, _ip, time, _domain] = rec;
            if time.len() != 12 {
                eprintln!("malformed datetime on line {i} in {path:?}: {time}");
            }
            let year = time[..4].parse()?;
            let month: u8 = time[4..6].parse()?;
            let day = time[6..8].parse()?;
            let hour = time[8..10].parse()?;
            let minute = time[10..12].parse()?;
            let time = PrimitiveDateTime::new(
                Date::from_calendar_date(year, month.try_into()?, day)?,
                Time::from_hms(hour, minute, 0)?,
            );
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
        data.push((name, events));
    }
    Ok(data)
}

#[derive(Debug, Clone, Copy)]
struct ValidSessionTime {
    start: PrimitiveDateTime,
    duration: Duration,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy)]
enum SessionTime {
    Valid(ValidSessionTime),
    UnknownStart {
        preceded_by: PrimitiveDateTime,
        end: PrimitiveDateTime,
    },
    UnknownEnd {
        start: PrimitiveDateTime,
        followed_by: PrimitiveDateTime,
    },
    TimeMachine {
        entrance: PrimitiveDateTime,
        exit: PrimitiveDateTime,
    },
}

#[derive(Debug, Clone, Copy)]
enum OrderCorrectness {
    InOrder,
    OutOfOrder,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy)]
struct Session<'u> {
    time: SessionTime,
    user: &'u str,
}

enum CleaningState<'u> {
    InUse {
        start_order: OrderCorrectness,
        user: &'u str,
        start: PrimitiveDateTime,
    },
    Unused,
}

fn sessionize<'u>(events: &'u [Event]) -> Vec<(Session<'u>, OrderCorrectness)> {
    use CleaningState::*;
    use OrderCorrectness::*;
    use SessionTime::*;
    let mut sessions = Vec::with_capacity(events.len() / 2);
    let mut state = Unused;
    let mut now = PrimitiveDateTime::MIN;
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
                                entrance: start,
                                exit: event.time,
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

enum OverlapState {
    Before,
    During,
}

struct HostTimelineCursor<It: Iterator<Item = ValidSessionTime>> {
    current: ValidSessionTime,
    end: PrimitiveDateTime,
    state: OverlapState,
    rest: It,
}

impl<It: Iterator<Item = ValidSessionTime>> PartialEq for HostTimelineCursor<It> {
    fn eq(&self, other: &Self) -> bool {
        self.next_transition() == other.next_transition()
    }
}

impl<It: Iterator<Item = ValidSessionTime>> Eq for HostTimelineCursor<It> {}

impl<It: Iterator<Item = ValidSessionTime>> PartialOrd for HostTimelineCursor<It> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.next_transition().partial_cmp(&other.next_transition())
    }
}

impl<It: Iterator<Item = ValidSessionTime>> Ord for HostTimelineCursor<It> {
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

    fn advance(self) -> Option<Self> {
        match self.state {
            OverlapState::Before => Some(Self {
                state: OverlapState::During,
                ..self
            }),
            OverlapState::During => Self::new(self.rest),
        }
    }

    fn next_transition(&self) -> PrimitiveDateTime {
        match self.state {
            OverlapState::Before => self.current.start,
            OverlapState::During => self.end,
        }
    }
}

fn overlaps(cleaned: &[(OsString, Vec<ValidSessionTime>)]) -> Vec<(PrimitiveDateTime, usize)> {
    let num_sessions: usize = cleaned.iter().map(|(_, v)| v.len()).sum();
    let mut changes = Vec::with_capacity(num_sessions * 2);
    let mut count = 0_usize;
    let mut fronts = cleaned
        .iter()
        .filter_map(|(_, ss)| HostTimelineCursor::new(ss.iter().cloned()).map(cmp::Reverse))
        .collect::<BinaryHeap<_>>();
    loop {
        let Some(up_next) = fronts.pop() else {
            break;
        };
        match up_next.0.state {
            OverlapState::Before => count += 1,
            OverlapState::During => count -= 1,
        }
        changes.push((up_next.0.next_transition(), count));
        if let Some(next) = up_next.0.advance() {
            fronts.push(cmp::Reverse(next));
        }
    }
    changes
}

fn bucketize(
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

fn go(paths: &[PathBuf]) -> Result<()> {
    let cleaned = read_from_paths(&paths)?
        .into_iter()
        .map(|(name, list)| {
            (
                name,
                sessionize(&list)
                    .into_iter()
                    .filter_map(|sess| {
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
