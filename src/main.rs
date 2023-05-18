#![feature(iterator_try_collect)]
use color_eyre::{
    eyre::{bail, eyre, Context},
    Result,
};
use std::{env, ffi::OsString, fmt::Display, path::PathBuf, time::Duration};
use time::{macros::datetime, PrimitiveDateTime};

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
    let datetime_format =
        time::macros::format_description!("[year][month][day][hour repr:24][minute]");
    for path in paths {
        let name = path
            .file_stem()
            .ok_or_else(|| eyre!("file path {path:?} has no stem"))?
            .to_owned();
        let mut events = Vec::new();
        for rec in csv::Reader::from_path(path)
            .wrap_err_with(|| eyre!("failed to read csv from path {path:?}"))?
            .into_deserialize()
        {
            let rec = match rec.wrap_err_with(|| eyre!("bad csv record in {path:?}")) {
                Ok(rec) => rec,
                Err(e) => {
                    eprintln!("{e:?}");
                    continue;
                }
            };
            let [user, action, _host, _ip, time, _domain]: [String; 6] = rec;
            let time = time::PrimitiveDateTime::parse(&time, datetime_format)?;
            let action = match action.as_str() {
                "on" => Action::LogOn,
                "off" => Action::LogOff,
                _ => bail!("invalid action field '{action}' in file {path:?}"),
            };
            events.push(Event { time, user, action });
        }
        data.push((name, events));
    }
    Ok(data)
}

#[derive(Debug, Clone, Copy)]
struct Session {
    delay: std::time::Duration,
    duration: std::time::Duration,
}

enum CleaningState<'u> {
    InUse {
        user: &'u str,
        delay: std::time::Duration,
    },
    Unused(std::time::Duration),
}

// before I was born at least :P
const THE_BEGINNING: PrimitiveDateTime = datetime!(2000-01-01 0:00);

fn clean(events: &[Event]) -> Vec<Session> {
    use CleaningState::*;
    let mut sessions = Vec::with_capacity(events.len() / 2);
    let mut prev_time = THE_BEGINNING;
    let mut state = Unused(std::time::Duration::ZERO);
    for event in events {
        // let since_last: std::time::Duration = (event.time - prev_time)
        //     .try_into()
        //     .wrap_err_with(|| eyre!("event is nonchronological: {event:?}"))?;
        let Ok(since_last) = (event.time - prev_time).try_into() else {
            eprintln!("bad time: {event:?}");
            continue
        };
        prev_time = event.time;
        state = match (state, event.action) {
            (InUse { delay, .. }, Action::LogOn) => {
                // double log-on. throw away first login
                InUse {
                    user: &event.user,
                    delay: delay + since_last,
                }
            }
            (InUse { user, delay }, Action::LogOff) => {
                if event.user == user {
                    // normal log off
                    sessions.push(Session {
                        delay,
                        duration: since_last,
                    });
                    Unused(std::time::Duration::ZERO)
                } else {
                    // missed log off and missed log on (is this possible?)
                    Unused(delay + since_last)
                }
            }
            (Unused(duration), Action::LogOn) => {
                // normal log on
                InUse {
                    user: &event.user,
                    delay: duration + since_last,
                }
            }
            (Unused(duration), Action::LogOff) => {
                // double log off
                Unused(duration + since_last)
            }
        };
    }
    sessions
}

// fn intervals(cleaned: &[(OsString, Vec<Session>)]) -> Vec<Interval<u64, &OsStr>> {
//     let mut now = Duration::ZERO;
//     cleaned
//         .into_iter()
//         .flat_map(|(name, sessions)| sessions.into_iter().map(|s| (name.as_os_str(), s)))
//         .map(|(name, s)| {
//             let start = now + s.delay;
//             let stop = start + s.duration;
//             now = stop;
//             Interval {
//                 start: start.as_secs(),
//                 stop: stop.as_secs(),
//                 val: name,
//             }
//         })
//         .collect()
// }

enum OverlapState {
    Before,
    During,
}

fn overlaps(cleaned: &[(OsString, Vec<Session>)]) -> Vec<(Duration, usize)> {
    let num_sessions: usize = cleaned.iter().map(|(_, v)| v.len()).sum();
    let mut changes = Vec::with_capacity(num_sessions * 2);
    let mut count = 0_usize;
    let mut now = Duration::ZERO;
    let mut fronts = cleaned
        .iter()
        .map(|(_n, v)| {
            (
                OverlapState::Before,
                Duration::ZERO,
                v.iter().fuse().peekable(),
            )
        })
        .collect::<Vec<_>>();
    loop {
        let up_next = fronts
            .iter_mut()
            .filter_map(|(state, cur, it)| {
                let Some(&s) = it.peek() else {
                    return None;
                };
                let time_since = now.checked_sub(*cur).expect("now fell behind");
                let until_end = match state {
                    OverlapState::Before => s.delay,
                    OverlapState::During => s.duration,
                }
                .checked_sub(time_since)
                .expect("advanced now past the end of a session");
                Some((it, s, state, cur, until_end))
            })
            .min_by_key(|(_, _, _, _, until_end)| *until_end);
        let Some((it, s, state, cur, timestep)) = up_next else {
            break;
        };
        (*state, *cur, count) = match state {
            OverlapState::Before => (OverlapState::During, *cur + s.delay, count + 1),
            OverlapState::During => {
                it.next();
                (OverlapState::Before, *cur + s.duration, count - 1)
            }
        };
        now += timestep;
        changes.push((timestep, count));
    }
    changes
}

fn go(paths: &[PathBuf]) -> Result<()> {
    let cleaned: Vec<_> = read_from_paths(&paths)?
        .into_iter()
        .inspect(|(name, _)| eprintln!("{name:?}"))
        .map(|(name, list)| (name, clean(&list)))
        .collect();
    let mut now = THE_BEGINNING;
    for (timestep, count) in overlaps(&cleaned) {
        now += timestep;
        println!(
            "{} {:02}:{:02}, {count}",
            now.date(),
            now.time().hour(),
            now.time().minute()
        )
    }
    // dbg!(&cleaned[0].1);
    // let tree = Lapper::new(intervals(&cleaned));
    // tree.merge_overlaps();
    // tree.depth()
    //     .inspect(|_| print!("."))
    //     .filter(|d| d.val > 1)
    //     .for_each(|d| {
    //         println!(
    //             "{:?} - {:?} : {}",
    //             THE_BEGINNING + Duration::from_secs(d.start),
    //             THE_BEGINNING + Duration::from_secs(d.stop),
    //             d.val
    //         );
    //     });
    // dbg!(tree.len());

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
    use time::PrimitiveDateTime;

    use crate::{go, read_from_paths, Action, Event, THE_BEGINNING};
    #[test]
    fn fab() -> Result<()> {
        let paths: Vec<_> = glob("machine/FAB??.csv")?.into_iter().try_collect()?;
        go(&paths)
    }

    #[test]
    fn time_travels() -> Result<()> {
        let paths: Vec<_> = glob("machine/*.csv")?.into_iter().try_collect()?;
        read_from_paths(&paths)?
            .into_iter()
            .map(|(name, list)| (name, find_time_travels(&list)))
            .filter(|(_, list)| !list.is_empty())
            .for_each(|(name, list)| {
                println!("\n{}", name.to_string_lossy());
                for (i, tt) in list.into_iter().enumerate() {
                    print!("{i}");
                    println!("\t   before: {}", tt.before);
                    println!("\t    after: {}", tt.after);
                    println!("\t  skipped:");
                    for e in tt.skipped {
                        println!("\t\t{}", e);
                    }
                    println!("\tfollowing: {}", tt.following);
                    println!()
                }
            });
        Ok(())
    }

    #[derive(Debug)]
    struct TimeTravel {
        before: Event,
        after: Event,
        skipped: Vec<Event>,
        following: Event,
    }

    fn find_time_travels(events: &[Event]) -> Vec<TimeTravel> {
        let mut x = Vec::new();
        let mut prev = &Event {
            time: THE_BEGINNING,
            user: String::new(),
            action: Action::LogOff,
        };
        let mut current: Option<TimeTravel> = None;
        for e in events {
            (prev, current) = match (prev.time <= e.time, current) {
                (true, None) => {
                    // normal
                    (e, None)
                }
                (true, Some(mut tt)) => {
                    // ending
                    tt.following = e.clone();
                    x.push(tt);
                    (e, None)
                }
                (false, None) => (
                    // starting
                    prev,
                    Some(TimeTravel {
                        before: prev.clone(),
                        after: e.clone(),
                        skipped: Vec::new(),
                        following: Event {
                            time: PrimitiveDateTime::MIN,
                            user: String::new(),
                            action: Action::LogOff,
                        },
                    }),
                ),
                (false, Some(mut tt)) => {
                    // continuing
                    tt.skipped.push(e.clone());
                    (prev, Some(tt))
                }
            };
        }
        x
    }
}
