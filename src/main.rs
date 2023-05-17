#![feature(iterator_try_collect)]
use color_eyre::{
    eyre::{bail, eyre},
    Result,
};
use std::{env, ffi::OsString, path::PathBuf};
use time::{macros::datetime, PrimitiveDateTime};

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum Action {
    LogOn,
    LogOff,
}
#[derive(Debug)]
struct Event {
    time: time::PrimitiveDateTime,
    user: String,
    action: Action,
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
        for rec in csv::Reader::from_path(path)?.into_deserialize() {
            let [user, action, _host, _ip, time, _domain]: [String; 6] = rec?;
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
            println!("bad time: {event:?}");
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

fn go(paths: &[PathBuf]) -> Result<()> {
    let cleaned: Vec<_> = read_from_paths(&paths)?
        .into_iter()
        .inspect(|(name, _)| println!("{name:?}"))
        .map(|(name, list)| (name, clean(&list)))
        .collect();

    dbg!(&cleaned[0].1);

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
