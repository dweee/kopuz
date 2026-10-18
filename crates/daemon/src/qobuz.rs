//! Qobuz royalty reports follow audible engine sessions, never stream resolution.
use crate::session::SessionHandle;
use api::ApiEvent;
use reader::Track;
use std::{
    sync::Mutex,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::{sync::watch, task::JoinHandle};

#[derive(Default)]
struct ListeningClock {
    last: Option<Instant>,
    playing: bool,
    elapsed: Duration,
}
impl ListeningClock {
    fn update(&mut self, now: Instant, playing: bool) {
        if self.playing
            && let Some(last) = self.last
        {
            self.elapsed += now.saturating_duration_since(last);
        }
        self.last = Some(now);
        self.playing = playing;
    }
}
pub struct Reporter {
    stopping: watch::Sender<bool>,
    tasks: Mutex<Vec<JoinHandle<()>>>,
}
impl Reporter {
    pub fn new() -> Self {
        let (stopping, _) = watch::channel(false);
        Self {
            stopping,
            tasks: Mutex::new(Vec::new()),
        }
    }
    pub fn committed(&self, session: SessionHandle, track: &Track, token: u64) {
        if track.id.service() != Some(config::MusicService::Qobuz) {
            return;
        }
        let track_id = track.id.key().into_owned();
        let duration = track.duration;
        let mut stopping = self.stopping.subscribe();
        let task = tokio::spawn(async move {
            let mut events = session.subscribe();
            let mut clock = ListeningClock::default();
            let mut started = None;
            let mut report = None;
            let mut start_task = None;
            let mut seen_live = false;
            let waiting_since = Instant::now();
            loop {
                let audible = session.audible_state();
                let now = Instant::now();
                let is_live = audible.contains(token);
                seen_live |= is_live;
                let is_playing = is_live && audible.playing && !*stopping.borrow();
                clock.update(now, is_playing);
                if is_playing && started.is_none() {
                    // A preload may resolve without ever being heard. Consume its pending
                    // stream only once this exact session becomes audible.
                    let Some((_resolved_source, client, mut stream)) =
                        server::source::take_playback_report(token)
                    else {
                        return;
                    };
                    if stream.track_id != track_id {
                        tracing::warn!("Qobuz playback report did not match the resolved track");
                        return;
                    }
                    stream.metadata["_kopuz_context_uuid"] =
                        serde_json::Value::String(uuid::Uuid::new_v4().to_string());
                    let stamp = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .map(|v| v.as_secs())
                        .unwrap_or(0);
                    started = Some(stamp);
                    let start_client = client.clone();
                    let start_stream = stream.clone();
                    start_task = Some(tokio::spawn(async move {
                        let result = tokio::time::timeout(
                            Duration::from_secs(4),
                            start_client.report_started(&start_stream),
                        )
                        .await;
                        if !matches!(result, Ok(Ok(()))) {
                            tracing::warn!(
                                "Qobuz playback-start report failed; not retrying an event with no idempotency key"
                            );
                        }
                    }));
                    report = Some((client, stream));
                }
                if (!is_live && seen_live)
                    || *stopping.borrow()
                    || (!seen_live && waiting_since.elapsed() > Duration::from_secs(30))
                {
                    break;
                }
                tokio::select! {
                    _=stopping.changed()=>{},
                    event=events.recv()=>{match event{Ok(ApiEvent::PlayerState(_)|ApiEvent::PlayerPosition{..})=>{},Err(tokio::sync::broadcast::error::RecvError::Closed)=>break,_=>{}}},
                    _=tokio::time::sleep(Duration::from_secs(1))=>{},
                }
            }
            clock.update(Instant::now(), false);
            if let Some(task) = start_task {
                let _ = task.await;
            }
            if let (Some(stamp), Some((client, stream))) = (started, report) {
                let listened = if duration > 0 {
                    clock.elapsed.as_secs().min(duration)
                } else {
                    clock.elapsed.as_secs()
                };
                if listened == 0 {
                    return;
                }
                for attempt in 0..2 {
                    let result = tokio::time::timeout(
                        Duration::from_secs(4),
                        client.report_ended(&stream, stamp, listened),
                    )
                    .await;
                    if matches!(result, Ok(Ok(()))) {
                        return;
                    }
                    if attempt == 0 {
                        tokio::time::sleep(Duration::from_millis(200)).await;
                    }
                }
                tracing::warn!("Qobuz playback-end report failed after bounded retry");
            }
        });
        if let Ok(mut tasks) = self.tasks.lock() {
            tasks.retain(|t| !t.is_finished());
            tasks.push(task);
        }
    }
    /// Bound shutdown so an unavailable service cannot prevent application exit.
    pub async fn shutdown(&self) {
        self.stopping.send_replace(true);
        let tasks = self
            .tasks
            .lock()
            .map(|mut t| std::mem::take(&mut *t))
            .unwrap_or_default();
        let _ = tokio::time::timeout(Duration::from_secs(10), async {
            for task in tasks {
                let _ = task.await;
            }
        })
        .await;
    }
}
impl Default for Reporter {
    fn default() -> Self {
        Self::new()
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn clock_counts_playing_time_not_pause_or_seek() {
        let start = Instant::now();
        let mut c = ListeningClock::default();
        c.update(start, true);
        c.update(start + Duration::from_secs(3), false);
        c.update(start + Duration::from_secs(30), true);
        c.update(start + Duration::from_secs(32), false);
        assert_eq!(c.elapsed, Duration::from_secs(5));
    }
    #[test]
    fn queued_gapless_uses_engine_token_until_switch_and_counts_fading() {
        let queued = crate::session::AudibleState {
            primary: Some(1),
            fading: None,
            playing: true,
        };
        assert!(queued.contains(1));
        assert!(!queued.contains(2));
        let fading = crate::session::AudibleState {
            primary: Some(2),
            fading: Some(1),
            playing: true,
        };
        assert!(fading.contains(1));
        assert!(fading.contains(2));
        let switched = crate::session::AudibleState {
            primary: Some(2),
            fading: None,
            playing: true,
        };
        assert!(!switched.contains(1));
        assert!(switched.contains(2));
    }
}
