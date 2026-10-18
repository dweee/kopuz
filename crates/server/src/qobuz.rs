//! Qobuz API transport. Session material is opaque to callers and never includes a password.
//!
//! Protocol references (implementation written independently): Music Assistant's Qobuz
//! provider for catalog/signing and anon7627/ricercar-qconnect src/{api,secret}.rs for
//! the September 2026 web-player runtime configuration and blob-based reporting.
//! https://github.com/music-assistant/server/tree/dev/music_assistant/providers/qobuz
//! https://github.com/anon7627/ricercar-qconnect
//! Direct signed getFileUrl is used; CMAF downloads, previews, and DRM bypass are absent.
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fmt,
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const API: &str = "https://www.qobuz.com/api.json/0.2/";
const WEB: &str = "https://play.qobuz.com";
const PAGE_SIZE: usize = 500;
#[derive(Default)]
struct RequestGate {
    previous: Option<Instant>,
    cooldown: Option<(Instant, Duration)>,
}
impl RequestGate {
    fn delay(&self, now: Instant) -> Duration {
        let interval = self
            .previous
            .map(|at| Duration::from_millis(500).saturating_sub(now.saturating_duration_since(at)))
            .unwrap_or_default();
        let cooldown = self
            .cooldown
            .map(|(at, duration)| duration.saturating_sub(now.saturating_duration_since(at)))
            .unwrap_or_default();
        interval.max(cooldown)
    }
    fn defer(&mut self, now: Instant, duration: Duration) {
        let remaining = self
            .cooldown
            .map(|(at, delay)| delay.saturating_sub(now.saturating_duration_since(at)))
            .unwrap_or_default();
        if duration > remaining {
            self.cooldown = Some((now, duration));
        }
    }
}
static REQUEST_GATE: tokio::sync::Mutex<RequestGate> = tokio::sync::Mutex::const_new(RequestGate {
    previous: None,
    cooldown: None,
});
async fn throttle() -> Result<()> {
    let waiting_since = Instant::now();
    loop {
        let mut gate = REQUEST_GATE.lock().await;
        let now = Instant::now();
        let delay = gate.delay(now);
        // Keep the full server cooldown, but do not leave a catalog operation waiting
        // indefinitely. A caller may retry later; no request is sent before its deadline.
        if delay > Duration::from_secs(30).saturating_sub(waiting_since.elapsed()) {
            return Err(err(QobuzErrorKind::Api));
        }
        if delay.is_zero() {
            gate.previous = Some(now);
            return Ok(());
        }
        drop(gate);
        // Recheck after waking: another response may have extended the server cooldown.
        tokio::time::sleep(delay).await;
    }
}
fn retry_after(value: Option<&str>, now: SystemTime) -> Duration {
    value
        .and_then(|value| {
            value
                .trim()
                .parse::<u64>()
                .ok()
                .map(Duration::from_secs)
                .or_else(|| {
                    httpdate::parse_http_date(value)
                        .ok()
                        .map(|deadline| deadline.duration_since(now).unwrap_or_default())
                })
        })
        .unwrap_or(Duration::from_secs(1))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QobuzErrorKind {
    Auth,
    Unavailable,
    Api,
    Network,
    InvalidSession,
}
#[derive(Debug)]
pub struct QobuzError {
    pub kind: QobuzErrorKind,
}
impl fmt::Display for QobuzError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self.kind {
            QobuzErrorKind::Auth => "Qobuz authentication failed or expired; sign in again",
            QobuzErrorKind::Unavailable => "Qobuz full-length stream or item unavailable",
            QobuzErrorKind::Api => "Qobuz API rejected the request or returned invalid data",
            QobuzErrorKind::Network => "Qobuz network request failed",
            QobuzErrorKind::InvalidSession => "Invalid Qobuz session or application credentials",
        })
    }
}
impl std::error::Error for QobuzError {}
fn err(kind: QobuzErrorKind) -> QobuzError {
    QobuzError { kind }
}
type Result<T> = std::result::Result<T, QobuzError>;

// Intentionally no Debug: tokens and application secrets must never enter diagnostics.
#[derive(Clone, Serialize, Deserialize)]
struct Session {
    app_id: String,
    app_secret: String,
    user_auth_token: String,
    user_id: String,
    #[serde(default)]
    web_discovered: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    device_id: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    credential_id: Option<Value>,
}
#[derive(Default)]
struct AppState {
    pair: Option<(String, String)>,
    last_refresh: Option<Instant>,
}
#[derive(Clone)]
pub struct QobuzClient {
    http: reqwest::Client,
    base: String,
    session: Session,
    application: Arc<Mutex<AppState>>,
}
// The stream URL is a bearer credential; do not derive Debug.
#[derive(Clone)]
pub struct QobuzStream {
    pub url: String,
    pub format_id: u32,
    pub track_id: String,
    pub metadata: Value,
}
fn id(value: &Value) -> Option<String> {
    value
        .as_str()
        .map(str::to_owned)
        .or_else(|| value.as_u64().map(|n| n.to_string()))
}
fn now() -> Result<String> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| err(QobuzErrorKind::Api))?
        .as_secs()
        .to_string())
}
fn http_client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .user_agent("Kopuz/0.21 (Qobuz client)")
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|_| err(QobuzErrorKind::Network))
}
fn signature(
    endpoint: &str,
    params: &BTreeMap<String, String>,
    timestamp: &str,
    secret: &str,
) -> String {
    let mut input = endpoint.replace('/', "");
    for (key, value) in params {
        input.push_str(key);
        input.push_str(value);
    }
    input.push_str(timestamp);
    input.push_str(secret);
    format!("{:x}", md5::compute(input))
}
/// Pending application credentials are deliberately not a usable authenticated session.
pub fn pending_credentials(app_id: &str, app_secret: &str) -> String {
    json!({"app_id":app_id,"app_secret":app_secret}).to_string()
}
pub fn app_credentials(packed: &str) -> Option<(String, String)> {
    let value: Value = serde_json::from_str(packed).ok()?;
    // Reauthentication must preserve discovery mode and fetch a current pair, rather
    // than turning a cached web pair into a permanent explicit application override.
    if value["web_discovered"].as_bool() == Some(true) {
        return None;
    }
    let app_id = value["app_id"].as_str()?;
    let secret = value["app_secret"].as_str()?;
    if app_id.is_empty() || secret.is_empty() {
        return None;
    }
    Some((app_id.into(), secret.into()))
}
impl QobuzClient {
    pub fn user_id(&self) -> &str {
        &self.session.user_id
    }

    pub fn from_session(packed: &str) -> Result<Self> {
        let session: Session =
            serde_json::from_str(packed).map_err(|_| err(QobuzErrorKind::InvalidSession))?;
        if [
            &session.app_id,
            &session.app_secret,
            &session.user_auth_token,
            &session.user_id,
        ]
        .iter()
        .any(|s| s.is_empty())
        {
            return Err(err(QobuzErrorKind::InvalidSession));
        }
        Ok(Self {
            http: http_client()?,
            base: API.into(),
            session,
            application: Arc::new(Mutex::new(AppState::default())),
        })
    }
    pub fn pack_session(&self) -> Result<String> {
        let mut session = self.session.clone();
        (session.app_id, session.app_secret) = self.application_credentials()?;
        serde_json::to_string(&session).map_err(|_| err(QobuzErrorKind::InvalidSession))
    }
    pub async fn login(
        username: &str,
        password: &str,
        app_id: Option<&str>,
        app_secret: Option<&str>,
    ) -> Result<Self> {
        let http = http_client()?;
        let web_discovered = app_id.filter(|s| !s.is_empty()).is_none();
        let (app_id, secrets) = match (
            app_id.filter(|s| !s.is_empty()),
            app_secret.filter(|s| !s.is_empty()),
        ) {
            (Some(id), Some(secret)) => (id.to_owned(), vec![secret.to_owned()]),
            (None, None) => discover(&http).await?,
            _ => return Err(err(QobuzErrorKind::InvalidSession)),
        };
        let client = Self {
            http,
            base: API.into(),
            session: Session {
                app_id,
                app_secret: secrets
                    .into_iter()
                    .next()
                    .ok_or_else(|| err(QobuzErrorKind::InvalidSession))?,
                user_auth_token: String::new(),
                user_id: String::new(),
                web_discovered,
                device_id: None,
                credential_id: None,
            },
            application: Arc::new(Mutex::new(AppState::default())),
        };
        client.finish_login(username, password).await
    }
    async fn finish_login(mut self, username: &str, password: &str) -> Result<Self> {
        self.authenticate(username, password).await?;
        // user/login verifies account credentials and the application ID. There is no
        // universally accessible catalog track with which to probe signing credentials.
        // The selected production/explicit secret is checked when a real stream is requested.
        Ok(self)
    }
    async fn authenticate(&mut self, username: &str, password: &str) -> Result<()> {
        let hashed = format!("{:x}", md5::compute(password.as_bytes()));
        // Form POST keeps the password hash out of URL logs. It is not persisted in Session.
        throttle().await?;
        let response = self
            .http
            .post(format!("{}user/login", self.base))
            .header("X-App-Id", self.application_credentials()?.0)
            .form(&[
                ("username", username),
                ("password", hashed.as_str()),
                ("app_id", self.session.app_id.as_str()),
                ("device_manufacturer_id", "kopuz"),
            ])
            .send()
            .await
            .map_err(|_| err(QobuzErrorKind::Network))?;
        let data = decode(response).await?;
        self.session.user_auth_token = data["user_auth_token"]
            .as_str()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| err(QobuzErrorKind::Auth))?
            .into();
        self.session.user_id = id(&data["user"]["id"]).ok_or_else(|| err(QobuzErrorKind::Auth))?;
        self.session.device_id = data
            .pointer("/user/device/id")
            .filter(|v| !v.is_null())
            .cloned();
        self.session.credential_id = data
            .pointer("/user/credential/id")
            .filter(|v| !v.is_null())
            .cloned();
        Ok(())
    }
    fn application_credentials(&self) -> Result<(String, String)> {
        let state = self
            .application
            .lock()
            .map_err(|_| err(QobuzErrorKind::InvalidSession))?;
        Ok(state
            .pair
            .clone()
            .unwrap_or_else(|| (self.session.app_id.clone(), self.session.app_secret.clone())))
    }
    async fn refresh_application(&self) -> Result<bool> {
        if !self.session.web_discovered {
            return Ok(false);
        }
        {
            let mut state = self
                .application
                .lock()
                .map_err(|_| err(QobuzErrorKind::InvalidSession))?;
            if state
                .last_refresh
                .is_some_and(|at| at.elapsed() < Duration::from_secs(60))
            {
                return Ok(false);
            }
            state.last_refresh = Some(Instant::now());
        }
        let (app_id, mut secrets) = discover(&self.http).await?;
        let secret = secrets
            .pop()
            .ok_or_else(|| err(QobuzErrorKind::InvalidSession))?;
        let pair = (app_id, secret);
        if self.application_credentials()? == pair {
            return Ok(false);
        }
        self.application
            .lock()
            .map_err(|_| err(QobuzErrorKind::InvalidSession))?
            .pair = Some(pair);
        Ok(true)
    }
    async fn get(&self, endpoint: &str, pairs: &[(&str, String)], signed: bool) -> Result<Value> {
        for attempt in 0..2 {
            throttle().await?;
            let (app_id, secret) = self.application_credentials()?;
            let mut params: BTreeMap<String, String> = pairs
                .iter()
                .map(|(k, v)| ((*k).into(), v.clone()))
                .collect();
            if signed {
                let timestamp = now()?;
                let sig = signature(endpoint, &params, &timestamp, &secret);
                params.insert("request_ts".into(), timestamp);
                params.insert("request_sig".into(), sig);
            }
            let response = self
                .http
                .get(format!("{}{endpoint}", self.base))
                .header("X-App-Id", &app_id)
                .header("X-User-Auth-Token", &self.session.user_auth_token)
                .query(&params)
                .send()
                .await
                .map_err(|_| err(QobuzErrorKind::Network))?;
            match decode(response).await {
                Err(error) if error.kind == QobuzErrorKind::InvalidSession && attempt == 0 => {
                    if self.refresh_application().await? {
                        continue;
                    }
                    return Err(error);
                }
                result => return result,
            }
        }
        Err(err(QobuzErrorKind::InvalidSession))
    }
    pub async fn validate(&self) -> Result<Value> {
        self.get(
            "user/get",
            &[("user_id", self.session.user_id.clone())],
            false,
        )
        .await
    }
    async fn all(&self, endpoint: &str, key: &str, pairs: &[(&str, String)]) -> Result<Vec<Value>> {
        let mut items = Vec::new();
        loop {
            let mut params = pairs.to_vec();
            params.push(("limit", PAGE_SIZE.to_string()));
            params.push(("offset", items.len().to_string()));
            let response = self.get(endpoint, &params, false).await?;
            let page = response.get(key).ok_or_else(|| err(QobuzErrorKind::Api))?;
            let batch = page["items"]
                .as_array()
                .ok_or_else(|| err(QobuzErrorKind::Api))?;
            if batch.is_empty() {
                break;
            }
            let count = batch.len();
            // A server repeating the previous page must not trap a library refresh forever.
            if items.len() >= count && items[items.len() - count..] == batch[..] {
                return Err(err(QobuzErrorKind::Api));
            }
            items.extend(batch.iter().cloned());
            let total = page["total"]
                .as_u64()
                .or_else(|| response.get(format!("{key}_count")).and_then(Value::as_u64));
            if total.is_some_and(|total| items.len() as u64 >= total)
                || (total.is_none() && count < PAGE_SIZE)
            {
                break;
            }
            if items.len() > 1_000_000 {
                return Err(err(QobuzErrorKind::Api));
            }
        }
        Ok(items)
    }
    pub async fn favorites(&self, kind: &str) -> Result<Vec<Value>> {
        if !matches!(kind, "tracks" | "albums" | "artists") {
            return Err(err(QobuzErrorKind::Api));
        }
        self.all(
            "favorite/getUserFavorites",
            kind,
            &[
                ("type", kind.into()),
                ("user_id", self.session.user_id.clone()),
            ],
        )
        .await
    }
    pub async fn playlists(&self) -> Result<Vec<Value>> {
        self.all(
            "playlist/getUserPlaylists",
            "playlists",
            &[("user_id", self.session.user_id.clone())],
        )
        .await
    }
    pub async fn playlist_tracks(&self, playlist_id: &str) -> Result<Vec<Value>> {
        self.all(
            "playlist/get",
            "tracks",
            &[
                ("playlist_id", playlist_id.into()),
                ("extra", "tracks".into()),
            ],
        )
        .await
    }
    pub async fn album_tracks(&self, album_id: &str) -> Result<Vec<Value>> {
        self.all("album/get", "tracks", &[("album_id", album_id.into())])
            .await
    }
    pub async fn artist_albums(&self, artist_id: &str) -> Result<Vec<Value>> {
        self.all(
            "artist/get",
            "albums",
            &[("artist_id", artist_id.into()), ("extra", "albums".into())],
        )
        .await
    }
    pub async fn search(&self, query: &str, limit: u32) -> Result<Value> {
        self.get(
            "catalog/search",
            &[
                ("query", query.into()),
                ("limit", limit.clamp(1, 500).to_string()),
            ],
            false,
        )
        .await
    }
    pub async fn album(&self, album_id: &str) -> Result<Value> {
        self.get("album/get", &[("album_id", album_id.into())], false)
            .await
    }
    pub async fn artist(&self, artist_id: &str) -> Result<Value> {
        self.get("artist/get", &[("artist_id", artist_id.into())], false)
            .await
    }
    pub async fn track(&self, track_id: &str) -> Result<Value> {
        self.get("track/get", &[("track_id", track_id.into())], false)
            .await
    }
    pub async fn stream_url(&self, track_id: &str, max_quality: u32) -> Result<QobuzStream> {
        if !matches!(max_quality, 27 | 7 | 6 | 5) {
            return Err(err(QobuzErrorKind::Api));
        }
        'quality: for quality in [27, 7, 6, 5].into_iter().filter(|q| *q <= max_quality) {
            for resolution in 0..2 {
                let response = self
                    .get(
                        "track/getFileUrl",
                        &[
                            ("format_id", quality.to_string()),
                            ("intent", "stream".into()),
                            ("track_id", track_id.into()),
                        ],
                        true,
                    )
                    .await;
                let data = match response {
                    Ok(data) => data,
                    Err(e) if e.kind == QobuzErrorKind::Unavailable => continue 'quality,
                    Err(e) => return Err(e),
                };
                // Reject samples explicitly; requesting intent=stream is necessary but insufficient.
                if data["sample"].as_bool() == Some(true)
                    || data["is_sample"].as_bool() == Some(true)
                    || data["intent"].as_str().is_some_and(|s| s != "stream")
                {
                    continue 'quality;
                }
                let Some(url) = data["url"].as_str().filter(|s| !s.is_empty()) else {
                    continue 'quality;
                };
                let parsed = reqwest::Url::parse(url).map_err(|_| err(QobuzErrorKind::Api))?;
                if parsed.scheme() != "https" {
                    return Err(err(QobuzErrorKind::Api));
                }
                if let Some(expiry) = parsed.query_pairs().find_map(|(key, value)| {
                    (key == "etsp").then(|| value.parse::<u64>().ok()).flatten()
                }) {
                    let current = now()?
                        .parse::<u64>()
                        .map_err(|_| err(QobuzErrorKind::Api))?;
                    if expiry <= current.saturating_add(60) {
                        if resolution == 0 {
                            continue;
                        }
                        return Err(err(QobuzErrorKind::Unavailable));
                    }
                }
                return Ok(QobuzStream {
                    url: url.into(),
                    format_id: data["format_id"].as_u64().unwrap_or(quality as u64) as u32,
                    track_id: track_id.into(),
                    metadata: data,
                });
            }
        }
        Err(err(QobuzErrorKind::Unavailable))
    }
    /// Call only after audio actually starts, not when a URL is resolved or prefetched.
    pub async fn report_started(&self, stream: &QobuzStream) -> Result<()> {
        let events = json!([{"track_id": stream.track_id.parse::<u64>().map_err(|_|err(QobuzErrorKind::Api))?,"date":now()?.parse::<u64>().map_err(|_|err(QobuzErrorKind::Api))?,"user_id":self.session.user_id.parse::<u64>().map_err(|_|err(QobuzErrorKind::InvalidSession))?,"format_id":stream.format_id}]);
        throttle().await?;
        let response = self
            .http
            .post(format!("{}track/reportStreamingStart", self.base))
            .header("X-App-Id", self.application_credentials()?.0)
            .header("X-User-Auth-Token", &self.session.user_auth_token)
            .form(&[("events", events.to_string())])
            .send()
            .await
            .map_err(|_| err(QobuzErrorKind::Network))?;
        let response = decode(response).await?;
        if response["status"] != "success" {
            return Err(err(QobuzErrorKind::Api));
        }
        Ok(())
    }
    /// Duration is actual audible listening time, excluding pauses and skipped seeks.
    pub async fn report_ended(
        &self,
        stream: &QobuzStream,
        started_unix_seconds: u64,
        seconds_listened: u64,
    ) -> Result<()> {
        let blob = stream.metadata["blob"]
            .as_str()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| err(QobuzErrorKind::Unavailable))?;
        let duration = seconds_listened.min(
            stream.metadata["duration"]
                .as_u64()
                .unwrap_or(seconds_listened),
        );
        if duration == 0 {
            return Ok(());
        }
        let context_uuid = stream.metadata["_kopuz_context_uuid"]
            .as_str()
            .and_then(|s| uuid::Uuid::parse_str(s).ok())
            .unwrap_or_else(uuid::Uuid::new_v4)
            .to_string();
        let body = json!({"events":[{"blob":blob,"track_context_uuid":context_uuid,"start_stream":iso8601(started_unix_seconds),"online":true,"local":false,"duration":duration}],"renderer_context":{"software_version":concat!("Kopuz/",env!("CARGO_PKG_VERSION"))}});
        throttle().await?;
        let response = self
            .http
            .post(format!("{}track/reportStreamingEndJson", self.base))
            .header("X-App-Id", self.application_credentials()?.0)
            .header("X-User-Auth-Token", &self.session.user_auth_token)
            .json(&body)
            .send()
            .await
            .map_err(|_| err(QobuzErrorKind::Network))?;
        let result = decode(response).await?;
        if result["status"] != "success" {
            return Err(err(QobuzErrorKind::Api));
        }
        Ok(())
    }
    async fn post(&self, endpoint: &str, fields: &[(&str, String)]) -> Result<Value> {
        throttle().await?;
        let response = self
            .http
            .post(format!("{}{endpoint}", self.base))
            .header("X-App-Id", self.application_credentials()?.0)
            .header("X-User-Auth-Token", &self.session.user_auth_token)
            .form(fields)
            .send()
            .await
            .map_err(|_| err(QobuzErrorKind::Network))?;
        decode(response).await
    }
    pub async fn set_favorite(&self, track_id: &str, on: bool) -> Result<()> {
        self.post(
            if on {
                "favorite/create"
            } else {
                "favorite/delete"
            },
            &[("track_ids", track_id.into())],
        )
        .await
        .map(|_| ())
    }
    pub async fn create_playlist(&self, name: &str) -> Result<String> {
        let response = self
            .post(
                "playlist/create",
                &[
                    ("name", name.into()),
                    ("is_public", "0".into()),
                    ("is_collaborative", "0".into()),
                ],
            )
            .await?;
        id(&response["id"]).ok_or_else(|| err(QobuzErrorKind::Api))
    }
    pub async fn add_playlist_tracks(&self, playlist_id: &str, track_ids: &[String]) -> Result<()> {
        self.post(
            "playlist/addTracks",
            &[
                ("playlist_id", playlist_id.into()),
                ("track_ids", track_ids.join(",")),
            ],
        )
        .await
        .map(|_| ())
    }
    pub async fn remove_playlist_tracks(
        &self,
        playlist_id: &str,
        playlist_track_ids: &[String],
    ) -> Result<()> {
        self.post(
            "playlist/deleteTracks",
            &[
                ("playlist_id", playlist_id.into()),
                ("playlist_track_ids", playlist_track_ids.join(",")),
            ],
        )
        .await
        .map(|_| ())
    }
}
async fn decode(response: reqwest::Response) -> Result<Value> {
    let status = response.status();
    if status.as_u16() == 429 {
        let delay = retry_after(
            response
                .headers()
                .get(reqwest::header::RETRY_AFTER)
                .and_then(|h| h.to_str().ok()),
            SystemTime::now(),
        );
        REQUEST_GATE.lock().await.defer(Instant::now(), delay);
        return Err(err(QobuzErrorKind::Api));
    }
    if status.as_u16() == 401 {
        return Err(err(QobuzErrorKind::Auth));
    }
    let data: Value = response
        .json()
        .await
        .map_err(|_| err(QobuzErrorKind::Api))?;
    let code = data["code"]
        .as_str()
        .map(str::to_owned)
        .or_else(|| data["code"].as_i64().map(|n| n.to_string()))
        .unwrap_or_default();
    let message = data["message"]
        .as_str()
        .unwrap_or_default()
        .to_ascii_lowercase();
    if code == "401"
        || message.contains("invalid user auth token")
        || message.contains("token expired")
        || message.contains("expired token")
        || message.contains("authentication")
    {
        return Err(err(QobuzErrorKind::Auth));
    }
    if message.contains("request_sig")
        || message.contains("app_id")
        || message.contains("app secret")
        || message.contains("application secret")
    {
        return Err(err(QobuzErrorKind::InvalidSession));
    }
    if status.as_u16() == 404 || code == "404" {
        return Err(err(QobuzErrorKind::Unavailable));
    }
    if status.as_u16() == 403
        && (message.contains("not streamable")
            || message.contains("not available")
            || message.contains("streaming rights"))
    {
        return Err(err(QobuzErrorKind::Unavailable));
    }
    if !status.is_success() || data["status"] == "error" {
        return Err(err(QobuzErrorKind::Api));
    }
    Ok(data)
}

async fn discover(http: &reqwest::Client) -> Result<(String, Vec<String>)> {
    let page = http
        .get(format!("{WEB}/login"))
        .send()
        .await
        .map_err(|_| err(QobuzErrorKind::Network))?
        .error_for_status()
        .map_err(|_| err(QobuzErrorKind::Api))?
        .text()
        .await
        .map_err(|_| err(QobuzErrorKind::Network))?;
    let pattern = regex::Regex::new(r#"src=["'](/resources/[^"']*/bundle\.js)["']"#)
        .map_err(|_| err(QobuzErrorKind::Api))?;
    let path = pattern
        .captures(&page)
        .and_then(|c| c.get(1))
        .ok_or_else(|| err(QobuzErrorKind::InvalidSession))?
        .as_str();
    let bundle = http
        .get(format!("{WEB}{path}"))
        .send()
        .await
        .map_err(|_| err(QobuzErrorKind::Network))?
        .error_for_status()
        .map_err(|_| err(QobuzErrorKind::Api))?
        .text()
        .await
        .map_err(|_| err(QobuzErrorKind::Network))?;
    parse_bundle(&bundle)
}
// Production runtime configuration, decoded independently from the public web bundle.
// Never use the plaintext appSecret environment constant: it is not the signing key.
fn parse_bundle(bundle: &str) -> Result<(String, Vec<String>)> {
    let invalid = || err(QobuzErrorKind::InvalidSession);
    let production = bundle
        .split_once("production:{api:{")
        .ok_or_else(invalid)?
        .1;
    let app_id = between(production, "appId:\"", "\"")
        .filter(|s| (6..=12).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_digit()))
        .ok_or_else(invalid)?;
    let initialization = bundle
        .split_once(".initialization=function(){")
        .ok_or_else(invalid)?
        .1
        .split('}')
        .next()
        .ok_or_else(invalid)?;
    let call = initialization
        .rsplit_once("initialSeed(\"")
        .ok_or_else(invalid)?
        .1;
    let seed = call.split('"').next().ok_or_else(invalid)?;
    let zone = between(call, "window.utimezone.", ")").ok_or_else(invalid)?;
    let table = bundle.find("timezones:[{offset:").ok_or_else(invalid)?;
    let head = &bundle[bundle[..table].rfind('{').ok_or_else(invalid)?..table];
    let index: usize = between(&format!("{head},"), &format!("{zone}:"), ",")
        .and_then(|s| s.parse().ok())
        .ok_or_else(invalid)?;
    let entries = &bundle[table + "timezones:[".len()..];
    let entry = entries
        .split_once("]}")
        .ok_or_else(invalid)?
        .0
        .split("},{")
        .nth(index)
        .ok_or_else(invalid)?;
    let info = between(entry, "info:\"", "\"").ok_or_else(invalid)?;
    let extras = between(entry, "extras:\"", "\"").ok_or_else(invalid)?;
    let encoded = format!("{seed}{info}{extras}");
    let encoded = encoded
        .get(..encoded.len().saturating_sub(44))
        .ok_or_else(invalid)?;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|_| invalid())?;
    let secret = String::from_utf8(bytes).map_err(|_| invalid())?;
    if secret.len() != 32 || !secret.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(invalid());
    }
    Ok((app_id.into(), vec![secret]))
}
fn between<'a>(text: &'a str, start: &str, end: &str) -> Option<&'a str> {
    text.split_once(start)?.1.split_once(end).map(|(s, _)| s)
}
fn iso8601(timestamp: u64) -> String {
    let days = (timestamp / 86400) as i64;
    let shifted = days + 719468;
    let era = shifted.div_euclid(146097);
    let day_of_era = shifted.rem_euclid(146097);
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36524 - day_of_era / 146096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_index + 2) / 5 + 1;
    let month = month_index + if month_index < 10 { 3 } else { -9 };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    let seconds = timestamp % 86400;
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.000Z",
        seconds / 3600,
        seconds % 3600 / 60,
        seconds % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::{Read, Write},
        net::TcpListener,
        sync::{Arc, Mutex},
    };

    type Fixture = (
        QobuzClient,
        Arc<Mutex<Vec<String>>>,
        std::thread::JoinHandle<()>,
    );
    fn client(responses: Vec<(u16, Value)>) -> Fixture {
        client_with_headers(
            responses
                .into_iter()
                .map(|(status, body)| (status, body, None))
                .collect(),
        )
    }
    fn client_with_headers(responses: Vec<(u16, Value, Option<&'static str>)>) -> Fixture {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let capture = requests.clone();
        let worker = std::thread::spawn(move || {
            for (status, body, retry_after) in responses {
                let (mut socket, _) = listener.accept().unwrap();
                socket
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut request = Vec::new();
                loop {
                    let mut chunk = [0; 4096];
                    let n = socket.read(&mut chunk).unwrap();
                    assert!(n > 0);
                    request.extend_from_slice(&chunk[..n]);
                    let Some(end) = request.windows(4).position(|s| s == b"\r\n\r\n") else {
                        continue;
                    };
                    let headers = String::from_utf8_lossy(&request[..end]);
                    let length = headers
                        .lines()
                        .find_map(|s| {
                            s.to_lowercase()
                                .strip_prefix("content-length:")
                                .and_then(|s| s.trim().parse::<usize>().ok())
                        })
                        .unwrap_or(0);
                    if request.len() >= end + 4 + length {
                        break;
                    }
                }
                capture
                    .lock()
                    .unwrap()
                    .push(String::from_utf8(request).unwrap());
                let body = body.to_string();
                let cooldown = retry_after
                    .map(|value| format!("Retry-After: {value}\r\n"))
                    .unwrap_or_default();
                write!(socket,"HTTP/1.1 {status} OK\r\n{cooldown}Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).unwrap();
            }
        });
        let mut client = QobuzClient::from_session(
            r#"{"app_id":"123","app_secret":"secret","user_auth_token":"token","user_id":"42"}"#,
        )
        .unwrap();
        client.base = format!("http://{address}/");
        (client, requests, worker)
    }
    #[test]
    fn signing_is_sorted_and_matches_protocol() {
        let params = BTreeMap::from([
            ("track_id".into(), "99".into()),
            ("intent".into(), "stream".into()),
            ("format_id".into(), "27".into()),
        ]);
        assert_eq!(
            signature("track/getFileUrl", &params, "1234", "key"),
            format!(
                "{:x}",
                md5::compute("trackgetFileUrlformat_id27intentstreamtrack_id991234key")
            )
        );
    }
    #[test]
    fn sessions_and_diagnostics_do_not_persist_passwords() {
        let pending = pending_credentials("123", "secret");
        assert_eq!(
            app_credentials(&pending),
            Some(("123".into(), "secret".into()))
        );
        assert!(QobuzClient::from_session(&pending).is_err());
        let packed = r#"{"app_id":"123","app_secret":"secret","user_auth_token":"token","user_id":"42","password":"discard-me"}"#;
        let client = QobuzClient::from_session(packed).unwrap();
        assert!(!client.pack_session().unwrap().contains("discard-me"));
        assert!(!err(QobuzErrorKind::Auth).to_string().contains("token="));
    }
    #[tokio::test]
    async fn login_posts_hash_without_retaining_password() {
        let (client, requests, worker) = client(vec![(
            200,
            json!({"user_auth_token":"new-token","user":{"id":57,"device":{"id":"device"},"credential":{"id":10}}}),
        )]);
        let client = client
            .finish_login("me@example.test", "private-password")
            .await
            .unwrap();
        worker.join().unwrap();
        let requests = requests.lock().unwrap();
        assert!(requests[0].starts_with("POST /user/login HTTP/1.1"));
        assert!(requests[0].contains(&format!("password={:x}", md5::compute("private-password"))));
        assert!(!requests[0].contains("private-password"));
        let packed = client.pack_session().unwrap();
        assert!(!packed.contains("password"));
        assert_eq!(client.user_id(), "57");
    }
    #[tokio::test]
    async fn pagination_uses_actual_count_when_server_caps_pages() {
        let (client, requests, worker) = client(vec![
            (
                200,
                json!({"tracks":{"items":[{"id":1},{"id":2}],"total":3}}),
            ),
            (200, json!({"tracks":{"items":[{"id":3}],"total":3}})),
        ]);
        assert_eq!(client.favorites("tracks").await.unwrap().len(), 3);
        worker.join().unwrap();
        let requests = requests.lock().unwrap();
        assert!(requests[0].contains("offset=0"));
        assert!(requests[1].contains("offset=2"));
    }
    #[tokio::test]
    async fn stream_falls_back_and_never_plays_a_preview() {
        let (client, requests, worker) = client(vec![
            (404, json!({"status":"error"})),
            (200, json!({"url":"https://cdn.test/preview","sample":true})),
            (
                200,
                json!({"url":"https://cdn.test/full","format_id":6,"sample":false,"intent":"stream"}),
            ),
        ]);
        let stream = client.stream_url("99", 27).await.unwrap();
        assert_eq!(stream.url, "https://cdn.test/full");
        assert_eq!(stream.format_id, 6);
        worker.join().unwrap();
        let requests = requests.lock().unwrap();
        for (request, quality) in requests.iter().zip([27, 7, 6]) {
            assert!(request.contains(&format!("format_id={quality}")));
            let line = request.lines().next().unwrap();
            let target = line.split_whitespace().nth(1).unwrap();
            let url = reqwest::Url::parse(&format!("http://fixture{target}")).unwrap();
            let query: BTreeMap<String, String> = url
                .query_pairs()
                .map(|(a, b)| (a.into_owned(), b.into_owned()))
                .collect();
            let params = BTreeMap::from([
                ("format_id".into(), quality.to_string()),
                ("intent".into(), "stream".into()),
                ("track_id".into(), "99".into()),
            ]);
            assert_eq!(
                query["request_sig"],
                signature("track/getFileUrl", &params, &query["request_ts"], "secret")
            );
        }
        assert_eq!(requests.len(), 3); // Resolving never emits a royalty event.
    }
    #[tokio::test]
    async fn expired_session_stops_quality_retry_immediately() {
        let (client, requests, worker) =
            client(vec![(401, json!({"message":"private upstream details"}))]);
        assert_eq!(
            client.stream_url("99", 27).await.err().unwrap().kind,
            QobuzErrorKind::Auth
        );
        worker.join().unwrap();
        assert_eq!(requests.lock().unwrap().len(), 1);
    }
    #[tokio::test]
    async fn token_error_in_json_is_auth_and_does_not_leak_upstream_message() {
        let (client, _, worker) = client(vec![(
            400,
            json!({"status":"error","message":"Invalid user auth token secret-token"}),
        )]);
        let error = client.validate().await.unwrap_err();
        assert_eq!(error.kind, QobuzErrorKind::Auth);
        assert!(!error.to_string().contains("secret-token"));
        worker.join().unwrap();
    }
    #[test]
    fn decodes_web_runtime_configuration_and_rejects_changed_bundles() {
        let secret = "0123456789abcdef0123456789abcdef"; // gitleaks:allow -- synthetic redaction-test fixture
        let encoded = base64::engine::general_purpose::STANDARD.encode(secret);
        let bundle = format!(
            r#"production:{{api:{{appId:"123456789"}}}};c.initialization=function(){{x.initialSeed("ignored",window.utimezone.old);x.initialSeed("{}",window.utimezone.london)}};table={{london:0,timezones:[{{offset:"GMT",name:"Europe/London",info:"{}",extras:"{}"}}]}}"#,
            &encoded[..4],
            &encoded[4..],
            "A".repeat(44)
        );
        assert_eq!(
            parse_bundle(&bundle).unwrap(),
            ("123456789".into(), vec![secret.into()])
        );
        assert!(parse_bundle("changed web runtime").is_err());
    }
    #[tokio::test]
    async fn expired_signed_url_is_resolved_again_once() {
        let fresh = now().unwrap().parse::<u64>().unwrap() + 3600;
        let (client, requests, worker) = client(vec![
            (
                200,
                json!({"url":"https://cdn.test/stale?etsp=1","format_id":27}),
            ),
            (
                200,
                json!({"url":format!("https://cdn.test/full?etsp={fresh}"),"format_id":27}),
            ),
        ]);
        assert!(
            client
                .stream_url("99", 27)
                .await
                .unwrap()
                .url
                .contains("/full?")
        );
        worker.join().unwrap();
        assert_eq!(requests.lock().unwrap().len(), 2);
    }
    #[tokio::test]
    async fn stale_stream_url_cannot_trigger_unbounded_retry() {
        let stale = json!({"url":"https://cdn.test/stale?etsp=1"});
        let (client, requests, worker) = client(vec![(200, stale.clone()), (200, stale)]);
        assert_eq!(
            client.stream_url("99", 27).await.err().unwrap().kind,
            QobuzErrorKind::Unavailable
        );
        worker.join().unwrap();
        assert_eq!(requests.lock().unwrap().len(), 2);
    }
    #[tokio::test]
    async fn signing_and_rate_errors_do_not_downgrade_quality() {
        for status in [400, 429] {
            let (client, requests, worker) = client(vec![(
                status,
                json!({"status":"error","message":"request_sig"}),
            )]);
            assert_eq!(
                client.stream_url("99", 27).await.err().unwrap().kind,
                if status == 400 {
                    QobuzErrorKind::InvalidSession
                } else {
                    QobuzErrorKind::Api
                }
            );
            worker.join().unwrap();
            assert_eq!(requests.lock().unwrap().len(), 1);
        }
    }
    #[tokio::test]
    async fn royalty_end_preserves_blob_and_actual_listening_time() {
        let (client, requests, worker) = client(vec![(200, json!({"status":"success"}))]);
        let stream = QobuzStream {
            url: "https://cdn.test/full".into(),
            format_id: 27,
            track_id: "99".into(),
            metadata: json!({"blob":"opaque-report-token","duration":120,"_kopuz_context_uuid":"a06428be-d32b-4365-981d-042dc2652131"}),
        };
        client.report_ended(&stream, 1790812800, 300).await.unwrap();
        worker.join().unwrap();
        let requests = requests.lock().unwrap();
        assert!(requests[0].starts_with("POST /track/reportStreamingEndJson HTTP/1.1"));
        let payload: Value =
            serde_json::from_str(requests[0].split_once("\r\n\r\n").unwrap().1).unwrap();
        assert_eq!(payload["events"][0]["blob"], "opaque-report-token");
        assert_eq!(payload["events"][0]["duration"], 120);
        assert_eq!(
            payload["events"][0]["track_context_uuid"],
            "a06428be-d32b-4365-981d-042dc2652131"
        );
        assert_eq!(
            payload["events"][0]["start_stream"],
            "2026-10-01T00:00:00.000Z"
        );
        assert!(
            uuid::Uuid::parse_str(payload["events"][0]["track_context_uuid"].as_str().unwrap())
                .is_ok()
        );
    }
    #[tokio::test]
    async fn missing_royalty_blob_is_never_fabricated() {
        let client = QobuzClient::from_session(
            r#"{"app_id":"123","app_secret":"secret","user_auth_token":"token","user_id":"42"}"#,
        )
        .unwrap();
        let stream = QobuzStream {
            url: "https://cdn.test/full".into(),
            format_id: 27,
            track_id: "99".into(),
            metadata: json!({}),
        };
        assert_eq!(
            client.report_ended(&stream, 0, 50).await.unwrap_err().kind,
            QobuzErrorKind::Unavailable
        );
    }
    #[tokio::test]
    #[ignore = "contacts the public Qobuz web player; no account required"]
    async fn live_web_bundle_discovery() {
        let (app_id, secrets) = discover(&http_client().unwrap()).await.unwrap();
        assert!((6..=12).contains(&app_id.len()));
        assert_eq!(secrets.len(), 1);
        assert_eq!(secrets[0].len(), 32);
    }
    #[tokio::test]
    async fn failed_app_rotation_is_throttled_and_does_not_downgrade() {
        let (mut client, requests, worker) = client(vec![(
            400,
            json!({"status":"error","message":"invalid request_sig"}),
        )]);
        client.session.web_discovered = true;
        client.application.lock().unwrap().last_refresh = Some(Instant::now());
        assert_eq!(
            client.stream_url("99", 27).await.err().unwrap().kind,
            QobuzErrorKind::InvalidSession
        );
        worker.join().unwrap();
        assert_eq!(requests.lock().unwrap().len(), 1);
    }
    #[test]
    fn rotated_app_pair_is_persisted_atomically() {
        let client = QobuzClient::from_session(
            r#"{"app_id":"123","app_secret":"secret","user_auth_token":"token","user_id":"42"}"#,
        )
        .unwrap();
        client.application.lock().unwrap().pair = Some(("456".into(), "rotated".into()));
        let session: Value = serde_json::from_str(&client.pack_session().unwrap()).unwrap();
        assert_eq!(session["app_id"], "456");
        assert_eq!(session["app_secret"], "rotated");
        assert_eq!(session["user_auth_token"], "token");
    }
    #[test]
    fn reauthentication_preserves_discovery_mode_and_explicit_overrides() {
        let base = json!({"app_id":"123456789","app_secret":"secret","user_auth_token":"token","user_id":"42"});
        assert_eq!(
            app_credentials(&base.to_string()),
            Some(("123456789".into(), "secret".into()))
        );
        let mut discovered = base;
        discovered["web_discovered"] = true.into();
        assert!(app_credentials(&discovered.to_string()).is_none());
        // The stored token remains usable until actually rejected by the service.
        assert!(QobuzClient::from_session(&discovered.to_string()).is_ok());
    }
    #[tokio::test]
    async fn login_needs_no_arbitrary_track_but_real_stream_validates_secret() {
        let (client, requests, worker) = client(vec![
            (200, json!({"user_auth_token":"new-token","user":{"id":42}})),
            (
                400,
                json!({"status":"error","message":"Invalid Request Signature parameter (request_sig)"}),
            ),
        ]);
        // This account has no guaranteed access to any unrelated test track. Login must
        // perform only account authentication, not fetch a sample or a fixed catalog ID.
        let client = client
            .finish_login("me@example.test", "private-password")
            .await
            .unwrap();
        assert_eq!(requests.lock().unwrap().len(), 1);
        assert_eq!(
            client
                .stream_url("actual-requested-track", 27)
                .await
                .err()
                .unwrap()
                .kind,
            QobuzErrorKind::InvalidSession
        );
        worker.join().unwrap();
        let requests = requests.lock().unwrap();
        assert_eq!(requests.len(), 2);
        assert!(requests[1].contains("track_id=actual-requested-track"));
        assert!(!requests.iter().any(|r| r.contains("5966783")));
    }
    #[test]
    fn retry_after_respects_seconds_dates_and_never_shortens_a_long_cooldown() {
        let now = UNIX_EPOCH + Duration::from_secs(1790812800);
        assert_eq!(retry_after(Some("30"), now), Duration::from_secs(30));
        let date = httpdate::fmt_http_date(now + Duration::from_secs(45));
        assert_eq!(retry_after(Some(&date), now), Duration::from_secs(45));
        assert_eq!(retry_after(Some("invalid"), now), Duration::from_secs(1));
        assert_eq!(
            retry_after(Some("18446744073709551615"), now),
            Duration::from_secs(u64::MAX)
        );
        let tick = Instant::now();
        let mut gate = RequestGate::default();
        gate.defer(tick, Duration::from_secs(3600));
        gate.defer(tick + Duration::from_secs(1), Duration::from_secs(30));
        assert_eq!(
            gate.delay(tick + Duration::from_secs(2)),
            Duration::from_secs(3598)
        );
        assert_eq!(gate.delay(tick + Duration::from_secs(3600)), Duration::ZERO);
    }
    #[tokio::test]
    async fn retry_after_delays_the_next_request_instead_of_just_returning_an_error() {
        let (client, requests, worker) = client_with_headers(vec![
            (429, json!({"status":"error"}), Some("1")),
            (200, json!({"id":42}), None),
        ]);
        assert_eq!(
            client.validate().await.unwrap_err().kind,
            QobuzErrorKind::Api
        );
        let cooldown_started = Instant::now();
        client.validate().await.unwrap();
        assert!(cooldown_started.elapsed() >= Duration::from_millis(950));
        worker.join().unwrap();
        assert_eq!(requests.lock().unwrap().len(), 2);
    }
}
