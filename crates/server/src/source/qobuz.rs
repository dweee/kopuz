//! Native Qobuz catalog and full-length playback; each configured account stays source-scoped.
use super::{
    AlbumType, ArtistView, AuthOutcome, Capabilities, FavoritesSync, LibrarySnapshot, MediaSource,
    PlaylistMeta, PlaylistOps, RadioSeeds, RemoteAlbum, SourceError, StreamInfo, mirror_added,
    mirror_created,
};
use crate::{
    qobuz::{QobuzClient, QobuzError, QobuzErrorKind, QobuzStream},
    server_ops::ServerConn,
};
use async_trait::async_trait;
use config::{MusicService, Source};
use db::Db;
use reader::models::TrackId;
use reader::{Album, ArtistCredit, Track};
use serde_json::Value;
use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
    sync::{Mutex, OnceLock},
};

impl From<QobuzError> for SourceError {
    fn from(error: QobuzError) -> Self {
        match error.kind {
            QobuzErrorKind::Auth => Self::Auth,
            QobuzErrorKind::Network => Self::Connectivity,
            _ => Self::Backend(error.to_string()),
        }
    }
}
type Reports = HashMap<u64, (Source, QobuzClient, QobuzStream)>;
fn reports() -> &'static Mutex<Reports> {
    static REPORTS: OnceLock<Mutex<Reports>> = OnceLock::new();
    REPORTS.get_or_init(|| Mutex::new(HashMap::new()))
}
/// Resolved streams are only announced when the daemon actually starts playing.
/// Merely searching, preloading or resolving a URL never reports a listen.
pub fn take_playback_report(token: u64) -> Option<(Source, QobuzClient, QobuzStream)> {
    reports().lock().ok()?.remove(&token)
}

fn cached_client(source: &Source, packed: &str) -> Result<QobuzClient, QobuzError> {
    type Clients = HashMap<String, (String, QobuzClient)>;
    static CLIENTS: OnceLock<Mutex<Clients>> = OnceLock::new();
    if let Ok(mut clients) = CLIENTS.get_or_init(|| Mutex::new(HashMap::new())).lock() {
        if let Some((previous, client)) = clients.get(source.as_str())
            && previous == packed
        {
            return Ok(client.clone());
        }
        let client = QobuzClient::from_session(packed)?;
        if clients.len() >= 128 {
            clients.clear();
        }
        clients.insert(
            source.as_str().to_owned(),
            (packed.to_owned(), client.clone()),
        );
        return Ok(client);
    }
    QobuzClient::from_session(packed)
}
pub(super) struct QobuzSource {
    db: Db,
    source: Source,
    client: Result<QobuzClient, QobuzError>,
    original_session: String,
}
impl QobuzSource {
    pub(super) fn new(db: Db, source: Source, conn: &ServerConn) -> Self {
        Self {
            db,
            source: source.clone(),
            client: cached_client(&source, &conn.token),
            original_session: conn.token.clone(),
        }
    }
    fn client(&self) -> Result<&QobuzClient, SourceError> {
        self.client.as_ref().map_err(|_| SourceError::Auth)
    }
    async fn resolve(
        &self,
        item_id: &str,
        playback_token: Option<u64>,
    ) -> Result<StreamInfo, SourceError> {
        let client = self.client()?;
        let stream = client.stream_url(item_id, 27).await?;
        let updated = client.pack_session()?;
        if updated != self.original_session {
            self.db
                .rotate_server_credentials(self.source.as_str(), &self.original_session, &updated)
                .await?;
        }
        let info = StreamInfo {
            url: stream.url.clone(),
            format: None,
            user_agent: None,
            duration_secs: stream.metadata["duration"].as_u64(),
            bitrate: None,
            content_length: None,
            loudness_db: None,
        };
        if let Some(token) = playback_token
            && let Ok(mut pending) = reports().lock()
        {
            if pending.len() >= 128 {
                pending.clear();
            }
            pending.insert(token, (self.source.clone(), client.clone(), stream));
        }
        Ok(info)
    }
    fn tracks(&self, values: &[Value], album: Option<&Value>) -> Vec<Track> {
        values
            .iter()
            .filter_map(|v| parse_track(v, album, &self.source))
            .collect()
    }
}
fn id(value: &Value) -> Option<String> {
    value
        .as_str()
        .filter(|v| !v.is_empty())
        .map(str::to_owned)
        .or_else(|| value.as_u64().map(|v| v.to_string()))
}
fn text(value: &Value) -> String {
    value.as_str().unwrap_or_default().to_owned()
}
fn cover(value: &Value) -> Option<String> {
    ["large", "small", "thumbnail"].iter().find_map(|key| {
        value["image"][key]
            .as_str()
            .filter(|url| url.starts_with("https://"))
            .map(str::to_owned)
    })
}
fn name(value: &Value) -> String {
    let n = text(&value["name"]);
    if n.is_empty() {
        text(&value["title"])
    } else {
        n
    }
}
fn parse_album(value: &Value) -> Option<Album> {
    let artist = &value["artist"];
    Some(Album {
        id: id(&value["id"])?,
        title: text(&value["title"]),
        artist: name(artist),
        genre: name(&value["genre"]),
        year: value["release_date_original"]
            .as_str()
            .and_then(|s| s.get(..4))
            .and_then(|s| s.parse().ok())
            .unwrap_or(0),
        cover_path: cover(value).map(PathBuf::from),
        manual_cover: false,
        artist_id: id(&artist["id"]),
        artist_key: id(&artist["id"]),
    })
}
fn parse_track(value: &Value, fallback_album: Option<&Value>, source: &Source) -> Option<Track> {
    let album = value
        .get("album")
        .filter(|a| a.is_object())
        .or(fallback_album)
        .unwrap_or(&Value::Null);
    let lead = value
        .get("performer")
        .filter(|a| a.is_object())
        .unwrap_or(&album["artist"]);
    let artist = name(lead);
    let mut credit = match id(&lead["id"]) {
        Some(id) => ArtistCredit::linked(&artist, id),
        None => ArtistCredit::unlinked(&artist),
    };
    credit.source = Some(source.clone());
    let title = text(&value["title"]);
    let version = text(&value["version"]);
    Some(Track {
        id: TrackId::Server {
            service: MusicService::Qobuz,
            item_id: id(&value["id"])?,
        },
        cover: cover(album),
        album_id: id(&album["id"]).unwrap_or_default(),
        title: if version.is_empty() {
            title
        } else {
            format!("{title} ({version})")
        },
        artist: artist.clone(),
        album: text(&album["title"]),
        duration: value["duration"].as_u64().unwrap_or(0),
        khz: value["maximum_sampling_rate"]
            .as_f64()
            .unwrap_or(0.0)
            .round() as u32,
        bitrate: 0,
        track_number: value["track_number"]
            .as_u64()
            .and_then(|n| n.try_into().ok()),
        disc_number: value["media_number"]
            .as_u64()
            .and_then(|n| n.try_into().ok()),
        musicbrainz_release_id: None,
        musicbrainz_recording_id: None,
        musicbrainz_track_id: None,
        playlist_item_id: id(&value["playlist_track_id"]),
        artists: vec![artist],
        credits: vec![credit],
        replay_gain: Default::default(),
    })
}
fn playlist_ids(refs: &[String]) -> Result<Vec<String>, SourceError> {
    refs.iter()
        .map(|reference| {
            let id = reference.strip_prefix("qobuz:").unwrap_or(reference);
            if id.is_empty()
                || !id.bytes().all(|b| b.is_ascii_digit())
                || id.parse::<u64>().is_err()
            {
                return Err(SourceError::InvalidInput(
                    "Only Qobuz track IDs can be added to a Qobuz playlist".into(),
                ));
            }
            Ok(id.to_owned())
        })
        .collect()
}
#[async_trait]
impl MediaSource for QobuzSource {
    fn source(&self) -> &Source {
        &self.source
    }
    fn db(&self) -> &Db {
        &self.db
    }
    fn capabilities(&self) -> Capabilities {
        Capabilities {
            edit_tags: false,
            delete_from_disk: false,
            scan_folders: false,
            folders: false,
            browse_folders: false,
            external_devices: false,
            browser_playback: false,
            sync: true,
            downloads: false,
            uploads: false,
            storage_quota: false,
            discover: false,
            dont_recommend: false,
            radio: RadioSeeds::NONE,
            play_queue: false,
            playlists: PlaylistOps::AddRemove,
            artist_view: ArtistView::Remote,
            albums: AlbumType::YtMusic,
            favorites_sync: FavoritesSync::Instant,
        }
    }
    async fn validate(&self) -> AuthOutcome {
        match self.client() {
            Ok(c) => match c.validate().await {
                Ok(_) => AuthOutcome::Valid,
                Err(e)
                    if matches!(
                        e.kind,
                        QobuzErrorKind::Auth | QobuzErrorKind::InvalidSession
                    ) =>
                {
                    AuthOutcome::Expired
                }
                Err(_) => AuthOutcome::Unreachable,
            },
            Err(_) => AuthOutcome::Expired,
        }
    }
    async fn resolve_stream(&self, item_id: &str) -> Result<StreamInfo, SourceError> {
        self.resolve(item_id, None).await
    }
    async fn resolve_stream_for_playback(
        &self,
        item_id: &str,
        token: u64,
    ) -> Result<StreamInfo, SourceError> {
        self.resolve(item_id, Some(token)).await
    }
    fn web_url(&self, track: &Track) -> Option<String> {
        Some(format!("https://open.qobuz.com/track/{}", track.id.key()))
    }
    fn album_web_url(&self, id: &str) -> Option<String> {
        Some(format!("https://open.qobuz.com/album/{id}"))
    }
    async fn search(&self, query: &str) -> Result<(Vec<Track>, Vec<Album>), SourceError> {
        let result = self.client()?.search(query, 100).await?;
        Ok((
            self.tracks(
                result["tracks"]["items"]
                    .as_array()
                    .map(Vec::as_slice)
                    .unwrap_or_default(),
                None,
            ),
            result["albums"]["items"]
                .as_array()
                .map(|a| a.iter().filter_map(parse_album).collect())
                .unwrap_or_default(),
        ))
    }
    async fn fetch_album_tracks(&self, id: &str) -> Result<Vec<Track>, SourceError> {
        let client = self.client()?;
        let album = client.album(id).await?;
        Ok(self.tracks(&client.album_tracks(id).await?, Some(&album)))
    }
    async fn fetch_album(&self, id: &str) -> Result<RemoteAlbum, SourceError> {
        let album = self.client()?.album(id).await?;
        Ok(RemoteAlbum {
            browse_id: id.to_owned(),
            title: text(&album["title"]),
            artist: Some(name(&album["artist"])),
            artist_id: self::id(&album["artist"]["id"]),
            year: album["release_date_original"]
                .as_str()
                .and_then(|s| s.get(..4))
                .map(str::to_owned),
            thumbnail: cover(&album),
            audio_playlist_id: None,
            tracks: self.fetch_album_tracks(id).await?,
        })
    }
    async fn fetch_album_by_ref(&self, id: &str) -> Result<Option<RemoteAlbum>, SourceError> {
        self.fetch_album(id.strip_prefix("qobuz:album:").unwrap_or(id))
            .await
            .map(Some)
    }
    async fn fetch_artist(
        &self,
        artist_id: &str,
    ) -> Result<crate::ytmusic::discover::YtArtist, SourceError> {
        use crate::ytmusic::discover::{DiscoverItem, DiscoverShelf, YtArtist};
        let client = self.client()?;
        let artist = client.artist(artist_id).await?;
        let items = client
            .artist_albums(artist_id)
            .await?
            .into_iter()
            .filter_map(|album| {
                Some(DiscoverItem::Album {
                    browse_id: id(&album["id"])?,
                    title: text(&album["title"]),
                    subtitle: name(&album["artist"]),
                    thumbnail: cover(&album),
                })
            })
            .collect();
        Ok(YtArtist {
            channel_id: artist_id.to_owned(),
            name: name(&artist),
            subscribers: None,
            description: artist["biography"]["content"].as_str().map(str::to_owned),
            banner_thumbnail: cover(&artist),
            shuffle_playlist_id: None,
            sections: vec![DiscoverShelf {
                title: "Albums".into(),
                strapline: None,
                more_browse_id: None,
                items,
                is_song_list: false,
            }],
        })
    }
    async fn fetch_library(&self) -> Result<LibrarySnapshot, SourceError> {
        let client = self.client()?;
        let values = client.favorites("albums").await?;
        let mut snapshot = LibrarySnapshot::default();
        let mut seen = HashSet::new();
        for value in values {
            if let Some(album) = parse_album(&value) {
                for track in self.fetch_album_tracks(&album.id).await? {
                    if seen.insert(track.id.clone()) {
                        snapshot.tracks.push(track);
                    }
                }
                snapshot.albums.push(album);
            }
        }
        for track in self.tracks(&client.favorites("tracks").await?, None) {
            if seen.insert(track.id.clone()) {
                snapshot.tracks.push(track);
            }
        }
        Ok(snapshot)
    }
    async fn fetch_favorites(&self) -> Result<Vec<String>, SourceError> {
        Ok(self
            .client()?
            .favorites("tracks")
            .await?
            .iter()
            .filter_map(|v| id(&v["id"]))
            .collect())
    }
    async fn push_favorite(&self, id: &str, on: bool) -> Result<(), SourceError> {
        self.client()?
            .set_favorite(id, on)
            .await
            .map_err(Into::into)
    }
    async fn fetch_playlists(&self) -> Result<Vec<PlaylistMeta>, SourceError> {
        Ok(self
            .client()?
            .playlists()
            .await?
            .iter()
            .filter_map(|v| {
                Some(PlaylistMeta {
                    id: id(&v["id"])?,
                    name: name(v),
                    image_tag: cover(v),
                })
            })
            .collect())
    }
    async fn fetch_playlist_entries(&self, id: &str) -> Result<Vec<Track>, SourceError> {
        Ok(self.tracks(&self.client()?.playlist_tracks(id).await?, None))
    }
    async fn add_to_playlist(
        &self,
        playlist: &str,
        refs: &[String],
    ) -> Result<Vec<String>, SourceError> {
        let ids = playlist_ids(refs)?;
        self.client()?.add_playlist_tracks(playlist, &ids).await?;
        mirror_added(&self.db, &self.source, playlist, refs).await?;
        Ok(refs.to_vec())
    }
    async fn create_playlist(&self, name: &str, refs: &[String]) -> Result<String, SourceError> {
        let ids = playlist_ids(refs)?;
        let client = self.client()?;
        let id = client.create_playlist(name).await?;
        if !refs.is_empty() {
            client.add_playlist_tracks(&id, &ids).await?;
        }
        mirror_created(&self.db, &self.source, &id, name, refs).await?;
        Ok(id)
    }
    async fn remove_from_playlist(
        &self,
        playlist: &str,
        track: &Track,
        _position: usize,
    ) -> Result<(), SourceError> {
        let entry = track.playlist_item_id.as_ref().ok_or_else(|| {
            SourceError::InvalidInput(
                "Qobuz playlist entry ID is missing; refresh the playlist".into(),
            )
        })?;
        self.client()?
            .remove_playlist_tracks(playlist, std::slice::from_ref(entry))
            .await?;
        self.remove_playlist_entry(playlist, _position).await
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn playback_reports_bind_account_and_blob_to_engine_token() {
        let mut pending = reports().lock().unwrap();
        for (token, account, blob) in [
            (u64::MAX - 10, "account-a", "first"),
            (u64::MAX - 11, "account-b", "second"),
            (u64::MAX - 12, "account-a", "repeat"),
        ] {
            let session=json!({"app_id":"fixture-app","app_secret":"fixture-secret","user_auth_token":account,"user_id":account}).to_string();
            let client = QobuzClient::from_session(&session).unwrap();
            pending.insert(
                token,
                (
                    Source::Server(account.into()),
                    client,
                    QobuzStream {
                        url: "https://example.test/audio.flac".into(),
                        format_id: 27,
                        track_id: "42".into(),
                        metadata: json!({"blob":blob}),
                    },
                ),
            );
        }
        drop(pending);
        for (token, account, blob) in [
            (u64::MAX - 10, "account-a", "first"),
            (u64::MAX - 11, "account-b", "second"),
            (u64::MAX - 12, "account-a", "repeat"),
        ] {
            let (source, client, stream) = take_playback_report(token).unwrap();
            assert_eq!(source.as_str(), account);
            assert_eq!(client.user_id(), account);
            assert_eq!(stream.metadata["blob"], blob);
            assert_eq!(stream.track_id, "42");
            assert!(
                take_playback_report(token).is_none(),
                "a committed play consumes its own report exactly once"
            );
        }
    }
    #[test]
    fn playlists_reject_cross_service_refs() {
        assert_eq!(
            playlist_ids(&["qobuz:12".into(), "34".into()]).unwrap(),
            ["12", "34"]
        );
        for value in ["spotify:12", "jellyfin:12", "qobuz:", "1/evil", "-1"] {
            assert!(playlist_ids(&[value.into()]).is_err());
        }
    }
    #[test]
    fn metadata_is_typed_and_scoped() {
        let source = Source::Server("qobuz-account-2".into());
        let value = json!({"id":42,"title":"Song","version":"Live","duration":121,"track_number":2,"media_number":1,"playlist_track_id":99,"maximum_sampling_rate":96,"performer":{"id":3,"name":"Singer"},"album":{"id":"album-id","title":"Record","artist":{"name":"Singer"},"image":{"large":"https://example.org/art.jpg"}}});
        let t = parse_track(&value, None, &source).unwrap();
        assert_eq!(t.id.uid(), "qobuz:42");
        assert_eq!(t.title, "Song (Live)");
        assert_eq!(t.album_id, "album-id");
        assert_eq!(t.credits[0].source, Some(source));
        assert_eq!(t.playlist_item_id.as_deref(), Some("99"));
        assert_eq!(t.khz, 96);
        assert!(t.id.local_path().is_none());
    }
    #[test]
    fn album_context_restores_missing_track_album() {
        let source = Source::Server("q".into());
        let album = json!({"id":"a","title":"Album","artist":{"id":5,"name":"Artist"}});
        let t = parse_track(&json!({"id":1,"title":"Track"}), Some(&album), &source).unwrap();
        assert_eq!(t.album, "Album");
        assert_eq!(t.artist, "Artist");
    }
}
