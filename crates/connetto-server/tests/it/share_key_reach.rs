//! Expiry resends only subscriptions reached by the authorization model.

use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use connetto_core::auth::Principal;
use connetto_core::messages::{
    BulkMessage, ControlMessage, FullResyncReason, FullResyncRequired, Grant, Handshake, Subscribe,
    SubscriptionSpec,
};
use connetto_core::test_support::TestGrantChecker;
use connetto_core::traits::{IncomingFrame, Transport};
use connetto_core::{Cursor, PROTOCOL_VERSION};
use connetto_server::openfga::{GrantMove, StoreUpkeep, UpkeepError};
use connetto_server::{
    LoopbackTransport, ManagerBuilder, Materializer, NoConnector, PageSpec, SessionManager,
    SnapshotEstimate, SnapshotPage, SnapshotSource, loopback, pg_write_target,
};
use connetto_test_harness::{ConnettoDefaults, Fixture, RosterAuth};
use subql::{CdcSource, PgChangeEvent, PgSqliteEmuSource, SourceItem};
use tracing::Instrument;

use super::share_key_clock::ExpiryClock;

const DDL: &str = "CREATE TABLE gated (id INT PRIMARY KEY, label TEXT); \
    CREATE TABLE plain (id INT PRIMARY KEY, label TEXT);";
const GATED: &str = "gated";
const PLAIN: &str = "plain";

/// Reports the deployment's key-gated tables.
struct ModelUpkeep {
    key_tables: Vec<String>,
}

impl StoreUpkeep for ModelUpkeep {
    fn keep_current<'a>(
        &'a self,
        _event: &'a PgChangeEvent,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<GrantMove>, UpkeepError>> + Send + 'a>> {
        Box::pin(async { Ok(Vec::new()) })
    }

    fn key_tables(&self) -> &[String] {
        &self.key_tables
    }
}

/// Carries the snapshot's keys in its payload.
#[derive(Clone, Copy)]
struct KeysSnapshot;

impl SnapshotSource for KeysSnapshot {
    type Error = std::convert::Infallible;

    #[expect(
        clippy::unused_async_trait_impl,
        reason = "the trait method is async and this body finishes without awaiting"
    )]
    async fn estimate(
        &self,
        _select_sql: &str,
        _binds: &[connetto_core::messages::BindValue],
        _caller: &Principal,
    ) -> Result<SnapshotEstimate, Self::Error> {
        Ok(SnapshotEstimate {
            rows: 1.0,
            width: 8,
        })
    }

    #[expect(
        clippy::unused_async_trait_impl,
        reason = "the trait method is async and this body finishes without awaiting"
    )]
    async fn snapshot_page(
        &self,
        _select_sql: &str,
        _binds: &[connetto_core::messages::BindValue],
        caller: &Principal,
        _page: &PageSpec,
    ) -> Result<SnapshotPage, Self::Error> {
        let patchset = caller
            .capabilities()
            .iter()
            .map(|key| key.key().clone())
            .collect::<Vec<_>>()
            .join(",")
            .into_bytes();
        let bytes = u64::try_from(patchset.len()).expect("a page length fits u64");
        Ok(SnapshotPage {
            patchset,
            cursor: Cursor::new(Vec::new()),
            next: None,
            filled: false,
            widest_row: bytes,
            rows: 1,
            bytes,
        })
    }
}

type Manager = Arc<SessionManager<KeysSnapshot, RosterAuth, ConnettoDefaults>>;

fn manager(fixture: &Fixture, clock: &ExpiryClock) -> Manager {
    ManagerBuilder::new(
        Materializer::builder(DDL)
            .build()
            .expect("build materializer"),
        KeysSnapshot,
        RosterAuth::granting("key:b"),
        Arc::new(TestGrantChecker),
        NoConnector,
        pg_write_target::<ConnettoDefaults>(fixture.admin().clone(), DDL)
            .expect("build write target"),
    )
    .with_upkeep(Arc::new(ModelUpkeep {
        key_tables: vec![GATED.to_owned()],
    }))
    .with_session(clock.session_config())
    .build()
}

async fn next_frame<T: Transport>(transport: &mut T) -> IncomingFrame {
    tokio::time::timeout(Duration::from_secs(10), transport.recv())
        .await
        .expect("a frame within ten seconds")
        .expect("recv frame")
        .expect("the connection is open")
}

async fn next_control<T: Transport>(transport: &mut T) -> ControlMessage {
    loop {
        if let IncomingFrame::Control(msg) = next_frame(transport).await {
            return msg;
        }
    }
}

async fn connect(manager: &Manager, grants: &[&str]) -> LoopbackTransport {
    let (server_end, mut client) = loopback();
    let server = Arc::clone(manager);
    tokio::spawn(
        async move { server.serve(server_end).await }.instrument(tracing::Span::current()),
    );
    let handshake = Handshake::new(PROTOCOL_VERSION, "share-key-reach")
        .with_grants(grants.iter().map(|grant| Grant::new(*grant)));
    client
        .send_control(ControlMessage::Handshake(handshake))
        .await
        .expect("send handshake");
    let ControlMessage::Challenge(_) = next_control(&mut client).await else {
        panic!("expected the leading challenge");
    };
    let ControlMessage::HandshakeAck(_) = next_control(&mut client).await else {
        panic!("expected the handshake ack");
    };
    client
}

async fn subscribe<T: Transport>(client: &mut T, label: &str, query: &str) {
    client
        .send_control(ControlMessage::Subscribe(Subscribe {
            sub_id: label.to_owned(),
            spec: SubscriptionSpec::new(query),
        }))
        .await
        .expect("send subscribe");
}

/// The control frames up to and including the first `stop` accepts.
async fn controls_until<T: Transport>(
    client: &mut T,
    stop: impl Fn(&ControlMessage) -> bool,
) -> Vec<ControlMessage> {
    let mut seen = Vec::new();
    loop {
        let msg = next_control(client).await;
        let done = stop(&msg);
        seen.push(msg);
        if done {
            return seen;
        }
    }
}

fn is_end(msg: &ControlMessage) -> bool {
    matches!(msg, ControlMessage::SnapshotEnd(_))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_expired_key_reaches_only_the_tables_the_model_gates() {
    let fixture = Fixture::acquire().await;
    let clock = ExpiryClock::new();
    let manager = manager(&fixture, &clock);
    let mut client = connect(&manager, &[&clock.grant("key:a"), "key:b"]).await;
    subscribe(&mut client, GATED, "SELECT * FROM gated").await;
    controls_until(&mut client, is_end).await;
    subscribe(&mut client, PLAIN, "SELECT * FROM plain").await;
    controls_until(&mut client, is_end).await;
    clock.advance(Duration::from_secs(1));

    let mut frames = Vec::new();
    loop {
        let frame = next_frame(&mut client).await;
        let done = match &frame {
            IncomingFrame::Control(ControlMessage::SnapshotEnd(end)) => end.sub_id == GATED,
            _ => false,
        };
        frames.push(frame);
        if done {
            break;
        }
    }

    let mut source = PgSqliteEmuSource::open_in_memory(DDL).expect("open change source");
    source
        .execute_sql("INSERT INTO plain VALUES (91, 'dispatch-fence')")
        .expect("insert fence row");
    while let Some(item) = source.next_item().await.expect("read change") {
        if let SourceItem::Event(event) = item {
            manager
                .dispatch_event(&event)
                .await
                .expect("dispatch fence");
        }
    }
    loop {
        let frame = next_frame(&mut client).await;
        if let IncomingFrame::Bulk(BulkMessage::LivePatch(patch)) = &frame {
            assert_eq!(patch.sub_id, PLAIN);
            break;
        }
        frames.push(frame);
    }

    let notices: Vec<&FullResyncRequired> = frames
        .iter()
        .filter_map(|frame| match frame {
            IncomingFrame::Control(ControlMessage::FullResyncRequired(notice)) => Some(notice),
            _ => None,
        })
        .collect();
    assert_eq!(
        notices.len(),
        1,
        "one resync, for the table the model gates"
    );
    assert_eq!(notices[0].sub_id, GATED);
    assert_eq!(notices[0].reason, FullResyncReason::AuthorizationChange);

    let pages: Vec<String> = frames
        .iter()
        .filter_map(|frame| match frame {
            IncomingFrame::Bulk(BulkMessage::SnapshotPatch(patch)) if patch.sub_id == GATED => {
                let decoded = zstd::decode_all(patch.patchset_zstd.as_slice()).expect("zstd");
                Some(String::from_utf8(decoded).expect("utf-8"))
            }
            _ => None,
        })
        .collect();
    assert_eq!(pages, ["key:b"], "the resend is read under the keys left");
}
