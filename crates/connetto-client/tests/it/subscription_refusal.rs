//! A subscription the server refuses with the one fixed phrase must reach the
//! live handle's error. `changed` returns the refusal instead of waiting for
//! the snapshot that never arrives, which is what the display hooks surface.
//! The refusal stands on later calls, reaches scalar and computed handles as
//! it does row handles, and touches only the handle it names. A non-fatal
//! error with any other detail refuses nothing.

use std::time::Duration;

use connetto_client::{ClientBuilder, LiveQuery};
use connetto_core::Cursor;
use connetto_core::messages::{
    BulkMessage, ControlMessage, HandshakeAck, NonFatalError, SUBSCRIPTION_REFUSED, SnapshotBegin,
    SnapshotEnd, SnapshotPatch, SubscriptionPriority, WriterGrant,
};
use connetto_core::traits::{IncomingFrame, Transport};
use connetto_server::{LoopbackTransport, loopback};
use diesel::{ExpressionMethods, QueryDsl};
use sqlite_diff_rs::{DiffOps, Insert, PatchSet, SimpleTable, Value};

/// The bound every wait here runs under.
const BOUND: Duration = Duration::from_secs(5);

const SQLITE_DDL: &str = "CREATE TABLE photos (id INTEGER PRIMARY KEY, content_state TEXT) STRICT;";

diesel::table! {
    /// The test photos table.
    photos (id) {
        /// Photo identifier.
        id -> diesel::sql_types::BigInt,
        /// Content standing, nullable.
        content_state -> diesel::sql_types::Nullable<diesel::sql_types::Text>,
    }
}

#[derive(Clone, PartialEq, diesel::Queryable, diesel::Selectable, Debug)]
#[diesel(table_name = photos)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
struct Photo {
    /// Photo identifier.
    id: i64,
    /// Content standing.
    content_state: Option<String>,
}

/// How the scripted server answers one subscription.
#[derive(Clone, Copy)]
enum Answer {
    /// The one fixed refusal phrase, and no snapshot.
    Refuse,
    /// A non-fatal error naming the subscription with another detail, then
    /// the snapshot.
    OtherError,
    /// The snapshot, one photo row.
    Serve,
    /// The one fixed refusal phrase, then a beat later the snapshot after
    /// all, as a server that re-serves a subscription it refused.
    RefuseThenServe,
}

/// Compressed changeset bytes inserting the one served photo.
fn photo_row() -> Vec<u8> {
    let insert = Insert::<_, String, Vec<u8>>::from(SimpleTable::new(
        "photos",
        &["id", "content_state"],
        &[0],
    ))
    .set(0, Value::Integer(1))
    .expect("set id")
    .set(1, Value::Text("available".to_owned()))
    .expect("set content_state");
    let patchset = PatchSet::<SimpleTable, String, Vec<u8>>::new().insert(insert);
    zstd::encode_all(patchset.build().as_slice(), 3).expect("compress the row")
}

/// A server that answers the handshake, waits for one subscription per
/// entry of `answers`, and then answers each in arrival order, a beat apart
/// so a handle the test left waiting is waiting when the earlier answers land.
fn scripted_server(answers: Vec<Answer>) -> LoopbackTransport {
    let (mut server, client_end) = loopback();
    tokio::spawn(async move {
        let Ok(Some(IncomingFrame::Control(ControlMessage::Handshake(_)))) = server.recv().await
        else {
            return;
        };
        let _ = server
            .send_control(ControlMessage::HandshakeAck(HandshakeAck {
                connection_id: "refusal".to_owned(),
                session_token: "refusal".to_owned(),
                resume_token: "refusal".to_owned(),
                current_cursor: Cursor::new(Vec::new()),
                schema_version: None,
                initial_credits: 64,
                writer: Some(WriterGrant {
                    number: 1,
                    frontier: 0,
                }),
            }))
            .await;
        let mut sub_ids = Vec::with_capacity(answers.len());
        while sub_ids.len() < answers.len() {
            match server.recv().await {
                Ok(Some(IncomingFrame::Control(ControlMessage::Subscribe(sub)))) => {
                    sub_ids.push(sub.sub_id);
                }
                Ok(Some(_)) => {}
                _ => return,
            }
        }
        for (sub_id, answer) in sub_ids.into_iter().zip(answers) {
            tokio::time::sleep(Duration::from_millis(100)).await;
            let detail = match answer {
                Answer::Refuse | Answer::RefuseThenServe => Some(SUBSCRIPTION_REFUSED),
                Answer::OtherError => Some("the server is busy"),
                Answer::Serve => None,
            };
            if let Some(detail) = detail {
                let _ = server
                    .send_control(ControlMessage::NonFatalError(NonFatalError {
                        related_to: Some(sub_id.clone()),
                        detail: detail.to_owned(),
                    }))
                    .await;
            }
            match answer {
                Answer::Refuse => continue,
                Answer::RefuseThenServe => tokio::time::sleep(Duration::from_millis(100)).await,
                Answer::OtherError | Answer::Serve => {}
            }
            let _ = server
                .send_control(ControlMessage::SnapshotBegin(SnapshotBegin {
                    sub_id: sub_id.clone(),
                    priority: SubscriptionPriority::default(),
                }))
                .await;
            let _ = server
                .send_bulk(BulkMessage::SnapshotPatch(SnapshotPatch {
                    sub_id: sub_id.clone(),
                    patchset_zstd: photo_row(),
                }))
                .await;
            let _ = server
                .send_control(ControlMessage::SnapshotEnd(SnapshotEnd {
                    sub_id,
                    cursor: Cursor::new(vec![1]),
                }))
                .await;
        }
        while let Ok(Some(_)) = server.recv().await {}
    });
    client_end
}

/// A running client over a server answering its subscriptions per `answers`.
async fn client_over(answers: Vec<Answer>) -> connetto_client::ConnettoClient<LoopbackTransport> {
    let (running, pump) = ClientBuilder::new(
        super::support::bundle(SQLITE_DDL),
        super::support::Once::new(scripted_server(answers)),
    )
    .signed_in(super::support::held("token"))
    .connect_with_pump()
    .await
    .expect("connect with pump");
    tokio::spawn(pump);
    running.client().clone()
}

/// A subscription the server refused reaches the live handle's error: its
/// `changed` returns the refusal instead of waiting for the snapshot that
/// never arrives, the text a display reads is the wire's own phrase, and a
/// later call answers the same refusal at once.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refused_subscription_reaches_the_live_handle_error() {
    let client = client_over(vec![Answer::Refuse]).await;
    let mut photos: LiveQuery<Photo> = client
        .watch(photos::table.order_by(photos::id))
        .await
        .expect("watch");

    let err = tokio::time::timeout(BOUND, photos.changed())
        .await
        .expect("the refusal must end the wait")
        .expect_err("the server refused the subscription");
    assert_eq!(
        err.to_string(),
        "subscription refused",
        "the display reads the wire's own phrase"
    );
    let again = tokio::time::timeout(Duration::from_millis(100), photos.changed())
        .await
        .expect("a standing refusal answers without waiting")
        .expect_err("the refusal stands");
    assert_eq!(again.to_string(), "subscription refused");
}

/// A refusal wakes every waiting handle, and one the server did not refuse
/// goes on waiting and then sees its rows.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refusal_leaves_the_other_handles_waiting() {
    let client = client_over(vec![Answer::Refuse, Answer::Serve]).await;
    let mut refused: LiveQuery<Photo> = client
        .watch(photos::table.order_by(photos::id))
        .await
        .expect("watch the refused query");
    let mut served: LiveQuery<Photo> = client
        .watch(photos::table.filter(photos::content_state.is_not_null()))
        .await
        .expect("watch the served query");
    // The served handle is already waiting when the other refusal lands.
    let waiting = tokio::spawn(async move {
        tokio::time::timeout(BOUND, served.changed())
            .await
            .expect("the served rows end the wait")
            .map(|()| served.rows())
    });
    tokio::time::timeout(BOUND, refused.changed())
        .await
        .expect("the refusal must end the wait")
        .expect_err("the server refused this subscription");
    let rows = waiting
        .await
        .expect("the waiting task")
        .expect("a refusal of another subscription leaves this one live");
    assert_eq!(
        rows,
        vec![Photo {
            id: 1,
            content_state: Some("available".to_owned()),
        }]
    );
}

/// A refused scalar aggregate and a refused computed read reach their
/// handles' errors as a row query's does.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refusal_reaches_value_and_computed_handles() {
    let client = client_over(vec![Answer::Refuse, Answer::Refuse]).await;
    let mut count = client
        .watch_value::<_, i64>(photos::table.count())
        .await
        .expect("watch the count");
    let mut ids = client
        .watch_rows::<_, (i64,)>(photos::table.select((photos::id,)))
        .await
        .expect("watch the computed ids");
    let err = tokio::time::timeout(BOUND, count.changed())
        .await
        .expect("the refusal must end the count's wait")
        .expect_err("the server refused the count");
    assert_eq!(err.to_string(), "subscription refused");
    let err = tokio::time::timeout(BOUND, ids.changed())
        .await
        .expect("the refusal must end the computed read's wait")
        .expect_err("the server refused the computed read");
    assert_eq!(err.to_string(), "subscription refused");
}

/// A non-fatal error naming the subscription with any other detail refuses
/// nothing, so the snapshot that follows still reaches the handle.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn another_non_fatal_detail_refuses_nothing() {
    let client = client_over(vec![Answer::OtherError]).await;
    let mut photos: LiveQuery<Photo> = client
        .watch(photos::table.order_by(photos::id))
        .await
        .expect("watch");
    tokio::time::timeout(BOUND, photos.changed())
        .await
        .expect("the snapshot ends the wait")
        .expect("another detail is no refusal");
    assert_eq!(photos.rows().len(), 1, "the served row reached the handle");
}

/// A subscription the server serves after refusing it is live again: the
/// handle that answered the refusal sees the rows once they arrive.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_re_served_subscription_clears_its_refusal() {
    let client = client_over(vec![Answer::RefuseThenServe]).await;
    let mut photos: LiveQuery<Photo> = client
        .watch(photos::table.order_by(photos::id))
        .await
        .expect("watch");
    tokio::time::timeout(BOUND, photos.changed())
        .await
        .expect("the refusal must end the wait")
        .expect_err("the server refused the subscription first");
    let served = tokio::time::timeout(BOUND, async {
        loop {
            if photos.changed().await.is_ok() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    assert!(served.is_ok(), "the re-served snapshot clears the refusal");
    assert_eq!(photos.rows().len(), 1, "the served row reached the handle");
}
