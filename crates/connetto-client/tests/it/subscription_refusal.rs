//! A subscription the server refuses with the one fixed phrase must reach the
//! live handle's error. `changed` returns the refusal instead of waiting for
//! the snapshot that never arrives, which is what the display hooks surface.

use std::time::Duration;

use connetto_client::{ClientBuilder, LiveQuery};
use connetto_core::Cursor;
use connetto_core::messages::{
    ControlMessage, HandshakeAck, NonFatalError, SUBSCRIPTION_REFUSED, WriterGrant,
};
use connetto_core::traits::{IncomingFrame, Transport};
use connetto_server::{LoopbackTransport, loopback};
use diesel::QueryDsl;

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

/// A server that answers the handshake, then refuses the first subscription
/// with the one fixed phrase and carries no snapshot.
fn refusing_server() -> LoopbackTransport {
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
        let sub_id = loop {
            match server.recv().await {
                Ok(Some(IncomingFrame::Control(ControlMessage::Subscribe(sub)))) => {
                    break sub.sub_id;
                }
                Ok(Some(_)) => {}
                _ => return,
            }
        };
        let _ = server
            .send_control(ControlMessage::NonFatalError(NonFatalError {
                related_to: Some(sub_id),
                detail: SUBSCRIPTION_REFUSED.to_owned(),
            }))
            .await;
        while let Ok(Some(_)) = server.recv().await {}
    });
    client_end
}

/// A subscription the server refused reaches the live handle's error: its
/// `changed` returns the refusal instead of waiting for the snapshot that
/// never arrives, and the text a display reads is the wire's own phrase.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refused_subscription_reaches_the_live_handle_error() {
    let (client, pump) = ClientBuilder::new(
        super::support::bundle(SQLITE_DDL),
        super::support::Once::new(refusing_server()),
    )
    .signed_in(super::support::held("token"))
    .connect_with_pump()
    .await
    .expect("connect with pump");
    tokio::spawn(pump);

    let mut photos: LiveQuery<Photo> = client
        .client()
        .watch(photos::table.order_by(photos::id))
        .await
        .expect("watch");

    let err = tokio::time::timeout(Duration::from_secs(5), photos.changed())
        .await
        .expect("the refusal must end the wait")
        .expect_err("the server refused the subscription");
    assert_eq!(
        err.to_string(),
        "subscription refused",
        "the display reads the wire's own phrase"
    );
}
