//! Asking for a content ticket and waiting for the one answer.
//!
//! The correlation is the client-chosen `request_id` the server echoes on the
//! grant and on every refusal, so the wait is a filter over the pump's event
//! stream rather than a second bookkeeping map inside the client.

use core::fmt::Display;
use core::sync::atomic::{AtomicU64, Ordering};

use connetto_client::live::ConnettoClient;
use connetto_client::{ClientEvent, ConnettoConnection};
use connetto_core::messages::{CONTENT_TICKET_REFUSED, CONTENT_TICKET_SIGNER_ERROR, ContentVerb};
use connetto_core::traits::Transport;
use connetto_file_core::{FileId, MaybeSend};
use tokio::sync::broadcast::error::RecvError;

use crate::error::ContentError;

/// Source of request ids unique within this process.
static NEXT_REQUEST: AtomicU64 = AtomicU64::new(0);

/// Asks for one ticket and returns the URL the server granted.
///
/// The subscription is taken before the request goes out, so an answer the
/// pump delivers immediately cannot be missed.
pub(crate) async fn request<T>(
    client: &ConnettoClient<T>,
    file_id: FileId,
    verb: ContentVerb,
) -> Result<String, ContentError>
where
    T: Transport + MaybeSend + 'static,
    T::Error: Display,
{
    let request_id = next_request_id();
    let mut events = client.events();
    client
        .request_content_ticket(request_id.clone(), *file_id.as_bytes(), verb)
        .await?;
    loop {
        match events.recv().await {
            Ok(ClientEvent::ContentTicket {
                request_id: id,
                url,
            }) if id == request_id => {
                return Ok(url);
            }
            Ok(ClientEvent::NonFatal { related_to, detail })
                if related_to.as_deref() == Some(request_id.as_str()) =>
            {
                return Err(refusal(&detail, file_id));
            }
            Ok(ClientEvent::RateLimited {
                related_to,
                retry_after_ms,
            }) if related_to.as_deref() == Some(request_id.as_str()) => {
                return Err(ContentError::TicketRateLimited { retry_after_ms });
            }
            Ok(_) => {}
            Err(RecvError::Lagged(_)) => return Err(ContentError::TicketLagged),
            // The link this request rode is gone, so no answer to it is
            // coming: the server correlates a refusal to a request only
            // within the session that carried it. Connection state is not one
            // of these, because it arrives as a queued notice a caller can
            // observe after the request already went out over a live wire,
            // and a request with no wire fails at the send instead.
            Err(RecvError::Closed) => return Err(ContentError::TicketAbandoned),
        }
    }
}

pub(crate) struct PendingTicket {
    pub(crate) file_id: FileId,
    request_id: String,
}

pub(crate) async fn request_connection_or<T, C>(
    connection: &mut ConnettoConnection<T>,
    file_id: FileId,
    verb: ContentVerb,
    observed: &mut Vec<ClientEvent>,
    cancel: C,
    pending: &mut Option<PendingTicket>,
) -> Result<Option<String>, ContentError>
where
    T: Transport,
    T::Error: Display,
    C: core::future::Future<Output = ()>,
{
    if pending.is_none() {
        let request_id = next_request_id();
        connection
            .request_content_ticket(request_id.clone(), *file_id.as_bytes(), verb)
            .await?;
        *pending = Some(PendingTicket {
            file_id,
            request_id,
        });
    }
    tokio::pin!(cancel);
    loop {
        let event = match connection.pump_one_or(cancel.as_mut()).await {
            Ok(Some(event)) => event,
            Ok(None) => return Ok(None),
            Err(err) => {
                pending.take();
                return Err(err.into());
            }
        };
        match event {
            ClientEvent::ContentTicket { request_id, url }
                if pending
                    .as_ref()
                    .is_some_and(|ticket| ticket.request_id == request_id) =>
            {
                pending.take();
                return Ok(Some(url));
            }
            ClientEvent::NonFatal { related_to, detail }
                if pending.as_ref().is_some_and(|ticket| {
                    related_to.as_deref() == Some(ticket.request_id.as_str())
                }) =>
            {
                pending.take();
                return Err(refusal(&detail, file_id));
            }
            ClientEvent::RateLimited {
                related_to,
                retry_after_ms,
            } if pending.as_ref().is_some_and(|ticket| {
                related_to.as_deref() == Some(ticket.request_id.as_str())
            }) =>
            {
                pending.take();
                return Err(ContentError::TicketRateLimited { retry_after_ms });
            }
            event @ (ClientEvent::Closed | ClientEvent::ServerClosed { .. }) => {
                pending.take();
                observed.push(event);
                return Err(ContentError::TicketAbandoned);
            }
            event => observed.push(event),
        }
    }
}

fn next_request_id() -> String {
    format!("content-{}", NEXT_REQUEST.fetch_add(1, Ordering::Relaxed))
}

/// Reads the two refusal details the ticket path defines.
fn refusal(detail: &str, file_id: FileId) -> ContentError {
    if detail == CONTENT_TICKET_SIGNER_ERROR {
        return ContentError::TicketSignerError { file_id };
    }
    debug_assert_eq!(
        detail, CONTENT_TICKET_REFUSED,
        "a non-fatal error correlated to a ticket request carries one of the two ticket details"
    );
    ContentError::TicketRefused { file_id }
}
