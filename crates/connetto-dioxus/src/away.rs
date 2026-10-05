//! The native away/return feeder (R94 step 5).
//!
//! Feeds the client's one away input from the desktop platform's lifecycle.
//! On iOS and Android it reads tao's `Suspended` and `Resumed` events, and on
//! the desktop it reads the window's focus, all through dioxus-desktop's
//! `use_wry_event_handler`. The browser's equivalent is the worker's
//! page-visibility feed, which the browser platform builds separately.

use connetto_client::{ConnettoClient, Moment, SystemClock};
use connetto_core::traits::{MaybeSend, Transport};
use dioxus_core::spawn;
use dioxus_desktop::tao::event::{Event, WindowEvent};
use dioxus_desktop::use_wry_event_handler;

/// What a platform event tells the client's away input to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AwayAction {
    /// Feed the client an away moment.
    Away,
    /// Feed the client a back moment.
    Back,
    /// The event feeds the client nothing.
    Nothing,
}

/// Map a tao platform event to the client's away input.
///
/// `Suspended` and a window losing focus mean the application went away, and
/// `Resumed` and a window gaining focus mean it came back. Every other event
/// feeds the client nothing, so the re-check reads only the real lifecycle
/// moments.
fn away_action<T>(event: &Event<'_, T>) -> AwayAction {
    match event {
        Event::Suspended => AwayAction::Away,
        Event::Resumed => AwayAction::Back,
        Event::WindowEvent {
            event: WindowEvent::Focused(focused),
            ..
        } => focused_to_action(*focused),
        _ => AwayAction::Nothing,
    }
}

/// Map the window's focus state to the client's away input.
///
/// Gaining focus means the application came back and losing it means it went
/// away, so `Focused(true)` is a back and `Focused(false)` is an away.
fn focused_to_action(focused: bool) -> AwayAction {
    if focused {
        AwayAction::Back
    } else {
        AwayAction::Away
    }
}

/// Feed this component's client away input from the platform's lifecycle.
///
/// Registers one wry event handler on the component's scope and maps the
/// platform's lifecycle to the client's away input (R94 decision 9). The
/// `Suspended` event and a window losing focus (`WindowEvent::Focused(false)`)
/// call `ConnettoClient::away`, and the `Resumed` event and a window gaining
/// focus (`WindowEvent::Focused(true)`) call `ConnettoClient::back`. Every
/// other event feeds the client nothing.
///
/// The handler runs on the event loop thread and spawns each call on the
/// component's scope, so the input is read for the component's lifetime.
/// Unmounting the component removes the handler and stops feeding the client.
/// On iOS and Android the `Suspended` and `Resumed` events carry the device
/// going to and out of sleep, and on the desktop the window's `Focused` event
/// is the lifecycle. The browser's equivalent is the worker's page-visibility
/// feed, which the browser platform builds separately.
pub fn use_away_input<T>(client: &ConnettoClient<T>)
where
    T: Transport + MaybeSend + 'static,
    T::Error: core::fmt::Display,
{
    let client = client.clone();
    use_wry_event_handler(move |event, _target| match away_action(event) {
        AwayAction::Away => {
            let at = Moment::now(&SystemClock);
            tracing::debug!(?at, ?event, "the platform reported the app going away");
            let client = client.clone();
            spawn(async move {
                client.away(at).await;
            });
        }
        AwayAction::Back => {
            let at = Moment::now(&SystemClock);
            tracing::debug!(?at, ?event, "the platform reported the app coming back");
            let client = client.clone();
            spawn(async move {
                client.back(at).await;
            });
        }
        AwayAction::Nothing => {}
    });
}

#[cfg(test)]
mod tests {
    use super::{AwayAction, away_action, focused_to_action};
    use dioxus_desktop::tao::event::Event;

    fn unrelated() -> Event<'static, ()> {
        Event::MainEventsCleared
    }

    fn suspended() -> Event<'static, ()> {
        Event::Suspended
    }

    fn resumed() -> Event<'static, ()> {
        Event::Resumed
    }

    #[test]
    fn the_lifecycle_events_feed_away_and_back_and_the_rest_feed_nothing() {
        // Suspended means the application went away.
        assert_eq!(away_action(&suspended()), AwayAction::Away);

        // Resumed means it came back.
        assert_eq!(away_action(&resumed()), AwayAction::Back);

        // A window gaining focus is a back, and losing focus is an away.
        assert_eq!(focused_to_action(true), AwayAction::Back);
        assert_eq!(focused_to_action(false), AwayAction::Away);

        // An unrelated event feeds the client nothing.
        assert_eq!(away_action(&unrelated()), AwayAction::Nothing);
    }
}
