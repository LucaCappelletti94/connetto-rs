//! The discovery policy, the discovery table as a pure state machine on an
//! injected clock.

use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use crate::CloseReason;
use crate::fingerprint::Fingerprint;

/// The backoff a fresh retry starts at.
pub(crate) const FIRST_WAIT: Duration = Duration::from_secs(5);
/// The longest backoff a retry waits.
pub(crate) const MAX_WAIT: Duration = Duration::from_secs(300);
/// The dials the policy lets run at once, the unauthenticated network's
/// bound on its sockets.
pub(crate) const MAX_DIALS: usize = 8;
/// The instances the policy tracks at once, the unauthenticated network's
/// bound on its memory and its events.
pub(crate) const MAX_INSTANCES: usize = 256;

/// The one state an instance is in, beside the device's standing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum InstanceState {
    /// Found, no live link yet.
    New,
    /// A live link carries the instance's fingerprint.
    Linked,
    /// A retry is pending.
    Waiting,
    /// A refusal, until the instance's fingerprint changes.
    Barred,
}

/// One found instance, under its fingerprint.
#[derive(Debug)]
pub(crate) struct Instance {
    /// The mDNS name the instance advertises under, fresh at every
    /// registration.
    name: String,
    state: InstanceState,
    /// The addresses the last resolve reported it at, dialled `IPv4`
    /// first, and the ones already reported as found, which a resolve
    /// replaces with its own.
    addresses: std::collections::BTreeSet<SocketAddr>,
    wait: Duration,
    /// When the pending retry is due, on a monotonic clock.
    retry_at: Option<Instant>,
    /// The instance's place in the find order, for the bound's eviction.
    seq: u64,
}

/// What a dial ends with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DialOutcome {
    /// One of the instance's addresses answered and linked.
    Linked,
    /// No address answered, so the retry backs off.
    Unreachable,
    /// An address or the link refused, so the instance is barred.
    Refused,
}

/// The actions a policy move leaves the device to take.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Action {
    /// Report the found instance at its address.
    Found(SocketAddr),
    /// Report the instance gone.
    Gone,
    /// Dial the instance's addresses, `IPv4` first.
    Dial,
    /// Browse again, the local addresses changed.
    Browse,
}

/// The policy against the discovery table, pure on its inputs and the clock
/// its caller hands it.
#[derive(Debug)]
pub(crate) struct Policy {
    /// The device's own fingerprint, the instances it ignores.
    own: Fingerprint,
    /// Whether the device dials what it finds.
    autolink: bool,
    instances: BTreeMap<Fingerprint, Instance>,
    /// The next instance's place in the find order.
    next_seq: u64,
    /// The dials running at once, keyed by fingerprint, freed only at the
    /// dial's outcome, whatever its instance did meanwhile.
    in_flight: BTreeSet<Fingerprint>,
}

/// A close reason that bars the instance until its fingerprint changes.
pub(crate) fn bars(reason: CloseReason) -> bool {
    matches!(
        reason,
        CloseReason::PeerRevoked | CloseReason::PeerExpired | CloseReason::Protocol
    )
}

impl Policy {
    /// The policy for the standing that just became serving, the device's own
    /// fingerprint `own`, dialing what it finds when `autolink`.
    pub(crate) fn new(own: Fingerprint, autolink: bool) -> Self {
        Self {
            own,
            autolink,
            instances: BTreeMap::new(),
            next_seq: 0,
            in_flight: BTreeSet::new(),
        }
    }

    /// A renewal moved the device's own fingerprint, which the browse ignores.
    pub(crate) fn set_own(&mut self, own: Fingerprint) {
        self.own = own;
    }

    /// The instance `name`, carrying `fp`, was found or resolved at
    /// `addrs`, the addresses of one resolve.
    pub(crate) fn found(
        &mut self,
        name: &str,
        fp: Fingerprint,
        addrs: &[SocketAddr],
    ) -> Vec<Action> {
        if fp == self.own {
            return Vec::new();
        }
        let mut actions = Vec::new();
        let fresh = !self.instances.contains_key(&fp);
        // A find beyond the bound evicts the oldest instance the link does
        // not carry, without an event, or takes nothing when every tracked
        // instance carries a link.
        if fresh && self.instances.len() >= MAX_INSTANCES {
            let Some((oldest, _evicted)) = self
                .instances
                .iter()
                .filter(|(_, entry)| entry.state != InstanceState::Linked)
                .min_by_key(|(_, entry)| entry.seq)
            else {
                return actions;
            };
            let oldest = *oldest;
            self.instances.remove(&oldest);
        }
        let seq = self.next_seq;
        if fresh {
            self.next_seq += 1;
        }
        let capacity = MAX_DIALS.saturating_sub(self.in_flight.len());
        let entry = self.instances.entry(fp).or_insert_with(|| Instance {
            name: name.to_string(),
            state: InstanceState::New,
            addresses: BTreeSet::new(),
            wait: FIRST_WAIT,
            retry_at: None,
            seq,
        });
        // A re-advertisement under a fresh name reports the peer again, so
        // the addresses it carried stand to be reported anew.
        if entry.name != name {
            entry.name = name.to_string();
            entry.addresses.clear();
        }
        // A resolve replaces the instance's address set with the addresses
        // it resolved at, so a set never grows past one resolve, and an
        // address reports once per resolve.
        let resolved: BTreeSet<SocketAddr> = addrs.iter().copied().collect();
        for addr in &resolved {
            if !entry.addresses.contains(addr) {
                actions.push(Action::Found(*addr));
            }
        }
        entry.addresses = resolved;
        if entry.state == InstanceState::New
            && self.autolink
            && capacity > 0
            && !self.in_flight.contains(&fp)
        {
            self.in_flight.insert(fp);
            actions.push(Action::Dial);
        }
        actions
    }

    /// The instance `fp` was removed.
    pub(crate) fn removed(&mut self, fp: Fingerprint) -> Vec<Action> {
        match self.instances.remove(&fp) {
            Some(_) => vec![Action::Gone],
            None => Vec::new(),
        }
    }

    /// A live link now carries `fp`, by dial or inbound.
    pub(crate) fn linked(&mut self, fp: Fingerprint) -> Vec<Action> {
        if let Some(entry) = self.instances.get_mut(&fp) {
            entry.state = InstanceState::Linked;
            entry.retry_at = None;
            entry.wait = FIRST_WAIT;
        }
        Vec::new()
    }

    /// The last live link to the peer behind `fp` closed with `reason`.
    pub(crate) fn unlinked(
        &mut self,
        now: Instant,
        fp: Fingerprint,
        reason: CloseReason,
    ) -> Vec<Action> {
        if let Some(entry) = self.instances.get_mut(&fp) {
            if bars(reason) {
                entry.state = InstanceState::Barred;
                entry.retry_at = None;
            } else if entry.state == InstanceState::Linked {
                entry.state = InstanceState::Waiting;
                entry.wait = FIRST_WAIT;
                entry.retry_at = if self.autolink {
                    Some(now + FIRST_WAIT)
                } else {
                    None
                };
            }
        }
        Vec::new()
    }

    /// A dial for `fp` ended with `outcome`.
    pub(crate) fn dial_result(
        &mut self,
        now: Instant,
        fp: Fingerprint,
        outcome: DialOutcome,
    ) -> Vec<Action> {
        if let Some(entry) = self.instances.get_mut(&fp) {
            match outcome {
                DialOutcome::Linked => {
                    if entry.state != InstanceState::Barred {
                        entry.state = InstanceState::Linked;
                        entry.retry_at = None;
                        entry.wait = FIRST_WAIT;
                    }
                }
                DialOutcome::Unreachable => {
                    if matches!(entry.state, InstanceState::New | InstanceState::Waiting) {
                        entry.state = InstanceState::Waiting;
                        if self.autolink {
                            entry.retry_at = Some(now + entry.wait);
                        }
                        entry.wait = (entry.wait * 2).min(MAX_WAIT);
                    }
                }
                DialOutcome::Refused => {
                    if matches!(entry.state, InstanceState::New | InstanceState::Waiting) {
                        entry.state = InstanceState::Barred;
                        entry.retry_at = None;
                    }
                }
            }
        }
        // The outcome frees the dial's place, whatever its instance did.
        self.in_flight.remove(&fp);
        Vec::new()
    }

    /// The local addresses changed, so the browse restarts.
    pub(crate) fn addresses_changed(&mut self) -> Vec<Action> {
        for entry in self.instances.values_mut() {
            if entry.state == InstanceState::Waiting {
                entry.state = InstanceState::New;
                entry.retry_at = None;
                entry.wait = FIRST_WAIT;
            }
        }
        vec![Action::Browse]
    }

    /// The instances whose dial starts now, the bound of running dials held.
    pub(crate) fn due(&mut self, now: Instant) -> Vec<Fingerprint> {
        let capacity = MAX_DIALS.saturating_sub(self.in_flight.len());
        if capacity == 0 {
            return Vec::new();
        }
        // The due instances in the order they were found, the oldest first.
        let mut due = self
            .instances
            .iter()
            .filter(|(fp, entry)| {
                if self.in_flight.contains(fp) {
                    return false;
                }
                // A fresh found dials when its turn comes, the bound allowing.
                match entry.state {
                    InstanceState::New => self.autolink,
                    InstanceState::Waiting => entry.retry_at.is_some_and(|at| at <= now),
                    InstanceState::Linked | InstanceState::Barred => false,
                }
            })
            .map(|(fp, entry)| (entry.seq, *fp))
            .collect::<Vec<_>>();
        due.sort_unstable_by_key(|(seq, _)| *seq);
        let mut started = Vec::new();
        for (_, fp) in due.into_iter().take(capacity) {
            self.in_flight.insert(fp);
            started.push(fp);
        }
        started
    }

    /// The next retry deadline, for the proofs.
    #[cfg(test)]
    pub(crate) fn next_retry(&self) -> Option<Instant> {
        self.instances
            .values()
            .filter_map(|entry| entry.retry_at)
            .min()
    }

    /// The instance's state, for the proofs.
    #[cfg(test)]
    pub(crate) fn state(&self, fp: &Fingerprint) -> Option<InstanceState> {
        self.instances.get(fp).map(|entry| entry.state)
    }

    /// The instance's resolved addresses, for a dial the proofs spawn.
    pub(crate) fn addresses(&self, fp: &Fingerprint) -> Vec<SocketAddr> {
        self.instances
            .get(fp)
            .map(|entry| entry.addresses.iter().copied().collect())
            .unwrap_or_default()
    }

    /// The instance's pending retry deadline, for the runner's timer.
    pub(crate) fn retry_at(&self, fp: &Fingerprint) -> Option<Instant> {
        self.instances.get(fp).and_then(|entry| entry.retry_at)
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::sync::LazyLock;
    use std::time::{Duration, Instant};

    use crate::CloseReason;

    use super::{
        Action, DialOutcome, FIRST_WAIT, InstanceState, MAX_DIALS, MAX_INSTANCES, MAX_WAIT, Policy,
    };
    use crate::fingerprint::Fingerprint;

    const OWN: Fingerprint = Fingerprint::new([0; 32]);
    const PEER: Fingerprint = Fingerprint::new([1; 32]);
    const OTHER: Fingerprint = Fingerprint::new([2; 32]);
    const RENEWED: Fingerprint = Fingerprint::new([3; 32]);
    const ADDR: SocketAddr =
        SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 443);
    const ADDR2: SocketAddr =
        SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 444);
    static BASE: LazyLock<Instant> = LazyLock::new(Instant::now);

    /// The one fixed clock the proofs stand on.
    fn now() -> Instant {
        *BASE
    }

    fn autolink() -> Policy {
        Policy::new(OWN, true)
    }

    /// Proof 1.
    #[test]
    fn the_own_fingerprint_is_ignored() {
        let mut policy = autolink();
        assert!(
            policy.found("n", OWN, &[ADDR]).is_empty(),
            "a self is ignored"
        );
        assert_eq!(policy.state(&OWN), None);
        // A renewal moves the own fingerprint, and the new one is ignored too.
        policy.set_own(RENEWED);
        assert_eq!(policy.found("n", RENEWED, &[ADDR]), Vec::new());
        assert!(policy.removed(OWN).is_empty(), "a self never reports gone");
    }

    /// Proof 2.
    #[test]
    fn a_found_instance_is_reported_and_dialled() {
        let mut policy = autolink();
        let actions = policy.found("n", PEER, &[ADDR]);
        assert_eq!(
            actions,
            vec![Action::Found(ADDR), Action::Dial],
            "a found instance reports and dials"
        );
        assert_eq!(policy.state(&PEER), Some(InstanceState::New));
        // A repeated resolve of the same address reports nothing and dials
        // nothing, and a resolve at a second address reports only that
        // address and stands alone in the instance's set.
        assert_eq!(policy.found("n", PEER, &[ADDR]), Vec::<Action>::new());
        assert_eq!(
            policy.found("n", PEER, &[ADDR2]),
            vec![Action::Found(ADDR2)]
        );
        assert_eq!(
            policy.addresses(&PEER),
            vec![ADDR2],
            "the resolve's addresses stand alone"
        );
    }

    /// Proof 3.
    #[test]
    fn a_linked_instance_is_not_redialled() {
        let mut policy = autolink();
        policy.found("n", PEER, &[ADDR]);
        policy.dial_result(now(), PEER, DialOutcome::Linked);
        assert_eq!(policy.state(&PEER), Some(InstanceState::Linked));
        // The browse keeps resolving it, and nothing dials.
        assert_eq!(policy.found("n", PEER, &[ADDR]), Vec::<Action>::new());
        assert_eq!(
            policy.found("n", PEER, &[ADDR2]),
            vec![Action::Found(ADDR2)],
            "a new address reports while linked"
        );
    }

    /// Proof 4.
    #[test]
    fn an_unreachable_dial_backs_off_to_the_cap() {
        let mut policy = autolink();
        policy.found("n", PEER, &[ADDR]);
        // The first dial ends, and the retry is due after the first wait.
        let mut due_at = now();
        policy.dial_result(due_at, PEER, DialOutcome::Unreachable);
        for wait in [5, 10, 20, 40, 80, 160, 300, 300] {
            let wait = Duration::from_secs(wait);
            let next = (wait * 2).min(MAX_WAIT);
            due_at += wait;
            let due = policy.due(due_at);
            assert_eq!(due, vec![PEER], "the retry is due");
            policy.dial_result(due_at, PEER, DialOutcome::Unreachable);
            assert_eq!(policy.state(&PEER), Some(InstanceState::Waiting));
            assert_eq!(policy.next_retry(), Some(due_at + next));
        }
        assert_eq!(policy.state(&PEER), Some(InstanceState::Waiting));
    }

    /// Proof 5.
    #[test]
    fn a_refused_instance_is_barred_until_its_fingerprint_changes() {
        let mut policy = autolink();
        // A dial the peer refuses.
        policy.found("n", PEER, &[ADDR]);
        policy.dial_result(now(), PEER, DialOutcome::Refused);
        assert_eq!(policy.state(&PEER), Some(InstanceState::Barred));
        assert!(
            !policy
                .found("n", PEER, &[ADDR])
                .contains(&Action::Found(ADDR))
        );
        assert!(
            !policy.found("n", PEER, &[ADDR2]).contains(&Action::Dial),
            "a barred instance never dials"
        );
        // A dial of the renewed fingerprint starts clean.
        let actions = policy.found("n", RENEWED, &[ADDR]);
        assert_eq!(actions, vec![Action::Found(ADDR), Action::Dial]);
        // A live link the kept list revokes, the other bar reasons included.
        let mut policy = autolink();
        policy.found("n", PEER, &[ADDR]);
        policy.dial_result(now(), PEER, DialOutcome::Linked);
        for reason in [
            CloseReason::PeerRevoked,
            CloseReason::PeerExpired,
            CloseReason::Protocol,
        ] {
            let mut policy = autolink();
            policy.found("n", PEER, &[ADDR]);
            policy.dial_result(now(), PEER, DialOutcome::Linked);
            policy.unlinked(now(), PEER, reason);
            assert_eq!(
                policy.state(&PEER),
                Some(InstanceState::Barred),
                "{reason:?} bars"
            );
            assert!(
                policy.due(now() + Duration::from_secs(3600)).is_empty(),
                "a bar never retries"
            );
        }
    }

    /// Proof 6.
    #[test]
    fn a_lost_link_redials_after_five_seconds() {
        for reason in [
            CloseReason::PeerLost,
            CloseReason::Closed,
            CloseReason::Duplicate,
        ] {
            let mut policy = autolink();
            policy.found("n", PEER, &[ADDR]);
            policy.dial_result(now(), PEER, DialOutcome::Linked);
            policy.unlinked(now(), PEER, reason);
            assert_eq!(
                policy.state(&PEER),
                Some(InstanceState::Waiting),
                "{reason:?} redials"
            );
            assert_eq!(policy.next_retry(), Some(now() + Duration::from_secs(5)));
            assert_eq!(policy.due(now()), Vec::<Fingerprint>::new());
            assert_eq!(policy.due(now() + Duration::from_secs(5)), vec![PEER]);
        }
    }

    /// Proof 7.
    #[test]
    fn a_removal_drops_the_retry_and_keeps_the_live_link() {
        // The retry, dropped with the entry.
        let mut policy = autolink();
        policy.found("n", PEER, &[ADDR]);
        policy.dial_result(now(), PEER, DialOutcome::Unreachable);
        assert_eq!(policy.removed(PEER), vec![Action::Gone]);
        assert_eq!(policy.state(&PEER), None);
        assert!(policy.next_retry().is_none());
        // The live link: the entry goes, the link is the node's, untouched.
        let mut policy = autolink();
        policy.found("n", PEER, &[ADDR]);
        policy.dial_result(now(), PEER, DialOutcome::Linked);
        assert_eq!(policy.removed(PEER), vec![Action::Gone]);
        assert_eq!(policy.state(&PEER), None);
        // A removal nothing found reports nothing.
        assert_eq!(policy.removed(OTHER), Vec::new());
    }

    /// Proof 8.
    #[test]
    fn a_local_address_change_resets_the_waiting() {
        // The waiting entry, dropped to new with its retry.
        let mut policy = autolink();
        policy.found("n", PEER, &[ADDR]);
        policy.dial_result(now(), PEER, DialOutcome::Unreachable);
        assert_eq!(policy.addresses_changed(), vec![Action::Browse]);
        assert_eq!(policy.state(&PEER), Some(InstanceState::New));
        assert!(policy.next_retry().is_none());
        // The linked entry, the link stays.
        let mut policy = autolink();
        policy.found("n", PEER, &[ADDR]);
        policy.dial_result(now(), PEER, DialOutcome::Linked);
        policy.addresses_changed();
        assert_eq!(policy.state(&PEER), Some(InstanceState::Linked));
        // The barred entry, the bar stays.
        let mut policy = autolink();
        policy.found("n", PEER, &[ADDR]);
        policy.dial_result(now(), PEER, DialOutcome::Refused);
        policy.addresses_changed();
        assert_eq!(policy.state(&PEER), Some(InstanceState::Barred));
    }

    /// Proof 9.
    #[test]
    fn an_inbound_link_moves_every_state_to_linked() {
        for start in [
            (InstanceState::New, false),
            (InstanceState::Waiting, true),
            (InstanceState::Barred, true),
        ] {
            let (state, wait) = start;
            let mut policy = autolink();
            policy.found("n", PEER, &[ADDR]);
            match state {
                InstanceState::New | InstanceState::Linked => {}
                InstanceState::Waiting => {
                    policy.dial_result(now(), PEER, DialOutcome::Unreachable);
                }
                InstanceState::Barred => {
                    policy.dial_result(now(), PEER, DialOutcome::Refused);
                }
            }
            assert_eq!(policy.state(&PEER), Some(state));
            policy.linked(PEER);
            assert_eq!(
                policy.state(&PEER),
                Some(InstanceState::Linked),
                "an inbound link lands from {state:?}"
            );
            if wait {
                assert!(
                    policy.next_retry().is_none(),
                    "the retry is dropped with the link"
                );
            }
        }
        // An inbound link from a peer the browse never found changes nothing.
        let mut policy = autolink();
        assert_eq!(policy.linked(OTHER), Vec::new());
        assert_eq!(policy.state(&OTHER), None);
    }

    /// Proof 10.
    #[test]
    fn leaving_the_serving_forgets_everything() {
        // The standing leaves, the runner drops the policy, and the instances
        // go with it. The proof holds the whole table at once and drops it.
        let mut policy = autolink();
        policy.found("n", PEER, &[ADDR]);
        policy.dial_result(now(), PEER, DialOutcome::Unreachable);
        policy.found("n", OTHER, &[ADDR2]);
        policy.set_own(OWN);
        drop(policy);
    }

    /// Proof 11.
    #[test]
    fn autolink_off_reports_but_never_dials() {
        let mut policy = Policy::new(OWN, false);
        assert_eq!(
            policy.found("n", PEER, &[ADDR]),
            vec![Action::Found(ADDR)],
            "the found peer reports"
        );
        assert_eq!(policy.state(&PEER), Some(InstanceState::New));
        // An inbound link still lands, and its close waits without a retry.
        policy.linked(PEER);
        policy.unlinked(now(), PEER, CloseReason::PeerLost);
        assert_eq!(policy.state(&PEER), Some(InstanceState::Waiting));
        assert!(policy.next_retry().is_none(), "no retry is armed");
        assert_eq!(policy.due(now() + Duration::from_secs(3600)), Vec::new());
        // The dial results the table removes never arrive, and the browse
        // keeps reporting new addresses.
        assert_eq!(
            policy.found("n", PEER, &[ADDR2]),
            vec![Action::Found(ADDR2)]
        );
    }

    /// The table's found row, column by column.
    #[test]
    fn the_found_row_holds_in_every_column() {
        // New, dial.
        let mut policy = autolink();
        assert_eq!(
            policy.found("n", PEER, &[ADDR]),
            vec![Action::Found(ADDR), Action::Dial]
        );
        // Linked, no dial.
        let mut policy = autolink();
        policy.found("n", PEER, &[ADDR]);
        policy.dial_result(now(), PEER, DialOutcome::Linked);
        assert_eq!(
            policy.found("n", PEER, &[ADDR2]),
            vec![Action::Found(ADDR2)]
        );
        // Waiting, keep the retry.
        let mut policy = autolink();
        policy.found("n", PEER, &[ADDR]);
        policy.dial_result(now(), PEER, DialOutcome::Unreachable);
        let retry = policy.next_retry();
        assert_eq!(
            policy.found("n", PEER, &[ADDR2]),
            vec![Action::Found(ADDR2)]
        );
        assert_eq!(policy.next_retry(), retry, "the retry is kept");
        // Barred, no dial.
        let mut policy = autolink();
        policy.found("n", PEER, &[ADDR]);
        policy.dial_result(now(), PEER, DialOutcome::Refused);
        assert_eq!(
            policy.found("n", PEER, &[ADDR2]),
            vec![Action::Found(ADDR2)]
        );
    }

    /// A re-advertisement under a fresh name, same fingerprint and address,
    /// reports the peer again, and a repeat of the same name does not.
    #[test]
    fn a_fresh_name_readvertised_reports_the_peer_again() {
        let mut policy = autolink();
        assert_eq!(
            policy.found("old", PEER, &[ADDR]),
            vec![Action::Found(ADDR), Action::Dial]
        );
        // The same name resolves again, nothing reports.
        assert_eq!(policy.found("old", PEER, &[ADDR]), Vec::<Action>::new());
        // A fresh name, same fingerprint and address, reports again while
        // the first dial is still in flight, so no second dial starts.
        assert_eq!(
            policy.found("fresh", PEER, &[ADDR]),
            vec![Action::Found(ADDR)]
        );
        // A linked peer re-advertised reports without a dial.
        let mut policy = autolink();
        policy.found("old", PEER, &[ADDR]);
        policy.dial_result(now(), PEER, DialOutcome::Linked);
        assert_eq!(
            policy.found("fresh", PEER, &[ADDR]),
            vec![Action::Found(ADDR)]
        );
        assert_eq!(policy.state(&PEER), Some(InstanceState::Linked));
    }

    /// The table's dial rows, the refused dial barred and the dial that
    /// lands linked.
    #[test]
    fn the_dial_rows_hold() {
        // A dial from a new instance lands linked.
        let mut policy = autolink();
        policy.found("n", PEER, &[ADDR]);
        policy.dial_result(now(), PEER, DialOutcome::Linked);
        assert_eq!(policy.state(&PEER), Some(InstanceState::Linked));
        // A dial from the waiting, the backoff doubling.
        let mut policy = autolink();
        policy.found("n", PEER, &[ADDR]);
        policy.dial_result(now(), PEER, DialOutcome::Unreachable);
        let due = now() + Duration::from_secs(5);
        let _ = policy.due(due);
        policy.dial_result(due, PEER, DialOutcome::Linked);
        assert_eq!(policy.state(&PEER), Some(InstanceState::Linked));
        assert!(policy.next_retry().is_none());
    }

    /// A dial result the link already answered is the link's truth.
    #[test]
    fn a_dial_result_never_demotes_a_live_link() {
        let mut policy = autolink();
        policy.found("n", PEER, &[ADDR]);
        policy.dial_result(now(), PEER, DialOutcome::Linked);
        // The other addresses gave up, or the peer refused them, after the
        // inbound link landed.
        policy.dial_result(now(), PEER, DialOutcome::Unreachable);
        assert_eq!(policy.state(&PEER), Some(InstanceState::Linked));
        policy.dial_result(now(), PEER, DialOutcome::Refused);
        assert_eq!(policy.state(&PEER), Some(InstanceState::Linked));
        // A bar, set by the close, is sticky under the late dial result.
        let mut policy = autolink();
        policy.found("n", PEER, &[ADDR]);
        policy.dial_result(now(), PEER, DialOutcome::Linked);
        policy.unlinked(now(), PEER, CloseReason::PeerRevoked);
        policy.dial_result(now(), PEER, DialOutcome::Linked);
        assert_eq!(policy.state(&PEER), Some(InstanceState::Barred));
    }

    /// A fingerprint at `i`, for the bound's proofs.
    fn fp_at(i: u16) -> Fingerprint {
        let mut bytes = [0u8; 32];
        bytes[0] = u8::try_from(i >> 8).expect("the high half of a u16 holds a byte");
        bytes[1] = u8::try_from(i & 0xff).expect("the low half of a u16 holds a byte");
        Fingerprint::new(bytes)
    }

    /// A loopback address at `i`, for the bound's proofs.
    fn addr_at(i: u16) -> SocketAddr {
        SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 443 + i)
    }

    /// Decision 13. A due dial waits its turn while the bound of running
    /// dials is full.
    #[test]
    fn a_due_dial_waits_its_turn_behind_the_running_dials() {
        let mut policy = autolink();
        let bound = u16::try_from(MAX_DIALS).expect("the dial bound holds a u16");
        for i in 1..=bound {
            assert!(
                policy
                    .found("n", fp_at(i), &[addr_at(i)])
                    .contains(&Action::Dial),
                "a running dial starts"
            );
        }
        let queued = fp_at(bound + 1);
        assert_eq!(
            policy.found("n", queued, &[addr_at(bound + 1)]),
            vec![Action::Found(addr_at(bound + 1))],
            "the dial behind the bound is queued"
        );
        assert!(
            policy.due(now()).is_empty(),
            "the bound holds while it is full"
        );
        // A running dial ends, and the queued one takes its turn.
        policy.dial_result(now(), fp_at(1), DialOutcome::Linked);
        assert_eq!(policy.due(now()), vec![queued]);
    }

    /// Decision 13. A queued retry takes its turn when a running dial ends.
    #[test]
    fn a_queued_retry_takes_its_turn_when_a_running_dial_ends() {
        let mut policy = autolink();
        // The retry's deadline passes while the bound of dials runs.
        policy.found("n", fp_at(1), &[addr_at(1)]);
        policy.dial_result(now(), fp_at(1), DialOutcome::Unreachable);
        let bound = u16::try_from(MAX_DIALS).expect("the dial bound holds a u16");
        for i in 2..=bound + 1 {
            policy.found("n", fp_at(i), &[addr_at(i)]);
        }
        let due_at = now() + FIRST_WAIT;
        assert!(
            policy.due(due_at).is_empty(),
            "the bound holds while it is full"
        );
        // A running dial ends, and the queued retry takes its turn.
        policy.dial_result(due_at, fp_at(2), DialOutcome::Linked);
        assert_eq!(policy.due(due_at), vec![fp_at(1)]);
    }

    /// Decision 13. A queued dial starts when a running dial ends, and a
    /// removal, a link, an unlink or an address change meanwhile never frees
    /// the slot before the outcome, nor starts a second dial.
    #[test]
    fn a_running_dial_holds_its_slot_until_its_outcome() {
        let bound = u16::try_from(MAX_DIALS).expect("the dial bound holds a u16");
        let queue = |policy: &mut Policy| {
            assert_eq!(
                policy.found("n", fp_at(bound + 1), &[addr_at(bound + 1)]),
                vec![Action::Found(addr_at(bound + 1))],
                "the running dial holds its slot"
            );
            assert!(policy.due(now()).is_empty(), "the bound still holds");
        };
        let settle = |policy: &mut Policy| {
            policy.dial_result(now(), fp_at(3), DialOutcome::Linked);
            assert_eq!(policy.due(now()), vec![fp_at(bound + 1)]);
        };
        // The instance is removed while its dial runs.
        let mut policy = autolink();
        for i in 1..=bound {
            policy.found("n", fp_at(i), &[addr_at(i)]);
        }
        assert_eq!(policy.removed(fp_at(3)), vec![Action::Gone]);
        queue(&mut policy);
        settle(&mut policy);
        // An inbound link lands while the dial runs.
        let mut policy = autolink();
        for i in 1..=bound {
            policy.found("n", fp_at(i), &[addr_at(i)]);
        }
        policy.linked(fp_at(3));
        assert_eq!(policy.state(&fp_at(3)), Some(InstanceState::Linked));
        queue(&mut policy);
        settle(&mut policy);
        // A barred close lands while the dial runs.
        let mut policy = autolink();
        for i in 1..=bound {
            policy.found("n", fp_at(i), &[addr_at(i)]);
        }
        policy.linked(fp_at(3));
        policy.unlinked(now(), fp_at(3), CloseReason::PeerRevoked);
        assert_eq!(policy.state(&fp_at(3)), Some(InstanceState::Barred));
        queue(&mut policy);
        settle(&mut policy);
        // The local addresses change while a waiting retry's dial runs.
        let mut policy = autolink();
        policy.found("n", PEER, &[ADDR]);
        policy.dial_result(now(), PEER, DialOutcome::Unreachable);
        let due_at = now() + FIRST_WAIT;
        assert_eq!(policy.due(due_at), vec![PEER], "the retry dials");
        assert_eq!(policy.addresses_changed(), vec![Action::Browse]);
        assert_eq!(policy.state(&PEER), Some(InstanceState::New));
        assert_eq!(
            policy.found("n", PEER, &[ADDR2]),
            vec![Action::Found(ADDR2)],
            "no second dial for a running one"
        );
        assert!(
            policy.due(due_at).is_empty(),
            "the running dial holds its slot"
        );
        policy.dial_result(due_at, PEER, DialOutcome::Unreachable);
        assert_eq!(policy.state(&PEER), Some(InstanceState::Waiting));
        assert_eq!(policy.next_retry(), Some(due_at + FIRST_WAIT));
    }

    /// Decision 13. Queued dials start oldest first, by the find's order,
    /// whatever the fingerprints order.
    #[test]
    fn queued_dials_start_oldest_first_not_by_fingerprint() {
        let mut policy = autolink();
        let bound = u16::try_from(MAX_DIALS).expect("the dial bound holds a u16");
        for i in 1..=bound {
            policy.found("n", fp_at(i), &[addr_at(i)]);
        }
        // The older instance carries the higher fingerprint.
        let older = fp_at(bound + 2);
        let younger = fp_at(bound + 1);
        policy.found("n", older, &[addr_at(bound + 2)]);
        policy.found("n", younger, &[addr_at(bound + 1)]);
        assert!(policy.due(now()).is_empty(), "the bound holds while full");
        policy.dial_result(now(), fp_at(1), DialOutcome::Linked);
        assert_eq!(
            policy.due(now()),
            vec![older],
            "the older instance starts, not the lower fingerprint"
        );
    }

    /// Decision 13. A find beyond the bound evicts the oldest instance not
    /// linked, without an event.
    #[test]
    fn a_find_beyond_the_bound_evicts_the_oldest_not_linked() {
        let bound = u16::try_from(MAX_INSTANCES).expect("the instance bound holds a u16");
        let beyond = fp_at(bound + 1);
        // The oldest tracked instance, not linked, is evicted.
        let mut policy = autolink();
        for i in 1..=bound {
            policy.found("n", fp_at(i), &[addr_at(i)]);
        }
        assert_eq!(
            policy.found("n", beyond, &[addr_at(bound + 1)]),
            vec![Action::Found(addr_at(bound + 1))],
            "the find reports, without an eviction event"
        );
        assert_eq!(policy.state(&beyond), Some(InstanceState::New));
        assert_eq!(policy.state(&fp_at(1)), None, "the oldest is evicted");
        // The evicted dial ends, and the next queued instance takes its place.
        policy.dial_result(now(), fp_at(1), DialOutcome::Unreachable);
        assert_eq!(policy.due(now()), vec![fp_at(9)]);
        // A linked instance is kept, and its successor is evicted.
        let mut policy = autolink();
        for i in 1..=bound {
            policy.found("n", fp_at(i), &[addr_at(i)]);
        }
        policy.dial_result(now(), fp_at(1), DialOutcome::Linked);
        assert_eq!(
            policy.found("n", beyond, &[addr_at(bound + 1)]),
            vec![Action::Found(addr_at(bound + 1)), Action::Dial],
            "the evicted dial still holds one place"
        );
        assert_eq!(policy.state(&fp_at(1)), Some(InstanceState::Linked));
        assert_eq!(
            policy.state(&fp_at(2)),
            None,
            "the oldest not linked is evicted"
        );
        // A bound full of linked instances takes no find.
        let mut policy = autolink();
        for i in 1..=bound {
            policy.found("n", fp_at(i), &[addr_at(i)]);
        }
        for i in 1..=bound {
            policy.dial_result(now(), fp_at(i), DialOutcome::Linked);
        }
        assert!(
            policy.found("n", beyond, &[addr_at(bound + 1)]).is_empty(),
            "a bound full of links takes no find"
        );
        assert_eq!(policy.state(&beyond), None);
        assert_eq!(policy.state(&fp_at(1)), Some(InstanceState::Linked));
        // A find of a tracked instance takes no eviction.
        let mut policy = autolink();
        for i in 1..=bound {
            policy.found("n", fp_at(i), &[addr_at(i)]);
        }
        assert_eq!(
            policy.found("n", fp_at(1), &[addr_at(bound + 1)]),
            vec![Action::Found(addr_at(bound + 1))],
            "a tracked instance re-found takes no eviction"
        );
        assert_eq!(policy.state(&fp_at(2)), Some(InstanceState::New));
    }

    /// A resolve replaces the instance's address set with the addresses it
    /// resolved at, so a set never grows past one resolve.
    #[test]
    fn a_resolve_replaces_the_instance_addresses() {
        let mut policy = autolink();
        policy.found("n", PEER, &[ADDR]);
        // A second resolve at a different address replaces the first.
        assert_eq!(
            policy.found("n", PEER, &[ADDR2]),
            vec![Action::Found(ADDR2)],
            "the new address reports once"
        );
        assert_eq!(
            policy.addresses(&PEER),
            vec![ADDR2],
            "the resolve's addresses stand alone"
        );
        // A repeated resolve of the same set reports nothing.
        assert_eq!(
            policy.found("n", PEER, &[ADDR2]),
            Vec::<Action>::new(),
            "a repeat reports nothing"
        );
    }
}
