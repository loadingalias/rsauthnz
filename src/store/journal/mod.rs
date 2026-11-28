//! The restore journal: its record format, the check of its hash chain, and its rules as functions from records to
//! decisions.
//!
//! A snapshot cannot show that it is current, so a binding that supports restore keeps a journal in its own failure
//! domain ([`Journal`](super::Journal)). The journal holds each fact that removes authority, the creation of each
//! authority anchor, the voids of refused operations, and the allocation floors. Each fact is monotone: it states that
//! the versions of a record at or below a value are dead. Thus a replay of the entries in any order, or more than once,
//! gives the same [`State`].
//!
//! The module does no I/O and orders no write. The commit driver calls its functions and orders each effect:
//!
//! 1. Before a commit, [`entries`] gives the end entry of the proposal, and after the commit its creation entry.
//!    [`Mark::next`] gives the stored form of each entry, which holds the link of the entry before it.
//! 2. After a start, the driver reads the journal after the low-water mark into a [`History`], which checks the chain.
//!    [`reconcile`] then gives the missing creation entries and the voids.
//! 3. For a snapshot, [`low_water`] gives its low-water mark. A restore from the snapshot reads the [`History`] after
//!    that mark, and [`restore`] gives what the restored store applies before it serves.
//!
//! ```
//! use rsauthnz::cbor::Value;
//! use rsauthnz::id::{AuthorityVersion, Human, Id, Principal};
//! use rsauthnz::limits::Limits;
//! use rsauthnz::store::journal::{self, Body, History, Mark};
//! use rsauthnz::store::Kind;
//! use rsauthnz::time::{Reading, ReadingSource};
//! use rsauthnz::transition::{Audit, Change, Dependency, OperationId, Proposal};
//!
//! let owner = Id::new("acme", "auth")?;
//! let audit = Audit {
//!     actor: Principal::Human(Id::<Human>::new("acme", "u-17")?),
//!     action: Id::new("acme.auth", "credential.remove")?,
//!     time: Reading::new(core::time::Duration::from_secs(1_000), None, ReadingSource::Caller),
//! };
//! let passkey = Kind::Credential.key(b"c-4")?;
//! let mut proposal = Proposal::new(OperationId::new(b"op-1")?, audit, &Value::Null, Limits::default())?;
//! proposal.read(Dependency::Version(passkey.clone(), AuthorityVersion::new(owner, &[3])?))?;
//! proposal.change(Change::End(passkey))?;
//!
//! // The removal of the passkey is a fact: each version of the record at or below 3 is dead.
//! let entries = journal::entries(&proposal, &[], &[])?;
//! let end = entries.end.ok_or("an end entry")?;
//! let append = Mark::EMPTY.next(&proposal.operation().id, &Body::End(end), Limits::default())?;
//!
//! // A restore from a snapshot with the empty mark reads the journal from its first entry.
//! let mut history = History::new(Mark::EMPTY);
//! history.extend(core::slice::from_ref(append.entry()), Limits::default())?;
//! assert_eq!(history.head(), append.head());
//! assert_eq!(journal::replay(history.entries())?.facts().count(), 1);
//! # Ok::<(), Box<dyn core::error::Error>>(())
//! ```

mod form;
mod rules;

use alloc::boxed::Box;
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;
use core::cmp::Ordering;
use core::fmt;
use core::num::NonZeroU64;
use core::time::Duration;

pub use rules::{
    Activation, Completion, Entries, Reconciliation, entries, keeps_anchor, low_water, reconcile, restore,
};

use super::{Kind, Sequence};
use crate::cbor;
use crate::crypto;
use crate::id::{Authority, AuthorityVersion, Human, Id};
use crate::limits::Limits;
use crate::transition::{Key, OperationId};

/// The link of an entry: the SHA-256 digest of its stored form. Each entry holds the link of the entry before it, so
/// a changed or removed entry breaks the chain at the entry after it.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Link(pub [u8; 32]);

impl fmt::Debug for Link {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Link({:02x?})", self.0)
    }
}

/// A position in the journal: the sequence of an entry and its link. The low-water mark of a snapshot is a mark, and
/// the snapshot keeps both parts. So is the head of a journal, after which the next entry follows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Mark {
    /// The sequence of the entry.
    pub sequence: Sequence,
    /// The link of the entry, which the entry after it holds.
    pub link: Link,
}

impl Mark {
    /// The mark before the first entry. The first entry holds its link: 32 zero bytes.
    pub const EMPTY: Self = Self {
        sequence: Sequence(0),
        link: Link([0; 32]),
    };

    /// The mark of a stored entry. A binding can recover its head from the last frame of its journal.
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse). It digests the stored bytes once.
    #[must_use]
    pub fn of(sequence: Sequence, data: &[u8]) -> Self {
        Self {
            sequence,
            link: Link(crypto::sha256(data)),
        }
    }

    /// Prepares one successor of this mark. The stored bytes bind its sequence and predecessor.
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse). It encodes the form within `limits` and digests it once.
    ///
    /// # Errors
    ///
    /// [`Error::Cbor`] for an entry that [`History::extend`] cannot read back with `limits`, and [`Error::Overflow`]
    /// after the last sequence.
    pub fn next(&self, operation: &OperationId, body: &Body, limits: Limits) -> Result<Append, Error> {
        let sequence = Sequence(self.sequence.0.checked_add(1).ok_or(Error::Overflow)?);
        let bytes = form::encode(sequence, &self.link, operation, body, limits).map_err(Error::Cbor)?;
        Ok(Append {
            after: *self,
            head: Self::of(sequence, &bytes),
            entry: super::Entry {
                sequence,
                data: bytes.into_boxed_slice(),
            },
        })
    }
}

/// A conditional journal append. [`Mark::next`] binds the two marks to the same immutable entry.
pub struct Append {
    after: Mark,
    head: Mark,
    entry: super::Entry,
}

impl fmt::Debug for Append {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Append").field(&self.entry).finish()
    }
}

impl Append {
    /// The head that the journal must still hold at the write.
    #[must_use]
    pub const fn after(&self) -> Mark {
        self.after
    }

    /// The head that the journal installs with the entry.
    #[must_use]
    pub const fn head(&self) -> Mark {
        self.head
    }

    /// The bytes and sequence to store.
    #[must_use]
    pub const fn entry(&self) -> &super::Entry {
        &self.entry
    }
}

/// The CBOR form of `anchors` within `limits`, the payload of an intent of
/// [`Effect::Journal`](crate::transition::Effect::Journal).
pub(crate) fn encode_anchors(anchors: &[Anchor], limits: Limits) -> Result<Vec<u8>, cbor::Error> {
    form::encode_anchors(anchors, limits)
}

/// The anchors of the payload of an intent of [`Effect::Journal`](crate::transition::Effect::Journal), or `None` for
/// another form within `limits`.
pub(crate) fn decode_anchors(payload: &[u8], limits: Limits) -> Option<Vec<Anchor>> {
    form::decode_anchors(payload, limits)
}

/// A journal entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    /// The sequence.
    pub sequence: Sequence,
    /// The identity of the operation that wrote the entry.
    pub operation: OperationId,
    /// What the entry records.
    pub body: Body,
}

impl Entry {
    /// The void of this entry, when its operation refuses or did not commit: `None` for a void or a floor, which no
    /// void cancels.
    #[must_use]
    pub const fn void(&self) -> Option<Body> {
        match self.body {
            Body::End(_) | Body::Creation(_) => Some(Body::Void(self.sequence)),
            Body::Void(_) | Body::Floor(_) => None,
        }
    }
}

/// What a journal entry records.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Body {
    /// The end entry of a commit, which is durable before the commit.
    End(End),
    /// The creation entry of a commit: the anchors that it created. It is durable after the commit, and before its
    /// acknowledgement.
    Creation(Vec<Anchor>),
    /// The void of the end or creation entry with this sequence: its operation did not commit. A replay ignores that
    /// entry.
    Void(Sequence),
    /// An allocation floor, which is durable before the commit of a value above the earlier floor.
    Floor(Floor),
}

/// The end entry of a commit: each fact that the commit makes true, and the transition of a consumption that pays
/// for an anchor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct End {
    /// The facts.
    pub facts: Vec<Fact>,
    /// The transition, when the commit consumes a value that pays for an anchor.
    pub consumption: Option<Consumption>,
}

/// A monotone fact: each version of the record `key` at or below `version` is dead. It records an end of a record
/// (a consumed one-use value, a revocation, a removal) at the version that the commit read, or the death of the
/// version that a write replaced, such as a session generation or a grant revision.
///
/// Both fact forms of the design map to it. A dead version at or below a value is the `dead` of a `renew` in the
/// model. A consumed or ended identity is an anchor that `Ends` ends (`unlink`, `recover`), the `revoked` line of a
/// `revoke`, a value of `bused` (`boot`), or a value of `bended` (`issue`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fact {
    /// The record.
    pub key: Key,
    /// The highest dead version.
    pub version: AuthorityVersion,
}

/// The transition of a consumption that pays for an anchor. A restore commits it again when its outcome is in doubt.
#[derive(Clone, PartialEq, Eq)]
pub struct Consumption {
    /// The request binding of the operation, which the outcome record of a completion keeps.
    pub binding: [u8; 32],
    /// The consumed value: its key, of a kind whose consumption pays for an anchor, and the version that the commit
    /// read. Two consumptions spend the same value when their values are equal.
    pub value: Fact,
    /// The key of each dependency of the commit.
    pub dependencies: Vec<Key>,
    /// The anchors that the commit creates.
    pub anchors: Vec<Anchor>,
}

impl fmt::Debug for Consumption {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Consumption")
            .field("value", &self.value)
            .field("dependencies", &self.dependencies)
            .field("anchors", &self.anchors)
            .finish_non_exhaustive()
    }
}

/// An authority anchor that a commit creates: a record whose loss can lock an account or the authority out.
#[derive(Clone, PartialEq, Eq)]
pub struct Anchor {
    /// The record.
    pub key: Key,
    /// The role of the anchor and its owner.
    pub role: Role,
    /// The version that the commit wrote.
    pub version: AuthorityVersion,
    /// The end that the commit wrote.
    pub end: Option<Duration>,
    /// The record form that the commit wrote. It can hold a secret, so `Debug` shows only its length.
    pub data: Box<[u8]>,
}

impl fmt::Debug for Anchor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Anchor")
            .field("key", &self.key)
            .field("role", &self.role)
            .field("version", &self.version)
            .field("end", &self.end)
            .field("data_len", &self.data.len())
            .finish()
    }
}

/// The role of an anchor and its owner.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Role {
    /// A sign-in method of the account: a passkey or a provider link.
    SignIn(Id<Human>),
    /// A CLI credential of the account. It is no sign-in method.
    Cli(Id<Human>),
    /// A recovery value of the account. It is no sign-in method.
    Recovery(Id<Human>),
    /// Account recovery or enrollment state. A restore keeps its current revision and device records.
    AccountState(Id<Human>),
    /// An administrator binding of the authority.
    Administrator(Id<Authority>),
}

/// The owner of an anchor: an account or the authority.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Owner<'a> {
    Account(&'a Id<Human>),
    Authority(&'a Id<Authority>),
}

impl Role {
    const fn owner(&self) -> Owner<'_> {
        match self {
            Self::SignIn(account) | Self::Cli(account) | Self::Recovery(account) | Self::AccountState(account) => {
                Owner::Account(account)
            }
            Self::Administrator(authority) => Owner::Authority(authority),
        }
    }

    /// Whether the last-anchor check counts the anchor: a sign-in method of an account, or an administrator binding.
    const fn protects(&self) -> bool {
        matches!(self, Self::SignIn(_) | Self::Administrator(_))
    }
}

/// An allocation floor: no value of the counter of `kind` above `value` committed before a later floor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Floor {
    /// The kind of the records whose values come from the counter, such as session generations.
    pub kind: Kind,
    /// The highest value that a commit can allocate.
    pub value: u64,
}

impl Floor {
    /// The floor that must be durable before a commit of `value`, a value of the counter of `kind`, when `durable` is
    /// its durable floor: `None` when `durable` covers `value`, else a floor that reserves the block of `block` values
    /// from `value`. Thus the commits of one block need one floor entry, and a restore raises the counter past each
    /// value that a commit can have released.
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse).
    ///
    /// # Errors
    ///
    /// [`Error::Overflow`] for a block past the largest value.
    pub fn reserve(kind: Kind, durable: u64, value: u64, block: NonZeroU64) -> Result<Option<Self>, Error> {
        if value <= durable {
            return Ok(None);
        }
        let value = value.checked_add(block.get() - 1).ok_or(Error::Overflow)?;
        Ok(Some(Self { kind, value }))
    }
}

/// The verified entries of a journal after a low-water mark: each one with the next sequence and the link of the entry
/// before it. The first one holds the link of the mark, so a journal of another history refuses.
#[derive(Clone, Debug)]
pub struct History {
    mark: Mark,
    head: Mark,
    entries: Vec<Entry>,
    /// The link that each entry holds: the link of the entry before it.
    held: Vec<Link>,
    /// The state of the first entries, which [`Self::state`] extends with the later ones.
    replayed: Replayed,
}

/// The state of the first `count` entries of a history, and the sequences that their voids cancel.
#[derive(Clone, Debug)]
struct Replayed {
    count: usize,
    voided: BTreeSet<Sequence>,
    state: State,
}

impl Replayed {
    /// The state of no entry.
    const EMPTY: Self = Self {
        count: 0,
        voided: BTreeSet::new(),
        state: State {
            dead: BTreeMap::new(),
            anchors: BTreeMap::new(),
            created: BTreeSet::new(),
            floors: BTreeMap::new(),
        },
    };
}

impl History {
    /// A history after the low-water mark `mark`, with no entry read yet.
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse).
    #[must_use]
    pub const fn new(mark: Mark) -> Self {
        Self {
            mark,
            head: mark,
            entries: Vec::new(),
            held: Vec::new(),
            replayed: Replayed::EMPTY,
        }
    }

    /// The low-water mark.
    #[must_use]
    pub const fn mark(&self) -> Mark {
        self.mark
    }

    /// The head: the mark of the last entry read, or the low-water mark before the first read. The next read of the
    /// journal starts after its sequence, and the next entry of the driver follows it.
    #[must_use]
    pub const fn head(&self) -> Mark {
        self.head
    }

    /// Adds a page of stored entries, in the order of their sequences, which a read after the sequence of
    /// [`Self::head`] gave.
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse). It reads and digests each entry once.
    ///
    /// # Errors
    ///
    /// [`Error::Missing`] when the page does not start at the next sequence: the journal does not reach back to the
    /// mark, or it has a gap. [`Error::Form`] for an entry with no valid form within `limits`, or with another
    /// sequence in its form. [`Error::Changed`] for an entry that does not hold the link of the entry before it, or of
    /// the mark: the history changed, or the journal is of another history. After an error, the history is not valid.
    pub fn extend(&mut self, page: &[super::Entry], limits: Limits) -> Result<(), Error> {
        for stored in page {
            let expected = Sequence(self.head.sequence.0.checked_add(1).ok_or(Error::Overflow)?);
            (stored.sequence == expected).ok_or(Error::Missing(expected))?;
            let (link, entry) = form::decode(&stored.data, limits)
                .filter(|(_, entry)| entry.sequence == expected)
                .ok_or(Error::Form(expected))?;
            (link == self.head.link).ok_or(Error::Changed(expected))?;
            self.head = Mark::of(expected, &stored.data);
            self.entries.push(entry);
            self.held.push(link);
        }
        Ok(())
    }

    /// The history after `mark`, a mark of this history, such as one that [`low_water`] gave.
    pub(crate) fn after(&self, mark: Mark) -> Self {
        let from = self.entries.partition_point(|entry| entry.sequence <= mark.sequence);
        Self {
            mark,
            head: self.head,
            entries: self.entries.get(from..).unwrap_or_default().to_vec(),
            held: self.held.get(from..).unwrap_or_default().to_vec(),
            replayed: Replayed::EMPTY,
        }
    }

    /// The state of the entries, the same as [`replay`] of [`Self::entries`]. It applies only the entries after its
    /// last call. After a new void, which can cancel an entry that it applied, it replays each entry again.
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse). It is linear in the new entries, or in all entries after a
    /// new void or a move of the mark.
    ///
    /// # Errors
    ///
    /// The errors of [`replay`].
    pub fn state(&mut self) -> Result<&State, Error> {
        let new = self.entries.get(self.replayed.count..).unwrap_or_default();
        if self.replayed.count == 0 || new.iter().any(|entry| matches!(entry.body, Body::Void(_))) {
            self.replayed = Replayed {
                voided: voids(&self.entries),
                ..Replayed::EMPTY
            };
        }
        for entry in self.entries.get(self.replayed.count..).unwrap_or_default() {
            if let Err(error) = self.replayed.state.apply(entry, &self.replayed.voided) {
                // The state now holds a part of an entry, so the next call replays each entry again.
                self.replayed = Replayed::EMPTY;
                return Err(error);
            }
        }
        self.replayed.count = self.entries.len();
        Ok(&self.replayed.state)
    }

    /// The mark before the entry at `index`.
    fn before(&self, index: usize) -> Mark {
        match (self.entries.get(index), self.held.get(index)) {
            (Some(entry), Some(link)) => Mark {
                sequence: Sequence(entry.sequence.0 - 1),
                link: *link,
            },
            _ => self.head,
        }
    }

    /// The entries after the mark, in the order of their sequences.
    #[must_use]
    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    /// Each key that a rule reads in the store for these entries: the key of each fact, each anchor, and each
    /// consumed value. Read each one into [`Reads::records`].
    #[must_use]
    pub fn keys(&self) -> BTreeSet<&Key> {
        let mut keys = BTreeSet::new();
        for entry in &self.entries {
            match &entry.body {
                Body::End(end) => {
                    keys.extend(end.facts.iter().map(|fact| &fact.key));
                    if let Some(consumption) = &end.consumption {
                        keys.insert(&consumption.value.key);
                        keys.extend(consumption.anchors.iter().map(|anchor| &anchor.key));
                    }
                }
                Body::Creation(anchors) => keys.extend(anchors.iter().map(|anchor| &anchor.key)),
                Body::Void(_) | Body::Floor(_) => {}
            }
        }
        keys
    }

    /// Each operation whose outcome record a rule reads for these entries: the operation of each consumption. Read
    /// each one, and each other candidate of [`reconcile`], into [`Reads::outcomes`].
    #[must_use]
    pub fn operations(&self) -> BTreeSet<&OperationId> {
        self.entries
            .iter()
            .filter(|entry| {
                matches!(
                    &entry.body,
                    Body::End(End {
                        consumption: Some(_),
                        ..
                    })
                )
            })
            .map(|entry| &entry.operation)
            .collect()
    }
}

/// The store reads of a rule: the version of each record, and whether each operation has an outcome record.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Reads {
    /// The version of the record of each key, or `None` for a key with no record.
    pub records: BTreeMap<Key, Option<AuthorityVersion>>,
    /// Whether the store has an outcome record of each operation.
    pub outcomes: BTreeMap<OperationId, bool>,
}

impl Reads {
    fn version(&self, key: &Key) -> Result<Option<&AuthorityVersion>, Error> {
        self.records.get(key).map(Option::as_ref).ok_or(Error::Unread)
    }

    fn outcome(&self, operation: &OperationId) -> Result<bool, Error> {
        self.outcomes.get(operation).copied().ok_or(Error::Unread)
    }

    /// Whether `fact` holds in the store: the record has no version at or below the version of the fact.
    fn holds(&self, fact: &Fact) -> Result<bool, Error> {
        match self.version(&fact.key)? {
            None => Ok(true),
            Some(version) => Ok(compare(version, &fact.version)? == Ordering::Greater),
        }
    }
}

fn compare(a: &AuthorityVersion, b: &AuthorityVersion) -> Result<Ordering, Error> {
    a.compare(b).map_err(|_| Error::Versions)
}

/// The state that a set of journal entries gives: the highest dead version of each key, the anchors of the creation
/// entries, the operations with a creation entry, and the highest floor of each counter. A voided entry adds nothing.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct State {
    dead: BTreeMap<Key, AuthorityVersion>,
    anchors: BTreeMap<Key, Anchor>,
    created: BTreeSet<OperationId>,
    floors: BTreeMap<Kind, u64>,
}

impl State {
    /// One fact for each key with a dead version: the highest one.
    pub fn facts(&self) -> impl Iterator<Item = Fact> {
        self.dead.iter().map(|(key, version)| Fact {
            key: key.clone(),
            version: version.clone(),
        })
    }

    /// The highest floor of each counter.
    pub fn floors(&self) -> impl Iterator<Item = Floor> {
        self.floors.iter().map(|(kind, value)| Floor {
            kind: *kind,
            value: *value,
        })
    }

    /// Whether a fact makes `version` of the record `key` dead.
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse).
    ///
    /// # Errors
    ///
    /// [`Error::Versions`] when the dead version of `key` has another owner.
    pub fn ends(&self, key: &Key, version: &AuthorityVersion) -> Result<bool, Error> {
        match self.dead.get(key) {
            None => Ok(false),
            Some(dead) => Ok(compare(version, dead)? != Ordering::Greater),
        }
    }

    /// The anchors of the creation entries that no void cancels.
    pub(crate) fn anchors(&self) -> impl Iterator<Item = &Anchor> {
        self.anchors.values()
    }

    /// The acknowledgement rule: a commit of an anchor change of an owner, or a lookup that reports it, is
    /// acknowledged only when each commit of that owner that created an anchor has its creation entry. Give each
    /// such commit in `anchor_commits`, the acknowledged one included when it created an anchor.
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse).
    #[must_use]
    pub fn acknowledges<'a>(&self, anchor_commits: impl IntoIterator<Item = &'a OperationId>) -> bool {
        anchor_commits
            .into_iter()
            .all(|operation| self.created.contains(operation))
    }

    /// Adds the facts, the anchors, or the floor of `entry`, unless `voided` holds its sequence.
    fn apply(&mut self, entry: &Entry, voided: &BTreeSet<Sequence>) -> Result<(), Error> {
        match &entry.body {
            Body::End(end) if !voided.contains(&entry.sequence) => {
                for fact in &end.facts {
                    self.kill(fact)?;
                }
            }
            Body::Creation(anchors) if !voided.contains(&entry.sequence) => {
                self.created.insert(entry.operation.clone());
                for anchor in anchors {
                    self.create(anchor)?;
                }
            }
            Body::Floor(floor) => {
                let value = self.floors.entry(floor.kind).or_insert(floor.value);
                *value = (*value).max(floor.value);
            }
            Body::End(_) | Body::Creation(_) | Body::Void(_) => {}
        }
        Ok(())
    }

    fn kill(&mut self, fact: &Fact) -> Result<(), Error> {
        match self.dead.get_mut(&fact.key) {
            None => {
                self.dead.insert(fact.key.clone(), fact.version.clone());
            }
            Some(dead) => {
                if compare(&fact.version, dead)? == Ordering::Greater {
                    dead.clone_from(&fact.version);
                }
            }
        }
        Ok(())
    }

    fn create(&mut self, anchor: &Anchor) -> Result<(), Error> {
        match self.anchors.get_mut(&anchor.key) {
            None => {
                self.anchors.insert(anchor.key.clone(), anchor.clone());
            }
            Some(earlier) => match compare(&anchor.version, &earlier.version)? {
                Ordering::Greater => earlier.clone_from(anchor),
                Ordering::Equal => (anchor == earlier).ok_or(Error::Versions)?,
                Ordering::Less => {}
            },
        }
        Ok(())
    }
}

/// Replays `entries` in any order: each fact, creation, and floor that no void in `entries` cancels. Each order, and
/// each repetition of an entry, gives the same state.
///
/// Cost class: [`Parse`](crate::limits::Class::Parse). It is linear in the entries.
///
/// # Errors
///
/// [`Error::Versions`] for two versions of one key with two owners, or two anchors of one key at one version with two
/// records.
pub fn replay(entries: &[Entry]) -> Result<State, Error> {
    let voided = voids(entries);
    let mut state = State::default();
    for entry in entries {
        state.apply(entry, &voided)?;
    }
    Ok(state)
}

/// The sequence of each entry that a void in `entries` cancels.
fn voids(entries: &[Entry]) -> BTreeSet<Sequence> {
    entries
        .iter()
        .filter_map(|entry| match entry.body {
            Body::Void(target) => Some(target),
            _ => None,
        })
        .collect()
}

/// The cause of a refused journal, entry, or rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The journal has no entry with this sequence: it does not reach back to the low-water mark, or it has a gap.
    /// Refuse the activation. Restore from another snapshot, or repair the journal.
    Missing(Sequence),
    /// The entry with this sequence does not hold the link of the entry before it, or of the mark: the retained
    /// history changed, or the journal is of another history. Refuse the activation.
    Changed(Sequence),
    /// The entry with this sequence has no valid form. Refuse the activation.
    Form(Sequence),
    /// The entry is larger than a bound of the limits, so a history with the same limits could not read it back.
    /// Refuse the proposal.
    Cbor(cbor::Error),
    /// A sequence or a floor is past the largest value. Refuse the proposal.
    Overflow,
    /// The proposal and its declaration give no journal entry: a declared key names no write of the proposal, a new
    /// record of an anchor kind has no role, a key names no record kind, or the proposal consumes two values that pay
    /// for an anchor. Refuse the proposal: it is a defect of its transition.
    Proposal,
    /// Two versions of one key have two owners, or two anchors of one key at one version have two records.
    Versions,
    /// A rule needs a store read that [`Reads`] does not have. Read each key of [`History::keys`] and each operation
    /// of [`History::operations`].
    Unread,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing(sequence) => write!(f, "the journal has no entry {}", sequence.0),
            Self::Changed(sequence) => write!(
                f,
                "the journal entry {} does not hold the link of the entry or the mark before it",
                sequence.0
            ),
            Self::Form(sequence) => write!(f, "the journal entry {} has no valid form", sequence.0),
            Self::Cbor(error) => write!(f, "the journal entry is larger than a bound of the limits: {error}"),
            Self::Overflow => f.write_str("a journal sequence or floor is past the largest value"),
            Self::Proposal => f.write_str("the proposal and its declaration give no journal entry"),
            Self::Versions => f.write_str("two journal records of one key do not compare"),
            Self::Unread => f.write_str("a journal rule needs a store read that it does not have"),
        }
    }
}

impl core::error::Error for Error {}

#[cfg(test)]
mod tests;
