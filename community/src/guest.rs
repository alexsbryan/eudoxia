//! Guests, judged along each host computer's own chain. A visit is a fill:
//! it takes one of its host's slots whose previous fill has ended, its
//! `until` at or before the new fill's signed time, or a counting Stop of it
//! earlier on the chain. Freeness comes from the chain behind the fill, never
//! from what a copy holds elsewhere: a hole in the chain makes the fills
//! after it Missing, and a fork freezes the fills on its branches. How many
//! slots each computer has is the keeper's setting the fill names, and with
//! none named, [`GUESTS_DEFAULT`]. A fill counts only with its guest's consent
//! to its own host, so another member's copy of a guest's key is refused and
//! takes nothing from the host the guest chose. One walk per chain, so the work is linear
//! in the chain.
use super::*;

/// The longest visit, from its fill's own signed time.
pub const VISIT_LONGEST: i64 = 48 * 60 * 60;
/// Each computer's guests at once while a fill names no setting.
pub const GUESTS_DEFAULT: u8 = 2;
/// The most a keeper's setting may give each computer.
pub const GUESTS_MOST: u8 = 8;

/// Every fill's verdict, and each fill the walk counted with its Stop.
pub(super) struct Fills<C: Vocabulary> {
    pub(super) verdicts: BTreeMap<Id<C>, Judged<C, ()>>,
    pub(super) stops: BTreeMap<Id<C>, Id<C>>,
}

type Line<'a, C> = (&'a Id<C>, &'a Statement<C>);

impl<'a, C: Vocabulary> Community<'a, C> {
    pub(super) fn fills(&self) -> &Fills<C> {
        self.memo.fills.get_or_init(|| self.walk_fills())
    }
    /// One pass over the held set to group lines by chain and to read which
    /// keys an Admit or another host's fill names; then one walk per chain
    /// that holds a fill.
    fn walk_fills(&self) -> Fills<C> {
        let mut chains: BTreeMap<&str, Vec<Line<'a, C>>> = BTreeMap::new();
        let mut named: BTreeSet<&str> = self.roots.members.keys().map(String::as_str).collect();
        let mut hosts: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
        for (id, op) in self.held() {
            chains.entry(op.author.as_str()).or_default().push((id, op));
            match &op.act {
                Act::Admit { key, .. } => drop(named.insert(key)),
                Act::Fill {
                    key, consent: true, ..
                } => drop(hosts.entry(key).or_default().insert(&op.author)),
                _ => {}
            }
        }
        // Never bound, and no other computer's fill names it (two hosts of
        // one key: neither is picked).
        let taken = |key: &str| named.contains(key) || hosts.get(key).is_some_and(|h| h.len() > 1);
        let mut fills = Fills {
            verdicts: BTreeMap::new(),
            stops: BTreeMap::new(),
        };
        for lines in chains.into_values() {
            if lines
                .iter()
                .any(|(_, op)| matches!(op.act, Act::Fill { .. }))
            {
                self.walk_chain(&lines, &taken, &mut fills);
            }
        }
        fills
    }
    /// The chain from its first line, in order, until it ends or forks; each
    /// fill past a fork Frozen, past a hole the hole's failure.
    fn walk_chain(
        &self,
        lines: &[Line<'a, C>],
        taken: &dyn Fn(&str) -> bool,
        fills: &mut Fills<C>,
    ) {
        let mut next: BTreeMap<Option<&Id<C>>, Vec<Line<'a, C>>> = BTreeMap::new();
        let ids: BTreeSet<&Id<C>> = lines.iter().map(|(id, _)| *id).collect();
        for line in lines {
            next.entry(line.1.prev.as_ref()).or_default().push(*line);
        }
        let mut walked = Vec::new();
        let mut at = None;
        while let Some(children) = next.get(&at) {
            if let [only] = children.as_slice() {
                walked.push(*only);
                at = Some(only.0);
                continue;
            }
            let branches: BTreeSet<Id<C>> = children.iter().map(|(id, _)| (*id).clone()).collect();
            let source = at.map_or(AuthorityRef::Genesis, |id| AuthorityRef::Act(id.clone()));
            let frozen = SourceFailure::Frozen { source, branches };
            self.after(&next, children, &frozen, fills);
            break;
        }
        let holes: BTreeSet<&Id<C>> = (lines.iter())
            .filter_map(|(_, op)| op.prev.as_ref().filter(|p| !ids.contains(p)))
            .collect();
        for hole in holes {
            let why = match self.get(hole) {
                Err(why) => why,
                Ok(_) => SourceFailure::Refused {
                    why: SourceFault::Closure,
                },
            };
            self.after(&next, &next[&Some(hole)], &why, fills);
        }
        self.slots(&walked, taken, fills);
    }
    /// `why` for every fill from `starts` on, by the chain's links.
    fn after(
        &self,
        next: &BTreeMap<Option<&Id<C>>, Vec<Line<'a, C>>>,
        starts: &[Line<'a, C>],
        why: &SourceFailure<Id<C>>,
        fills: &mut Fills<C>,
    ) {
        let mut pending = starts.to_vec();
        while let Some((id, op)) = pending.pop() {
            if matches!(op.act, Act::Fill { .. }) {
                fills.verdicts.insert(id.clone(), Err(why.clone()));
            }
            pending.extend(next.get(&Some(id)).into_iter().flatten());
        }
    }
    /// The walk itself: each fill against the fills still on before it.
    fn slots(&self, walked: &[Line<'a, C>], taken: &dyn Fn(&str) -> bool, fills: &mut Fills<C>) {
        let mut on: Vec<(&Id<C>, i64)> = Vec::new();
        let mut used: BTreeSet<&str> = BTreeSet::new();
        // The fills this walk counted: a Stop frees only its own chain's.
        let mut mine: BTreeSet<&Id<C>> = BTreeSet::new();
        for (id, op) in walked {
            match &op.act {
                Act::Correct {
                    corrects,
                    replacement: None,
                } if mine.contains(corrects)
                    && !fills.stops.contains_key(corrects)
                    && self.assess(id).is_ok() =>
                {
                    on.retain(|(fill, _)| *fill != corrects);
                    fills.stops.insert(corrects.clone(), (*id).clone());
                }
                Act::Fill {
                    key,
                    until,
                    under,
                    consent,
                } => {
                    let fresh = !taken(key) && used.insert(key.as_str());
                    let verdict = match consent {
                        false => refused(SourceFault::Consent),
                        true => self.fill(op.at, *until, under.as_ref(), fresh, &mut on),
                    };
                    if verdict.is_ok() {
                        on.push((id, *until));
                        mine.insert(id);
                    }
                    fills.verdicts.insert((*id).clone(), verdict);
                }
                _ => {}
            }
        }
    }
    /// One fill at `at`: within its bounds, under the setting it names, and
    /// with fewer fills on than that setting gives.
    fn fill(
        &self,
        at: i64,
        until: i64,
        under: Option<&Id<C>>,
        fresh: bool,
        on: &mut Vec<(&Id<C>, i64)>,
    ) -> Judged<C, ()> {
        let per = match under {
            None => GUESTS_DEFAULT,
            Some(setting) => self.setting(setting)?,
        };
        if !fresh || !(1..=VISIT_LONGEST).contains(&until.saturating_sub(at)) {
            return refused(SourceFault::Guest);
        }
        on.retain(|(_, ends)| *ends > at);
        if on.len() >= usize::from(per) {
            return refused(SourceFault::Full);
        }
        Ok(())
    }
    /// A setting counts only as an office act the office walk selected: the
    /// keeper's, under a held office.
    pub(super) fn setting(&self, id: &Id<C>) -> Judged<C, u8> {
        let resolution = self.resolution();
        match &self.get(id)?.act {
            Act::Slots { per_computer } if resolution.selected.contains(id) => Ok(*per_computer),
            _ => Err(
                office_failure(&resolution.state).unwrap_or(SourceFailure::Refused {
                    why: SourceFault::Office,
                }),
            ),
        }
    }
}
