//! Adapter-level proof of the native door shape: async acquisition stays outside
//! the kernel, a start forwards once, and checks keep the *same* held use.
//! Native socket/browser integration still has to run its existing scene bars.
mod profiles;
use eudoxia::*;
use profiles::*;
use std::{
    cell::{Cell, RefCell},
    collections::BTreeSet,
    rc::Rc,
};

struct Reach;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Stage {
    Idle,
    Reserved(u64),
    Streaming(u64),
    Closed,
}
struct Service {
    stage: Stage,
    reserves: usize,
    starts: Vec<Vec<u8>>,
    checks: usize,
    ends: usize,
}
#[derive(Clone)]
struct Owner {
    service: Rc<RefCell<Service>>,
    inputs: Rc<RefCell<Inputs>>,
    resource: Resource,
    clock: Rc<Cell<i64>>,
    serial: Rc<Cell<u64>>,
}
#[derive(Clone, Copy)]
enum Offered {
    Yes,
    Withdrawn,
}
#[derive(Clone, Copy)]
enum Choice {
    Yes,
    Stop,
}
struct Inputs {
    offered: Offered,
    choice: Choice,
}
struct Slot {
    owner: Owner,
    id: u64,
}
impl Slot {
    fn pending_for(&self, owner: &Owner) -> bool {
        Rc::ptr_eq(&self.owner.service, &owner.service)
            && self.owner.resource == owner.resource
            && owner.service.borrow().stage == Stage::Reserved(self.id)
    }
}
impl Drop for Slot {
    fn drop(&mut self) {
        let mut s = self.owner.service.borrow_mut();
        s.stage = Stage::Closed;
        s.ends += 1;
    }
}
enum Mode {
    Start(Option<(Slot, Vec<u8>)>),
    Check(u64),
}
struct Guard {
    owner: Owner,
    mode: Mode,
    operation: Operation,
}
enum Witness {
    Start {
        slot: Slot,
        body: Vec<u8>,
        exact: Fingerprint,
    },
    Check {
        id: u64,
        exact: Fingerprint,
    },
}
enum Output {
    Started { slot: Slot, next: Lease<Guard> },
    Checked(Lease<Guard>),
}
struct Active {
    slot: Slot,
    next: Lease<Guard>,
}
impl Owner {
    fn new() -> Self {
        Self::named("library")
    }
    fn named(name: &str) -> Self {
        Self {
            service: Rc::new(RefCell::new(Service {
                stage: Stage::Idle,
                reserves: 0,
                starts: vec![],
                checks: 0,
                ends: 0,
            })),
            inputs: Rc::new(RefCell::new(Inputs {
                offered: Offered::Yes,
                choice: Choice::Yes,
            })),
            resource: Resource::new(format!("house/{name}")).unwrap(),
            clock: Rc::new(Cell::new(30)),
            serial: Rc::new(Cell::new(0)),
        }
    }
    // Models the existing async Using::ask reply. This is a concrete pending
    // acquisition, not executable authorization; dropping it releases the slot.
    fn acquire(&self) -> Result<Slot, &'static str> {
        let mut s = self.service.borrow_mut();
        if matches!(s.stage, Stage::Reserved(_) | Stage::Streaming(_)) {
            return Err("full");
        }
        let id = self.serial.get() + 1;
        self.serial.set(id);
        s.stage = Stage::Reserved(id);
        s.reserves += 1;
        Ok(Slot {
            owner: self.clone(),
            id,
        })
    }
    fn effect(&self, slot: &Slot) -> Effect<Reach> {
        // Owner-generated identity of the single owned pending request/body.
        let mut e = request(4, "use");
        e.resource = self.resource.clone();
        e.request = Id::new(format!("request-{}", slot.id)).unwrap();
        Effect::from_bytes(e, slot.id.to_be_bytes().to_vec())
    }
    fn start_acquired(&self, slot: Slot, body: Vec<u8>) -> Result<Active, String> {
        let e = self.effect(&slot);
        let guard = Guard {
            owner: self.clone(),
            mode: Mode::Start(Some((slot, body))),
            operation: op("use"),
        };
        let output = with_resource(guard, |live| {
            let p = live
                .derive(e, &Evidence::default())
                .map_err(|e| e.to_string())?;
            let r = live.prepare(p).map_err(|e| e.to_string())?;
            live.execute(r).map_err(|e| e.to_string())
        })
        .map_err(str::to_string)??;
        match output {
            Output::Started { slot, next } => Ok(Active { slot, next }),
            _ => Err("start returned no connection".into()),
        }
    }
    fn withdraw(&self) {
        self.inputs.borrow_mut().offered = Offered::Withdrawn;
    }
    fn stop_future(&self) {
        self.inputs.borrow_mut().choice = Choice::Stop;
    }
}
impl Active {
    fn check(self) -> Result<Self, String> {
        let Self { slot, next } = self;
        let guard = Guard {
            owner: slot.owner.clone(),
            mode: Mode::Check(slot.id),
            operation: op("use"),
        };
        let output = next.execute_unit(guard).map_err(|e| format!("{e:?}"))?;
        match output {
            Output::Checked(next) => Ok(Self { slot, next }),
            _ => Err("check tried to open another request".into()),
        }
    }
    fn stop(self) {
        self.next.stop();
    }
}
impl ResourceGuard for Guard {
    type Action = Reach;
    type Witness = Witness;
    type Output = Output;
    type Error = &'static str;
    fn ingress(&self) -> KeyIngress {
        KeyIngress {
            actor: person(4),
            operation: self.operation.clone(),
        }
    }
    fn current(&mut self) -> Result<Basis, Self::Error> {
        let inputs = self.owner.inputs.borrow();
        let mut lend = policy("service-owner");
        lend.source = reference(self.owner.resource.as_str().as_bytes());
        lend.scope.coverage = Coverage::Exact(self.owner.resource.clone());
        lend.scope.operations = [op("use")].into();
        lend.scope.interval = Interval::new(0, 40).unwrap();
        let mut choice = lend.clone();
        choice.owner = eudoxia::Owner::new("person-choice").unwrap();
        let choice_state = match &self.mode {
            Mode::Start(_) => {
                choice.source = reference(
                    format!("private-choice:{}", self.owner.resource.as_str()).as_bytes(),
                );
                match inputs.choice {
                    Choice::Yes => FactState::Established,
                    Choice::Stop => FactState::Refused(Reason::Profile(id("stopped"))),
                }
            }
            Mode::Check(use_id) => {
                choice.source = reference(
                    format!("admitted:{}:{use_id}", self.owner.resource.as_str()).as_bytes(),
                );
                if self.owner.service.borrow().stage == Stage::Streaming(*use_id) {
                    FactState::Established
                } else {
                    FactState::Refused(Reason::Profile(id("no-active-use")))
                }
            }
        };
        let lend_state = match inputs.offered {
            Offered::Yes => FactState::Established,
            Offered::Withdrawn => FactState::Refused(Reason::Profile(id("withdrawn"))),
        };
        let facts = vec![
            Fact {
                source: lend.source.clone(),
                state: lend_state,
            },
            Fact {
                source: choice.source.clone(),
                state: choice_state,
            },
        ];
        Ok(snapshot(self.owner.clock.get(), vec![lend, choice], facts))
    }
    fn prepare(
        &mut self,
        effect: &Effect<Reach>,
        obligations: &BTreeSet<Obligation>,
    ) -> Result<Witness, Self::Error> {
        if !obligations.is_empty() {
            return Err("unknown condition");
        }
        let exact = effect.fingerprint();
        match &mut self.mode {
            Mode::Start(pending) => {
                let (slot, body) = pending.take().ok_or("already prepared")?;
                if !slot.pending_for(&self.owner) || effect.arguments() != slot.id.to_be_bytes() {
                    return Err("wrong pending request");
                }
                Ok(Witness::Start { slot, body, exact })
            }
            Mode::Check(id) => {
                if self.owner.service.borrow().stage != Stage::Streaming(*id)
                    || effect.arguments() != id.to_be_bytes()
                {
                    return Err("wrong active use");
                }
                Ok(Witness::Check { id: *id, exact })
            }
        }
    }
    fn commit(&mut self, a: Authorized<'_, Self>) -> Result<Output, Self::Error> {
        let (e, w, _, next) = a.into_lease(LeaseContract::new(id("native-lend-use"), 2).unwrap());
        match w {
            Witness::Start { slot, body, exact } => {
                if !slot.pending_for(&self.owner) {
                    return Err("foreign or stale reservation");
                }
                let mut s = self.owner.service.borrow_mut();
                if exact != e.fingerprint() || s.stage != Stage::Reserved(slot.id) {
                    return Err("stale reservation");
                }
                s.stage = Stage::Streaming(slot.id);
                s.starts.push(body);
                Ok(Output::Started { slot, next })
            }
            Witness::Check { id, exact } => {
                let mut s = self.owner.service.borrow_mut();
                if exact != e.fingerprint() || s.stage != Stage::Streaming(id) {
                    return Err("stale active use");
                }
                s.checks += 1;
                Ok(Output::Checked(next))
            }
        }
    }
}

#[test]
fn a_post_is_forwarded_once_and_idle_checks_keep_one_original_slot() {
    let owner = Owner::new();
    let body = b"POST /start-job with a non-repeatable body".to_vec();
    let mut active = owner
        .start_acquired(owner.acquire().unwrap(), body.clone())
        .unwrap();
    for at in [31, 32, 33] {
        owner.clock.set(at);
        active = active.check().unwrap();
        assert!(owner.acquire().is_err());
    }
    let s = owner.service.borrow();
    assert_eq!(s.starts, vec![body]);
    assert_eq!((s.reserves, s.checks, s.ends), (1, 3, 0));
    drop(s);
    active.stop();
    assert_eq!(owner.service.borrow().ends, 1);
    assert!(owner.acquire().is_ok());
}

#[test]
fn a_change_while_async_acquisition_waited_cannot_forward_the_pending_body() {
    let owner = Owner::new();
    let pending = owner.acquire().unwrap();
    owner.withdraw();
    assert!(
        owner
            .start_acquired(pending, b"must not reach the backend".to_vec())
            .is_err()
    );
    let s = owner.service.borrow();
    assert!(s.starts.is_empty());
    assert_eq!((s.reserves, s.ends), (1, 1));
}

#[test]
fn withdrawal_closes_the_existing_use_once_and_an_independent_use_continues() {
    let (owner, other) = (Owner::new(), Owner::named("radio"));
    let active = owner
        .start_acquired(owner.acquire().unwrap(), vec![1])
        .unwrap();
    let ongoing = other
        .start_acquired(other.acquire().unwrap(), vec![2])
        .unwrap();
    owner.clock.set(31);
    owner.withdraw();
    assert!(active.check().is_err());
    other.clock.set(31);
    let ongoing = ongoing.check().unwrap();
    assert_eq!(owner.service.borrow().ends, 1);
    assert_eq!(other.service.borrow().ends, 0);
    assert_eq!(owner.service.borrow().starts.len(), 1);
    ongoing.stop();
    assert_eq!(other.service.borrow().ends, 1);
}

#[test]
fn the_existing_future_only_stop_rule_is_not_silently_changed_to_cancellation() {
    let owner = Owner::new();
    let active = owner
        .start_acquired(owner.acquire().unwrap(), vec![1])
        .unwrap();
    owner.stop_future();
    owner.clock.set(31);
    let active = active.check().unwrap();
    assert_eq!(owner.service.borrow().starts.len(), 1);
    assert_eq!(owner.service.borrow().ends, 0);
    active.stop();
    let pending = owner.acquire().unwrap();
    assert!(owner.start_acquired(pending, vec![2]).is_err());
    assert_eq!(owner.service.borrow().starts.len(), 1);
}

#[test]
fn a_pending_reservation_for_another_lend_cannot_satisfy_this_lends_condition() {
    let (a, b) = (Owner::new(), Owner::named("radio"));
    let foreign = a.acquire().unwrap();
    let own = b.acquire().unwrap();
    assert!(
        b.start_acquired(foreign, b"must not use another lend's slot".to_vec())
            .is_err()
    );
    assert!(b.service.borrow().starts.is_empty());
    assert_eq!(b.service.borrow().reserves, 1);
    let active = b.start_acquired(own, vec![2]).unwrap();
    assert_eq!(b.service.borrow().starts.len(), 1);
    active.stop();
}
