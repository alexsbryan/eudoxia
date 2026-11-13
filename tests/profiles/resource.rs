//! Concrete imperative owner. The reservation mutex is the resource's boundary,
//! never mutable authority shared with the pure kernel.
use super::*;
use std::{
    collections::BTreeSet,
    sync::{
        Arc, Mutex,
        atomic::{AtomicI64, Ordering},
    },
};

pub struct Read;
#[derive(Default)]
pub struct State {
    pub held: usize,
    pub capacity: usize,
    pub attempts: usize,
    pub effects: Vec<Vec<u8>>,
    pub fail: bool,
    pub backend_auth: Vec<&'static str>,
}
#[derive(Clone)]
pub struct Door {
    pub basis: Arc<Mutex<Basis>>,
    pub clock: Arc<AtomicI64>,
    pub state: Arc<Mutex<State>>,
    pub actor: Principal,
    pub operation: Operation,
    pub purpose: Purpose,
}
pub struct Reservation {
    exact: Fingerprint,
    state: Arc<Mutex<State>>,
    account: &'static str,
    secret: &'static str,
}
impl Drop for Reservation {
    fn drop(&mut self) {
        self.state.lock().unwrap().held -= 1;
    }
}
pub struct Output {
    pub body: Vec<u8>,
    pub account: &'static str,
    pub record: DecisionRecord,
    pub lease: Lease<Door>,
}
impl Door {
    pub fn new(basis: Basis, actor: u8, operation: &str) -> Self {
        Self {
            clock: Arc::new(AtomicI64::new(basis.at())),
            basis: Arc::new(Mutex::new(basis)),
            state: Arc::new(Mutex::new(State {
                capacity: 1,
                ..State::default()
            })),
            actor: person(actor),
            operation: op(operation),
            purpose: Purpose::Live,
        }
    }
    pub fn at(&self, at: i64) {
        self.clock.store(at, Ordering::SeqCst);
    }
    pub fn install(&self, basis: Basis) {
        *self.basis.lock().unwrap() = basis;
    }
    pub fn effects(&self) -> usize {
        self.state.lock().unwrap().effects.len()
    }
    pub fn run(&self, effect: Effect<Read>, evidence: &Evidence) -> Result<Output, String> {
        with_resource(self.clone(), |live| {
            let p = live.derive(effect, evidence).map_err(|e| e.to_string())?;
            let r = live.prepare(p).map_err(|e| e.to_string())?;
            live.execute(r).map_err(|e| e.to_string())
        })
        .unwrap()
    }
}
impl ResourceGuard for Door {
    type Action = Read;
    type Witness = Reservation;
    type Output = Output;
    type Error = &'static str;
    fn ingress(&self) -> KeyIngress {
        KeyIngress {
            actor: self.actor,
            operation: self.operation.clone(),
        }
    }
    fn purpose(&self) -> Purpose {
        self.purpose
    }
    fn current(&mut self) -> Result<Basis, Self::Error> {
        self.basis
            .lock()
            .unwrap()
            .observed_at(self.clock.load(Ordering::SeqCst))
            .map_err(|_| "authority needs reinterpretation")
    }
    fn prepare(
        &mut self,
        effect: &Effect<Read>,
        obligations: &BTreeSet<Obligation>,
    ) -> Result<Reservation, Self::Error> {
        for o in obligations {
            if o.kind != id("credential")
                || o.argument != id("readers-only")
                || o.phase != Phase::Before
            {
                return Err("unknown mandatory condition");
            }
        }
        let mut s = self.state.lock().unwrap();
        if s.held >= s.capacity {
            return Err("full");
        }
        s.held += 1;
        Ok(Reservation {
            exact: effect.fingerprint(),
            state: self.state.clone(),
            account: "readers-account",
            secret: if obligations.is_empty() {
                "none"
            } else {
                "lender-held-readers-secret"
            },
        })
    }
    fn commit(&mut self, a: Authorized<'_, Self>) -> Result<Output, Self::Error> {
        let (e, w, record, lease) =
            a.into_lease(LeaseContract::new(id("lend:library"), 2).unwrap());
        if e.fingerprint() != w.exact {
            return Err("different reservation");
        }
        let mut s = self.state.lock().unwrap();
        s.attempts += 1;
        if s.fail {
            return Err("backend failed");
        }
        s.effects.push(e.arguments().to_vec());
        s.backend_auth.push(w.secret);
        Ok(Output {
            body: e.arguments().to_vec(),
            account: w.account,
            record,
            lease,
        })
    }
}
