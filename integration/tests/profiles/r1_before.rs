//! Frozen pre-swap native R1 predicates, copied from svrngs core at cce47451.
//! Test oracle only. Original messages, IDs, keys and verification stay native.
use std::collections::BTreeMap;
use svrngs_core::{
    grant::{Why, bare_id},
    pass::{Label, Pass, PassFault, Whose, carried_name},
    *,
};

pub fn signed(pass: &Pass) -> bool {
    let one =
        |sig: &str| sig.len() == 128 && sig.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
    let approved = match (&pass.op, &pass.approver, &pass.approval) {
        (None, _, None) => true,
        (Some(_), Some(by), Some(sig)) => one(sig) && verify_hex(by, &pass.approval_message(), sig),
        _ => false,
    };
    one(&pass.sig) && approved && verify_hex(&pass.person, &pass.message(), &pass.sig)
}
pub fn check(pass: &Pass, holder: &str, lend: &Label, now: i64) -> Result<(), PassFault> {
    if pass.op.is_some() {
        return Err(PassFault::NotReach);
    }
    if !signed(pass) {
        return Err(PassFault::Unsigned);
    }
    if pass.holder != holder {
        return Err(PassFault::NotTheHolder);
    }
    if now >= pass.until {
        return Err(PassFault::Lapsed);
    }
    if &pass.app != lend && !pass.reads.contains(lend) {
        return Err(PassFault::NotNamed);
    }
    Ok(())
}
pub fn carries(
    pass: &Pass,
    link: &Pass,
    to: &str,
    lend: &Label,
    now: i64,
) -> Result<(), PassFault> {
    check(link, to, lend, now)?;
    check(pass, &link.person, lend, now)?;
    let within = link.reads.iter().all(|r| pass.reads.contains(r));
    match within && link.app == pass.app && link.until <= pass.until {
        true => Ok(()),
        false => Err(PassFault::Wider),
    }
}
fn may(pass: &Pass, group: &str, holder: &str, kind: Option<&str>, at: i64) -> Result<(), Why> {
    if pass.holder != holder {
        return Err(Why::NotTheHolder);
    }
    if at >= pass.until {
        return Err(Why::Lapsed);
    }
    let Some(kind) = kind else {
        return Err(Why::Decides);
    };
    let carries = match pass.app.whose() {
        Whose::Carried => Label::carried(kind, group) == pass.app,
        Whose::Computer(key) => Label::of(&key, &carried_name(kind, group)) == pass.app,
    };
    if carries { Ok(()) } else { Err(Why::OtherKind) }
}
pub fn entry(
    pass: &Pass,
    line: &Op<SignedOp>,
    group: &str,
    held: &BTreeMap<OpId, &Op<SignedOp>>,
) -> Result<(), Why> {
    if !signed(pass) {
        return Err(Why::Unsigned);
    }
    if pass
        .op
        .as_ref()
        .is_some_and(|id| *id != bare_id(line, group))
    {
        return Err(Why::Unapproved);
    }
    match &line.kind.act {
        RailAct::Record { payload } => {
            may(pass, group, &line.actor, Some(payload.app()), line.ts_unix)
        }
        RailAct::Correct {
            corrects,
            replacement,
        } => {
            let kind = held
                .get(corrects)
                .map(|t| t.kind.act.payload().map_or("", Payload::app));
            match kind {
                Some(k) if replacement.as_ref().is_none_or(|r| r.app() == k) => {
                    may(pass, group, &line.actor, Some(k), line.ts_unix)
                }
                held => Err(held.map_or(Why::Unheld, |_| Why::OtherKind)),
            }
        }
        _ => may(pass, group, &line.actor, None, line.ts_unix),
    }
}
pub fn approving(pass: &Pass, line: &Op<SignedOp>, group: &str, now: i64) -> Option<Pass> {
    let payload = match &line.kind.act {
        RailAct::Record { payload } => Ok(Some(payload)),
        RailAct::Correct { replacement, .. } => Ok(replacement.as_ref()),
        _ => Err(()),
    };
    let scoped = payload
        .is_ok_and(|p| p.is_none_or(|p| may(pass, group, &line.actor, Some(p.app()), now).is_ok()));
    let live = now < pass.until && line.ts_unix < pass.until;
    let approves = pass.approver.is_some() && pass.op.is_none() && signed(pass);
    (scoped && live && approves && pass.holder == line.actor).then(|| Pass {
        op: Some(bare_id(line, group)),
        ..pass.clone()
    })
}

/// Frozen from web/src/lib.rs::approve_line before the swap; native parsing and
/// JS-array construction are outside this original eligibility calculation.
pub fn approve_in_open(
    approver: &str,
    group: &str,
    reach: &Pass,
    issued: &Pass,
    line: &Op<SignedOp>,
    now: i64,
) -> Result<Pass, &'static str> {
    let grant = line.kind.grant.as_ref().ok_or("no write grant")?;
    let named = |p: &Pass| p.approver.as_deref() == Some(approver);
    let ours = named(reach)
        && named(grant)
        && grant == issued
        && reach.app.whose() == grant.app.whose()
        && now.abs_diff(line.ts_unix) <= 300;
    if !ours || check(reach, &line.actor, &reach.app, now).is_err() {
        return Err("this app has no live authority here");
    }
    approving(grant, line, group, now).ok_or("this entry was not approved")
}
