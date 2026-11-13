//! Laws of what an app may write as its person: a reading app writes
//! nothing, and that is the app's identity, checked before any owner's
//! rule; a write counts only in the app's own part.
use eudoxia_community::app::{self, Act, Class, Through, Unwritten, Write};

/// The Ed25519 base point: a key that reads as one.
const KEY: [u8; 32] = [
    0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
];
const PERSON: &str = "5866666666666666666666666666666666666666666666666666666666666666";
const GROUP: &str = "the-group";

fn write(class: Class, act: Option<Act<'static>>, here: bool) -> Write<'static> {
    Write {
        node: &KEY,
        group: GROUP,
        person: PERSON,
        app: "money",
        class,
        act,
        through: Through::Route { here, sized: true },
    }
}

/// A carried app that reads others' lends writes nothing in the record;
/// one that does not, writes its own part.
#[test]
fn a_reading_app_cannot_write() {
    let who = (GROUP, PERSON);
    assert_eq!(
        app::writes(&KEY, who, "money", Class::Connector),
        Err(Unwritten::Reads)
    );
    assert_eq!(app::writes(&KEY, who, "money", Class::Record), Ok(()));
    let record = write(Class::Connector, Some(Act::Record), true);
    assert_eq!(app::write(&record, || ()), Err(Unwritten::Reads));
}

/// The class is refused before any owner's rule is read: a reading app's
/// write is refused as a reader's whatever the rules would say of it.
#[test]
fn the_class_is_checked_before_any_owner_rule() {
    let elsewhere = write(Class::Connector, Some(Act::Record), false);
    assert_eq!(app::write(&elsewhere, || ()), Err(Unwritten::Reads));
    let other = write(
        Class::Connector,
        Some(Act::Correct {
            target: Some("talk"),
        }),
        true,
    );
    assert_eq!(app::write(&other, || ()), Err(Unwritten::Reads));
    let shapeless = write(Class::Connector, None, true);
    assert_eq!(app::write(&shapeless, || ()), Err(Unwritten::Reads));
}

/// A record app's write counts in its own part only, from the computer
/// carrying it; a correction of another part's entry, or of one not held,
/// does not.
#[test]
fn a_record_app_writes_its_own_part() {
    let counted = write(Class::Record, Some(Act::Record), true);
    assert_eq!(app::write(&counted, || 7), Ok(7));
    let own = write(
        Class::Record,
        Some(Act::Correct {
            target: Some("money"),
        }),
        true,
    );
    assert_eq!(app::write(&own, || ()), Ok(()));
    let other = write(
        Class::Record,
        Some(Act::Correct {
            target: Some("talk"),
        }),
        true,
    );
    assert_eq!(app::write(&other, || ()), Err(Unwritten::OtherPart));
    let unheld = write(Class::Record, Some(Act::Correct { target: None }), true);
    assert_eq!(app::write(&unheld, || ()), Err(Unwritten::OtherPart));
    let elsewhere = write(Class::Record, Some(Act::Record), false);
    assert_eq!(app::write(&elsewhere, || ()), Err(Unwritten::Elsewhere));
}

/// A lent app's answer is refused in the order its facts are read.
#[test]
fn an_answer_is_refused_in_order() {
    let answer = |read, both, lent, theirs| Write {
        through: Through::Answer {
            read,
            both,
            lent,
            theirs,
        },
        ..write(Class::Record, Some(Act::Record), true)
    };
    let refused = |w: Write| app::write(&w, || ()).err();
    assert_eq!(
        refused(answer(false, false, false, false)),
        Some(Unwritten::Unread)
    );
    assert_eq!(
        refused(answer(true, false, false, false)),
        Some(Unwritten::NotBoth)
    );
    assert_eq!(
        refused(answer(true, true, false, false)),
        Some(Unwritten::NotLent)
    );
    assert_eq!(
        refused(answer(true, true, true, false)),
        Some(Unwritten::OtherPart)
    );
    assert_eq!(refused(answer(true, true, true, true)), None);
}
