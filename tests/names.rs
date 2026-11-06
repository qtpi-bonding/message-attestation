//! Signed speaker names. Needs the `resolver` feature: `from_registry` is the
//! only way a deliverer makes a `ResolvedPrincipal`.

mod common;

use common::*;
use identity_crypto::transcripts::delivery_transcript;
use identity_crypto::{pb, PrincipalId};
use message_attestation::{
    sign_delivery, sign_message, verify_delivery, AttestationError, DeliveryPolicy,
    MemoryReplayStore, OutgoingMessage, RegisteredName, ResolvedPrincipal, UnsignedDelivery,
};

fn resolved(id: &PrincipalId, name: &str) -> ResolvedPrincipal {
    ResolvedPrincipal::from_registry(id.clone(), RegisteredName::parse(name).unwrap())
}

struct Setup {
    dl: Deliverer,
    a: Author,
    b: Author,
    recipient: Author,
    own: Vec<identity_crypto::PublicKey>,
    trusted: Vec<PrincipalId>,
}

fn setup() -> Setup {
    let dl = deliverer(T0);
    Setup {
        trusted: vec![dl.id.clone()],
        dl,
        a: author(T0),
        b: author(T0),
        recipient: author(T0),
        own: vec![device_key()],
    }
}

impl Setup {
    fn outgoing(&self, a: &Author, id: &str) -> OutgoingMessage {
        let m = message(id, vec![room("r")]);
        OutgoingMessage {
            message: sign_message(&a.session, a.delegation.clone(), &self.dl.id, T0, &m).unwrap(),
            via: vec![room("r")],
        }
    }

    fn unsigned(&self, names: Vec<ResolvedPrincipal>) -> UnsignedDelivery {
        let mut u = unsigned(
            &self.recipient,
            &self.own,
            1,
            T0,
            vec![self.outgoing(&self.a, "m-a"), self.outgoing(&self.b, "m-b")],
        );
        u.names = names;
        u
    }

    fn sign(&self, u: UnsignedDelivery) -> Result<pb::Delivery, AttestationError> {
        sign_delivery(self.dl.device.signing_key_pair(), &self.dl.delegation, u)
    }

    fn policy(&self) -> DeliveryPolicy<'_> {
        DeliveryPolicy {
            trusted: &self.trusted,
            self_id: &self.recipient.id,
            own_devices: &self.own,
            max_age_secs: None,
            now_unix: T0,
        }
    }

    fn verify(&self, d: &pb::Delivery) -> Result<message_attestation::Verified, AttestationError> {
        verify_delivery(d, &self.policy(), &MemoryReplayStore::default())
    }

    /// Replaces field 10 by hand and signs the raw transcript, as a buggy deliverer could.
    fn with_raw_names(&self, names: Vec<(String, &str)>) -> pb::Delivery {
        let mut d = self.sign(self.unsigned(vec![])).unwrap();
        d.names = names
            .into_iter()
            .map(|(principal_id, name)| pb::PrincipalName { principal_id, name: name.to_string() })
            .collect();
        let t = delivery_transcript(&d).unwrap();
        d.signature = self.dl.device.signing_key_pair().sign_bytes(&t).unwrap().to_vec();
        d
    }
}

#[test]
fn from_registry_exists_with_the_resolver_feature() {
    let p = resolved(&author(T0).id, "gp");
    assert_eq!(p.name().as_str(), "gp");
}

#[test]
fn signed_names_round_trip_to_verified_messages() {
    let s = setup();
    let d = s.sign(s.unsigned(vec![resolved(&s.a.id, "gp"), resolved(&s.b.id, "worker-gait")])).unwrap();
    assert_eq!(d.names.len(), 2);
    let v = s.verify(&d).unwrap().delivery;
    assert_eq!(v.messages()[0].author_name().map(|n| n.as_str()), Some("gp"));
    assert_eq!(v.messages()[1].author_name().map(|n| n.as_str()), Some("worker-gait"));
    assert_eq!(v.messages()[0].view().author_name, Some("gp"));
    let got: Vec<(String, String)> =
        v.names().iter().map(|n| (n.id().to_string(), n.name().as_str().to_string())).collect();
    let mut want = vec![(s.a.id.to_string(), "gp".to_string()), (s.b.id.to_string(), "worker-gait".to_string())];
    want.sort();
    assert_eq!(got, want);
}

#[test]
fn an_unnamed_author_has_no_name() {
    let s = setup();
    let d = s.sign(s.unsigned(vec![resolved(&s.a.id, "gp")])).unwrap();
    let v = s.verify(&d).unwrap().delivery;
    assert_eq!(v.messages()[0].author_name().map(|n| n.as_str()), Some("gp"));
    assert!(v.messages()[1].author_name().is_none());
    assert_eq!(v.messages()[1].view().author_name, None);
}

#[test]
fn sign_sorts_names_by_principal() {
    let s = setup();
    let mut ids = [s.a.id.to_string(), s.b.id.to_string()];
    ids.sort();
    let (first, second) = if ids[0] == s.a.id.to_string() { (&s.a, &s.b) } else { (&s.b, &s.a) };
    let d = s.sign(s.unsigned(vec![resolved(&second.id, "two"), resolved(&first.id, "one")])).unwrap();
    let got: Vec<&str> = d.names.iter().map(|n| n.principal_id.as_str()).collect();
    assert_eq!(got, [ids[0].as_str(), ids[1].as_str()]);
    drop(s.verify(&d).unwrap());
}

#[test]
fn a_name_for_a_non_author_is_refused_at_sign_and_verify() {
    let s = setup();
    let e = s.sign(s.unsigned(vec![resolved(&s.recipient.id, "gp")])).unwrap_err();
    match e {
        AttestationError::StrayName { principal } => assert_eq!(principal, s.recipient.id.to_string()),
        other => panic!("{other:?}"),
    }
    let d = s.with_raw_names(vec![(s.recipient.id.to_string(), "gp")]);
    assert!(matches!(s.verify(&d), Err(AttestationError::StrayName { .. })));
}

#[test]
fn a_duplicate_name_is_refused_at_sign() {
    let s = setup();
    let e = s.sign(s.unsigned(vec![resolved(&s.a.id, "gp"), resolved(&s.a.id, "gp2")]));
    assert!(matches!(e, Err(AttestationError::Transcript(_))), "{e:?}");
}

#[test]
fn an_invalid_name_in_a_signed_delivery_is_refused_at_verify() {
    let s = setup();
    for bad in ["a\"b", "a<b", "a\nb", "a\u{202e}b", "p256:x", " gp", "a  b", "José"] {
        let d = s.with_raw_names(vec![(s.a.id.to_string(), bad)]);
        let e = s.verify(&d).unwrap_err();
        assert!(matches!(e, AttestationError::InvalidName { .. }), "{bad:?}: {e:?}");
    }
    let too_long = "a".repeat(65);
    let d = s.with_raw_names(vec![(s.a.id.to_string(), &too_long)]);
    assert!(matches!(s.verify(&d), Err(AttestationError::InvalidName { .. })));
}
