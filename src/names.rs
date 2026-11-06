//! Speaker names: a display name a registry bound to a principal, checked
//! before it can reach a prompt. The charset is a second layer behind the
//! attribute escaping in `render.rs`, which stays the security boundary.

use identity_crypto::PrincipalId;

use crate::AttestationError;

pub const MAX_NAME_LEN: usize = 64;

fn invalid(reason: &'static str) -> AttestationError {
    AttestationError::InvalidName { reason }
}

/// A name that passed the rule: 1 to `MAX_NAME_LEN` bytes of `[A-Za-z0-9 ._-]`,
/// no leading or trailing space, no two spaces in a row. Freely constructible,
/// because validity is a property of the string and a consumer must rebuild
/// one from its own log to re-render.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct RegisteredName(String);

impl RegisteredName {
    pub fn parse(s: &str) -> Result<Self, AttestationError> {
        if s.is_empty() {
            return Err(invalid("empty"));
        }
        if s.len() > MAX_NAME_LEN {
            return Err(invalid("longer than 64 bytes"));
        }
        if !s.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b' ' | b'.' | b'_' | b'-')) {
            return Err(invalid("only [A-Za-z0-9 ._-] is allowed"));
        }
        if s.starts_with(' ') || s.ends_with(' ') {
            return Err(invalid("leading or trailing space"));
        }
        if s.contains("  ") {
            return Err(invalid("two spaces in a row"));
        }
        Ok(Self(s.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A name the registry bound to this principal. Signing takes only these, so
/// a deliverer cannot sign an invalid name. There are two constructors:
/// `from_signed` (crate-private, used for entries of a Delivery whose
/// signature verified) and `from_registry` (only with the `resolver` feature).
///
/// The feature is not access control: any crate may enable it. The guarantee
/// is that it is greppable.
#[cfg_attr(
    not(feature = "resolver"),
    doc = "\n\n`from_registry` does not exist without the `resolver` feature:\n\n```compile_fail,E0599\nuse identity_crypto::jwk_duo::GenerationService;\nuse identity_crypto::principal_id;\nuse message_attestation::{RegisteredName, ResolvedPrincipal};\n\nlet id = principal_id(&GenerationService::generate_key_duo());\nlet name = RegisteredName::parse(\"gp\").unwrap();\nlet _ = ResolvedPrincipal::from_registry(id, name);\n```"
)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedPrincipal {
    id: PrincipalId,
    name: RegisteredName,
}

impl ResolvedPrincipal {
    pub fn id(&self) -> &PrincipalId {
        &self.id
    }

    pub fn name(&self) -> &RegisteredName {
        &self.name
    }

    #[cfg(feature = "resolver")]
    pub fn from_registry(id: PrincipalId, name: RegisteredName) -> Self {
        Self { id, name }
    }

    pub(crate) fn from_signed(id: PrincipalId, name: RegisteredName) -> Self {
        Self { id, name }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registered_name_accepts_the_allowed_set() {
        for ok in ["gp", "worker-gait", "Ada L. 2"] {
            assert_eq!(RegisteredName::parse(ok).unwrap().as_str(), ok);
        }
        assert!(RegisteredName::parse(&"a".repeat(MAX_NAME_LEN)).is_ok());
    }

    #[test]
    fn registered_name_refuses() {
        let long = "a".repeat(65);
        let table: [(&str, &str); 11] = [
            ("", "empty"),
            (&long, "65 bytes"),
            ("a\"b", "quote"),
            ("a<b", "angle"),
            ("a\nb", "newline"),
            ("a\u{202e}b", "bidi override"),
            ("p256:x", "principal lookalike"),
            (" gp", "leading space"),
            ("gp ", "trailing space"),
            ("a  b", "double space"),
            ("Jos\u{e9}", "non-ascii letter"),
        ];
        for (name, why) in table {
            let e = RegisteredName::parse(name).unwrap_err();
            assert!(matches!(e, AttestationError::InvalidName { .. }), "{why}: {e:?}");
        }
    }
}
