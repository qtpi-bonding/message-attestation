//! The deliverer's principal, read from a delegation's genesis key.

use identity_crypto::{pb, PrincipalId, PublicKey};

use crate::AttestationError;

/// The principal whose genesis key roots `d`, the deliverer's device delegation.
pub(crate) fn delegation_principal(d: &pb::KeyDelegation) -> Result<PrincipalId, AttestationError> {
    let genesis = d.principal_genesis.as_ref().ok_or_else(|| {
        AttestationError::Transcript("missing signer_device.principal_genesis".into())
    })?;
    let key =
        PublicKey::try_from(genesis).map_err(|e| AttestationError::Transcript(Box::new(e)))?;
    Ok(PrincipalId::from_genesis(key))
}
