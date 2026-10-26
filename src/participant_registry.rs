use frost_secp256k1_tr::Identifier;
use std::collections::{BTreeSet, HashMap};

#[derive(Debug, Clone)]
pub struct ParticipantEntry {
    pub mtls_public_key: Vec<u8>,
    pub frost_id: Identifier,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistryError {
    EmptyPublicKey,
    DuplicatePublicKey,
    DuplicateFrostId,
    UnknownPeer,
}

impl std::fmt::Display for RegistryError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RegistryError::EmptyPublicKey => {
                write!(formatter, "The public key is empty")
            }
            RegistryError::DuplicatePublicKey => {
                write!(formatter, "Duplicate mTLS public key")
            }
            RegistryError::DuplicateFrostId => {
                write!(formatter, "Duplicate FROST identifier")
            }
            RegistryError::UnknownPeer => {
                write!(formatter, "Unknown participant public key")
            }
        }
    }
}

impl std::error::Error for RegistryError {}

#[derive(Debug)]
pub struct ParticipantRegistry {
    by_public_key: HashMap<Vec<u8>, Identifier>,
}

impl ParticipantRegistry {
    /// Creates a participant registry and rejects duplicate public keys or FROST identifiers
    pub fn new(entries: impl IntoIterator<Item = ParticipantEntry>) -> Result<Self, RegistryError> {
        let mut by_public_key = HashMap::new();
        let mut seen_frost_ids = BTreeSet::new();

        for entry in entries {
            if entry.mtls_public_key.is_empty() {
                return Err(RegistryError::EmptyPublicKey);
            }

            if by_public_key.contains_key(&entry.mtls_public_key) {
                return Err(RegistryError::DuplicatePublicKey);
            }

            if !seen_frost_ids.insert(entry.frost_id.clone()) {
                return Err(RegistryError::DuplicateFrostId);
            }

            by_public_key.insert(entry.mtls_public_key, entry.frost_id);
        }
        Ok(Self { by_public_key })
    }

    /// Returns the FROST identifier assigned to an authenticated public key, or an error if the key is unknown
    pub fn frost_id_for_authenticated_key(
        &self,
        public_key: &[u8],
    ) -> Result<Identifier, RegistryError> {
        self.by_public_key
            .get(public_key)
            .cloned()
            .ok_or(RegistryError::UnknownPeer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frost_id(value: &[u8]) -> Identifier {
        Identifier::derive(value).expect("valid test identifier")
    }

    fn entry(key: &[u8], id: &[u8]) -> ParticipantEntry {
        ParticipantEntry {
            mtls_public_key: key.to_vec(),
            frost_id: frost_id(id),
        }
    }

    #[test]
    fn accepts_unique_participants() {
        let registry =
            ParticipantRegistry::new([entry(b"key-alice", b"alice"), entry(b"key-bob", b"bob")])
                .expect("valid participant map");

        assert_eq!(
            registry.frost_id_for_authenticated_key(b"key-alice"),
            Ok(frost_id(b"alice")),
        );
    }

    #[test]
    fn rejects_duplicate_public_keys() {
        let result =
            ParticipantRegistry::new([entry(b"same-key", b"alice"), entry(b"same-key", b"bob")]);

        assert!(matches!(result, Err(RegistryError::DuplicatePublicKey)));
    }

    #[test]
    fn rejects_duplicate_frost_ids() {
        let result = ParticipantRegistry::new([
            entry(b"key-alice", b"same-id"),
            entry(b"key-bob", b"same-id"),
        ]);

        assert!(matches!(result, Err(RegistryError::DuplicateFrostId)));
    }

    #[test]
    fn rejects_unknown_peers() {
        let registry = ParticipantRegistry::new([entry(b"key-alice", b"alice")])
            .expect("valid participant map");

        assert_eq!(
            registry.frost_id_for_authenticated_key(b"unknown-key"),
            Err(RegistryError::UnknownPeer),
        );
    }
}
