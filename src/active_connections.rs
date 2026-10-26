use frost_secp256k1_tr::Identifier;
use std::collections::BTreeSet;
use std::error::Error;
use std::fmt;
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActiveConnectionError {
    DuplicateConnection,
    LockPoisoned,
}

impl fmt::Display for ActiveConnectionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ActiveConnectionError::DuplicateConnection => {
                write!(
                    formatter,
                    "A connection to this FROST participant is already active"
                )
            }
            ActiveConnectionError::LockPoisoned => {
                write!(formatter, "The active-connection registry is unavailable")
            }
        }
    }
}

impl Error for ActiveConnectionError {}

pub struct ActiveConnectionRegistry {
    active_frost_ids: Mutex<BTreeSet<Identifier>>,
}

impl ActiveConnectionRegistry {
    /// Creates an empty registry for active peer connections
    pub fn new() -> Self {
        Self {
            active_frost_ids: Mutex::new(BTreeSet::new()),
        }
    }

    /// Reserves a FROST ID and rejects a second active connection to that ID
    pub fn reserve(
        self: &Arc<Self>,
        remote_frost_id: Identifier,
    ) -> Result<ActiveConnectionGuard, ActiveConnectionError> {
        // Lock the registry before checking or inserting the ID
        let mut active_frost_ids = self
            .active_frost_ids
            .lock()
            .map_err(|_| ActiveConnectionError::LockPoisoned)?;

        // Insert the ID. BTreeSet rejects a duplicate
        if !active_frost_ids.insert(remote_frost_id) {
            return Err(ActiveConnectionError::DuplicateConnection);
        }

        // Return a guard that owns this reservation
        Ok(ActiveConnectionGuard {
            registry: Arc::clone(self),
            remote_frost_id,
        })
    }

    /// Checks whether a FROST ID has an active connection
    pub fn is_active(&self, remote_frost_id: &Identifier) -> Result<bool, ActiveConnectionError> {
        let active_frost_ids = self
            .active_frost_ids
            .lock()
            .map_err(|_| ActiveConnectionError::LockPoisoned)?;

        Ok(active_frost_ids.contains(remote_frost_id))
    }
}

pub struct ActiveConnectionGuard {
    registry: Arc<ActiveConnectionRegistry>,
    remote_frost_id: Identifier,
}

impl Drop for ActiveConnectionGuard {
    fn drop(&mut self) {
        // Release the ID when the connection handler ends
        if let Ok(mut active_frost_ids) = self.registry.active_frost_ids.lock() {
            active_frost_ids.remove(&self.remote_frost_id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn frost_id(value: u16) -> Identifier {
        value.try_into().expect("Invalid test FROST ID")
    }

    #[test]
    fn accepts_a_single_connection() {
        let registry = Arc::new(ActiveConnectionRegistry::new());

        let bob_frost_id = frost_id(2);

        let connection_guard = registry
            .reserve(bob_frost_id)
            .expect("First connection should be accepted");

        assert!(
            registry.is_active(&bob_frost_id).unwrap(),
            "Bob should have an active connection"
        );

        drop(connection_guard);

        assert!(
            !registry.is_active(&bob_frost_id).unwrap(),
            "Bob's ID should be released after the connection ends"
        );
    }

    #[test]
    fn rejects_a_second_connection_to_the_same_peer() {
        let registry = Arc::new(ActiveConnectionRegistry::new());

        let bob_frost_id = frost_id(2);

        let _first_connection = registry
            .reserve(bob_frost_id)
            .expect("First connection should be accepted");

        let second_connection = registry.reserve(bob_frost_id);

        assert_eq!(
            second_connection.err(),
            Some(ActiveConnectionError::DuplicateConnection)
        );
    }

    #[test]
    fn allows_connections_to_different_peers() {
        let registry = Arc::new(ActiveConnectionRegistry::new());

        let bob_frost_id = frost_id(2);
        let charlie_frost_id = frost_id(3);

        let _bob_connection = registry
            .reserve(bob_frost_id)
            .expect("Bob's connection should be accepted");

        let _charlie_connection = registry
            .reserve(charlie_frost_id)
            .expect("Charlie's connection should be accepted");

        assert!(registry.is_active(&bob_frost_id).unwrap());
        assert!(registry.is_active(&charlie_frost_id).unwrap());
    }
}
