use crate::active_connections::ActiveConnectionRegistry;
use crate::mtls::build_tls_acceptor;
use crate::mtls::build_tls_connector;
use crate::mtls::load_public_key_from_certificate;
use crate::mtls::start_mtls_server;
use crate::mtls::PeerConnection;
use crate::participant_registry::ParticipantEntry;
use crate::participant_registry::ParticipantRegistry;
use frost::Identifier;
use frost_secp256k1_tr as frost;
use std::error::Error;
use std::io;
use std::io::ErrorKind;
use std::sync::Arc;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::TlsConnector;

/// Store the configuration for one remote participant
#[derive(Debug, Clone)]
pub struct PeerConfig {
    // The FROST ID assigned to this participant
    pub frost_id: Identifier,
    // The network address used for outgoing connections
    pub address: String,
    // The DNS name that must match the peer certificate's SAN
    pub server_name: String,
    // The certificate used to build the local participant registry
    pub certificate_path: String,
}

/// Store the configuration for one local node
pub struct NodeConfig {
    // The node's FROST ID
    pub local_frost_id: Identifier,
    // The address on which this node accepts incoming connections
    pub listen_address: String,
    // The CA certificate used to verify trusted peers
    pub ca_certificate_path: String,
    // This node's own mTLS certificate and private key
    pub local_certificate_path: String,
    pub local_private_key_path: String,
    // The remote participants known to this node
    // Do not include this node itself
    pub peers: Vec<PeerConfig>,
}

/// Store the initialized network components for one node
pub struct Node {
    local_frost_id: Identifier,
    listen_address: String,
    peers: Vec<PeerConfig>,

    tls_acceptor: TlsAcceptor,
    tls_connector: TlsConnector,

    participant_registry: Arc<ParticipantRegistry>,
    active_connection_registry: Arc<ActiveConnectionRegistry>,
}

impl Node {
    /// Loads the node configuration and creates its network components
    pub fn from_config(config: NodeConfig) -> Result<Self, Box<dyn Error + Send + Sync>> {
        // Load this node's public key
        let local_public_key = load_public_key_from_certificate(&config.local_certificate_path)?;

        // Build the participant map from the remote certificates
        let mut participant_entries = Vec::new();

        for peer in &config.peers {
            // A node must not list itself as a remote participant
            if peer.frost_id == config.local_frost_id {
                return Err(io::Error::new(
                    ErrorKind::InvalidInput,
                    "The local FROST ID must not appear in the peer list",
                )
                .into());
            }

            // Load the public key that identifies this remote participant
            let peer_public_key = load_public_key_from_certificate(&peer.certificate_path)?;

            // Reject the local certificate under another participant entry
            if peer_public_key == local_public_key {
                return Err(io::Error::new(
                    ErrorKind::InvalidInput,
                    "A peer certificate uses the local participant's public key",
                )
                .into());
            }

            // Bind the remote public key to its assigned FROST ID
            participant_entries.push(ParticipantEntry {
                mtls_public_key: peer_public_key,
                frost_id: peer.frost_id,
            });
        }

        // Validate the participant map
        // This also rejects duplicate public keys and duplicate FROST IDs
        let participant_registry = Arc::new(ParticipantRegistry::new(participant_entries)?);

        // Configure the incoming mTLS connection
        let tls_acceptor = build_tls_acceptor(
            &config.ca_certificate_path,
            &config.local_certificate_path,
            &config.local_private_key_path,
        )?;

        // Configure the outgoing mTLS connection
        let tls_connector = build_tls_connector(
            &config.ca_certificate_path,
            &config.local_certificate_path,
            &config.local_private_key_path,
        )?;

        // Create the registry for active connections
        let active_connection_registry = Arc::new(ActiveConnectionRegistry::new());

        // Return the initialized node
        Ok(Self {
            local_frost_id: config.local_frost_id,
            listen_address: config.listen_address,
            peers: config.peers,
            tls_acceptor,
            tls_connector,
            participant_registry,
            active_connection_registry,
        })
    }

    /// Returns this node's assigned FROST ID
    pub fn local_frost_id(&self) -> Identifier {
        self.local_frost_id
    }

    /// Returns the validated participant registry
    pub fn participant_registry(&self) -> Arc<ParticipantRegistry> {
        Arc::clone(&self.participant_registry)
    }

    /// Returns the active-connection registry used by this node
    pub fn active_connection_registry(&self) -> Arc<ActiveConnectionRegistry> {
        Arc::clone(&self.active_connection_registry)
    }

    /// Returns a clone of the configured TLS acceptor
    pub fn tls_acceptor(&self) -> TlsAcceptor {
        self.tls_acceptor.clone()
    }

    /// Returns a clone of the configured TLS connector
    pub fn tls_connector(&self) -> TlsConnector {
        self.tls_connector.clone()
    }

    /// Starts the listener and returns its address and verified peer connections
    pub async fn start_server(
        &self,
    ) -> Result<
        (
            std::net::SocketAddr,
            tokio::sync::mpsc::Receiver<PeerConnection>,
        ),
        Box<dyn Error + Send + Sync>,
    > {
        start_mtls_server(
            &self.listen_address,
            self.tls_acceptor.clone(),
            Arc::clone(&self.participant_registry),
            Arc::clone(&self.active_connection_registry),
            self.local_frost_id,
        )
        .await
    }

    /// Connects to a configured peer when this node is the initiator
    pub async fn connect_to_peer(
        &self,
        remote_frost_id: Identifier,
    ) -> Result<PeerConnection, Box<dyn Error + Send + Sync>> {
        // Find the peer in the local configuration
        let peer = self
            .peers
            .iter()
            .find(|peer| peer.frost_id == remote_frost_id)
            .ok_or_else(|| {
                io::Error::new(
                    ErrorKind::NotFound,
                    "The requested peer is not in the configuration",
                )
            })?;

        // Enforce the connection-direction rule before connecting
        // The smaller FROST ID must initiate the connection
        if self.local_frost_id >= peer.frost_id {
            return Err(io::Error::new(
                ErrorKind::PermissionDenied,
                "This node must wait for the remote participant to connect",
            )
            .into());
        }

        // Convert the configured server name
        let server_name: ServerName<'static> =
            peer.server_name.clone().try_into().map_err(|_| {
                io::Error::new(ErrorKind::InvalidInput, "The peer server name is invalid")
            })?;

        // Establish mTLS and bind the authenticated peer to its FROST ID
        crate::mtls::connect_to_peer(
            &peer.address,
            server_name,
            self.tls_connector.clone(),
            Arc::clone(&self.participant_registry),
            Arc::clone(&self.active_connection_registry),
            self.local_frost_id,
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initializes_node_and_builds_participant_registry() -> Result<(), Box<dyn Error + Send + Sync>>
    {
        // Assign the test FROST IDs
        let alice_frost_id: Identifier = 1_u16.try_into().expect("Invalid Alice FROST ID");

        let bob_frost_id: Identifier = 2_u16.try_into().expect("Invalid Bob FROST ID");

        let charlie_frost_id: Identifier = 3_u16.try_into().expect("Invalid Charlie FROST ID");

        // Configure Alice and her remote peers
        let alice_config = NodeConfig {
            local_frost_id: alice_frost_id,
            listen_address: "127.0.0.1:10001".to_string(),
            ca_certificate_path: "certs/ca.crt".to_string(),
            local_certificate_path: "certs/alice.crt".to_string(),
            local_private_key_path: "certs/alice.key".to_string(),

            peers: vec![
                PeerConfig {
                    frost_id: bob_frost_id,
                    address: "127.0.0.1:10002".to_string(),
                    server_name: "bob.localhost".to_string(),
                    certificate_path: "certs/bob.crt".to_string(),
                },
                PeerConfig {
                    frost_id: charlie_frost_id,
                    address: "127.0.0.1:10003".to_string(),
                    server_name: "charlie.localhost".to_string(),
                    certificate_path: "certs/charlie.crt".to_string(),
                },
            ],
        };

        // Initialize Alice's network components
        let alice_node = Node::from_config(alice_config)?;

        // Check Alice's local identity
        assert_eq!(alice_node.local_frost_id(), alice_frost_id);

        // Verify the public-key-to-FROST-ID binding for Bob
        let bob_public_key = load_public_key_from_certificate("certs/bob.crt")?;

        assert_eq!(
            alice_node
                .participant_registry()
                .frost_id_for_authenticated_key(&bob_public_key)?,
            bob_frost_id
        );

        // Verify the public-key-to-FROST-ID binding for Charlie
        let charlie_public_key = load_public_key_from_certificate("certs/charlie.crt")?;

        assert_eq!(
            alice_node
                .participant_registry()
                .frost_id_for_authenticated_key(&charlie_public_key)?,
            charlie_frost_id
        );

        Ok(())
    }

    #[tokio::test]
    async fn hands_authenticated_connection_to_node() -> Result<(), Box<dyn Error + Send + Sync>> {
        use crate::message_framing::receive_frame;
        use std::io;
        use std::time::Duration;
        use tokio::io::AsyncWriteExt;

        // Assign the FROST IDs.
        let alice_frost_id: Identifier = 1_u16.try_into().expect("Invalid Alice FROST ID");

        let bob_frost_id: Identifier = 2_u16.try_into().expect("Invalid Bob FROST ID");

        // Configure Bob with an ephemeral listening port.
        let bob_config = NodeConfig {
            local_frost_id: bob_frost_id,
            listen_address: "127.0.0.1:0".to_string(),
            ca_certificate_path: "certs/ca.crt".to_string(),
            local_certificate_path: "certs/bob.crt".to_string(),
            local_private_key_path: "certs/bob.key".to_string(),

            peers: vec![PeerConfig {
                frost_id: alice_frost_id,
                address: "127.0.0.1:0".to_string(),
                server_name: "alice.localhost".to_string(),
                certificate_path: "certs/alice.crt".to_string(),
            }],
        };

        // Initialize Bob and start his incoming listener.
        let bob_node = Node::from_config(bob_config)?;

        let (bob_address, mut incoming_connections) = bob_node.start_server().await?;

        // Configure Alice to connect to Bob's actual listener address.
        let alice_config = NodeConfig {
            local_frost_id: alice_frost_id,
            listen_address: "127.0.0.1:0".to_string(),
            ca_certificate_path: "certs/ca.crt".to_string(),
            local_certificate_path: "certs/alice.crt".to_string(),
            local_private_key_path: "certs/alice.key".to_string(),

            peers: vec![PeerConfig {
                frost_id: bob_frost_id,
                address: bob_address.to_string(),
                server_name: "bob.localhost".to_string(),
                certificate_path: "certs/bob.crt".to_string(),
            }],
        };

        let alice_node = Node::from_config(alice_config)?;

        // Alice initiates the connection because ID 1 is smaller than ID 2.
        let mut alice_connection = tokio::time::timeout(
            Duration::from_secs(5),
            alice_node.connect_to_peer(bob_frost_id),
        )
        .await??;

        assert_eq!(alice_connection.remote_frost_id, bob_frost_id,);

        // Receive the connection that Bob's server authenticated.
        let mut bob_connection =
            tokio::time::timeout(Duration::from_secs(5), incoming_connections.recv())
                .await?
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "Bob did not receive an authenticated connection",
                    )
                })?;

        // Verify that Bob's application receives Alice's verified identity.
        assert_eq!(bob_connection.remote_frost_id, alice_frost_id,);

        // Close Alice's TLS connection cleanly.
        alice_connection.tls_stream.shutdown().await?;

        let message_from_alice = receive_frame(&mut bob_connection.tls_stream).await?;

        assert!(
            message_from_alice.is_none(),
            "Bob received an unexpected message during shutdown",
        );

        // Close Bob's TLS connection cleanly.
        bob_connection.tls_stream.shutdown().await?;

        let message_from_bob = receive_frame(&mut alice_connection.tls_stream).await?;

        assert!(
            message_from_bob.is_none(),
            "Alice received an unexpected message during shutdown",
        );

        Ok(())
    }
}
