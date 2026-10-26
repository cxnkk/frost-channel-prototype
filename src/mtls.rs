use crate::active_connections::ActiveConnectionGuard;
use crate::active_connections::ActiveConnectionRegistry;
use crate::message_framing::receive_frame;
use crate::participant_registry::ParticipantRegistry;
use frost_secp256k1_tr::Identifier;
use std::error::Error;
use std::fs::File;
use std::io;
use std::io::BufReader;
use std::io::ErrorKind;
use std::pin::Pin;
use std::sync::Arc;
use std::task::Context;
use std::task::Poll;
use tokio::io::AsyncRead;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWrite;
use tokio::io::AsyncWriteExt;
use tokio::io::ReadBuf;
use tokio::net::TcpListener;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio_rustls::rustls::pki_types::CertificateDer;
use tokio_rustls::rustls::pki_types::PrivateKeyDer;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::server::WebPkiClientVerifier;
use tokio_rustls::rustls::ClientConfig;
use tokio_rustls::rustls::RootCertStore;
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::server::TlsStream;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::TlsConnector;
use x509_parser::prelude::FromDer;
use x509_parser::prelude::X509Certificate;

/// Represents an authenticated TLS connection in either direction
pub enum PeerTlsStream {
    // This node initiated the connection
    Client(tokio_rustls::client::TlsStream<TcpStream>),
    // The remote participant initiated the connection
    Server(tokio_rustls::server::TlsStream<TcpStream>),
}

/// Allows message framing to read from either type of TLS connection
impl AsyncRead for PeerTlsStream {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            PeerTlsStream::Client(tls_stream) => Pin::new(tls_stream).poll_read(context, buffer),
            PeerTlsStream::Server(tls_stream) => Pin::new(tls_stream).poll_read(context, buffer),
        }
    }
}

/// Allows message framing to write to either type of TLS connection.
impl AsyncWrite for PeerTlsStream {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            PeerTlsStream::Client(tls_stream) => Pin::new(tls_stream).poll_write(context, buffer),
            PeerTlsStream::Server(tls_stream) => Pin::new(tls_stream).poll_write(context, buffer),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            PeerTlsStream::Client(tls_stream) => Pin::new(tls_stream).poll_flush(context),
            PeerTlsStream::Server(tls_stream) => Pin::new(tls_stream).poll_flush(context),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            PeerTlsStream::Client(tls_stream) => Pin::new(tls_stream).poll_shutdown(context),
            PeerTlsStream::Server(tls_stream) => Pin::new(tls_stream).poll_shutdown(context),
        }
    }
}

/// Stores an authenticated peer connection and its verified identity
pub struct PeerConnection {
    // The TLS stream can be an incoming or outgoing connection
    pub tls_stream: PeerTlsStream,
    // The ID resolved from the authenticated peer certificate
    pub remote_frost_id: Identifier,
    // Keeps this participant's connection reservation active
    _active_connection_guard: ActiveConnectionGuard,
}

/// Loads a certificate from a file and extracts its public key for the participant registry
pub fn load_public_key_from_certificate(
    certificate_path: &str,
) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
    // Load the certificate
    let certificates = load_certificates(certificate_path)?;

    // Get the first certificate
    let certificate = certificates
        .first()
        .ok_or_else(|| io::Error::new(ErrorKind::InvalidData, "The certificate file is empty"))?;

    // Parse the certificate
    let (_, parsed_certificate) = X509Certificate::from_der(certificate.as_ref())?;

    // Extract the public key in DER format
    let public_key = parsed_certificate.public_key().raw.to_vec();

    Ok(public_key)
}

/// Loads certificates from a PEM file and returns them for TLS configuration
fn load_certificates(
    certificate_path: &str,
) -> Result<Vec<CertificateDer<'static>>, Box<dyn Error + Send + Sync>> {
    // Open the certificate file
    let certificate_file = File::open(certificate_path)?;
    let mut certificate_reader = BufReader::new(certificate_file);

    // Read all certificates from the PEM file
    let certificates =
        rustls_pemfile::certs(&mut certificate_reader).collect::<Result<Vec<_>, _>>()?;

    // Reject an empty certificate file
    if certificates.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("No certificates found in {certificate_path}"),
        )
        .into());
    }

    Ok(certificates)
}

/// Loads a private key from a PEM file for TLS authentication
fn load_private_key(
    private_key_path: &str,
) -> Result<PrivateKeyDer<'static>, Box<dyn Error + Send + Sync>> {
    // Open the private key file
    let private_key_file = File::open(private_key_path)?;
    let mut private_key_reader = BufReader::new(private_key_file);

    // Read the private key
    let private_key = rustls_pemfile::private_key(&mut private_key_reader)?;

    // Reject a file without a supported private key
    let private_key = private_key.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("No private key found in {private_key_path}"),
        )
    })?;

    Ok(private_key)
}

/// Creates a TLS acceptor that verifies client certificates and presents this node's certificate
pub fn build_tls_acceptor(
    ca_certificate_path: &str,
    server_certificate_path: &str,
    server_private_key_path: &str,
) -> Result<TlsAcceptor, Box<dyn Error + Send + Sync>> {
    // Load the CA certificate
    let ca_certificates = load_certificates(ca_certificate_path)?;

    // Create the trust store for client certificates
    let mut root_cert_store = RootCertStore::empty();

    for ca_certificate in ca_certificates {
        root_cert_store.add(ca_certificate)?;
    }

    // Require clients to present a trusted certificate
    let client_certificate_verifier =
        WebPkiClientVerifier::builder(Arc::new(root_cert_store)).build()?;

    // Load the server certificate and private key
    let server_certificates = load_certificates(server_certificate_path)?;

    let server_private_key = load_private_key(server_private_key_path)?;

    // Configure TLS with mandatory client authentication
    let server_config = ServerConfig::builder()
        .with_client_cert_verifier(client_certificate_verifier)
        .with_single_cert(server_certificates, server_private_key)?;

    // Create the acceptor for incoming TLS connections
    let tls_acceptor = TlsAcceptor::from(Arc::new(server_config));

    Ok(tls_acceptor)
}

/// Creates a TLS connector that verifies the server and presents this node's client certificate
pub fn build_tls_connector(
    ca_certificate_path: &str,
    client_certificate_path: &str,
    client_private_key_path: &str,
) -> Result<TlsConnector, Box<dyn Error + Send + Sync>> {
    // Load the CA certificate
    let ca_certificates = load_certificates(ca_certificate_path)?;

    // Create the trust store for server certificates
    let mut root_cert_store = RootCertStore::empty();

    for ca_certificate in ca_certificates {
        root_cert_store.add(ca_certificate)?;
    }

    // Load this participants certificate and private key
    let client_certificates = load_certificates(client_certificate_path)?;

    let client_private_key = load_private_key(client_private_key_path)?;

    // Configure TLS to verify the server and present our certificate
    let client_config = ClientConfig::builder()
        .with_root_certificates(root_cert_store)
        .with_client_auth_cert(client_certificates, client_private_key)?;

    // Create the TLS connector
    let tls_connector = TlsConnector::from(Arc::new(client_config));

    Ok(tls_connector)
}

/// Extracts the public key from the client certificate authenticated by the TLS handshake
fn get_authenticated_peer_public_key(
    tls_stream: &TlsStream<TcpStream>,
) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
    // Get the TLS connection
    let (_, tls_connection) = tls_stream.get_ref();

    // Get the certificates from the authenticated peer
    let peer_certificates = tls_connection.peer_certificates().ok_or_else(|| {
        io::Error::new(
            ErrorKind::PermissionDenied,
            "The peer has no authenticated certificate.",
        )
    })?;

    // Get the peer's leaf certificate
    let peer_certificate = peer_certificates.first().ok_or_else(|| {
        io::Error::new(
            ErrorKind::PermissionDenied,
            "The peer has no authenticated certificate.",
        )
    })?;

    // Parse the certificate
    let (_, parsed_certificate) = X509Certificate::from_der(peer_certificate.as_ref())?;

    // Get the public key in DER format
    let public_key = parsed_certificate.public_key().raw.to_vec();

    Ok(public_key)
}

/// Extracts the public key from the server certificate authenticated by the TLS handshake
fn get_authenticated_server_public_key(
    tls_stream: &tokio_rustls::client::TlsStream<TcpStream>,
) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
    // Get the TLS connection
    let (_, tls_connection) = tls_stream.get_ref();

    // Get the server certificate
    let server_certificates = tls_connection.peer_certificates().ok_or_else(|| {
        io::Error::new(
            ErrorKind::PermissionDenied,
            "The server has no authenticated certificate",
        )
    })?;

    let server_certificate = server_certificates.first().ok_or_else(|| {
        io::Error::new(
            ErrorKind::PermissionDenied,
            "The server certificate list is empty",
        )
    })?;

    // Parse the certificate
    let (_, parsed_certificate) = X509Certificate::from_der(server_certificate.as_ref())?;

    // Extract the public-key bytes
    let public_key = parsed_certificate.public_key().raw.to_vec();

    Ok(public_key)
}

// TODO: Continue here
/// Starts the mTLS listener and returns authenticated incoming connections to the application through channel
pub async fn start_mtls_server(
    listen_address: &str,
    tls_acceptor: TlsAcceptor,
    participant_registry: Arc<ParticipantRegistry>,
    active_connection_registry: Arc<ActiveConnectionRegistry>,
    local_frost_id: Identifier,
) -> Result<(std::net::SocketAddr, mpsc::Receiver<PeerConnection>), Box<dyn Error + Send + Sync>> {
    // Open the TCP listener
    let tcp_listener = TcpListener::bind(listen_address).await?;

    // Get the actual address. This also works when the port is 0
    let bound_address = tcp_listener.local_addr()?;

    println!(
        "mTLS listener started on {} for participant {:?}",
        listen_address, local_frost_id
    );

    // Create a channel for authenticated incoming connections
    let (connection_sender, connection_receiver) = mpsc::channel::<PeerConnection>(32);

    // Run the listener in a background task
    tokio::spawn(async move {
        loop {
            // Wait for the next incoming TCP connection
            let (tcp_stream, peer_address) = match tcp_listener.accept().await {
                Ok(connection) => connection,
                Err(error) => {
                    eprintln!("TCP listener failed: {}", error);

                    break;
                }
            };

            // Clone the shared state for this connection
            let connection_tls_acceptor = tls_acceptor.clone();

            let connection_participant_registry = Arc::clone(&participant_registry);

            let connection_active_registry = Arc::clone(&active_connection_registry);

            let connection_sender = connection_sender.clone();

            let connection_local_frost_id = local_frost_id;

            // Authenticate each connection in a separate task
            tokio::spawn(async move {
                match accept_peer_connection(
                    tcp_stream,
                    peer_address,
                    connection_tls_acceptor,
                    connection_participant_registry,
                    connection_active_registry,
                    connection_local_frost_id,
                )
                .await
                {
                    Ok(peer_connection) => {
                        // Give the authenticated connection to the application
                        if connection_sender.send(peer_connection).await.is_err() {
                            eprintln!("The application no longer accepts incoming connections");
                        }
                    }
                    Err(error) => {
                        eprintln!(
                            "Rejected incoming connection from {}: {}",
                            peer_address, error
                        );
                    }
                }
            });
        }
    });

    // Return the receiver to the application
    Ok((bound_address, connection_receiver))
}

/// Authenticates an incoming peer, resolves its FROST ID and returns the active TLS connection
pub async fn accept_peer_connection(
    tcp_stream: TcpStream,
    peer_address: std::net::SocketAddr,
    tls_acceptor: TlsAcceptor,
    participant_registry: Arc<ParticipantRegistry>,
    active_connection_registry: Arc<ActiveConnectionRegistry>,
    local_frost_id: Identifier,
) -> Result<PeerConnection, Box<dyn Error + Send + Sync>> {
    // Perform the mTLS handshake
    let tls_stream = tls_acceptor.accept(tcp_stream).await?;

    println!("mTLS handshake completed with {}", peer_address);

    // Get the public key from the authenticated peer certificate
    let peer_public_key = get_authenticated_peer_public_key(&tls_stream)?;

    // Resolve the peer's assigned FROST ID
    let frost_id = participant_registry.frost_id_for_authenticated_key(&peer_public_key)?;

    // Accept incoming connections only from participants with a smaller FROST ID.
    if frost_id >= local_frost_id {
        return Err(io::Error::new(
            ErrorKind::PermissionDenied,
            format!(
                "Rejected incoming connection from {:?}: \
                 the remote FROST ID must be smaller than the local FROST ID",
                frost_id
            ),
        )
        .into());
    }

    // Reserve the remote FROST ID. The reservation remains active while PeerConnection exists
    let active_connection_guard =
        active_connection_registry
            .reserve(frost_id)
            .map_err(|error| {
                io::Error::new(
                    ErrorKind::AlreadyExists,
                    format!(
                        "Cannot accept a second connection from {:?}: {}",
                        frost_id, error
                    ),
                )
            })?;

    println!(
        "Authenticated peer {} as FROST participant {:?}",
        peer_address, frost_id
    );

    // Return the verified connection and its reservation guard
    Ok(PeerConnection {
        tls_stream: PeerTlsStream::Server(tls_stream),
        remote_frost_id: frost_id,
        _active_connection_guard: active_connection_guard,
    })
}

/// Authenticates an incoming peer, looks up its FROST ID, and keeps the encrypted connection open
async fn handle_peer_connection(
    tcp_stream: TcpStream,
    peer_address: std::net::SocketAddr,
    tls_acceptor: TlsAcceptor,
    participant_registry: Arc<ParticipantRegistry>,
    active_connection_registry: Arc<ActiveConnectionRegistry>,
    local_frost_id: Identifier,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    // Authenticate the peer and obtain its verified connection
    let mut peer_connection = accept_peer_connection(
        tcp_stream,
        peer_address,
        tls_acceptor,
        participant_registry,
        active_connection_registry,
        local_frost_id,
    )
    .await?;

    // Store the authenticated FROST ID for message handling
    let remote_frost_id = peer_connection.remote_frost_id;

    // Read complete messages until the peer closes the connection
    loop {
        let message = receive_frame(&mut peer_connection.tls_stream).await?;

        let Some(message) = message else {
            break;
        };

        println!(
            "Received one complete message of {} bytes from FROST particiapnt {:?}",
            message.len(),
            remote_frost_id
        );

        // The message is framed, but we do not process DKG messages yet
    }

    println!("Connection closed for participant {:?}", remote_frost_id);

    Ok(())
}

/// Opens an mTLS connection, identifies the remote FROST participant, and returns the connection and its FROST ID
pub async fn connect_to_peer(
    peer_address: &str,
    server_name: ServerName<'static>,
    tls_connector: TlsConnector,
    participant_registry: Arc<ParticipantRegistry>,
    active_connection_registry: Arc<ActiveConnectionRegistry>,
    local_frost_id: Identifier,
) -> Result<PeerConnection, Box<dyn Error + Send + Sync>> {
    // Open the TCP connection
    let tcp_stream = TcpStream::connect(peer_address).await?;

    // Perform the mTLS handshake
    // Rustls verifies the server certificate and its server name
    let tls_stream = tls_connector.connect(server_name, tcp_stream).await?;

    // Get the authenticated servers public key
    let server_public_key = get_authenticated_server_public_key(&tls_stream)?;

    // Look up the assigned FROST ID
    let frost_id = participant_registry
        .frost_id_for_authenticated_key(&server_public_key)
        .map_err(|error| {
            io::Error::new(
                ErrorKind::PermissionDenied,
                format!("The server is not in the participant registry: {:?}", error),
            )
        })?;

    // Initiate outgoing connections only to participants with a larger FROST ID
    if local_frost_id >= frost_id {
        return Err(io::Error::new(
            ErrorKind::PermissionDenied,
            format!(
                "Rejected outgoing connection to {:?}: \
                 the local FROST ID must be smaller than the remote FROST ID",
                frost_id
            ),
        )
        .into());
    }

    // Reserve the remote FROST ID.
    // Reject a second active connection to this participant.
    let active_connection_guard =
        active_connection_registry
            .reserve(frost_id)
            .map_err(|error| {
                io::Error::new(
                    ErrorKind::AlreadyExists,
                    format!(
                        "Cannot connect to FROST participant {:?}: {}",
                        frost_id, error
                    ),
                )
            })?;

    // Return the connection  and the verified participant ID
    println!(
        "Connected to FROST participant {:?} at {}",
        frost_id, peer_address
    );

    // Return the connection and keep its reservation alive
    Ok(PeerConnection {
        tls_stream: PeerTlsStream::Client(tls_stream),
        remote_frost_id: frost_id,
        _active_connection_guard: active_connection_guard,
    })
}

/// Starts a TCP listener and handles incoming peer connections
pub async fn run_mtls_server(
    listen_address: &str,
    tls_acceptor: TlsAcceptor,
    participant_registry: Arc<ParticipantRegistry>,
    active_connection_registry: Arc<ActiveConnectionRegistry>,
    local_frost_id: Identifier,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    // Open the TCP listener
    let tcp_listener = TcpListener::bind(listen_address).await?;

    println!(
        "mTLS listener started on {} for FROST participant {:?}",
        listen_address, local_frost_id
    );

    // Accept incoming connections
    loop {
        let (tcp_stream, peer_address) = tcp_listener.accept().await?;

        // Give each connection its own handler
        let connection_tls_acceptor = tls_acceptor.clone();

        let connection_registry = Arc::clone(&participant_registry);

        let connection_active_registry = Arc::clone(&active_connection_registry);

        let connection_local_frost_id = local_frost_id.clone();

        tokio::spawn(async move {
            if let Err(error) = handle_peer_connection(
                tcp_stream,
                peer_address,
                connection_tls_acceptor,
                connection_registry,
                connection_active_registry,
                connection_local_frost_id,
            )
            .await
            {
                eprintln!(
                    "Connection from {} rejected or closed {}",
                    peer_address, error
                );
            }
        });
    }
}

#[cfg(test)]
mod certificate_tests {
    use super::load_public_key_from_certificate;
    use crate::participant_registry::{ParticipantEntry, ParticipantRegistry};
    use frost_secp256k1_tr as frost;

    #[test]
    fn test_certificate_public_keys_map_to_correct_frost_ids() {
        // Load the public keys from both certificates
        let alice_public_key = load_public_key_from_certificate("certs/alice.crt")
            .expect("Failed to load Alice's public key");

        let bob_public_key = load_public_key_from_certificate("certs/bob.crt")
            .expect("Failed to load Bob's public key");

        // Confirm that the public keys are different
        assert_ne!(alice_public_key, bob_public_key);

        // Assign a separate FROST ID to each participant
        let alice_frost_id: frost::Identifier = 1_u16.try_into().expect("Invalid Alice FROST ID");

        let bob_frost_id: frost::Identifier = 2_u16.try_into().expect("Invalid Bob FROST ID");

        // Build the participant registry
        let participant_registry = ParticipantRegistry::new([
            ParticipantEntry {
                mtls_public_key: alice_public_key.clone(),
                frost_id: alice_frost_id,
            },
            ParticipantEntry {
                mtls_public_key: bob_public_key.clone(),
                frost_id: bob_frost_id,
            },
        ])
        .expect("Failed to create the participant registry");

        // Verify Alice's mapping
        assert_eq!(
            participant_registry
                .frost_id_for_authenticated_key(&alice_public_key)
                .expect("Alice was not found"),
            alice_frost_id
        );

        // Verify Bob's mapping
        assert_eq!(
            participant_registry
                .frost_id_for_authenticated_key(&bob_public_key)
                .expect("Bob was not found"),
            bob_frost_id
        );
    }
}

#[cfg(test)]
mod mtls_integration_tests {
    use super::*;

    use crate::active_connections::ActiveConnectionGuard;
    use crate::dkg_handler::receive_dkg_message;
    use crate::dkg_handler::ReceivedDkgPayload;
    use crate::dkg_messages::DkgMessage;
    use crate::dkg_messages::DkgMessageKind;
    use crate::echo_broadcast::EchoBroadcastInstance;
    use crate::echo_broadcast::EchoBroadcastMessage;
    use crate::echo_broadcast::EchoBroadcastOutcome;
    use crate::echo_broadcast::EchoBroadcastPhase;
    use crate::message_framing::receive_frame;
    use crate::message_framing::send_frame;
    use crate::node::Node;
    use crate::node::NodeConfig;
    use crate::node::PeerConfig;
    use crate::participant_registry::ParticipantEntry;
    use frost_secp256k1_tr as frost;
    use frost_secp256k1_tr::Identifier;
    use rand_core::OsRng;
    use std::collections::BTreeMap;
    use std::io;
    use std::io::ErrorKind;
    use std::sync::Arc;
    use tokio::io::AsyncRead;
    use tokio::io::AsyncReadExt;
    use tokio::io::AsyncWrite;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;
    use tokio::net::TcpStream;
    use tokio_rustls::rustls::pki_types::ServerName;
    use tokio_rustls::TlsAcceptor;

    // Stores an authenticated incoming connection and its reservation.
    type AcceptedTestPeer = (PeerTlsStream, Identifier, ActiveConnectionGuard);

    // Accepts and authenticates a peer, then resolves its FROST ID.
    async fn accept_test_peer(
        tcp_listener: &TcpListener,
        tls_acceptor: &TlsAcceptor,
        participant_registry: Arc<ParticipantRegistry>,
        active_connection_registry: Arc<ActiveConnectionRegistry>,
        local_frost_id: Identifier,
    ) -> Result<AcceptedTestPeer, Box<dyn Error + Send + Sync>> {
        // Accept the TCP connection.
        let (tcp_stream, peer_address) = tcp_listener.accept().await?;

        let peer_connection = accept_peer_connection(
            tcp_stream,
            peer_address,
            tls_acceptor.clone(),
            Arc::clone(&participant_registry),
            Arc::clone(&active_connection_registry),
            local_frost_id,
        )
        .await?;

        Ok((
            peer_connection.tls_stream,
            peer_connection.remote_frost_id,
            peer_connection._active_connection_guard,
        ))
    }

    // Encodes and sends one echo-broadcast message in a DKG envelope.
    async fn send_echo_broadcast_message<W>(
        writer: &mut W,
        echo_message: &EchoBroadcastMessage,
    ) -> Result<(), Box<dyn Error + Send + Sync>>
    where
        W: AsyncWrite + Unpin,
    {
        // Encode the echo-broadcast message.
        let echo_payload = echo_message.encode()?;

        // Wrap it in the outer DKG message.
        let dkg_message = DkgMessage {
            kind: DkgMessageKind::EchoBroadcast,
            payload: echo_payload,
        };

        // Encode and send the complete framed message.
        let encoded_dkg_message = dkg_message.encode();

        send_frame(writer, &encoded_dkg_message).await?;

        Ok(())
    }

    /// Receives an echo-broadcast message and checks the authenticated sender.
    async fn receive_echo_broadcast_message<R>(
        reader: &mut R,
        authenticated_sender_id: Identifier,
    ) -> Result<EchoBroadcastMessage, Box<dyn Error + Send + Sync>>
    where
        R: AsyncRead + Unpin,
    {
        // 1. Receive and decode the DKG message using the DKG handler.
        let received_dkg_message = receive_dkg_message(reader, authenticated_sender_id)
            .await?
            .ok_or_else(|| {
                io::Error::new(
                    ErrorKind::UnexpectedEof,
                    "Connection closed before the DKG message arrived",
                )
            })?;

        // 2. Get the echo-broadcast payload.
        match received_dkg_message.payload {
            ReceivedDkgPayload::EchoBroadcast(echo_message) => Ok(echo_message),

            // Reject a different DKG message type.
            _ => Err(
                io::Error::new(ErrorKind::InvalidData, "Expected an echo-broadcast message").into(),
            ),
        }
    }

    // Sends one recipient-specific FROST Part 2 package over mTLS.
    async fn send_round2_package<W>(
        writer: &mut W,
        round2_package: &frost::keys::dkg::round2::Package,
    ) -> Result<(), Box<dyn Error + Send + Sync>>
    where
        W: AsyncWrite + Unpin,
    {
        // 1. Serialize the public Round 2 package.
        let serialized_package = round2_package.serialize()?;

        // 2. Wrap the package in a direct DKG message.
        let dkg_message = DkgMessage {
            kind: DkgMessageKind::Round2Direct,
            payload: serialized_package,
        };

        // 3. Encode and send the complete message over mTLS.
        let encoded_message = dkg_message.encode();

        send_frame(writer, &encoded_message).await?;

        Ok(())
    }

    // Receives and deserializes one recipient-specific FROST Part 2 package.
    async fn receive_round2_package<R>(
        reader: &mut R,
    ) -> Result<frost::keys::dkg::round2::Package, Box<dyn Error + Send + Sync>>
    where
        R: AsyncRead + Unpin,
    {
        // 1. Receive one complete framed message.
        let encoded_message = receive_frame(reader).await?.ok_or_else(|| {
            io::Error::new(
                ErrorKind::UnexpectedEof,
                "Connection closed before the Round 2 package arrived",
            )
        })?;

        // 2. Decode the outer DKG message.
        let dkg_message = DkgMessage::decode(&encoded_message)?;

        // 3. Require a direct Round 2 message.
        if dkg_message.kind != DkgMessageKind::Round2Direct {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                "Expected a direct Round 2 package",
            )
            .into());
        }

        // 4. Deserialize the FROST package.
        let round2_package = frost::keys::dkg::round2::Package::deserialize(&dkg_message.payload)?;

        Ok(round2_package)
    }

    fn require_delivered_echo_value(
        outcome: EchoBroadcastOutcome,
        receiver_name: &str,
        broadcaster_id: Identifier,
    ) -> Result<Vec<u8>, io::Error> {
        // Return the package when the broadcast succeeds
        match outcome {
            EchoBroadcastOutcome::Delivered(package_bytes) => Ok(package_bytes),
            // Report an error when the broadcast has not delivered a package
            other => Err(io::Error::new(
                ErrorKind::InvalidData,
                format!(
                    "{} did not deliver the package from {:?}: {:?}",
                    receiver_name, broadcaster_id, other
                ),
            )),
        }
    }

    #[tokio::test]
    async fn authenticates_peers_and_resolves_frost_ids() -> Result<(), Box<dyn Error + Send + Sync>>
    {
        // Load the public keys from both certificates
        let alice_public_key = load_public_key_from_certificate("certs/alice.crt")?;

        let bob_public_key = load_public_key_from_certificate("certs/bob.crt")?;

        // Assign the FROST IDs for this test
        let alice_frost_id: Identifier = 1u16.try_into().expect("Invalid Alice FROST ID");

        let bob_frost_id: Identifier = 2u16.try_into().expect("Invalid Bob FROST ID");

        // Create Alice's registry
        // Alice must know which FROST ID belongs to Bob
        let alice_registry = Arc::new(ParticipantRegistry::new([ParticipantEntry {
            mtls_public_key: bob_public_key,
            frost_id: bob_frost_id,
        }])?);

        // Create Bob's registry
        // Bob must know which FROST ID belongs to Alice
        let bob_registry = Arc::new(ParticipantRegistry::new([ParticipantEntry {
            mtls_public_key: alice_public_key,
            frost_id: alice_frost_id,
        }])?);

        // Configure Bob's mTLS server
        let bob_tls_acceptor =
            build_tls_acceptor("certs/ca.crt", "certs/bob.crt", "certs/bob.key")?;

        // Start a local TCP listener for Bob
        // Port 0 lets the operating system select an available port
        let bob_listener = TcpListener::bind("127.0.0.1:0").await?;

        let bob_address = bob_listener.local_addr()?;

        // Accept Alice's connection in a separate task
        let server_registry = Arc::clone(&bob_registry);

        // Create Bob's registry for active peer connections
        // All of Bob's connections handlers must share this registry
        let bob_active_connections = Arc::new(ActiveConnectionRegistry::new());

        // Clone the registry so the connection task can use it
        let server_active_connections = Arc::clone(&bob_active_connections);

        let bob_server_task = tokio::spawn(async move {
            let (tcp_stream, peer_address) = bob_listener.accept().await?;

            handle_peer_connection(
                tcp_stream,
                peer_address,
                bob_tls_acceptor,
                server_registry,
                server_active_connections,
                bob_frost_id,
            )
            .await
        });

        // Configure Alice's mTLS client
        let alice_tls_connector =
            build_tls_connector("certs/ca.crt", "certs/alice.crt", "certs/alice.key")?;

        // Use the server name from Bob's certificate
        let bob_server_name: ServerName<'static> = "bob.localhost".to_owned().try_into()?;

        // Create Alice's registry for outgoing and incoming connections
        // The same registry must be shared by all of Alice's connection handlers
        let alice_active_connections = Arc::new(ActiveConnectionRegistry::new());

        // Connect Alice to Bob and resolve Bob's FROST ID
        let bob_address_string = bob_address.to_string();

        let mut alice_connection = connect_to_peer(
            &bob_address_string,
            bob_server_name,
            alice_tls_connector,
            Arc::clone(&alice_registry),
            Arc::clone(&alice_active_connections),
            alice_frost_id,
        )
        .await?;

        // Verify that Alice obtained Bob's assigned FROST ID
        assert_eq!(
            alice_connection.remote_frost_id, bob_frost_id,
            "Alice resolved the wrong FROST ID for Bob"
        );

        // Close Alice's TLS connection gracefully
        alice_connection.tls_stream.shutdown().await?;

        // Drop the connection and release Alice's reservation
        drop(alice_connection);

        // Verify that Bob handled the closed connection
        bob_server_task.await??;

        // Test the connection-direction rule
        // Bob has ID 2. Alice has ID 1
        // Bob must not initiate a connection to Alice

        // Configure Alice's mTLS server
        let alice_tls_acceptor =
            build_tls_acceptor("certs/ca.crt", "certs/alice.crt", "certs/alice.key")?;

        let alice_listener = TcpListener::bind("127.0.0.1:0").await?;

        let alice_address = alice_listener.local_addr()?;

        // Start Alice's server
        // It must reject incoming connections from participants with a larger FROST ID
        let alice_server_registry = Arc::clone(&alice_registry);

        // Create Alice's registry for active peer connections
        let alice_active_connection = Arc::new(ActiveConnectionRegistry::new());

        // Share the registry with Alice's connection handler
        let alice_server_active_connection = Arc::clone(&alice_active_connection);

        let alice_server_task = tokio::spawn(async move {
            let (tcp_stream, peer_address) = alice_listener.accept().await?;

            handle_peer_connection(
                tcp_stream,
                peer_address,
                alice_tls_acceptor,
                alice_server_registry,
                alice_server_active_connection,
                alice_frost_id,
            )
            .await
        });

        // Configure Bob's mTLS client
        let bob_tls_connector =
            build_tls_connector("certs/ca.crt", "certs/bob.crt", "certs/bob.key")?;

        let alice_server_name: ServerName<'static> = "alice.localhost".to_owned().try_into()?;

        // Bob tries to connect to Alice
        let alice_address_string = alice_address.to_string();

        let bob_connection_result = connect_to_peer(
            &alice_address_string,
            alice_server_name,
            bob_tls_connector,
            Arc::clone(&bob_registry),
            Arc::clone(&bob_active_connections),
            bob_frost_id,
        )
        .await;

        // Verify that Bob's outgoing connection is rejected
        assert!(
            bob_connection_result.is_err(),
            "Bob must not initiate a connection to Alice"
        );

        // Verify that Alice also rejects the incoming connection
        let alice_server_result = alice_server_task.await?;

        assert!(
            alice_server_result.is_err(),
            "Alice must reject an incoming connection from Bob"
        );

        Ok(())
    }

    #[tokio::test]
    async fn sends_framed_message_over_mtls() -> Result<(), Box<dyn Error + Send + Sync>> {
        // Load both public keys
        let alice_public_key = load_public_key_from_certificate("certs/alice.crt")?;

        let bob_public_key = load_public_key_from_certificate("certs/bob.crt")?;

        // Assign the FROST IDs for this test
        let alice_frost_id: Identifier = 1_u16.try_into().expect("Invalid Alice FROST ID");

        let bob_frost_id: Identifier = 2_u16.try_into().expect("Invalid Bob FROST ID");

        // Bob must map Alice's authenticated mTLS public key to Alice's FROST ID
        let bob_registry = Arc::new(ParticipantRegistry::new([ParticipantEntry {
            mtls_public_key: alice_public_key.clone(),
            frost_id: alice_frost_id,
        }])?);

        // Create Alice's participant registry
        let alice_registry = Arc::new(ParticipantRegistry::new([ParticipantEntry {
            mtls_public_key: bob_public_key,
            frost_id: bob_frost_id,
        }])?);

        // Create Bob's TLS server
        let bob_tls_acceptor =
            build_tls_acceptor("certs/ca.crt", "certs/bob.crt", "certs/bob.key")?;

        // Open a local TCP listener
        let bob_listener = TcpListener::bind("127.0.0.1:0").await?;

        let bob_address = bob_listener.local_addr()?;

        // Create a reference to Bob's registry for his server task
        let bob_server_registry = Arc::clone(&bob_registry);

        // Accept Alice's connection and receive one framed message
        let bob_server_task = tokio::spawn(async move {
            let (tcp_stream, _) = bob_listener.accept().await?;

            let mut tls_stream = bob_tls_acceptor.accept(tcp_stream).await?;

            // Get Alice's public key from the authenticated TLS connection
            let alice_public_key = get_authenticated_peer_public_key(&tls_stream)?;

            // Resolve Alice's FROST ID from Bob's registry
            let authenticated_alice_id =
                bob_server_registry.frost_id_for_authenticated_key(&alice_public_key)?;

            // Receive one complete framed message
            let encoded_dkg_message = receive_frame(&mut tls_stream).await?.ok_or_else(|| {
                io::Error::new(
                    ErrorKind::UnexpectedEof,
                    "Alice closed the connection before sending a message",
                )
            })?;

            // Decode the outer DKG message
            let dkg_message = DkgMessage::decode(&encoded_dkg_message)?;

            if dkg_message.kind != DkgMessageKind::EchoBroadcast {
                return Err(io::Error::new(
                    ErrorKind::InvalidData,
                    "Expected an echo-broadcast message",
                )
                .into());
            }

            // Decode the echo-broadcast message
            let echo_message = EchoBroadcastMessage::decode(&dkg_message.payload)?;

            // Check that the original broadcaster matches the authenticated sender
            if echo_message.phase != EchoBroadcastPhase::Initial
                || echo_message.original_broadcaster_id != authenticated_alice_id
            {
                return Err(io::Error::new(
                    ErrorKind::PermissionDenied,
                    "The initial broadcast does not match the authenticated sender",
                )
                .into());
            }

            // Wait for Alice's clean TLS shutdown
            let next_message = receive_frame(&mut tls_stream).await?;

            if next_message.is_some() {
                return Err(io::Error::new(
                    ErrorKind::InvalidData,
                    "Received an unexpected second message",
                )
                .into());
            }

            // Close Bob's TLS connection gracefully
            tls_stream.shutdown().await?;

            Ok::<EchoBroadcastMessage, Box<dyn Error + Send + Sync>>(echo_message)
        });

        // Configure Alice's TLS client
        let alice_tls_connector =
            build_tls_connector("certs/ca.crt", "certs/alice.crt", "certs/alice.key")?;

        let bob_server_name: ServerName<'static> = "bob.localhost".to_owned().try_into()?;

        // Connect Alice to Bob and verify Bob's FROST ID
        let mut alice_connection = connect_to_peer(
            &bob_address.to_string(),
            bob_server_name,
            alice_tls_connector,
            Arc::clone(&alice_registry),
            Arc::new(ActiveConnectionRegistry::new()),
            alice_frost_id,
        )
        .await?;

        assert_eq!(
            alice_connection.remote_frost_id, bob_frost_id,
            "Alice resolved the wrong FROST ID for Bob"
        );

        // Create the initial broadcast value
        let expected_echo_message = EchoBroadcastMessage {
            phase: EchoBroadcastPhase::Initial,
            original_broadcaster_id: alice_frost_id,
            value: Some(b"test FROST Part 1 package".to_vec()),
        };

        // Wrap the echo-broadcast message in the DKG envelope
        let dkg_message = DkgMessage {
            kind: DkgMessageKind::EchoBroadcast,
            payload: expected_echo_message
                .encode()
                .expect("Failed to encode echo-broadcast message"),
        };

        // Encode the outer message and send it over mTLS
        let encoded_dkg_message = dkg_message.encode();

        send_frame(&mut alice_connection.tls_stream, &encoded_dkg_message).await?;

        // Tell Bob that Alice will not send more messages.
        alice_connection.tls_stream.shutdown().await?;

        // Wait for Bob to complete his TLS shutdown.
        // A clean end of stream means that Bob sent no more messages.
        let next_message = receive_frame(&mut alice_connection.tls_stream).await?;

        if next_message.is_some() {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                "Bob sent an unexpected message during shutdown",
            )
            .into());
        }

        // Drop the connection and release the active-connection guard.
        drop(alice_connection);

        // Verify that Bob received the exact payload
        let received_message = bob_server_task.await??;

        assert_eq!(
            received_message, expected_echo_message,
            "Bob received a different echo-broadcast message"
        );

        Ok(())
    }

    #[tokio::test]
    async fn three_participants_complete_echo_broadcast_over_mtls(
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        // ---------------------------------------------------------
        // Step A: Define the three participants.
        // ---------------------------------------------------------

        let alice_frost_id: Identifier = 1_u16.try_into().expect("Invalid Alice FROST ID");

        let bob_frost_id: Identifier = 2_u16.try_into().expect("Invalid Bob FROST ID");

        let charlie_frost_id: Identifier = 3_u16.try_into().expect("Invalid Charlie FROST ID");

        // ---------------------------------------------------------
        // Step B: Generate the real FROST Part 1 packages.
        // ---------------------------------------------------------

        let mut rng = OsRng;

        // Alice creates her Part 1 secret and public packages
        let (alice_round1_secret_package, alice_round1_package) =
            frost::keys::dkg::part1(alice_frost_id, 3, 2, &mut rng)?;

        // Bob creates his Part 1 secret and public packages
        let (bob_round1_secret_package, bob_round1_package) =
            frost::keys::dkg::part1(bob_frost_id, 3, 2, &mut rng)?;

        // Charlie creates her Part 1 secret and public packages
        let (charlie_round1_secret_package, charlie_round1_package) =
            frost::keys::dkg::part1(charlie_frost_id, 3, 2, &mut rng)?;

        // Serialize the public package for network transmission
        let alice_round1_package_bytes = alice_round1_package.serialize()?;

        let bob_round1_package_bytes = bob_round1_package.serialize()?;

        let charlie_round1_package_bytes = charlie_round1_package.serialize()?;

        // ---------------------------------------------------------
        // Step C: Reserve local addresses for the three nodes.
        // ---------------------------------------------------------

        // We bind the listeners before we create the node configuration
        // Port 0 lets the operating system choose an available port

        let alice_listener = TcpListener::bind("127.0.0.1:0").await?;

        let bob_listener = TcpListener::bind("127.0.0.1:0").await?;

        let charlie_listener = TcpListener::bind("127.0.0.1:0").await?;

        let alice_address = alice_listener.local_addr()?;
        let bob_address = bob_listener.local_addr()?;
        let charlie_address = charlie_listener.local_addr()?;

        // ---------------------------------------------------------
        // Step D: Build Alice's node configuration.
        // ---------------------------------------------------------

        let alice_config = NodeConfig {
            local_frost_id: alice_frost_id,
            listen_address: alice_address.to_string(),

            ca_certificate_path: "certs/ca.crt".to_string(),
            local_certificate_path: "certs/alice.crt".to_string(),
            local_private_key_path: "certs/alice.key".to_string(),

            peers: vec![
                PeerConfig {
                    frost_id: bob_frost_id,
                    address: bob_address.to_string(),
                    server_name: "bob.localhost".to_string(),
                    certificate_path: "certs/bob.crt".to_string(),
                },
                PeerConfig {
                    frost_id: charlie_frost_id,
                    address: charlie_address.to_string(),
                    server_name: "charlie.localhost".to_string(),
                    certificate_path: "certs/charlie.crt".to_string(),
                },
            ],
        };

        let alice_node = Node::from_config(alice_config)?;

        assert_eq!(alice_node.local_frost_id(), alice_frost_id);

        // ---------------------------------------------------------
        // Step E: Build Bob's node configuration.
        // ---------------------------------------------------------

        let bob_config = NodeConfig {
            local_frost_id: bob_frost_id,
            listen_address: bob_address.to_string(),

            ca_certificate_path: "certs/ca.crt".to_string(),
            local_certificate_path: "certs/bob.crt".to_string(),
            local_private_key_path: "certs/bob.key".to_string(),

            peers: vec![
                PeerConfig {
                    frost_id: alice_frost_id,
                    address: alice_address.to_string(),
                    server_name: "alice.localhost".to_string(),
                    certificate_path: "certs/alice.crt".to_string(),
                },
                PeerConfig {
                    frost_id: charlie_frost_id,
                    address: charlie_address.to_string(),
                    server_name: "charlie.localhost".to_string(),
                    certificate_path: "certs/charlie.crt".to_string(),
                },
            ],
        };

        let bob_node = Node::from_config(bob_config)?;

        assert_eq!(bob_node.local_frost_id(), bob_frost_id,);

        // ---------------------------------------------------------
        // Step F: Build Charlie's node configuration.
        // ---------------------------------------------------------

        let charlie_config = NodeConfig {
            local_frost_id: charlie_frost_id,
            listen_address: charlie_address.to_string(),

            ca_certificate_path: "certs/ca.crt".to_string(),
            local_certificate_path: "certs/charlie.crt".to_string(),
            local_private_key_path: "certs/charlie.key".to_string(),

            peers: vec![
                PeerConfig {
                    frost_id: alice_frost_id,
                    address: alice_address.to_string(),
                    server_name: "alice.localhost".to_string(),
                    certificate_path: "certs/alice.crt".to_string(),
                },
                PeerConfig {
                    frost_id: bob_frost_id,
                    address: bob_address.to_string(),
                    server_name: "bob.localhost".to_string(),
                    certificate_path: "certs/bob.crt".to_string(),
                },
            ],
        };

        let charlie_node = Node::from_config(charlie_config)?;

        assert_eq!(charlie_node.local_frost_id(), charlie_frost_id,);

        // ---------------------------------------------------------
        // Step G: Start Bob's incoming connection handler.
        // ---------------------------------------------------------

        let bob_tls_acceptor = bob_node.tls_acceptor();

        let bob_server_registry = bob_node.participant_registry();

        let bob_server_active_connections = bob_node.active_connection_registry();

        let bob_server_task = tokio::spawn(async move {
            accept_test_peer(
                &bob_listener,
                &bob_tls_acceptor,
                bob_server_registry,
                bob_server_active_connections,
                bob_frost_id,
            )
            .await
        });

        // ---------------------------------------------------------
        // Step H: Start Charlie's incoming connection handler.
        // Charlie accepts connections from Alice and Bob.
        // ---------------------------------------------------------

        let charlie_tls_acceptor = charlie_node.tls_acceptor();

        let charlie_server_registry = charlie_node.participant_registry();

        let charlie_server_active_connections = charlie_node.active_connection_registry();

        let charlie_server_task = tokio::spawn(async move {
            let mut accepted_connections = BTreeMap::new();

            // Accept Alice and Bob
            for _ in 0..2 {
                let (tls_stream, remote_frost_id, active_connection_guard) = accept_test_peer(
                    &charlie_listener,
                    &charlie_tls_acceptor,
                    Arc::clone(&charlie_server_registry),
                    Arc::clone(&charlie_server_active_connections),
                    charlie_frost_id,
                )
                .await?;

                // Store the connection by the authenticated FROST ID
                if accepted_connections
                    .insert(remote_frost_id, (tls_stream, active_connection_guard))
                    .is_some()
                {
                    return Err(io::Error::new(
                        ErrorKind::AlreadyExists,
                        "Duplicate connection to a participant",
                    )
                    .into());
                }
            }

            Ok::<_, Box<dyn Error + Send + Sync>>(accepted_connections)
        });

        // ---------------------------------------------------------
        // Step I: Establish the three authenticated connections.
        // ---------------------------------------------------------

        // Alice has the smallest ID. She initiates connections to Bob and Charlie
        let mut alice_to_bob = alice_node.connect_to_peer(bob_frost_id).await?;

        assert_eq!(alice_to_bob.remote_frost_id, bob_frost_id);

        // Bob accepts Alice's connection
        let (mut bob_alice_stream, authenticated_alice_id, _bob_alice_guard) =
            bob_server_task.await??;

        assert_eq!(authenticated_alice_id, alice_frost_id);

        // Alice initiates a connection to Charlie
        let mut alice_to_charlie = alice_node.connect_to_peer(charlie_frost_id).await?;

        assert_eq!(alice_to_charlie.remote_frost_id, charlie_frost_id);

        // Bob has the middle ID. He initiates a connection to Charlie
        let mut bob_to_charlie = bob_node.connect_to_peer(charlie_frost_id).await?;

        assert_eq!(bob_to_charlie.remote_frost_id, charlie_frost_id);

        // Charlie has accepted both incoming connections
        let mut charlie_connections = charlie_server_task.await??;

        let (mut charlie_alice_stream, _charlie_alice_guard) = charlie_connections
            .remove(&alice_frost_id)
            .expect("Charlie did not accept Alice");

        let (mut charlie_bob_stream, _charlie_bob_guard) = charlie_connections
            .remove(&bob_frost_id)
            .expect("Charlie did not accept Bob");

        // ---------------------------------------------------------
        // Step D: Create a receiver for every remote broadcast
        // ---------------------------------------------------------

        // Every participant must receive the other two Part 1 packages
        let all_participant_ids = [alice_frost_id, bob_frost_id, charlie_frost_id];

        // Bob and Charlie receive Alice's broadcast
        let mut bob_receives_alice_broadcast =
            EchoBroadcastInstance::new(bob_frost_id, alice_frost_id, all_participant_ids)?;

        let mut charlie_receives_alice_broadcast =
            EchoBroadcastInstance::new(charlie_frost_id, alice_frost_id, all_participant_ids)?;

        // Alice and Charlie receive Bob's broadcast.
        let mut alice_receives_bob_broadcast =
            EchoBroadcastInstance::new(alice_frost_id, bob_frost_id, all_participant_ids)?;

        let mut charlie_receives_bob_broadcast =
            EchoBroadcastInstance::new(charlie_frost_id, bob_frost_id, all_participant_ids)?;

        // Alice and Bob receive Charlie's broadcast.
        let mut alice_receives_charlie_broadcast =
            EchoBroadcastInstance::new(alice_frost_id, charlie_frost_id, all_participant_ids)?;

        let mut bob_receives_charlie_broadcast =
            EchoBroadcastInstance::new(bob_frost_id, charlie_frost_id, all_participant_ids)?;

        // ---------------------------------------------------------
        // Step E: Each participant broadcasts its real Part 1 package.
        // ---------------------------------------------------------

        let alice_initial_message = EchoBroadcastMessage {
            phase: EchoBroadcastPhase::Initial,
            original_broadcaster_id: alice_frost_id,
            value: Some(alice_round1_package_bytes.clone()),
        };

        let bob_initial_message = EchoBroadcastMessage {
            phase: EchoBroadcastPhase::Initial,
            original_broadcaster_id: bob_frost_id,
            value: Some(bob_round1_package_bytes.clone()),
        };

        let charlie_initial_message = EchoBroadcastMessage {
            phase: EchoBroadcastPhase::Initial,
            original_broadcaster_id: charlie_frost_id,
            value: Some(charlie_round1_package_bytes.clone()),
        };

        // Alice sends her package to Bob and Charlie
        send_echo_broadcast_message(&mut alice_to_bob.tls_stream, &alice_initial_message).await?;

        send_echo_broadcast_message(&mut alice_to_charlie.tls_stream, &alice_initial_message)
            .await?;

        // Bob sends his package to Alice and Charlie
        send_echo_broadcast_message(&mut bob_alice_stream, &bob_initial_message).await?;

        send_echo_broadcast_message(&mut bob_to_charlie.tls_stream, &bob_initial_message).await?;

        // Charlile sends her package to Alice and Bob
        send_echo_broadcast_message(&mut charlie_alice_stream, &charlie_initial_message).await?;

        send_echo_broadcast_message(&mut charlie_bob_stream, &charlie_initial_message).await?;

        // ---------------------------------------------------------
        // Step F: Receive and validate all initial packages.
        // ---------------------------------------------------------

        // Bob receives Alice's package
        let alice_initial_at_bob =
            receive_echo_broadcast_message(&mut bob_alice_stream, authenticated_alice_id).await?;

        bob_receives_alice_broadcast
            .receive_initial_message(authenticated_alice_id, &alice_initial_at_bob)?;

        // Charlie receives Alice's package
        let alice_initial_at_charlie =
            receive_echo_broadcast_message(&mut charlie_alice_stream, alice_frost_id).await?;

        charlie_receives_alice_broadcast
            .receive_initial_message(alice_frost_id, &alice_initial_at_charlie)?;

        // Alice receives Bob's package.
        let bob_initial_at_alice = receive_echo_broadcast_message(
            &mut alice_to_bob.tls_stream,
            alice_to_bob.remote_frost_id,
        )
        .await?;

        alice_receives_bob_broadcast
            .receive_initial_message(alice_to_bob.remote_frost_id, &bob_initial_at_alice)?;

        // Charlie receives Bob's package.
        let bob_initial_at_charlie =
            receive_echo_broadcast_message(&mut charlie_bob_stream, bob_frost_id).await?;

        charlie_receives_bob_broadcast
            .receive_initial_message(bob_frost_id, &bob_initial_at_charlie)?;

        // Alice receives Charlie's package.
        let charlie_initial_at_alice = receive_echo_broadcast_message(
            &mut alice_to_charlie.tls_stream,
            alice_to_charlie.remote_frost_id,
        )
        .await?;

        alice_receives_charlie_broadcast
            .receive_initial_message(alice_to_charlie.remote_frost_id, &charlie_initial_at_alice)?;

        // Bob receives Charlie's package.
        let charlie_initial_at_bob = receive_echo_broadcast_message(
            &mut bob_to_charlie.tls_stream,
            bob_to_charlie.remote_frost_id,
        )
        .await?;

        bob_receives_charlie_broadcast
            .receive_initial_message(bob_to_charlie.remote_frost_id, &charlie_initial_at_bob)?;

        // ---------------------------------------------------------
        // Step G: Create each recipient's echo.
        // ---------------------------------------------------------

        // Bob and Charlie echo Alice's package to each other
        let bob_echo_for_alice = bob_receives_alice_broadcast.create_echo_message()?;

        let charlie_echo_for_alice = charlie_receives_alice_broadcast.create_echo_message()?;

        // Alice and Charlie echo Bob's package to each other.
        let alice_echo_for_bob = alice_receives_bob_broadcast.create_echo_message()?;

        let charlie_echo_for_bob = charlie_receives_bob_broadcast.create_echo_message()?;

        // Alice and Bob echo Charlie's package to each other.
        let alice_echo_for_charlie = alice_receives_charlie_broadcast.create_echo_message()?;

        let bob_echo_for_charlie = bob_receives_charlie_broadcast.create_echo_message()?;

        // ---------------------------------------------------------
        // Step H: Send the echoes over the authenticated channels.
        // ---------------------------------------------------------

        // Bob echoes Alice's package to Charlie
        send_echo_broadcast_message(&mut bob_to_charlie.tls_stream, &bob_echo_for_alice).await?;

        // Charlie echoes Alice's package to Bob
        send_echo_broadcast_message(&mut charlie_bob_stream, &charlie_echo_for_alice).await?;

        // Alice echoes Bob's package to Charlie
        send_echo_broadcast_message(&mut alice_to_charlie.tls_stream, &alice_echo_for_bob).await?;

        // Charlie echoes Bob's package to Alice
        send_echo_broadcast_message(&mut charlie_alice_stream, &charlie_echo_for_bob).await?;

        // Alice echoes Charlie's package to Bob
        send_echo_broadcast_message(&mut alice_to_bob.tls_stream, &alice_echo_for_charlie).await?;

        // Bob echoes Charlie's package to Alice
        send_echo_broadcast_message(&mut bob_alice_stream, &bob_echo_for_charlie).await?;

        // ---------------------------------------------------------
        // Step I: Receive and record the echoes.
        // ---------------------------------------------------------

        // Bob receives Charlie's echo of Alice's package
        let charlie_echo_at_bob = receive_echo_broadcast_message(
            &mut bob_to_charlie.tls_stream,
            bob_to_charlie.remote_frost_id,
        )
        .await?;

        bob_receives_alice_broadcast
            .record_echo(bob_to_charlie.remote_frost_id, &charlie_echo_at_bob)?;

        // Charlie receives Bob's echo of Alice's package
        let bob_echo_at_charlie =
            receive_echo_broadcast_message(&mut charlie_bob_stream, bob_frost_id).await?;

        charlie_receives_alice_broadcast.record_echo(bob_frost_id, &bob_echo_at_charlie)?;

        // Alice receives Charlie's echo of Bob's package.
        let charlie_echo_at_alice = receive_echo_broadcast_message(
            &mut alice_to_charlie.tls_stream,
            alice_to_charlie.remote_frost_id,
        )
        .await?;

        alice_receives_bob_broadcast
            .record_echo(alice_to_charlie.remote_frost_id, &charlie_echo_at_alice)?;

        // Charlie receives Alice's echo of Bob's package.
        let alice_echo_at_charlie =
            receive_echo_broadcast_message(&mut charlie_alice_stream, alice_frost_id).await?;

        charlie_receives_bob_broadcast.record_echo(alice_frost_id, &alice_echo_at_charlie)?;

        // Alice receives Bob's echo of Charlie's package.
        let bob_echo_at_alice = receive_echo_broadcast_message(
            &mut alice_to_bob.tls_stream,
            alice_to_bob.remote_frost_id,
        )
        .await?;

        alice_receives_charlie_broadcast
            .record_echo(alice_to_bob.remote_frost_id, &bob_echo_at_alice)?;

        // Bob receives Alice's echo of Charlie's package.
        let alice_echo_at_bob =
            receive_echo_broadcast_message(&mut bob_alice_stream, authenticated_alice_id).await?;

        bob_receives_charlie_broadcast.record_echo(alice_frost_id, &alice_echo_at_bob)?;

        // ---------------------------------------------------------
        // Step J: Get the delivered package bytes.
        // ---------------------------------------------------------

        let alice_package_at_bob = require_delivered_echo_value(
            bob_receives_alice_broadcast.outcome(),
            "Bob",
            alice_frost_id,
        )?;

        let alice_package_at_charlie = require_delivered_echo_value(
            charlie_receives_alice_broadcast.outcome(),
            "Charlie",
            alice_frost_id,
        )?;

        let bob_package_at_alice = require_delivered_echo_value(
            alice_receives_bob_broadcast.outcome(),
            "Alice",
            bob_frost_id,
        )?;

        let bob_package_at_charlie = require_delivered_echo_value(
            charlie_receives_bob_broadcast.outcome(),
            "Charlie",
            bob_frost_id,
        )?;

        let charlie_package_at_alice = require_delivered_echo_value(
            alice_receives_charlie_broadcast.outcome(),
            "Alice",
            charlie_frost_id,
        )?;

        let charlie_package_at_bob = require_delivered_echo_value(
            bob_receives_charlie_broadcast.outcome(),
            "Bob",
            charlie_frost_id,
        )?;

        // ---------------------------------------------------------
        // Step K: Deserialize the real FROST packages.
        // ---------------------------------------------------------

        let alice_package_received_by_bob =
            frost::keys::dkg::round1::Package::deserialize(&alice_package_at_bob)?;

        let alice_package_received_by_charlie =
            frost::keys::dkg::round1::Package::deserialize(&alice_package_at_charlie)?;

        let bob_package_received_by_alice =
            frost::keys::dkg::round1::Package::deserialize(&bob_package_at_alice)?;

        let bob_package_received_by_charlie =
            frost::keys::dkg::round1::Package::deserialize(&bob_package_at_charlie)?;

        let charlie_package_received_by_alice =
            frost::keys::dkg::round1::Package::deserialize(&charlie_package_at_alice)?;

        let charlie_package_received_by_bob =
            frost::keys::dkg::round1::Package::deserialize(&charlie_package_at_bob)?;

        // ---------------------------------------------------------
        // Step L: Verify the delivered packages.
        // ---------------------------------------------------------

        assert_eq!(
            alice_package_received_by_bob, alice_round1_package,
            "Bob received the wrong package from Alice",
        );

        assert_eq!(
            alice_package_received_by_charlie, alice_round1_package,
            "Charlie received the wrong package from Alice",
        );

        assert_eq!(
            bob_package_received_by_alice, bob_round1_package,
            "Alice received the wrong package from Bob",
        );

        assert_eq!(
            bob_package_received_by_charlie, bob_round1_package,
            "Charlie received the wrong package from Bob",
        );

        assert_eq!(
            charlie_package_received_by_alice, charlie_round1_package,
            "Alice received the wrong package from Charlie",
        );

        assert_eq!(
            charlie_package_received_by_bob, charlie_round1_package,
            "Bob received the wrong package from Charlie",
        );

        println!("All three participants broadcast their real FROST Part 1 packages.");

        println!("Every participant received and deserialized the other two packages.");

        // ---------------------------------------------------------
        // Step M: Build each participant's received Part 1 map.
        // ---------------------------------------------------------

        // Alice stores Bob's and Charlie's packages
        let mut alice_received_round1_packages = BTreeMap::new();

        alice_received_round1_packages.insert(bob_frost_id, bob_package_received_by_alice.clone());

        alice_received_round1_packages
            .insert(charlie_frost_id, charlie_package_received_by_alice.clone());

        // Bob stores Alice's and Charlie's packages.
        let mut bob_received_round1_packages = BTreeMap::new();

        bob_received_round1_packages.insert(alice_frost_id, alice_package_received_by_bob.clone());

        bob_received_round1_packages
            .insert(charlie_frost_id, charlie_package_received_by_bob.clone());

        // Charlie stores Alice's and Bob's packages.
        let mut charlie_received_round1_packages = BTreeMap::new();

        charlie_received_round1_packages
            .insert(alice_frost_id, alice_package_received_by_charlie.clone());

        charlie_received_round1_packages
            .insert(bob_frost_id, bob_package_received_by_charlie.clone());

        // ---------------------------------------------------------
        // Step N: Run DKG Part 2 for each participant.
        // ---------------------------------------------------------

        // Alice creates her secret package and recipient-specific packages
        let (alice_round2_secret_package, alice_round2_packages) =
            frost::keys::dkg::part2(alice_round1_secret_package, &alice_received_round1_packages)?;

        // Bob creates his secret package and recipient-specific packages.
        let (bob_round2_secret_package, bob_round2_packages) =
            frost::keys::dkg::part2(bob_round1_secret_package, &bob_received_round1_packages)?;

        // Charlie creates her secret package and recipient-specific packages.
        let (charlie_round2_secret_package, charlie_round2_packages) = frost::keys::dkg::part2(
            charlie_round1_secret_package,
            &charlie_received_round1_packages,
        )?;

        println!("All three participants completed DKG Part 2.");

        // ---------------------------------------------------------
        // Step O: Send all Round 2 packages over mTLS.
        // ---------------------------------------------------------

        // Alice sends her package for Bob
        send_round2_package(
            &mut alice_to_bob.tls_stream,
            alice_round2_packages
                .get(&bob_frost_id)
                .expect("Alice's package for Bob is missing"),
        )
        .await?;

        // Alice sends her package for Charlie.
        send_round2_package(
            &mut alice_to_charlie.tls_stream,
            alice_round2_packages
                .get(&charlie_frost_id)
                .expect("Alice's package for Charlie is missing"),
        )
        .await?;

        // Bob sends his package for Alice.
        send_round2_package(
            &mut bob_alice_stream,
            bob_round2_packages
                .get(&alice_frost_id)
                .expect("Bob's package for Alice is missing"),
        )
        .await?;

        // Bob sends his package for Charlie.
        send_round2_package(
            &mut bob_to_charlie.tls_stream,
            bob_round2_packages
                .get(&charlie_frost_id)
                .expect("Bob's package for Charlie is missing"),
        )
        .await?;

        // Charlie sends her package for Alice.
        send_round2_package(
            &mut charlie_alice_stream,
            charlie_round2_packages
                .get(&alice_frost_id)
                .expect("Charlie's package for Alice is missing"),
        )
        .await?;

        // Charlie sends her package for Bob.
        send_round2_package(
            &mut charlie_bob_stream,
            charlie_round2_packages
                .get(&bob_frost_id)
                .expect("Charlie's package for Bob is missing"),
        )
        .await?;

        println!("All six Round 2 packages were sent over mTLS.");

        // ---------------------------------------------------------
        // Step P: Receive the Round 2 packages.
        // ---------------------------------------------------------

        // Alice receives Bob's package and Charlie's package.
        // Alice reads from her own client-side streams.
        let bob_round2_package_at_alice =
            receive_round2_package(&mut alice_to_bob.tls_stream).await?;

        let charlie_round2_package_at_alice =
            receive_round2_package(&mut alice_to_charlie.tls_stream).await?;

        // Bob receives Alice's package and Charlie's package.
        // Bob reads Alice's package from the server-side stream
        // that accepted Alice's connection.
        let alice_round2_package_at_bob = receive_round2_package(&mut bob_alice_stream).await?;

        let charlie_round2_package_at_bob =
            receive_round2_package(&mut bob_to_charlie.tls_stream).await?;

        // Charlie receives Alice's package and Bob's package.
        // Charlie reads from the server-side streams that accepted
        // Alice's and Bob's connections.
        let alice_round2_package_at_charlie =
            receive_round2_package(&mut charlie_alice_stream).await?;

        let bob_round2_package_at_charlie = receive_round2_package(&mut charlie_bob_stream).await?;

        // ---------------------------------------------------------
        // Step Q: Build each participant's received Round 2 map.
        // ---------------------------------------------------------

        // The map keys come from the authenticated peer identity already associated with each connection

        let mut alice_received_round2_packages = BTreeMap::new();

        alice_received_round2_packages.insert(bob_frost_id, bob_round2_package_at_alice);

        alice_received_round2_packages.insert(charlie_frost_id, charlie_round2_package_at_alice);

        let mut bob_received_round2_packages = BTreeMap::new();

        bob_received_round2_packages.insert(alice_frost_id, alice_round2_package_at_bob);

        bob_received_round2_packages.insert(charlie_frost_id, charlie_round2_package_at_bob);

        let mut charlie_received_round2_packages = BTreeMap::new();

        charlie_received_round2_packages.insert(alice_frost_id, alice_round2_package_at_charlie);

        charlie_received_round2_packages.insert(bob_frost_id, bob_round2_package_at_charlie);

        // Each participant must have exactly one package from each peer.
        assert_eq!(alice_received_round2_packages.len(), 2);
        assert_eq!(bob_received_round2_packages.len(), 2);
        assert_eq!(charlie_received_round2_packages.len(), 2);

        println!("Each participant received two Round 2 packages.");

        // ---------------------------------------------------------
        // Step R: Complete DKG Part 3 for each participant.
        // ---------------------------------------------------------

        // Alice computes her key share and the group public-key package
        let (alice_key_package, alice_public_key_package) = frost::keys::dkg::part3(
            &alice_round2_secret_package,
            &alice_received_round1_packages,
            &alice_received_round2_packages,
        )?;

        // Bob computes his key share and the group public-key package.
        let (bob_key_package, bob_public_key_package) = frost::keys::dkg::part3(
            &bob_round2_secret_package,
            &bob_received_round1_packages,
            &bob_received_round2_packages,
        )?;

        // Charlie computes her key share and the group public-key package.
        let (charlie_key_package, charlie_public_key_package) = frost::keys::dkg::part3(
            &charlie_round2_secret_package,
            &charlie_received_round1_packages,
            &charlie_received_round2_packages,
        )?;

        // ---------------------------------------------------------
        // Step S: Verify that every participant has the same result.
        // ---------------------------------------------------------

        // All participants must compute the same public-key package
        assert_eq!(
            alice_public_key_package, bob_public_key_package,
            "Alice and Bob computed different public-key packages"
        );

        assert_eq!(
            alice_public_key_package, charlie_public_key_package,
            "Alice and Charlie computed different public-key packages",
        );

        assert_eq!(
            bob_public_key_package, charlie_public_key_package,
            "Bob and Charlie computed different public-key packages",
        );

        // Each local key package must belong to its assigned FROST ID.
        assert_eq!(
            alice_key_package.identifier(),
            &alice_frost_id,
            "Alice received the wrong local key package",
        );

        assert_eq!(
            bob_key_package.identifier(),
            &bob_frost_id,
            "Bob received the wrong local key package",
        );

        assert_eq!(
            charlie_key_package.identifier(),
            &charlie_frost_id,
            "Charlie received the wrong local key package",
        );

        // The public-key package must describe all three participants.
        assert_eq!(
            alice_public_key_package.max_signers(),
            3,
            "The public-key package has the wrong participant count",
        );

        println!("DKG Part 3 passed: all participants computed the same public-key package.");

        // ---------------------------------------------------------
        // Step : Close each TLS connection.
        // ---------------------------------------------------------

        // Close Alice's connection to Bob.
        alice_to_bob.tls_stream.shutdown().await?;

        assert!(receive_frame(&mut bob_alice_stream).await?.is_none(),);

        bob_alice_stream.shutdown().await?;

        assert!(receive_frame(&mut alice_to_bob.tls_stream).await?.is_none(),);

        // Close Alice's connection to Charlie.
        alice_to_charlie.tls_stream.shutdown().await?;

        assert!(receive_frame(&mut charlie_alice_stream).await?.is_none(),);

        charlie_alice_stream.shutdown().await?;

        assert!(receive_frame(&mut alice_to_charlie.tls_stream)
            .await?
            .is_none(),);

        // Close Bob's connection to Charlie.
        bob_to_charlie.tls_stream.shutdown().await?;

        assert!(receive_frame(&mut charlie_bob_stream).await?.is_none(),);

        charlie_bob_stream.shutdown().await?;

        assert!(receive_frame(&mut bob_to_charlie.tls_stream)
            .await?
            .is_none(),);

        Ok(())
    }
}
