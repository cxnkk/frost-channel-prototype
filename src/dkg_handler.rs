use crate::dkg_messages::DkgMessage;
use crate::dkg_messages::DkgMessageKind;
use crate::echo_broadcast::EchoBroadcastMessage;
use crate::echo_broadcast::EchoBroadcastPhase;
use crate::message_framing::receive_frame;
use crate::message_framing::send_frame;
use frost::Identifier;
use frost_secp256k1_tr as frost;
use std::error::Error;
use std::io;
use std::io::ErrorKind;
use tokio::io::AsyncRead;
use tokio::io::AsyncWrite;

// Store a decoded DKG message and its authenticated sender
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReceivedDkgPayload {
    EchoBroadcast(EchoBroadcastMessage),
    Round2Direct(Vec<u8>),
    Abort(Vec<u8>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceivedDkgMessage {
    // This ID comes from the authenticated mTLS connection
    pub authenticated_sender_id: Identifier,
    // This contains the decoded protocol message
    pub payload: ReceivedDkgPayload,
}

// Send one DKG message over an authenticated connection

/// Encodes a DKG message and sends it as a framed network message
pub async fn send_dkg_message<W>(
    writer: &mut W,
    dkg_message: &DkgMessage,
) -> Result<(), Box<dyn Error + Send + Sync>>
where
    W: AsyncWrite + Unpin,
{
    // Encode the DKG envelope
    let encoded_message = dkg_message.encode();

    // Send the complete envelope as one framed message
    send_frame(writer, &encoded_message).await?;

    Ok(())
}

// Receive and decode one DKG message

/// Receives one framed DKG message and binds it to the authenticated sender
pub async fn receive_dkg_message<R>(
    reader: &mut R,
    authenticated_sender_id: Identifier,
) -> Result<Option<ReceivedDkgMessage>, Box<dyn Error + Send + Sync>>
where
    R: AsyncRead + Unpin,
{
    // Receive one complete framed message
    let encoded_message = receive_frame(reader).await?;

    // A clean disconnect means that there is no next message
    let Some(encoded_message) = encoded_message else {
        return Ok(None);
    };

    // Decode the outer DKG envelope
    let dkg_message = DkgMessage::decode(&encoded_message)?;

    // Decode the payload according to its message type
    let received_payload = match dkg_message.kind {
        DkgMessageKind::EchoBroadcast => {
            // Decode the echo-broadcast message
            let echo_message = EchoBroadcastMessage::decode(&dkg_message.payload)?;

            // An initial broadcast must come from its original broadcaster
            if echo_message.phase == EchoBroadcastPhase::Initial
                && echo_message.original_broadcaster_id != authenticated_sender_id
            {
                return Err(io::Error::new(
                    ErrorKind::PermissionDenied,
                    "The initial broadcaster ID does not match the authenticated sender",
                )
                .into());
            }

            // For an echo message, the authenticated sender is the forwarder
            // The original broadcaster may be a different participant
            ReceivedDkgPayload::EchoBroadcast(echo_message)
        }
        DkgMessageKind::Round2Direct => {
            // The recipient will deserialize the FROST Round 2 package
            ReceivedDkgPayload::Round2Direct(dkg_message.payload)
        }
        DkgMessageKind::Abort => {
            // Keep the abort payload for the protocol handler
            ReceivedDkgPayload::Abort(dkg_message.payload)
        }
    };

    // Return the decoded message with the sender ID from mTLS
    Ok(Some(ReceivedDkgMessage {
        authenticated_sender_id,
        payload: received_payload,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::dkg_messages::DkgMessageKind;
    use crate::echo_broadcast::EchoBroadcastMessage;
    use crate::echo_broadcast::EchoBroadcastPhase;
    use tokio::io::duplex;

    fn test_frost_id(value: u16) -> Identifier {
        value.try_into().expect("Invalid test FROST ID")
    }

    #[tokio::test]
    async fn receives_an_initial_broadcast_from_its_authenticated_sender() {
        // Create an in-memory connection.
        let (mut sender, mut receiver) = duplex(4096);

        let alice_frost_id = test_frost_id(1);

        // Create Alice's initial message.
        let echo_message = EchoBroadcastMessage {
            phase: EchoBroadcastPhase::Initial,
            original_broadcaster_id: alice_frost_id,
            value: Some(vec![10, 20, 30]),
        };

        // Wrap the echo message in the DKG envelope.
        let dkg_message = DkgMessage {
            kind: DkgMessageKind::EchoBroadcast,
            payload: echo_message
                .encode()
                .expect("Failed to encode echo message"),
        };

        // Send the message.
        send_dkg_message(&mut sender, &dkg_message)
            .await
            .expect("Failed to send DKG message");

        // Receive it as a message from authenticated Alice.
        let received_message = receive_dkg_message(&mut receiver, alice_frost_id)
            .await
            .expect("Failed to receive DKG message")
            .expect("Connection closed unexpectedly");

        // Check the authenticated identity and decoded payload.
        assert_eq!(received_message.authenticated_sender_id, alice_frost_id,);

        assert_eq!(
            received_message.payload,
            ReceivedDkgPayload::EchoBroadcast(echo_message),
        );
    }

    #[tokio::test]
    async fn rejects_an_initial_broadcast_with_a_false_sender_id() {
        let (mut sender, mut receiver) = duplex(4096);

        let alice_frost_id = test_frost_id(1);
        let bob_frost_id = test_frost_id(2);

        // The message claims that Bob is the original broadcaster.
        let echo_message = EchoBroadcastMessage {
            phase: EchoBroadcastPhase::Initial,
            original_broadcaster_id: bob_frost_id,
            value: Some(vec![1, 2, 3]),
        };

        let dkg_message = DkgMessage {
            kind: DkgMessageKind::EchoBroadcast,
            payload: echo_message
                .encode()
                .expect("Failed to encode echo message"),
        };

        send_dkg_message(&mut sender, &dkg_message)
            .await
            .expect("Failed to send DKG message");

        // The receiver knows that the authenticated sender is Alice.
        let result = receive_dkg_message(&mut receiver, alice_frost_id).await;

        assert_eq!(
            result.unwrap_err().to_string(),
            "The initial broadcaster ID does not match the authenticated sender",
        );
    }

    #[tokio::test]
    async fn accepts_an_echo_forwarded_by_another_participant() {
        let (mut sender, mut receiver) = duplex(4096);

        let alice_frost_id = test_frost_id(1);
        let bob_frost_id = test_frost_id(2);

        // Bob forwards an echo for Alice's broadcast.
        let echo_message = EchoBroadcastMessage {
            phase: EchoBroadcastPhase::Echo,
            original_broadcaster_id: alice_frost_id,
            value: Some(vec![4, 5, 6]),
        };

        let dkg_message = DkgMessage {
            kind: DkgMessageKind::EchoBroadcast,
            payload: echo_message
                .encode()
                .expect("Failed to encode echo message"),
        };

        send_dkg_message(&mut sender, &dkg_message)
            .await
            .expect("Failed to send DKG message");

        let received_message = receive_dkg_message(&mut receiver, bob_frost_id)
            .await
            .expect("Failed to receive DKG message")
            .expect("Connection closed unexpectedly");

        assert_eq!(received_message.authenticated_sender_id, bob_frost_id,);

        assert_eq!(
            received_message.payload,
            ReceivedDkgPayload::EchoBroadcast(echo_message),
        );
    }

    #[tokio::test]
    async fn returns_none_after_a_clean_disconnect() {
        let (sender, mut receiver) = duplex(4096);

        // Close the sending side.
        drop(sender);

        let result = receive_dkg_message(&mut receiver, test_frost_id(1))
            .await
            .expect("Unexpected receive error");

        assert!(result.is_none());
    }
}
