use std::io;
use std::io::ErrorKind;

// Define the current network protocol version.
const PROTOCOL_VERSION: u8 = 1;

// The header contains one byte for the version and one byte for the message
const MESSAGE_HEADER_SIZE: usize = 2;

/// Defines the message types used by the DKG network
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DkgMessageKind {
    EchoBroadcast = 1,
    Round2Direct = 2,
    Abort = 3,
}

impl TryFrom<u8> for DkgMessageKind {
    type Error = io::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::EchoBroadcast),
            2 => Ok(Self::Round2Direct),
            3 => Ok(Self::Abort),
            _ => Err(io::Error::new(
                ErrorKind::InvalidData,
                "Unknown DKG message type",
            )),
        }
    }
}

/// Stores the DKG message type and its payload
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DkgMessage {
    pub kind: DkgMessageKind,

    // Contains the encoded echo-broadcast message, the serialized Round 2 package, or the abort reason
    pub payload: Vec<u8>,
}

impl DkgMessage {
    /// Encodes the message header and payload into bytes for transmission
    pub fn encode(&self) -> Vec<u8> {
        let mut encoded_message = Vec::with_capacity(MESSAGE_HEADER_SIZE + self.payload.len());

        // Write the protocol version and message type
        encoded_message.push(PROTOCOL_VERSION);
        encoded_message.push(self.kind as u8);

        // Append the payload
        encoded_message.extend_from_slice(&self.payload);

        encoded_message
    }

    /// Validates and decodes a message received from the network
    pub fn decode(encoded_message: &[u8]) -> Result<Self, io::Error> {
        // Check that the complete header and a payload are present
        if encoded_message.len() <= MESSAGE_HEADER_SIZE {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                "DKG message is too short",
            ));
        }

        // Check the protocol version
        if encoded_message[0] != PROTOCOL_VERSION {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                "Unsupported protocol version",
            ));
        }

        // Decode the message type
        let kind = DkgMessageKind::try_from(encoded_message[1])?;

        // Extract the payload
        let payload = encoded_message[MESSAGE_HEADER_SIZE..].to_vec();

        Ok(Self { kind, payload })
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn encodes_and_decodes_an_echo_broadcast_message() {
        // Create a test message
        let original_message = DkgMessage {
            kind: DkgMessageKind::EchoBroadcast,
            payload: vec![1, 2, 3, 4],
        };

        // Encode the message
        let encoded_message = original_message.encode();

        // Decode the message
        let decoded_message =
            DkgMessage::decode(&encoded_message).expect("Failed to decode echo broadcast message");

        // Check that the message is unchanged
        assert_eq!(decoded_message, original_message);
    }

    #[test]
    fn encodes_and_decodes_a_round2_message() {
        let original_message = DkgMessage {
            kind: DkgMessageKind::Round2Direct,
            payload: vec![10, 20, 30],
        };

        let encoded_message = original_message.encode();

        let decoded_message =
            DkgMessage::decode(&encoded_message).expect("Failed to decode Round 2 message");

        assert_eq!(decoded_message, original_message);
    }

    #[test]
    fn rejects_an_unknown_message_type() {
        let encoded_message = vec![PROTOCOL_VERSION, 99, 1];

        let result = DkgMessage::decode(&encoded_message);

        assert_eq!(result.unwrap_err().kind(), ErrorKind::InvalidData);
    }

    #[test]
    fn rejects_an_unsupported_protocol_version() {
        let encoded_message = vec![99, DkgMessageKind::Abort as u8, 1];

        let result = DkgMessage::decode(&encoded_message);

        assert_eq!(result.unwrap_err().kind(), ErrorKind::InvalidData);
    }

    #[test]
    fn rejects_a_truncated_message() {
        let encoded_message = vec![0_u8; MESSAGE_HEADER_SIZE];

        let result = DkgMessage::decode(&encoded_message);

        assert_eq!(result.unwrap_err().kind(), ErrorKind::InvalidData);
    }
}
