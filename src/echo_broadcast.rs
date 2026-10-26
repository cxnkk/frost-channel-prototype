use frost::Identifier;
use frost_secp256k1_tr as frost;

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;
use std::io;
use std::io::ErrorKind;

// Define the message format limits
// The outer KDG message uses 2 bytes for its header
// EchoBroadcastMessage adds its own header
// The total encoded message must fit within message_framing.rs's limit
const FROST_IDENTIFIER_SIZE: usize = 32;
const ECHO_HEADER_SIZE: usize = 1 + FROST_IDENTIFIER_SIZE + 1 + 4;
const DKG_MESSAGE_HEADER_SIZE: usize = 2;
const MAX_APPLICATION_MESSAGE_SIZE: usize = 1024 * 1024;

const MAX_ECHO_PAYLOAD_SIZE: usize =
    MAX_APPLICATION_MESSAGE_SIZE - DKG_MESSAGE_HEADER_SIZE - ECHO_HEADER_SIZE;

/// Define the message phases
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EchoBroadcastPhase {
    // The original broadcaster sends its value
    Initial = 1,

    // A recipient echoes the value it received, or null
    Echo = 2,
}

impl TryFrom<u8> for EchoBroadcastPhase {
    type Error = io::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Initial),
            2 => Ok(Self::Echo),
            _ => Err(io::Error::new(
                ErrorKind::InvalidData,
                "Unknown echo-broadcast phase",
            )),
        }
    }
}

/// Define an echo-broadcast message
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EchoBroadcastMessage {
    pub phase: EchoBroadcastPhase,

    // Identifies the participant that started this broadcast
    pub original_broadcaster_id: Identifier,

    // Some(payload) contains the value. None represents null. Null is valid only in the Echo phase
    pub value: Option<Vec<u8>>,
}

impl EchoBroadcastMessage {
    /// Encodes an echo-broadcast message into bytes
    pub fn encode(&self) -> Result<Vec<u8>, io::Error> {
        // An initial broadcast must contain a value
        if self.phase == EchoBroadcastPhase::Initial && self.value.is_none() {
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                "An initial broadcast cannot contain null",
            ));
        }

        // Validate the payload
        if let Some(payload) = &self.value {
            if payload.is_empty() {
                return Err(io::Error::new(
                    ErrorKind::InvalidInput,
                    "An echo-broadcast payload cannot be empty",
                ));
            }

            if payload.len() > MAX_ECHO_PAYLOAD_SIZE {
                return Err(io::Error::new(
                    ErrorKind::InvalidInput,
                    "The echo-broadcast payload is too large",
                ));
            }
        }

        // Serialize the original broadcaster's FROST ID
        let identifier_bytes = self.original_broadcaster_id.serialize();

        if identifier_bytes.len() != FROST_IDENTIFIER_SIZE {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                "Unexpected FROST Identifier length",
            ));
        }

        // Encode the value flag and payload length
        // Flag 0: null value
        // Flag 1: payload is present
        let (value_flag, payload_length) = match &self.value {
            Some(payload) => (1_u8, payload.len()),
            None => (0_u8, 0_usize),
        };

        let payload_length_u32 = u32::try_from(payload_length).map_err(|_| {
            io::Error::new(
                ErrorKind::InvalidInput,
                "Payload lenght cannot be represented as u32",
            )
        })?;

        // Build the encoded message
        let mut encoded_message = Vec::with_capacity(ECHO_HEADER_SIZE + payload_length);

        encoded_message.push(self.phase as u8);
        encoded_message.extend_from_slice(&identifier_bytes);
        encoded_message.push(value_flag);
        encoded_message.extend_from_slice(&payload_length_u32.to_be_bytes());

        if let Some(payload) = &self.value {
            encoded_message.extend_from_slice(payload);
        }

        Ok(encoded_message)
    }

    /// Decodes an echo-broadcast message and validates its fields
    pub fn decode(encoded_message: &[u8]) -> Result<Self, io::Error> {
        // Check that the complete header is present
        // A null echo contains no payload, so the header alone is valid
        if encoded_message.len() < ECHO_HEADER_SIZE {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                "Echo-broadcast header is incomplete",
            ));
        }

        // Check the total encoded message size
        if encoded_message.len() > MAX_APPLICATION_MESSAGE_SIZE - DKG_MESSAGE_HEADER_SIZE {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                "Echo-broadcast message is too large",
            ));
        }

        // Decode the message phase
        let phase = EchoBroadcastPhase::try_from(encoded_message[0])?;

        // Decode the original broadcaster's FROST ID
        let identifier_start = 1;
        let identifier_end = identifier_start + FROST_IDENTIFIER_SIZE;

        let original_broadcaster_id = Identifier::deserialize(
            &encoded_message[identifier_start..identifier_end],
        )
        .map_err(|_| {
            io::Error::new(
                ErrorKind::InvalidData,
                "Invalid original broadcaster FROST ID",
            )
        })?;

        // Read the value flag and payload length
        let value_flag = encoded_message[identifier_end];

        let length_start = identifier_end + 1;
        let length_end = length_start + 4;

        let mut payload_length_bytes = [0_u8; 4];
        payload_length_bytes.copy_from_slice(&encoded_message[length_start..length_end]);

        let payload_length = u32::from_be_bytes(payload_length_bytes) as usize;

        if payload_length > MAX_ECHO_PAYLOAD_SIZE {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                "Echo-broadcast payload is too large",
            ));
        }

        // Check that the declared length matches the actual payload
        let actual_payload_length = encoded_message.len() - ECHO_HEADER_SIZE;

        if actual_payload_length != payload_length {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                "Echo-broadcast payload length does not match",
            ));
        }

        // Decode the value
        let value = match value_flag {
            0 => {
                // A null value is valid only during the echo phase
                if phase != EchoBroadcastPhase::Echo || payload_length != 0 {
                    return Err(io::Error::new(ErrorKind::InvalidData, "Invalid null echo"));
                }

                None
            }
            1 => {
                if payload_length == 0 {
                    return Err(io::Error::new(
                        ErrorKind::InvalidData,
                        "A present value cannot have an empty payload",
                    ));
                }

                Some(encoded_message[ECHO_HEADER_SIZE..].to_vec())
            }
            _ => {
                return Err(io::Error::new(
                    ErrorKind::InvalidData,
                    "Unknown echo-broadcast value flag",
                ));
            }
        };

        // An initial broadcast must contain a value
        if phase == EchoBroadcastPhase::Initial && value.is_none() {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                "An initial broadcast cannot contain null",
            ));
        }

        Ok(Self {
            phase,
            original_broadcaster_id,
            value,
        })
    }
}

///Define errors from the echo-broadcast state machine
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EchoBroadcastError {
    DuplicateParticipantId,
    ParticipantNotInRoster,
    LocalParticipantIsBroadcaster,
    WrongOriginalBroadcaster,
    InvalidPhase,
    InitialAlreadyDecided,
    InitialValueRequired,
    InitialValueNotReady,
    UnexpectedEchoSender,
    DuplicateEcho,
    EmptyPayload,
}

impl fmt::Display for EchoBroadcastError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateParticipantId => {
                write!(formatter, "Duplicate participant ID")
            }
            Self::ParticipantNotInRoster => {
                write!(formatter, "Participant is not in the roster")
            }
            Self::LocalParticipantIsBroadcaster => {
                write!(
                    formatter,
                    "The local participant cannot use a receiver instance for its own broadcast"
                )
            }
            Self::WrongOriginalBroadcaster => {
                write!(formatter, "Wrong original broadcaster")
            }
            Self::InvalidPhase => {
                write!(formatter, "Invalid echo-broadcast phase")
            }
            Self::InitialAlreadyDecided => {
                write!(
                    formatter,
                    "The initial broadcast value has already been decided"
                )
            }
            Self::InitialValueRequired => {
                write!(formatter, "Initial broadcast value is required")
            }
            Self::InitialValueNotReady => {
                write!(
                    formatter,
                    "The initial value or its timeout has not been decided"
                )
            }
            Self::UnexpectedEchoSender => {
                write!(formatter, "Unexpected echo sender")
            }
            Self::DuplicateEcho => {
                write!(formatter, "Duplicate echo from one participant")
            }
            Self::EmptyPayload => {
                write!(formatter, "The payload is empty")
            }
        }
    }
}

impl Error for EchoBroadcastError {}

/// Define the local result of one broadcast instance
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EchoBroadcastOutcome {
    // The instance needs more messages
    Pending,

    // All required values match. The receiver can use this value
    Delivered(Vec<u8>),

    // The values differ, or the initial value is null
    Aborted,
}

// Track one broadcaster's value at one receiving participant
// Create one instance for each other participant's Part 1 broadcast
// The original broadcaster does not need a receiver instance for its own value
pub struct EchoBroadcastInstance {
    local_frost_id: Identifier,
    original_broadcaster_id: Identifier,

    // Peers that must echo to this local participant
    expected_echo_senders: BTreeSet<Identifier>,

    // True after an initial value arrives or the initial-value timer expires
    initial_decided: bool,

    // None means the receiver did not receive the initial value in time
    initial_value: Option<Vec<u8>>,

    // The map key comes from the authenticated mTLS connection
    echoes: BTreeMap<Identifier, Option<Vec<u8>>>,
}

impl EchoBroadcastInstance {
    /// Creates a receiver state for one original broadcaster
    pub fn new(
        local_frost_id: Identifier,
        original_broadcaster_id: Identifier,
        participant_ids: impl IntoIterator<Item = Identifier>,
    ) -> Result<Self, EchoBroadcastError> {
        // Build the roster and reject duplicate IDs
        let mut participant_set = BTreeSet::new();

        for participant_id in participant_ids {
            if !participant_set.insert(participant_id) {
                return Err(EchoBroadcastError::DuplicateParticipantId);
            }
        }

        // Confirm that the local participant and broadcaster are in the roster
        if !participant_set.contains(&local_frost_id)
            || !participant_set.contains(&original_broadcaster_id)
        {
            return Err(EchoBroadcastError::ParticipantNotInRoster);
        }

        // This instance is for a remote broadcaster
        if local_frost_id == original_broadcaster_id {
            return Err(EchoBroadcastError::LocalParticipantIsBroadcaster);
        }

        // Expect echoes from all participants except the local participant and the original broadcaster
        let expected_echo_senders = participant_set
            .into_iter()
            .filter(|participant_id| {
                *participant_id != local_frost_id && *participant_id != original_broadcaster_id
            })
            .collect();

        Ok(Self {
            local_frost_id,
            original_broadcaster_id,
            expected_echo_senders,
            initial_decided: false,
            initial_value: None,
            echoes: BTreeMap::new(),
        })
    }

    /// Records an initial value received over the authenticated channel
    pub fn receive_initial_message(
        &mut self,
        authenticated_sender_id: Identifier,
        message: &EchoBroadcastMessage,
    ) -> Result<(), EchoBroadcastError> {
        // Only an initial message is valid here
        if message.phase != EchoBroadcastPhase::Initial {
            return Err(EchoBroadcastError::InvalidPhase);
        }

        // The authenticated sender and the claimed broadcaster must match
        if authenticated_sender_id != self.original_broadcaster_id
            || message.original_broadcaster_id != self.original_broadcaster_id
        {
            return Err(EchoBroadcastError::WrongOriginalBroadcaster);
        }

        // The initial value can be set only once
        if self.initial_decided {
            return Err(EchoBroadcastError::InitialAlreadyDecided);
        }

        // An initial message must contain a value
        let initial_value = message
            .value
            .as_ref()
            .ok_or(EchoBroadcastError::EmptyPayload)?;

        if initial_value.is_empty() {
            return Err(EchoBroadcastError::EmptyPayload);
        }

        self.initial_value = Some(initial_value.clone());
        self.initial_decided = true;

        Ok(())
    }

    /// Records that the initial-value timer expired without a value
    pub fn record_initial_timeout(&mut self) -> Result<(), EchoBroadcastError> {
        // Do not replace a value that has already been decided
        if self.initial_decided {
            return Err(EchoBroadcastError::InitialAlreadyDecided);
        }

        // Store null. The caller must now send a null echo
        self.initial_value = None;
        self.initial_decided = true;

        Ok(())
    }

    /// Creates the echo message for the value received, or null after timeout
    pub fn create_echo_message(&self) -> Result<EchoBroadcastMessage, EchoBroadcastError> {
        // The receiver must decide its initial value befor it can echo
        if !self.initial_decided {
            return Err(EchoBroadcastError::InitialValueNotReady);
        }

        Ok(EchoBroadcastMessage {
            phase: EchoBroadcastPhase::Echo,
            original_broadcaster_id: self.original_broadcaster_id,
            value: self.initial_value.clone(),
        })
    }

    /// Returns the peers that must receive this participant's echo
    pub fn echo_recipients(&self) -> Vec<Identifier> {
        self.expected_echo_senders.iter().copied().collect()
    }

    /// Records an echo from an authenticated peer
    pub fn record_echo(
        &mut self,
        authenticated_sender_id: Identifier,
        message: &EchoBroadcastMessage,
    ) -> Result<(), EchoBroadcastError> {
        // Only an echo message is valid here
        if message.phase != EchoBroadcastPhase::Echo {
            return Err(EchoBroadcastError::InvalidPhase);
        }

        // The echo must refer to this original broadcaster
        if message.original_broadcaster_id != self.original_broadcaster_id {
            return Err(EchoBroadcastError::WrongOriginalBroadcaster);
        }

        // The authenticated sender must be an expected echo sender
        if !self
            .expected_echo_senders
            .contains(&authenticated_sender_id)
        {
            return Err(EchoBroadcastError::UnexpectedEchoSender);
        }

        // Reject a payload that is empty instead of null
        if let Some(value) = &message.value {
            if value.is_empty() {
                return Err(EchoBroadcastError::EmptyPayload);
            }
        }

        // Accept no more than one echo from each participant
        if self.echoes.contains_key(&authenticated_sender_id) {
            return Err(EchoBroadcastError::DuplicateEcho);
        }

        self.echoes
            .insert(authenticated_sender_id, message.value.clone());

        Ok(())
    }

    /// Returns the current result of this broadcast instance
    pub fn outcome(&self) -> EchoBroadcastOutcome {
        // Wait until the initial value or its timeouts is decided
        if !self.initial_decided {
            return EchoBroadcastOutcome::Pending;
        }

        // A conflict with any received echo means this broadcast aborts
        if self
            .echoes
            .values()
            .any(|echoed_value| echoed_value != &self.initial_value)
        {
            return EchoBroadcastOutcome::Aborted;
        }

        // Wait until every expected participant echoed
        if self.echoes.len() != self.expected_echo_senders.len() {
            return EchoBroadcastOutcome::Pending;
        }

        // Delivery only a non-null value that matches every echo
        match &self.initial_value {
            Some(value) => EchoBroadcastOutcome::Delivered(value.clone()),
            None => EchoBroadcastOutcome::Aborted,
        }
    }

    /// Returns the local participant's FROST ID
    pub fn local_frost_id(&self) -> Identifier {
        self.local_frost_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_frost_id(value: u16) -> Identifier {
        value.try_into().expect("Invalid test FROST Identifier")
    }

    fn test_initial_message(broadcaster_id: Identifier, value: Vec<u8>) -> EchoBroadcastMessage {
        EchoBroadcastMessage {
            phase: EchoBroadcastPhase::Initial,
            original_broadcaster_id: broadcaster_id,
            value: Some(value),
        }
    }

    fn test_echo_message(
        broadcaster_id: Identifier,
        value: Option<Vec<u8>>,
    ) -> EchoBroadcastMessage {
        EchoBroadcastMessage {
            phase: EchoBroadcastPhase::Echo,
            original_broadcaster_id: broadcaster_id,
            value,
        }
    }

    fn three_participant_instance() -> EchoBroadcastInstance {
        let alice_id = test_frost_id(1);
        let bob_id = test_frost_id(2);
        let charlie_id = test_frost_id(3);

        EchoBroadcastInstance::new(bob_id, alice_id, [alice_id, bob_id, charlie_id])
            .expect("Failed to create a echo-broadcast instance")
    }

    #[test]
    fn encodes_and_decodes_an_initial_message() {
        let original_message = test_initial_message(test_frost_id(1), vec![10, 20, 30]);

        let encoded_message = original_message
            .encode()
            .expect("Failed to encode initial message");

        let decoded_message = EchoBroadcastMessage::decode(&encoded_message)
            .expect("Failed to decode initial message");

        assert_eq!(decoded_message, original_message)
    }

    #[test]
    fn encodes_and_decodes_a_null_echo() {
        let original_message = test_echo_message(test_frost_id(1), None);

        let encoded_message = original_message
            .encode()
            .expect("Failed to encode null echo");

        let decoded_message =
            EchoBroadcastMessage::decode(&encoded_message).expect("Failed to decode null echo ");

        assert_eq!(decoded_message, original_message)
    }

    #[test]
    fn delivers_when_all_echoes_match() {
        let alice_id = test_frost_id(1);
        let charlie_id = test_frost_id(3);
        let package = vec![1, 2, 3];

        let mut instance = three_participant_instance();

        let initial_message = test_initial_message(alice_id, package.clone());

        instance
            .receive_initial_message(alice_id, &initial_message)
            .expect("Failed to record initial message");

        let echo_message = instance
            .create_echo_message()
            .expect("Failed to create echo message");

        instance
            .record_echo(charlie_id, &echo_message)
            .expect("Failed to record matching echo");

        assert_eq!(instance.outcome(), EchoBroadcastOutcome::Delivered(package));
    }

    #[test]
    fn aborts_when_an_echo_has_a_different_value() {
        let alice_id = test_frost_id(1);
        let charlie_id = test_frost_id(3);

        let mut instance = three_participant_instance();

        let initial_message = test_initial_message(alice_id, vec![1, 2, 3]);

        instance
            .receive_initial_message(alice_id, &initial_message)
            .expect("Failed to record initial message");

        // Charlie echoes a different value
        let conflicting_echo = test_echo_message(alice_id, Some(vec![9, 9, 9]));

        instance
            .record_echo(charlie_id, &conflicting_echo)
            .expect("Failed to record echo");

        assert_eq!(instance.outcome(), EchoBroadcastOutcome::Aborted)
    }

    #[test]
    fn aborts_when_no_initial_value_was_received() {
        let alice_id = test_frost_id(1);
        let charlie_id = test_frost_id(3);

        let mut instance = three_participant_instance();

        instance
            .record_initial_timeout()
            .expect("Failed to record initial timeout");

        let null_echo = test_echo_message(alice_id, None);

        instance
            .record_echo(charlie_id, &null_echo)
            .expect("Failed to record null echo");

        // Null is not a valid Part 1 package to deliver
        assert_eq!(instance.outcome(), EchoBroadcastOutcome::Aborted);
    }

    #[test]
    fn waits_until_all_expected_echoes_arrive() {
        let alice_id = test_frost_id(1);
        let charlie_id = test_frost_id(3);
        let package = vec![1, 2, 3];

        let mut instance = three_participant_instance();

        let initial_message = test_initial_message(alice_id, package);

        instance
            .receive_initial_message(alice_id, &initial_message)
            .expect("Failed to receive initial message");

        assert_eq!(instance.outcome(), EchoBroadcastOutcome::Pending);

        let echo_message = instance
            .create_echo_message()
            .expect("Failed to crate echo message");

        instance
            .record_echo(charlie_id, &echo_message)
            .expect("Failed to record echo");

        assert!(matches!(
            instance.outcome(),
            EchoBroadcastOutcome::Delivered(_),
        ));
    }

    #[test]
    fn rejects_an_echo_from_an_unexpected_sender() {
        let alice_id = test_frost_id(1);
        let bob_id = test_frost_id(2);

        let mut instance = three_participant_instance();

        let echo_message = test_echo_message(alice_id, Some(vec![1]));

        // Bob is the local participant. He cannot echo himself
        let result = instance.record_echo(bob_id, &echo_message);

        assert_eq!(result, Err(EchoBroadcastError::UnexpectedEchoSender));
    }

    #[test]
    fn rejects_a_duplicate_echo() {
        let alice_id = test_frost_id(1);
        let charlie_id = test_frost_id(3);

        // Instance => Local = Bob, Original = Alice, Participants = Alice, Bob, Charlie
        let mut instance = three_participant_instance();

        // Sets the initial message to Alice with the value
        let initial_message = test_initial_message(alice_id, vec![1, 2, 3]);

        // Sets initial.value and initial.decided of EchoBroadcastInstance
        instance
            .receive_initial_message(alice_id, &initial_message)
            .expect("Failed to record initial message");

        let echo_message = instance
            .create_echo_message()
            .expect("Failed to create echo message");

        instance
            .record_echo(charlie_id, &echo_message)
            .expect("Failed to record first echo");

        let duplicate_result = instance.record_echo(charlie_id, &echo_message);

        assert_eq!(duplicate_result, Err(EchoBroadcastError::DuplicateEcho));
    }

    #[test]
    fn accepts_an_echo_that_arrives_before_the_initial_message() {
        let alice_id = test_frost_id(1);
        let charlie_id = test_frost_id(3);
        let package = vec![1, 2, 3];

        let mut instance = three_participant_instance();

        let echo_message = test_echo_message(alice_id, Some(package.clone()));

        // The network can deliver Charlie's echo before Alice's package
        instance
            .record_echo(charlie_id, &echo_message)
            .expect("Failed to buffer early echo");

        assert_eq!(instance.outcome(), EchoBroadcastOutcome::Pending);

        let initial_message = test_initial_message(alice_id, package.clone());

        instance
            .receive_initial_message(alice_id, &initial_message)
            .expect("Failed to record initial message");

        assert_eq!(instance.outcome(), EchoBroadcastOutcome::Delivered(package));
    }

    #[test]
    fn three_participants_deliver_the_same_value() {
        // Define the three participants
        let alice_id = test_frost_id(1);
        let bob_id = test_frost_id(2);
        let charlie_id = test_frost_id(3);

        let participants = [alice_id, bob_id, charlie_id];
        let package = vec![10, 20, 30, 40];

        // Create a receiver for Alice's broadcast at Bob and Charlie
        let mut bob_instance = EchoBroadcastInstance::new(bob_id, alice_id, participants)
            .expect("Failed to create Bob's broadcast instance");

        let mut charlie_instance = EchoBroadcastInstance::new(charlie_id, alice_id, participants)
            .expect("Failed to create Charlie's broadcast instance");

        // Alice sends the same initial value to both participants
        let initial_message = test_initial_message(alice_id, package.clone());

        bob_instance
            .receive_initial_message(alice_id, &initial_message)
            .expect("Bob failed to receive Alice's value");

        charlie_instance
            .receive_initial_message(alice_id, &initial_message)
            .expect("Charlie failed to receive Alice's value");

        // Bob and Charlie create their echo messages
        let bob_echo = bob_instance
            .create_echo_message()
            .expect("Bob failed to create an echo message");

        let charlie_echo = charlie_instance
            .create_echo_message()
            .expect("Charlie failed to create an echo message");

        // Each participant records the other participant's echo
        bob_instance
            .record_echo(charlie_id, &charlie_echo)
            .expect("Bob failed to record Charlie's echo");

        charlie_instance
            .record_echo(bob_id, &bob_echo)
            .expect("Charlie failed to record Bob's echo");

        // Both participants must deliver the same value
        assert_eq!(
            bob_instance.outcome(),
            EchoBroadcastOutcome::Delivered(package.clone())
        );

        assert_eq!(
            charlie_instance.outcome(),
            EchoBroadcastOutcome::Delivered(package)
        );
    }

    #[test]
    fn three_participants_abort_when_alice_sends_different_values() {
        // Define the three participants
        let alice_id = test_frost_id(1);
        let bob_id = test_frost_id(2);
        let charlie_id = test_frost_id(3);

        let participants = [alice_id, bob_id, charlie_id];

        let bob_value = vec![10, 20, 30];
        let charlie_value = vec![90, 80, 70];

        // Create a receiver for Alice's broadcast at Bob and Charlie
        let mut bob_instance = EchoBroadcastInstance::new(bob_id, alice_id, participants)
            .expect("Failed to create Bob's broadcast instance");

        let mut charlie_instance = EchoBroadcastInstance::new(charlie_id, alice_id, participants)
            .expect("Failed to create Charlie's broadcast instance");

        // Simulate Alice sending different values to Bob and Charlie
        let message_to_bob = test_initial_message(alice_id, bob_value);

        let message_to_charlie = test_initial_message(alice_id, charlie_value);

        bob_instance
            .receive_initial_message(alice_id, &message_to_bob)
            .expect("Bob failed to receive Alice's value");

        charlie_instance
            .receive_initial_message(alice_id, &message_to_charlie)
            .expect("Charlie failed to receive Alice's value");

        // Bob and Charlie echo the values they each received
        let bob_echo = bob_instance
            .create_echo_message()
            .expect("Bob failed to create an echo");

        let charlie_echo = charlie_instance
            .create_echo_message()
            .expect("Charlie failed to create an echo");

        // Each participant records the other participant's echo
        bob_instance
            .record_echo(charlie_id, &charlie_echo)
            .expect("Bob failed to record Charlie's echo");

        charlie_instance
            .record_echo(bob_id, &bob_echo)
            .expect("Charlie failed to record Bob's echo");

        // Both participants must reject the inconsistent value.
        assert_eq!(bob_instance.outcome(), EchoBroadcastOutcome::Aborted,);

        assert_eq!(charlie_instance.outcome(), EchoBroadcastOutcome::Aborted,);
    }
}
