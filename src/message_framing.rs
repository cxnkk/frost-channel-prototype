use std::io;
use tokio::io::AsyncRead;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWrite;
use tokio::io::AsyncWriteExt;

// Set the maximum size of one network message
pub const MAX_MESSAGE_SIZE: usize = 1024 * 1024;

/// Send one length-prefixed message
pub async fn send_frame<W>(writer: &mut W, message: &[u8]) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    // Reject empty messages
    if message.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Cannot send an empty message",
        ));
    }

    // Reject messages that exceed the configured limit.
    if message.len() > MAX_MESSAGE_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Message exceeds the maximum allowed size",
        ));
    }

    // Encode the message length as a 4-byte big-endian value.
    let message_length = u32::try_from(message.len()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "Message length cannot be represented as u32",
        )
    })?;

    writer.write_all(&message_length.to_be_bytes()).await?;
    writer.write_all(message).await?;
    writer.flush().await?;

    Ok(())
}

/// Receive one complete message. Return None when the peer closes the connection between messages
pub async fn receive_frame<R>(reader: &mut R) -> io::Result<Option<Vec<u8>>>
where
    R: AsyncRead + Unpin,
{
    // Read the first byte of the message header
    let mut message_length_bytes = [0_u8; 4];

    let bytes_read = reader.read(&mut message_length_bytes[..1]).await?;

    // A clean end of stream means that the peer has closed the connection
    if bytes_read == 0 {
        return Ok(None);
    }

    // Read the remaining three header bytes. An incomplete header is an error
    reader.read_exact(&mut message_length_bytes[1..]).await?;

    // Decode and validate the message length
    let message_length = u32::from_be_bytes(message_length_bytes) as usize;

    if message_length == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Received an empty message",
        ));
    }

    if message_length > MAX_MESSAGE_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Received a message that exceeds the maximum allowed size",
        ));
    }

    // Read exactly the declared number of payload bytes
    let mut message = vec![0_u8; message_length];

    reader.read_exact(&mut message).await?;

    Ok(Some(message))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn sends_and_receives_a_complete_message() {
        // Create an in-memory connection for the test
        let (mut sender, mut receiver) = tokio::io::duplex(4096);

        let expected_message = vec![0_u8, 1, 2, 127, 255];

        // Send one framed message
        send_frame(&mut sender, &expected_message)
            .await
            .expect("Failed to send the message");

        // Receive the complete message
        let received_message = receive_frame(&mut receiver)
            .await
            .expect("Failed to receive the message")
            .expect("The sender closed unexpectedly");

        // Confirm that the payload is unchanged
        assert_eq!(received_message, expected_message)
    }

    #[tokio::test]
    async fn rejects_an_empty_message() {
        let (mut sender, _receiver) = tokio::io::duplex(4096);

        let result = send_frame(&mut sender, &[]).await;

        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidInput);
    }

    #[tokio::test]
    async fn rejects_an_oversized_message() {
        let (mut sender, _receiver) = tokio::io::duplex(4096);

        let message = vec![0_u8; MAX_MESSAGE_SIZE + 1];

        let result = send_frame(&mut sender, &message).await;

        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidInput);
    }

    #[tokio::test]
    async fn returns_none_after_a_clean_disconnect() {
        let (sender, mut receiver) = tokio::io::duplex(4096);

        drop(sender);

        let result = receive_frame(&mut receiver)
            .await
            .expect("Unexpected receive error");

        assert!(result.is_none());
    }
}
