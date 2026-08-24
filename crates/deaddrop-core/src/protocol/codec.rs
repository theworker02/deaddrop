use crate::{DdError, MAX_FRAME_SIZE, Result};
use serde::{Serialize, de::DeserializeOwned};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub fn encode_cbor<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    ciborium::into_writer(value, &mut buf)
        .map_err(|e| DdError::invalid_frame(format!("cbor encode: {e}")))?;
    if buf.len() as u32 > MAX_FRAME_SIZE {
        return Err(DdError::protocol(
            crate::ErrorCode::Ddp1006LimitExceeded,
            "encoded object exceeds max frame",
        ));
    }
    Ok(buf)
}

pub fn decode_cbor<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    if bytes.len() as u32 > MAX_FRAME_SIZE {
        return Err(DdError::protocol(
            crate::ErrorCode::Ddp1006LimitExceeded,
            "frame too large",
        ));
    }
    ciborium::from_reader(bytes).map_err(|e| DdError::invalid_frame(format!("cbor decode: {e}")))
}

pub async fn write_frame_async<W: AsyncWriteExt + Unpin>(w: &mut W, payload: &[u8]) -> Result<()> {
    if payload.len() as u32 > MAX_FRAME_SIZE {
        return Err(DdError::protocol(
            crate::ErrorCode::Ddp1006LimitExceeded,
            "frame too large",
        ));
    }
    w.write_all(&(payload.len() as u32).to_be_bytes()).await?;
    w.write_all(payload).await?;
    w.flush().await?;
    Ok(())
}

pub async fn read_frame_async<R: AsyncReadExt + Unpin>(r: &mut R) -> Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf);
    if len > MAX_FRAME_SIZE {
        return Err(DdError::protocol(
            crate::ErrorCode::Ddp1006LimitExceeded,
            "frame too large",
        ));
    }
    let mut buf = vec![0u8; len as usize];
    r.read_exact(&mut buf).await?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CapabilityDoc;

    #[test]
    fn malformed_cbor_is_error_not_panic() {
        assert!(decode_cbor::<CapabilityDoc>(&[]).is_err());
        assert!(decode_cbor::<CapabilityDoc>(&[0xff, 0x00, 0x01]).is_err());
    }

    #[test]
    fn caps_roundtrip() {
        let c = CapabilityDoc::local_v2();
        let b = encode_cbor(&c).unwrap();
        let d: CapabilityDoc = decode_cbor(&b).unwrap();
        assert_eq!(c, d);
    }

    #[test]
    fn random_bytes_do_not_panic_message_or_envelope() {
        use crate::DropEnvelope;
        use crate::protocol::Message;
        let mut seed = 0x9e37_79b9_7f4a_7c15u64;
        for _ in 0..256 {
            seed = seed.wrapping_mul(0x5851_f42d_4c95_7f2d).wrapping_add(1);
            let n = (seed % 64) as usize;
            let bytes: Vec<u8> = (0..n)
                .map(|i| (seed.wrapping_add(i as u64 * 17) >> ((i % 8) * 8)) as u8)
                .collect();
            let _ = decode_cbor::<Message>(&bytes);
            let _ = decode_cbor::<DropEnvelope>(&bytes);
            let _ = decode_cbor::<CapabilityDoc>(&bytes);
        }
    }
}
