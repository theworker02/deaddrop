use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ErrorCode {
    Ddp1001InvalidFrame,
    Ddp1002UnsupportedVersion,
    Ddp1003UnknownCriticalExtension,
    Ddp1004UnsupportedHash,
    Ddp1005BadIdentifier,
    Ddp1006LimitExceeded,
    Ddp1007Expired,
    Ddp1008NotRecipient,
    Ddp1009Sealed,
    Dds2001StoreFull,
    Dds2002CorruptChunk,
    Dds2003MissingChunk,
    Dds2004CorruptMetadata,
    Dda3001AuthFailed,
    Dda3002Replay,
    Ddr4001RouteUnavailable,
    Ddr4002ReplicationExhausted,
    Ddi5001UnknownContact,
    Ddc6001Crypto,
    Ddi7001Io,
    Ddx0000Internal,
}

impl ErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ddp1001InvalidFrame => "DDP1001_INVALID_FRAME",
            Self::Ddp1002UnsupportedVersion => "DDP1002_UNSUPPORTED_VERSION",
            Self::Ddp1003UnknownCriticalExtension => "DDP1003_UNKNOWN_CRITICAL_EXTENSION",
            Self::Ddp1004UnsupportedHash => "DDP1004_UNSUPPORTED_HASH",
            Self::Ddp1005BadIdentifier => "DDP1005_BAD_IDENTIFIER",
            Self::Ddp1006LimitExceeded => "DDP1006_LIMIT_EXCEEDED",
            Self::Ddp1007Expired => "DDP1007_EXPIRED",
            Self::Ddp1008NotRecipient => "DDP1008_NOT_RECIPIENT",
            Self::Ddp1009Sealed => "DDP1009_SEALED",
            Self::Dds2001StoreFull => "DDS2001_STORE_FULL",
            Self::Dds2002CorruptChunk => "DDS2002_CORRUPT_CHUNK",
            Self::Dds2003MissingChunk => "DDS2003_MISSING_CHUNK",
            Self::Dds2004CorruptMetadata => "DDS2004_CORRUPT_METADATA",
            Self::Dda3001AuthFailed => "DDA3001_AUTH_FAILED",
            Self::Dda3002Replay => "DDA3002_REPLAY",
            Self::Ddr4001RouteUnavailable => "DDR4001_ROUTE_UNAVAILABLE",
            Self::Ddr4002ReplicationExhausted => "DDR4002_REPLICATION_EXHAUSTED",
            Self::Ddi5001UnknownContact => "DDI5001_UNKNOWN_CONTACT",
            Self::Ddc6001Crypto => "DDC6001_CRYPTO",
            Self::Ddi7001Io => "DDI7001_IO",
            Self::Ddx0000Internal => "DDX0000_INTERNAL",
        }
    }

    pub fn category(self) -> &'static str {
        match self {
            Self::Ddp1001InvalidFrame
            | Self::Ddp1002UnsupportedVersion
            | Self::Ddp1003UnknownCriticalExtension
            | Self::Ddp1004UnsupportedHash
            | Self::Ddp1005BadIdentifier
            | Self::Ddp1006LimitExceeded
            | Self::Ddp1007Expired
            | Self::Ddp1008NotRecipient
            | Self::Ddp1009Sealed => "protocol",
            Self::Dds2001StoreFull
            | Self::Dds2002CorruptChunk
            | Self::Dds2003MissingChunk
            | Self::Dds2004CorruptMetadata => "store",
            Self::Dda3001AuthFailed | Self::Dda3002Replay => "auth",
            Self::Ddr4001RouteUnavailable | Self::Ddr4002ReplicationExhausted => "routing",
            Self::Ddi5001UnknownContact => "identity",
            Self::Ddc6001Crypto => "crypto",
            Self::Ddi7001Io => "io",
            Self::Ddx0000Internal => "internal",
        }
    }

    pub fn retryable(self) -> bool {
        matches!(
            self,
            Self::Dds2001StoreFull | Self::Ddr4001RouteUnavailable | Self::Ddi7001Io
        )
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum DdError {
    #[error("{code}: {message}")]
    Coded {
        code: ErrorCode,
        message: String,
        context: Option<String>,
    },
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

impl DdError {
    pub fn protocol(code: ErrorCode, message: impl Into<String>) -> Self {
        Self::Coded {
            code,
            message: message.into(),
            context: None,
        }
    }

    pub fn with_context(mut self, ctx: impl Into<String>) -> Self {
        if let Self::Coded { context, .. } = &mut self {
            *context = Some(ctx.into());
        }
        self
    }

    pub fn code(&self) -> ErrorCode {
        match self {
            Self::Coded { code, .. } => *code,
            Self::Io(_) => ErrorCode::Ddi7001Io,
        }
    }

    pub fn retryable(&self) -> bool {
        self.code().retryable()
    }

    pub fn crypto(msg: impl Into<String>) -> Self {
        Self::protocol(ErrorCode::Ddc6001Crypto, msg)
    }

    pub fn invalid_frame(msg: impl Into<String>) -> Self {
        Self::protocol(ErrorCode::Ddp1001InvalidFrame, msg)
    }
}
