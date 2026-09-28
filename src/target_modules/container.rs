use super::{IntentError, NetworkAttachmentIntent, TargetIdentity};
use crate::evidence::ProtectedValue;
use crate::observation::ResourceRef;
use std::num::{NonZeroU16, NonZeroU32, NonZeroU64};

/// An explicit image reference, with no inferred tag or platform.
pub struct ImageReference(ProtectedValue);

impl ImageReference {
    pub fn new(bytes: Vec<u8>) -> Result<Self, IntentError> {
        let Ok(value) = std::str::from_utf8(&bytes) else {
            return Err(IntentError::InvalidImage);
        };
        if value.is_empty() || value.chars().any(char::is_whitespace) || value.contains('\0') {
            return Err(IntentError::InvalidImage);
        }
        Ok(Self(ProtectedValue::new(bytes)))
    }

    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl std::fmt::Debug for ImageReference {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ImageReference([redacted])")
    }
}

/// An authored assignment, including an explicitly empty value.
pub struct EnvironmentAssignment {
    key: ProtectedValue,
    value: ProtectedValue,
}

impl EnvironmentAssignment {
    pub fn new(key: Vec<u8>, value: Vec<u8>) -> Result<Self, IntentError> {
        if key.is_empty()
            || key.contains(&b'=')
            || key.contains(&0)
            || value.contains(&0)
            || std::str::from_utf8(&key).is_err()
            || std::str::from_utf8(&value).is_err()
        {
            return Err(IntentError::InvalidEnvironment);
        }
        Ok(Self {
            key: ProtectedValue::new(key),
            value: ProtectedValue::new(value),
        })
    }

    #[must_use]
    pub fn key(&self) -> &[u8] {
        self.key.as_bytes()
    }

    #[must_use]
    pub fn value(&self) -> &[u8] {
        self.value.as_bytes()
    }
}

impl std::fmt::Debug for EnvironmentAssignment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("EnvironmentAssignment([redacted])")
    }
}

/// An argument is one Engine exec-form element, never a shell fragment.
pub struct Argument(ProtectedValue);

impl Argument {
    pub fn new(bytes: Vec<u8>) -> Result<Self, IntentError> {
        if bytes.contains(&0) || std::str::from_utf8(&bytes).is_err() {
            return Err(IntentError::InvalidArgument);
        }
        Ok(Self(ProtectedValue::new(bytes)))
    }

    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl std::fmt::Debug for Argument {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Argument([redacted])")
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Protocol {
    Tcp,
    Udp,
}

/// A fixed host port. Runtime-assigned ports are deliberately not inferred.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PortBinding {
    pub host: NonZeroU16,
    pub container: NonZeroU16,
    pub protocol: Protocol,
}

/// A bind path or an explicitly declared named-volume dependency.
pub enum MountSource {
    Bind(ProtectedValue),
    Volume(ResourceRef),
}

impl std::fmt::Debug for MountSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Bind(_) => f.write_str("Bind([redacted])"),
            Self::Volume(reference) => f.debug_tuple("Volume").field(reference).finish(),
        }
    }
}

pub struct Mount {
    source: MountSource,
    target: ProtectedValue,
    read_only: bool,
}

impl std::fmt::Debug for Mount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Mount")
            .field("source", &self.source)
            .field("target", &"[redacted]")
            .field("read_only", &self.read_only)
            .finish()
    }
}

impl Mount {
    pub fn bind(source: Vec<u8>, target: Vec<u8>, read_only: bool) -> Result<Self, IntentError> {
        if !valid_absolute_path(&source) || !valid_absolute_path(&target) {
            return Err(IntentError::InvalidMount);
        }
        Ok(Self {
            source: MountSource::Bind(ProtectedValue::new(source)),
            target: ProtectedValue::new(target),
            read_only,
        })
    }

    pub fn volume(
        source: ResourceRef,
        target: Vec<u8>,
        read_only: bool,
    ) -> Result<Self, IntentError> {
        if !valid_absolute_path(&target) {
            return Err(IntentError::InvalidMount);
        }
        Ok(Self {
            source: MountSource::Volume(source),
            target: ProtectedValue::new(target),
            read_only,
        })
    }

    #[must_use]
    pub const fn source(&self) -> &MountSource {
        &self.source
    }

    #[must_use]
    pub fn target(&self) -> &[u8] {
        self.target.as_bytes()
    }

    #[must_use]
    pub const fn read_only(&self) -> bool {
        self.read_only
    }
}

fn valid_absolute_path(value: &[u8]) -> bool {
    value.starts_with(b"/") && !value.contains(&0) && std::str::from_utf8(value).is_ok()
}

/// Exec-form health check; no shell evaluation is requested.
/// The fields are private so callers cannot bypass duration and command checks.
///
/// ```compile_fail
/// use docker_lens::target::{Argument, Healthcheck};
/// use std::num::{NonZeroU32, NonZeroU64};
/// let _ = Healthcheck {
///     command: vec![Argument::new(b"health".to_vec()).unwrap()],
///     interval_ns: NonZeroU64::new(1).unwrap(),
///     timeout_ns: NonZeroU64::new(1).unwrap(),
///     retries: NonZeroU32::new(1).unwrap(),
/// };
/// ```
#[derive(Debug)]
pub struct Healthcheck {
    command: Vec<Argument>,
    interval_ns: NonZeroU64,
    timeout_ns: NonZeroU64,
    retries: NonZeroU32,
}

impl Healthcheck {
    pub fn new(
        command: Vec<Argument>,
        interval_ns: NonZeroU64,
        timeout_ns: NonZeroU64,
        retries: NonZeroU32,
    ) -> Result<Self, IntentError> {
        if command.is_empty()
            || command[0].bytes().is_empty()
            || !(1_000_000..=i64::MAX as u64).contains(&interval_ns.get())
            || !(1_000_000..=i64::MAX as u64).contains(&timeout_ns.get())
            || retries.get() > i32::MAX as u32
        {
            return Err(IntentError::InvalidHealthcheck);
        }
        Ok(Self {
            command,
            interval_ns,
            timeout_ns,
            retries,
        })
    }

    #[must_use]
    pub fn command(&self) -> &[Argument] {
        &self.command
    }

    #[must_use]
    pub const fn interval_ns(&self) -> NonZeroU64 {
        self.interval_ns
    }

    #[must_use]
    pub const fn timeout_ns(&self) -> NonZeroU64 {
        self.timeout_ns
    }

    #[must_use]
    pub const fn retries(&self) -> NonZeroU32 {
        self.retries
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RestartPolicy {
    No,
    Always,
    UnlessStopped,
    /// Zero means unlimited retries, as in the Engine API.
    OnFailure {
        maximum_retries: u32,
    },
}

/// All settings are caller-authored; source `Config.*` is never promoted here.
#[derive(Debug)]
pub struct ContainerIntent {
    pub reference: ResourceRef,
    pub identity: TargetIdentity,
    pub image: ImageReference,
    pub environment: Vec<EnvironmentAssignment>,
    pub ports: Vec<PortBinding>,
    pub mounts: Vec<Mount>,
    pub networks: Vec<NetworkAttachmentIntent>,
    pub entrypoint: Option<Vec<Argument>>,
    pub command: Option<Vec<Argument>>,
    pub healthcheck: Option<Healthcheck>,
    pub restart: Option<RestartPolicy>,
}
