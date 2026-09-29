use super::{IntentError, NetworkAttachmentIntent, TargetIdentity};
use crate::evidence::ProtectedValue;
use crate::observation::ResourceRef;
use std::net::IpAddr;
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

/// An omitted host address and an explicitly authored address are distinct.
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum PortHostIp {
    Unspecified,
    Address(IpAddr),
}

impl std::fmt::Debug for PortHostIp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PortHostIp([redacted])")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PortHostPort {
    Fixed(NonZeroU16),
    /// An authored request for Engine allocation, not an observed assigned port.
    Ephemeral,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct HostBinding {
    pub host_ip: PortHostIp,
    pub host_port: PortHostPort,
}

impl std::fmt::Debug for HostBinding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("HostBinding([redacted])")
    }
}

/// One exposed container port/protocol, optionally with several host bindings.
pub struct PortPublication {
    pub container: NonZeroU16,
    pub protocol: Protocol,
    bindings: Vec<HostBinding>,
}

impl PortPublication {
    #[must_use]
    pub fn exposed(container: NonZeroU16, protocol: Protocol) -> Self {
        Self {
            container,
            protocol,
            bindings: Vec::new(),
        }
    }

    pub fn published(
        container: NonZeroU16,
        protocol: Protocol,
        bindings: Vec<HostBinding>,
    ) -> Result<Self, IntentError> {
        if bindings.is_empty() {
            return Err(IntentError::InvalidPort);
        }
        Ok(Self {
            container,
            protocol,
            bindings,
        })
    }

    #[must_use]
    pub fn bindings(&self) -> &[HostBinding] {
        &self.bindings
    }
}

impl From<PortBinding> for PortPublication {
    fn from(value: PortBinding) -> Self {
        Self {
            container: value.container,
            protocol: value.protocol,
            bindings: vec![HostBinding {
                host_ip: PortHostIp::Unspecified,
                host_port: PortHostPort::Fixed(value.host),
            }],
        }
    }
}

impl std::fmt::Debug for PortPublication {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PortPublication([redacted])")
    }
}

/// `Inherit` omits the native field; Engine merging determines the effective value.
/// In particular, overriding the entrypoint may reset an image's default command.
/// `Clear` is authored intent, not a guarantee that an empty native array clears
/// an image default. Clearing a command requires an explicit exec entrypoint.
#[derive(Debug, Default)]
pub enum ImageCommand {
    #[default]
    Inherit,
    Clear,
    Exec(Vec<Argument>),
}

/// A bind path or an explicitly declared named-volume dependency.
pub enum MountSource {
    Bind(ProtectedValue),
    Volume(ResourceRef),
    Tmpfs(TmpfsOptions),
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TmpfsOptions {
    pub size_bytes: Option<NonZeroU64>,
    pub mode: Option<u32>,
}

impl std::fmt::Debug for MountSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Bind(_) => f.write_str("Bind([redacted])"),
            Self::Volume(reference) => f.debug_tuple("Volume").field(reference).finish(),
            Self::Tmpfs(_) => f.write_str("Tmpfs([redacted])"),
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

    pub fn tmpfs(
        target: Vec<u8>,
        read_only: bool,
        options: TmpfsOptions,
    ) -> Result<Self, IntentError> {
        if !valid_absolute_path(&target)
            || options.mode.is_some_and(|mode| mode > 0o7777)
            || options
                .size_bytes
                .is_some_and(|size| size.get() > i64::MAX as u64)
        {
            return Err(IntentError::InvalidMount);
        }
        Ok(Self {
            source: MountSource::Tmpfs(options),
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

pub struct ContainerLabel {
    key: ProtectedValue,
    value: ProtectedValue,
}

impl ContainerLabel {
    pub fn new(key: Vec<u8>, value: Vec<u8>) -> Result<Self, IntentError> {
        if key.is_empty() || !valid_text(&key) || !valid_text(&value) {
            return Err(IntentError::InvalidContainerLabel);
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

impl std::fmt::Debug for ContainerLabel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ContainerLabel([redacted])")
    }
}

fn valid_text(value: &[u8]) -> bool {
    !value.contains(&0) && std::str::from_utf8(value).is_ok()
}

pub struct ContainerUser(ProtectedValue);

impl ContainerUser {
    pub fn new(bytes: Vec<u8>) -> Result<Self, IntentError> {
        if bytes.is_empty() || !valid_text(&bytes) {
            return Err(IntentError::InvalidContainerUser);
        }
        Ok(Self(ProtectedValue::new(bytes)))
    }

    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl std::fmt::Debug for ContainerUser {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ContainerUser([redacted])")
    }
}

pub struct WorkingDirectory(ProtectedValue);

impl WorkingDirectory {
    pub fn new(bytes: Vec<u8>) -> Result<Self, IntentError> {
        if !valid_absolute_path(&bytes) {
            return Err(IntentError::InvalidWorkingDirectory);
        }
        Ok(Self(ProtectedValue::new(bytes)))
    }

    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl std::fmt::Debug for WorkingDirectory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("WorkingDirectory([redacted])")
    }
}

pub struct ContainerHostname(ProtectedValue);

impl ContainerHostname {
    pub fn new(bytes: Vec<u8>) -> Result<Self, IntentError> {
        if bytes.is_empty()
            || !valid_text(&bytes)
            || bytes.contains(&b':')
            || bytes.iter().any(u8::is_ascii_whitespace)
        {
            return Err(IntentError::InvalidContainerHostname);
        }
        Ok(Self(ProtectedValue::new(bytes)))
    }

    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl std::fmt::Debug for ContainerHostname {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ContainerHostname([redacted])")
    }
}

/// A protected native token used only in its typed Engine field.
pub struct ContainerToken(ProtectedValue);

impl ContainerToken {
    pub fn new(bytes: Vec<u8>) -> Result<Self, IntentError> {
        if bytes.is_empty() || !valid_text(&bytes) {
            return Err(IntentError::InvalidContainerSetting);
        }
        Ok(Self(ProtectedValue::new(bytes)))
    }

    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl std::fmt::Debug for ContainerToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ContainerToken([redacted])")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemoryLimit {
    Unlimited,
    Bytes(NonZeroU64),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PidsLimit {
    Unlimited,
    Count(NonZeroU64),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UlimitValue {
    Unlimited,
    Value(u64),
}

pub struct Ulimit {
    pub name: ContainerToken,
    pub soft: UlimitValue,
    pub hard: UlimitValue,
}

impl std::fmt::Debug for Ulimit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Ulimit([redacted])")
    }
}

pub struct ExtraHost {
    pub name: ContainerHostname,
    pub address: IpAddr,
}

impl std::fmt::Debug for ExtraHost {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ExtraHost([redacted])")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DevicePermissions {
    pub read: bool,
    pub write: bool,
    pub create: bool,
}

pub struct DeviceMapping {
    pub host_path: WorkingDirectory,
    pub container_path: WorkingDirectory,
    pub permissions: DevicePermissions,
}

/// Closed security options; additional native forms require separate review.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SecurityOption {
    NoNewPrivileges(bool),
}

impl std::fmt::Debug for DeviceMapping {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DeviceMapping([redacted])")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LogDriver {
    JsonFile,
    Local,
    None,
}

pub struct LogConfig {
    pub driver: LogDriver,
    pub options: Vec<ContainerLabel>,
}

impl std::fmt::Debug for LogConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("LogConfig([redacted])")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UserNamespaceMode {
    Host,
}

#[derive(Default)]
pub struct ContainerSettings {
    pub labels: Vec<ContainerLabel>,
    pub user: Option<ContainerUser>,
    pub working_dir: Option<WorkingDirectory>,
    pub hostname: Option<ContainerHostname>,
    pub read_only_rootfs: Option<bool>,
    pub init: Option<bool>,
    pub stop_signal: Option<Argument>,
    pub stop_timeout_seconds: Option<u32>,
    pub memory_limit: Option<MemoryLimit>,
    pub pids_limit: Option<PidsLimit>,
    pub shm_size_bytes: Option<NonZeroU64>,
    pub ulimits: Vec<Ulimit>,
    pub devices: Vec<DeviceMapping>,
    pub cap_add: Vec<ContainerToken>,
    pub cap_drop: Vec<ContainerToken>,
    pub security_options: Vec<SecurityOption>,
    pub sysctls: Vec<ContainerLabel>,
    pub group_add: Vec<ContainerUser>,
    pub dns: Vec<IpAddr>,
    pub extra_hosts: Vec<ExtraHost>,
    pub log_config: Option<LogConfig>,
    pub userns_mode: Option<UserNamespaceMode>,
}

impl std::fmt::Debug for ContainerSettings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ContainerSettings([redacted])")
    }
}

/// Shell text is handed to Engine as one argument; DockerLens never evaluates it.
#[derive(Debug)]
pub enum HealthTest {
    Exec(Vec<Argument>),
    Shell(Argument),
    Disabled,
}

#[derive(Debug)]
pub struct Healthcheck {
    test: HealthTest,
    interval_ns: Option<NonZeroU64>,
    timeout_ns: Option<NonZeroU64>,
    retries: Option<NonZeroU32>,
    start_period_ns: Option<u64>,
    start_interval_ns: Option<u64>,
}

impl Healthcheck {
    pub fn new(
        command: Vec<Argument>,
        interval_ns: NonZeroU64,
        timeout_ns: NonZeroU64,
        retries: NonZeroU32,
    ) -> Result<Self, IntentError> {
        Self::configured(
            HealthTest::Exec(command),
            Some(interval_ns),
            Some(timeout_ns),
            Some(retries),
        )
    }

    pub fn configured(
        test: HealthTest,
        interval_ns: Option<NonZeroU64>,
        timeout_ns: Option<NonZeroU64>,
        retries: Option<NonZeroU32>,
    ) -> Result<Self, IntentError> {
        let valid_test = match &test {
            HealthTest::Exec(command) => !command.is_empty() && !command[0].bytes().is_empty(),
            HealthTest::Shell(command) => !command.bytes().is_empty(),
            HealthTest::Disabled => {
                interval_ns.is_none() && timeout_ns.is_none() && retries.is_none()
            }
        };
        if !valid_test
            || interval_ns
                .is_some_and(|value| !(1_000_000..=i64::MAX as u64).contains(&value.get()))
            || timeout_ns.is_some_and(|value| !(1_000_000..=i64::MAX as u64).contains(&value.get()))
            || retries.is_some_and(|value| value.get() > i32::MAX as u32)
        {
            return Err(IntentError::InvalidHealthcheck);
        }
        Ok(Self {
            test,
            interval_ns,
            timeout_ns,
            retries,
            start_period_ns: None,
            start_interval_ns: None,
        })
    }

    #[must_use]
    pub const fn test(&self) -> &HealthTest {
        &self.test
    }

    pub fn with_start_period(mut self, nanoseconds: u64) -> Result<Self, IntentError> {
        if matches!(self.test, HealthTest::Disabled)
            || (nanoseconds != 0 && nanoseconds < 1_000_000)
            || nanoseconds > i64::MAX as u64
        {
            return Err(IntentError::InvalidHealthcheck);
        }
        self.start_period_ns = Some(nanoseconds);
        Ok(self)
    }

    pub fn with_start_interval(mut self, nanoseconds: u64) -> Result<Self, IntentError> {
        if matches!(self.test, HealthTest::Disabled)
            || (nanoseconds != 0 && nanoseconds < 1_000_000)
            || nanoseconds > i64::MAX as u64
        {
            return Err(IntentError::InvalidHealthcheck);
        }
        self.start_interval_ns = Some(nanoseconds);
        Ok(self)
    }

    #[must_use]
    pub const fn interval_ns(&self) -> Option<NonZeroU64> {
        self.interval_ns
    }

    #[must_use]
    pub const fn timeout_ns(&self) -> Option<NonZeroU64> {
        self.timeout_ns
    }

    #[must_use]
    pub const fn retries(&self) -> Option<NonZeroU32> {
        self.retries
    }

    #[must_use]
    pub const fn start_period_ns(&self) -> Option<u64> {
        self.start_period_ns
    }

    #[must_use]
    pub const fn start_interval_ns(&self) -> Option<u64> {
        self.start_interval_ns
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
    pub ports: Vec<PortPublication>,
    pub mounts: Vec<Mount>,
    pub networks: Vec<NetworkAttachmentIntent>,
    pub entrypoint: ImageCommand,
    pub command: ImageCommand,
    pub healthcheck: Option<Healthcheck>,
    pub restart: Option<RestartPolicy>,
    pub settings: ContainerSettings,
}
