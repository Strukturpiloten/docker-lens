//! Engine facts are observations, not inferred from a requested target version.

use std::collections::HashSet;
use std::num::NonZeroU16;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_OBSERVATION_ID: AtomicU64 = AtomicU64::new(1);

/// Process-local identity for one acquisition. It is not an Engine identifier,
/// persistent fixture key, or proof of daemon contact.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct ObservationId(u64);

impl ObservationId {
    /// Allocate an opaque identity without reusing one within this process.
    pub fn fresh() -> Result<Self, ObservationIdError> {
        NEXT_OBSERVATION_ID
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |next| {
                next.checked_add(1)
            })
            .map(Self)
            .map_err(|_| ObservationIdError::Exhausted)
    }
}

impl std::fmt::Debug for ObservationId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ObservationId([opaque])")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObservationIdError {
    Exhausted,
}

/// Exact Docker Engine API version; it is independent of the Engine release.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Ord, PartialOrd)]
pub struct ApiVersion {
    pub major: NonZeroU16,
    pub minor: u16,
}

impl ApiVersion {
    /// Construct a two-component API version without assuming a supported range.
    #[must_use]
    pub const fn new(major: NonZeroU16, minor: u16) -> Self {
        Self { major, minor }
    }
}

/// Engine release text is kept separate from API negotiation.
/// The value is untrusted and therefore intentionally omitted from `Debug`.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct EngineRelease(String);

impl EngineRelease {
    /// Retain the exact reported release, if nonempty.
    pub fn new(value: String) -> Option<Self> {
        (!value.is_empty()).then_some(Self(value))
    }

    /// Read the release for explicit, trusted display decisions.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for EngineRelease {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("EngineRelease([redacted])")
    }
}

/// Do not infer privilege mode from the client's UID or socket path.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum DaemonMode {
    Rootful,
    Rootless,
    Unknown,
}

/// A capability must be observed or independently validated for its exact daemon.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CapabilityState {
    Available,
    Unavailable,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Capability {
    StandaloneContainer,
    BindMount,
    /// Configured shared bind-relabel retention only; no SELinux effect claim.
    BindRelabelShared,
    /// Configured private bind-relabel retention only; no SELinux effect claim.
    BindRelabelPrivate,
    TmpfsMount,
    NamedVolume,
    VolumeLabels,
    VolumeExternalReference,
    BridgeNetwork,
    NetworkExternalReference,
    /// External network internal-flag requirement, not created bridge behavior.
    NetworkExternalInternalExpectation,
    NetworkInternal,
    NetworkIpv6,
    NetworkIpam,
    NetworkIpamDriver,
    NetworkOptions,
    NetworkLabels,
    NetworkAliases,
    NetworkStaticAddress,
    NetworkMultipleAttachment,
    HostNetwork,
    PortPublish,
    PortExposeOnly,
    PortHostIpv4,
    PortHostIpv6,
    PortMultipleBindings,
    PortEphemeral,
    UserNamespace,
    EnvironmentAssignment,
    Command,
    CommandClear,
    Entrypoint,
    EntrypointClear,
    Healthcheck,
    HealthShell,
    HealthDisabled,
    HealthStartPeriod,
    HealthStartInterval,
    RestartPolicy,
    ContainerLabels,
    ContainerUser,
    ContainerWorkdir,
    ContainerHostname,
    ReadOnlyRootfs,
    ContainerInit,
    StopSignal,
    StopTimeout,
    MemoryLimit,
    PidsLimit,
    ShmSize,
    Ulimits,
    UlimitNofile,
    DeviceMappings,
    LinuxCapabilities,
    CapAddNetBindService,
    CapDropSysAdmin,
    SecurityOptions,
    Sysctls,
    SysctlIpv4Forward,
    SupplementaryGroups,
    DnsServers,
    ExtraHosts,
    LogConfig,
    LogOptionMaxSize,
}

/// The exact daemon scope of a capability claim.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapabilityScope {
    pub observation_id: ObservationId,
    pub release: EngineRelease,
    pub api_version: ApiVersion,
    pub mode: DaemonMode,
}

/// Claims carry provenance and exact scope. `Unknown` is never positive.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapabilityFact {
    pub capability: Capability,
    pub state: CapabilityState,
    pub provenance: FactProvenance,
    pub scope: Option<CapabilityScope>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FactProvenance {
    DaemonResponse,
    NativeConformance,
    Unknown,
}

/// Facts have no default values that could be mistaken for confirmed support.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DaemonFacts {
    pub observation_id: ObservationId,
    pub release: Option<EngineRelease>,
    pub api_version: Option<ApiVersion>,
    pub minimum_api_version: Option<ApiVersion>,
    pub mode: DaemonMode,
    pub capabilities: Vec<CapabilityFact>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CapabilityError {
    MissingDaemonIdentity,
    InvalidApiRange,
    DuplicateCapability,
    InvalidProvenance,
    ScopeMismatch,
    UnknownTargetMode,
    InvalidTargetApiRange,
    InvalidPackageRevision,
    EmptyEvidenceKey,
    InvalidEvidenceRunUrl,
    InvalidEvidenceCandidateSha,
    InvalidEvidenceArtifactName,
    EvidenceLaneMismatch,
    EvidenceKeyMismatch,
    IncompleteEvidenceShapes,
    DuplicateEvidenceShape,
    EvidenceShapeMismatch,
    DuplicateProfile,
    ProfileNotReviewed,
}

/// Exact Debian package revision, including any epoch and distribution suffix.
/// It is not the Engine release reported by `/version`.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct DebianPackageRevision(String);

impl DebianPackageRevision {
    pub fn new(value: String) -> Result<Self, CapabilityError> {
        if value.is_empty()
            || value
                .bytes()
                .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
        {
            return Err(CapabilityError::InvalidPackageRevision);
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for DebianPackageRevision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DebianPackageRevision([redacted])")
    }
}

/// Package provenance is part of the exact target, never inferred from Engine release text.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum EngineBuild {
    Upstream,
    DebianPackage(DebianPackageRevision),
}

/// SHA-256 of an independently reviewed, immutable native capability record.
/// A digest alone does not establish that such evidence was actually reviewed.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct CapabilityEvidenceKey([u8; 32]);

impl CapabilityEvidenceKey {
    pub fn sha256(digest: [u8; 32]) -> Result<Self, CapabilityError> {
        (digest != [0; 32])
            .then_some(Self(digest))
            .ok_or(CapabilityError::EmptyEvidenceKey)
    }

    /// Explicitly retrieve the digest for evidence lookup or audit records.
    #[must_use]
    pub const fn as_sha256_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Debug for CapabilityEvidenceKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CapabilityEvidenceKey([opaque sha256])")
    }
}

/// The native matrix lane that exercised one exact build and daemon mode.
/// Lane names match the reviewed native workflow; they are not capability claims.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeEvidenceLane {
    Debian11Rootful,
    Debian11Rootless,
    UpstreamRootful,
    UpstreamRootless,
}

impl NativeEvidenceLane {
    /// Artifact name emitted by the reviewed native workflow for this lane.
    #[must_use]
    pub const fn artifact_name(self) -> &'static str {
        match self {
            Self::Debian11Rootful => "dockerlens-native-debian11-rootful",
            Self::Debian11Rootless => "dockerlens-native-debian11-rootless",
            Self::UpstreamRootful => "dockerlens-native-upstream-rootful",
            Self::UpstreamRootless => "dockerlens-native-upstream-rootless",
        }
    }

    fn matches_identity(self, identity: &TargetProfileIdentity) -> bool {
        let debian11 = matches!(identity.build(), EngineBuild::DebianPackage(revision)
            if revision.as_str() == "20.10.5+dfsg1-1+deb11u2")
            && identity.release().as_str() == "20.10.5+dfsg1"
            && identity.advertised_api_version()
                == ApiVersion::new(NonZeroU16::new(1).unwrap(), 41)
            && identity.acquisition_api_version()
                == ApiVersion::new(NonZeroU16::new(1).unwrap(), 41)
            && identity.rendering_api_version() == ApiVersion::new(NonZeroU16::new(1).unwrap(), 41);
        identity.release().as_str() == "29.8.1"
            && matches!(
                (self, identity.build(), identity.mode()),
                (
                    Self::UpstreamRootful,
                    EngineBuild::Upstream,
                    DaemonMode::Rootful
                ) | (
                    Self::UpstreamRootless,
                    EngineBuild::Upstream,
                    DaemonMode::Rootless
                )
            )
            || debian11
                && matches!(
                    (self, identity.mode()),
                    (Self::Debian11Rootful, DaemonMode::Rootful)
                        | (Self::Debian11Rootless, DaemonMode::Rootless)
                )
    }
}

/// Locator for an immutable native capability record. Syntactic validation
/// does not establish that the run passed, the artifact exists, or review occurred.
/// Only a crate-owned catalog entry can authorize planning.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeEvidenceReference {
    lane: NativeEvidenceLane,
    run_url: String,
    candidate_sha: String,
    artifact_name: String,
    manifest_key: CapabilityEvidenceKey,
    record_key: CapabilityEvidenceKey,
}

impl NativeEvidenceReference {
    pub fn new(
        lane: NativeEvidenceLane,
        run_url: String,
        candidate_sha: String,
        artifact_name: String,
        manifest_key: CapabilityEvidenceKey,
        record_key: CapabilityEvidenceKey,
    ) -> Result<Self, CapabilityError> {
        let Some(run_path) =
            run_url.strip_prefix("https://github.com/Strukturpiloten/docker-lens/actions/runs/")
        else {
            return Err(CapabilityError::InvalidEvidenceRunUrl);
        };
        let Some((run_id, attempt)) = run_path.split_once("/attempts/") else {
            return Err(CapabilityError::InvalidEvidenceRunUrl);
        };
        if ![run_id, attempt].iter().all(|part| {
            part.as_bytes()
                .first()
                .is_some_and(|byte| (b'1'..=b'9').contains(byte))
                && part.bytes().all(|byte| byte.is_ascii_digit())
        }) {
            return Err(CapabilityError::InvalidEvidenceRunUrl);
        }
        if candidate_sha.len() != 40
            || !candidate_sha
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(CapabilityError::InvalidEvidenceCandidateSha);
        }
        if artifact_name != lane.artifact_name() {
            return Err(CapabilityError::InvalidEvidenceArtifactName);
        }
        Ok(Self {
            lane,
            run_url,
            candidate_sha,
            artifact_name,
            manifest_key,
            record_key,
        })
    }

    #[must_use]
    pub const fn lane(&self) -> NativeEvidenceLane {
        self.lane
    }

    #[must_use]
    pub fn run_url(&self) -> &str {
        &self.run_url
    }

    #[must_use]
    pub fn candidate_sha(&self) -> &str {
        &self.candidate_sha
    }

    /// Name of the immutable per-lane artifact uploaded by the native run.
    #[must_use]
    pub fn artifact_name(&self) -> &str {
        &self.artifact_name
    }

    #[must_use]
    pub fn record_key(&self) -> &CapabilityEvidenceKey {
        &self.record_key
    }

    /// Digest of the native lane's sanitized manifest, before review metadata
    /// was added to the checked-in record envelope.
    #[must_use]
    pub fn manifest_key(&self) -> &CapabilityEvidenceKey {
        &self.manifest_key
    }
}

/// Version dimensions for one exact offline target. Acquisition and rendering
/// may use different API versions, each independently reviewed for this build.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct TargetProfileIdentity {
    build: EngineBuild,
    release: EngineRelease,
    advertised_api_version: ApiVersion,
    acquisition_api_version: ApiVersion,
    rendering_api_version: ApiVersion,
    mode: DaemonMode,
}

impl TargetProfileIdentity {
    pub fn new(
        build: EngineBuild,
        release: EngineRelease,
        advertised_api_version: ApiVersion,
        acquisition_api_version: ApiVersion,
        rendering_api_version: ApiVersion,
        mode: DaemonMode,
    ) -> Result<Self, CapabilityError> {
        if mode == DaemonMode::Unknown {
            return Err(CapabilityError::UnknownTargetMode);
        }
        let minimum = ApiVersion::new(NonZeroU16::new(1).expect("nonzero"), 41);
        if advertised_api_version.major.get() != 1
            || acquisition_api_version < minimum
            || rendering_api_version < minimum
            || acquisition_api_version > advertised_api_version
            || rendering_api_version > advertised_api_version
        {
            return Err(CapabilityError::InvalidTargetApiRange);
        }
        Ok(Self {
            build,
            release,
            advertised_api_version,
            acquisition_api_version,
            rendering_api_version,
            mode,
        })
    }

    #[must_use]
    pub const fn build(&self) -> &EngineBuild {
        &self.build
    }
    #[must_use]
    pub fn release(&self) -> &EngineRelease {
        &self.release
    }
    #[must_use]
    pub const fn advertised_api_version(&self) -> ApiVersion {
        self.advertised_api_version
    }
    #[must_use]
    pub const fn acquisition_api_version(&self) -> ApiVersion {
        self.acquisition_api_version
    }
    #[must_use]
    pub const fn rendering_api_version(&self) -> ApiVersion {
        self.rendering_api_version
    }
    #[must_use]
    pub const fn mode(&self) -> DaemonMode {
        self.mode
    }
}

/// Candidate offline target, including an immutable evidence key. It becomes
/// usable only after exact resolution in the reviewed catalog, and is never a
/// live daemon observation.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct TargetProfile {
    identity: TargetProfileIdentity,
    evidence_key: CapabilityEvidenceKey,
}

impl TargetProfile {
    #[must_use]
    pub fn new(identity: TargetProfileIdentity, evidence_key: CapabilityEvidenceKey) -> Self {
        Self {
            identity,
            evidence_key,
        }
    }

    #[must_use]
    pub const fn identity(&self) -> &TargetProfileIdentity {
        &self.identity
    }

    #[must_use]
    pub fn release(&self) -> &EngineRelease {
        self.identity.release()
    }
    #[must_use]
    pub const fn rendering_api_version(&self) -> ApiVersion {
        self.identity.rendering_api_version()
    }
    #[must_use]
    pub const fn mode(&self) -> DaemonMode {
        self.identity.mode()
    }
    #[must_use]
    pub fn evidence_key(&self) -> &CapabilityEvidenceKey {
        &self.evidence_key
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TargetCapabilityFact {
    pub capability: Capability,
    pub state: CapabilityState,
}

/// Closed renderer branches that a positive catalog fact must cover. Native
/// review supplies the evidence; this list only prevents partial admission.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) enum NativeCapabilityShape {
    StandaloneCreate,
    NamedVolumeCreate,
    VolumeCreateLabels,
    NamedVolumeMountReadWrite,
    NamedVolumeMountReadOnly,
    ExternalVolumeReference,
    BridgeNetworkCreate,
    BridgeNetworkAttach,
    ExternalNetworkReference,
    ExternalNetworkInternalFalse,
    ExternalNetworkInternalTrue,
    InternalBridgeNetworkCreate,
    Ipv6BridgeNetworkCreate,
    NetworkIpamV4,
    NetworkIpamV6,
    NetworkIpamGateway,
    NetworkIpamRange,
    NetworkIpamAuxiliary,
    NetworkIpamDefaultDriver,
    NetworkBridgeMtu,
    NetworkBridgeIcc,
    NetworkBridgeIccDisabled,
    NetworkBridgeMasquerade,
    NetworkBridgeMasqueradeEnabled,
    NetworkBridgeHostBindingIp,
    NetworkCreateLabels,
    NetworkPrimaryAliases,
    NetworkSecondaryAliases,
    NetworkStaticIpv4,
    NetworkStaticIpv6,
    NetworkSecondaryConnect,
    FixedTcpPort,
    FixedUdpPort,
    ExposedOnlyPort,
    FixedIpv4HostPort,
    EphemeralIpv4HostPort,
    FixedIpv6HostPort,
    EphemeralIpv6HostPort,
    MultipleFixedPortBindings,
    MultipleEphemeralPortBindings,
    EphemeralHostPort,
    BindMountReadWrite,
    BindMountReadOnly,
    BindMountSharedRelabelReadWrite,
    BindMountSharedRelabelReadOnly,
    BindMountPrivateRelabelReadWrite,
    BindMountPrivateRelabelReadOnly,
    TmpfsMountReadWrite,
    TmpfsMountReadOnly,
    TmpfsMountOptions,
    EnvironmentValue,
    EnvironmentEmptyValue,
    ExecCommand,
    ClearCommand,
    ExecEntrypoint,
    ClearEntrypoint,
    ExecHealthcheck,
    ShellHealthcheck,
    DisabledHealthcheck,
    HealthStartPeriodZero,
    HealthStartPeriodPositive,
    HealthStartIntervalZero,
    HealthStartIntervalPositive,
    ContainerCreateLabels,
    ContainerUser,
    ContainerWorkdir,
    ContainerHostname,
    ReadOnlyRootfsTrue,
    ReadOnlyRootfsFalse,
    ContainerInitTrue,
    ContainerInitFalse,
    StopSignal,
    StopTimeoutZero,
    StopTimeoutPositive,
    MemoryBytes,
    MemoryUnlimited,
    PidsCount,
    PidsUnlimited,
    ShmSize,
    UlimitsFinite,
    UlimitsUnlimited,
    UlimitNofile,
    DeviceMappings,
    LinuxCapAdd,
    LinuxCapDrop,
    CapAddNetBindService,
    CapDropSysAdmin,
    NoNewPrivilegesEnabled,
    NoNewPrivilegesDisabled,
    Sysctls,
    SysctlIpv4Forward,
    SupplementaryGroups,
    DnsIpv4,
    DnsIpv6,
    ExtraHostsIpv4,
    ExtraHostsIpv6,
    LogJsonFile,
    LogLocal,
    LogNone,
    LogOptions,
    LogOptionMaxSize,
    RestartNo,
    RestartAlways,
    RestartUnlessStopped,
    RestartOnFailureUnlimited,
    RestartOnFailureLimited,
}

impl NativeCapabilityShape {
    fn capability(self) -> Capability {
        match self {
            Self::StandaloneCreate => Capability::StandaloneContainer,
            Self::NamedVolumeCreate
            | Self::NamedVolumeMountReadWrite
            | Self::NamedVolumeMountReadOnly => Capability::NamedVolume,
            Self::VolumeCreateLabels => Capability::VolumeLabels,
            Self::ExternalVolumeReference => Capability::VolumeExternalReference,
            Self::BridgeNetworkCreate | Self::BridgeNetworkAttach => Capability::BridgeNetwork,
            Self::ExternalNetworkReference => Capability::NetworkExternalReference,
            Self::ExternalNetworkInternalFalse | Self::ExternalNetworkInternalTrue => {
                Capability::NetworkExternalInternalExpectation
            }
            Self::InternalBridgeNetworkCreate => Capability::NetworkInternal,
            Self::Ipv6BridgeNetworkCreate => Capability::NetworkIpv6,
            Self::NetworkIpamV4
            | Self::NetworkIpamV6
            | Self::NetworkIpamGateway
            | Self::NetworkIpamRange
            | Self::NetworkIpamAuxiliary => Capability::NetworkIpam,
            Self::NetworkIpamDefaultDriver => Capability::NetworkIpamDriver,
            Self::NetworkBridgeMtu
            | Self::NetworkBridgeIcc
            | Self::NetworkBridgeIccDisabled
            | Self::NetworkBridgeMasquerade
            | Self::NetworkBridgeMasqueradeEnabled
            | Self::NetworkBridgeHostBindingIp => Capability::NetworkOptions,
            Self::NetworkCreateLabels => Capability::NetworkLabels,
            Self::NetworkPrimaryAliases | Self::NetworkSecondaryAliases => {
                Capability::NetworkAliases
            }
            Self::NetworkStaticIpv4 | Self::NetworkStaticIpv6 => Capability::NetworkStaticAddress,
            Self::NetworkSecondaryConnect => Capability::NetworkMultipleAttachment,
            Self::FixedTcpPort | Self::FixedUdpPort => Capability::PortPublish,
            Self::ExposedOnlyPort => Capability::PortExposeOnly,
            Self::FixedIpv4HostPort | Self::EphemeralIpv4HostPort => Capability::PortHostIpv4,
            Self::FixedIpv6HostPort | Self::EphemeralIpv6HostPort => Capability::PortHostIpv6,
            Self::MultipleFixedPortBindings | Self::MultipleEphemeralPortBindings => {
                Capability::PortMultipleBindings
            }
            Self::EphemeralHostPort => Capability::PortEphemeral,
            Self::BindMountReadWrite | Self::BindMountReadOnly => Capability::BindMount,
            Self::BindMountSharedRelabelReadWrite | Self::BindMountSharedRelabelReadOnly => {
                Capability::BindRelabelShared
            }
            Self::BindMountPrivateRelabelReadWrite | Self::BindMountPrivateRelabelReadOnly => {
                Capability::BindRelabelPrivate
            }
            Self::TmpfsMountReadWrite | Self::TmpfsMountReadOnly | Self::TmpfsMountOptions => {
                Capability::TmpfsMount
            }
            Self::EnvironmentValue | Self::EnvironmentEmptyValue => {
                Capability::EnvironmentAssignment
            }
            Self::ExecCommand => Capability::Command,
            Self::ClearCommand => Capability::CommandClear,
            Self::ExecEntrypoint => Capability::Entrypoint,
            Self::ClearEntrypoint => Capability::EntrypointClear,
            Self::ExecHealthcheck => Capability::Healthcheck,
            Self::ShellHealthcheck => Capability::HealthShell,
            Self::DisabledHealthcheck => Capability::HealthDisabled,
            Self::HealthStartPeriodZero | Self::HealthStartPeriodPositive => {
                Capability::HealthStartPeriod
            }
            Self::HealthStartIntervalZero | Self::HealthStartIntervalPositive => {
                Capability::HealthStartInterval
            }
            Self::ContainerCreateLabels => Capability::ContainerLabels,
            Self::ContainerUser => Capability::ContainerUser,
            Self::ContainerWorkdir => Capability::ContainerWorkdir,
            Self::ContainerHostname => Capability::ContainerHostname,
            Self::ReadOnlyRootfsTrue | Self::ReadOnlyRootfsFalse => Capability::ReadOnlyRootfs,
            Self::ContainerInitTrue | Self::ContainerInitFalse => Capability::ContainerInit,
            Self::StopSignal => Capability::StopSignal,
            Self::StopTimeoutZero | Self::StopTimeoutPositive => Capability::StopTimeout,
            Self::MemoryBytes | Self::MemoryUnlimited => Capability::MemoryLimit,
            Self::PidsCount | Self::PidsUnlimited => Capability::PidsLimit,
            Self::ShmSize => Capability::ShmSize,
            Self::UlimitsFinite | Self::UlimitsUnlimited => Capability::Ulimits,
            Self::UlimitNofile => Capability::UlimitNofile,
            Self::DeviceMappings => Capability::DeviceMappings,
            Self::LinuxCapAdd | Self::LinuxCapDrop => Capability::LinuxCapabilities,
            Self::CapAddNetBindService => Capability::CapAddNetBindService,
            Self::CapDropSysAdmin => Capability::CapDropSysAdmin,
            Self::NoNewPrivilegesEnabled | Self::NoNewPrivilegesDisabled => {
                Capability::SecurityOptions
            }
            Self::Sysctls => Capability::Sysctls,
            Self::SysctlIpv4Forward => Capability::SysctlIpv4Forward,
            Self::SupplementaryGroups => Capability::SupplementaryGroups,
            Self::DnsIpv4 | Self::DnsIpv6 => Capability::DnsServers,
            Self::ExtraHostsIpv4 | Self::ExtraHostsIpv6 => Capability::ExtraHosts,
            Self::LogJsonFile | Self::LogLocal | Self::LogNone | Self::LogOptions => {
                Capability::LogConfig
            }
            Self::LogOptionMaxSize => Capability::LogOptionMaxSize,
            Self::RestartNo
            | Self::RestartAlways
            | Self::RestartUnlessStopped
            | Self::RestartOnFailureUnlimited
            | Self::RestartOnFailureLimited => Capability::RestartPolicy,
        }
    }

    pub(crate) fn required_for(capability: Capability) -> Option<&'static [Self]> {
        match capability {
            Capability::StandaloneContainer => Some(&[Self::StandaloneCreate]),
            Capability::NamedVolume => Some(&[
                Self::NamedVolumeCreate,
                Self::NamedVolumeMountReadWrite,
                Self::NamedVolumeMountReadOnly,
            ]),
            Capability::VolumeLabels => Some(&[Self::VolumeCreateLabels]),
            Capability::VolumeExternalReference => Some(&[Self::ExternalVolumeReference]),
            Capability::BridgeNetwork => {
                Some(&[Self::BridgeNetworkCreate, Self::BridgeNetworkAttach])
            }
            Capability::NetworkExternalReference => Some(&[Self::ExternalNetworkReference]),
            Capability::NetworkExternalInternalExpectation => Some(&[
                Self::ExternalNetworkInternalFalse,
                Self::ExternalNetworkInternalTrue,
            ]),
            Capability::NetworkInternal => Some(&[Self::InternalBridgeNetworkCreate]),
            Capability::NetworkIpv6 => Some(&[Self::Ipv6BridgeNetworkCreate]),
            Capability::NetworkIpam => Some(&[
                Self::NetworkIpamV4,
                Self::NetworkIpamV6,
                Self::NetworkIpamGateway,
                Self::NetworkIpamRange,
                Self::NetworkIpamAuxiliary,
            ]),
            Capability::NetworkIpamDriver => Some(&[Self::NetworkIpamDefaultDriver]),
            Capability::NetworkOptions => Some(&[
                Self::NetworkBridgeMtu,
                Self::NetworkBridgeIcc,
                Self::NetworkBridgeIccDisabled,
                Self::NetworkBridgeMasquerade,
                Self::NetworkBridgeMasqueradeEnabled,
                Self::NetworkBridgeHostBindingIp,
            ]),
            Capability::NetworkLabels => Some(&[Self::NetworkCreateLabels]),
            Capability::NetworkAliases => {
                Some(&[Self::NetworkPrimaryAliases, Self::NetworkSecondaryAliases])
            }
            Capability::NetworkStaticAddress => {
                Some(&[Self::NetworkStaticIpv4, Self::NetworkStaticIpv6])
            }
            Capability::NetworkMultipleAttachment => Some(&[Self::NetworkSecondaryConnect]),
            Capability::PortPublish => Some(&[Self::FixedTcpPort, Self::FixedUdpPort]),
            Capability::PortExposeOnly => Some(&[Self::ExposedOnlyPort]),
            Capability::PortHostIpv4 => {
                Some(&[Self::FixedIpv4HostPort, Self::EphemeralIpv4HostPort])
            }
            Capability::PortHostIpv6 => {
                Some(&[Self::FixedIpv6HostPort, Self::EphemeralIpv6HostPort])
            }
            Capability::PortMultipleBindings => Some(&[
                Self::MultipleFixedPortBindings,
                Self::MultipleEphemeralPortBindings,
            ]),
            Capability::PortEphemeral => Some(&[Self::EphemeralHostPort]),
            Capability::BindMount => Some(&[Self::BindMountReadWrite, Self::BindMountReadOnly]),
            Capability::BindRelabelShared => Some(&[
                Self::BindMountSharedRelabelReadWrite,
                Self::BindMountSharedRelabelReadOnly,
            ]),
            Capability::BindRelabelPrivate => Some(&[
                Self::BindMountPrivateRelabelReadWrite,
                Self::BindMountPrivateRelabelReadOnly,
            ]),
            Capability::TmpfsMount => Some(&[
                Self::TmpfsMountReadWrite,
                Self::TmpfsMountReadOnly,
                Self::TmpfsMountOptions,
            ]),
            Capability::EnvironmentAssignment => {
                Some(&[Self::EnvironmentValue, Self::EnvironmentEmptyValue])
            }
            Capability::Command => Some(&[Self::ExecCommand]),
            Capability::CommandClear => Some(&[Self::ClearCommand]),
            Capability::Entrypoint => Some(&[Self::ExecEntrypoint]),
            Capability::EntrypointClear => Some(&[Self::ClearEntrypoint]),
            Capability::Healthcheck => Some(&[Self::ExecHealthcheck]),
            Capability::HealthShell => Some(&[Self::ShellHealthcheck]),
            Capability::HealthDisabled => Some(&[Self::DisabledHealthcheck]),
            Capability::HealthStartPeriod => {
                Some(&[Self::HealthStartPeriodZero, Self::HealthStartPeriodPositive])
            }
            Capability::HealthStartInterval => Some(&[
                Self::HealthStartIntervalZero,
                Self::HealthStartIntervalPositive,
            ]),
            Capability::ContainerLabels => Some(&[Self::ContainerCreateLabels]),
            Capability::ContainerUser => Some(&[Self::ContainerUser]),
            Capability::ContainerWorkdir => Some(&[Self::ContainerWorkdir]),
            Capability::ContainerHostname => Some(&[Self::ContainerHostname]),
            Capability::ReadOnlyRootfs => {
                Some(&[Self::ReadOnlyRootfsTrue, Self::ReadOnlyRootfsFalse])
            }
            Capability::ContainerInit => Some(&[Self::ContainerInitTrue, Self::ContainerInitFalse]),
            Capability::StopSignal => Some(&[Self::StopSignal]),
            Capability::StopTimeout => Some(&[Self::StopTimeoutZero, Self::StopTimeoutPositive]),
            Capability::MemoryLimit => Some(&[Self::MemoryBytes, Self::MemoryUnlimited]),
            Capability::PidsLimit => Some(&[Self::PidsCount, Self::PidsUnlimited]),
            Capability::ShmSize => Some(&[Self::ShmSize]),
            Capability::Ulimits => Some(&[Self::UlimitsFinite, Self::UlimitsUnlimited]),
            Capability::UlimitNofile => Some(&[Self::UlimitNofile]),
            Capability::DeviceMappings => Some(&[Self::DeviceMappings]),
            Capability::LinuxCapabilities => Some(&[Self::LinuxCapAdd, Self::LinuxCapDrop]),
            Capability::CapAddNetBindService => Some(&[Self::CapAddNetBindService]),
            Capability::CapDropSysAdmin => Some(&[Self::CapDropSysAdmin]),
            Capability::SecurityOptions => {
                Some(&[Self::NoNewPrivilegesEnabled, Self::NoNewPrivilegesDisabled])
            }
            Capability::Sysctls => Some(&[Self::Sysctls]),
            Capability::SysctlIpv4Forward => Some(&[Self::SysctlIpv4Forward]),
            Capability::SupplementaryGroups => Some(&[Self::SupplementaryGroups]),
            Capability::DnsServers => Some(&[Self::DnsIpv4, Self::DnsIpv6]),
            Capability::ExtraHosts => Some(&[Self::ExtraHostsIpv4, Self::ExtraHostsIpv6]),
            Capability::LogConfig => Some(&[
                Self::LogJsonFile,
                Self::LogLocal,
                Self::LogNone,
                Self::LogOptions,
            ]),
            Capability::LogOptionMaxSize => Some(&[Self::LogOptionMaxSize]),
            Capability::RestartPolicy => Some(&[
                Self::RestartNo,
                Self::RestartAlways,
                Self::RestartUnlessStopped,
                Self::RestartOnFailureUnlimited,
                Self::RestartOnFailureLimited,
            ]),
            Capability::HostNetwork | Capability::UserNamespace => None,
        }
    }
}

/// Internal reviewed-catalog entry bound to immutable native evidence.
pub(crate) struct TargetCapabilityRecord {
    pub profile: TargetProfile,
    pub evidence: NativeEvidenceReference,
    pub capabilities: Vec<TargetCapabilityFact>,
    pub admitted_shapes: Vec<NativeCapabilityShape>,
}

pub struct TargetCapabilityCatalog {
    records: Vec<TargetCapabilityRecord>,
}

impl TargetCapabilityCatalog {
    /// Only the four exact profiles backed by crate-owned reviewed records.
    #[must_use]
    pub fn reviewed() -> Self {
        Self::from_records(crate::reviewed_catalog::records())
            .expect("checked-in reviewed records satisfy capability admission")
    }

    /// Discover exact reviewed profiles and their immutable evidence keys.
    pub fn profiles(&self) -> impl ExactSizeIterator<Item = &TargetProfile> {
        self.records.iter().map(|record| &record.profile)
    }

    /// Private admission gate for records compiled into the reviewed catalog.
    /// A nonempty production call requires independently reviewed native evidence.
    fn from_records(records: Vec<TargetCapabilityRecord>) -> Result<Self, CapabilityError> {
        let mut profiles = HashSet::new();
        for record in &records {
            if !profiles.insert(record.profile.identity()) {
                return Err(CapabilityError::DuplicateProfile);
            }
            if !record
                .evidence
                .lane
                .matches_identity(record.profile.identity())
            {
                return Err(CapabilityError::EvidenceLaneMismatch);
            }
            if record.evidence.record_key != *record.profile.evidence_key() {
                return Err(CapabilityError::EvidenceKeyMismatch);
            }
            let mut capabilities = HashSet::new();
            if !record
                .capabilities
                .iter()
                .all(|fact| capabilities.insert(fact.capability))
            {
                return Err(CapabilityError::DuplicateCapability);
            }
            let available: HashSet<_> = record
                .capabilities
                .iter()
                .filter(|fact| fact.state == CapabilityState::Available)
                .map(|fact| fact.capability)
                .collect();
            let mut shapes = HashSet::new();
            for shape in &record.admitted_shapes {
                if !shapes.insert(*shape) {
                    return Err(CapabilityError::DuplicateEvidenceShape);
                }
                if !available.contains(&shape.capability()) {
                    return Err(CapabilityError::EvidenceShapeMismatch);
                }
            }
            for capability in available {
                let Some(required) = NativeCapabilityShape::required_for(capability) else {
                    return Err(CapabilityError::IncompleteEvidenceShapes);
                };
                if !required.iter().all(|shape| shapes.contains(shape)) {
                    return Err(CapabilityError::IncompleteEvidenceShapes);
                }
            }
        }
        Ok(Self { records })
    }

    /// Only crate tests may fabricate records to exercise matching rules.
    #[cfg(test)]
    pub(crate) fn from_test_records(
        records: Vec<TargetCapabilityRecord>,
    ) -> Result<Self, CapabilityError> {
        Self::from_records(records)
    }

    pub fn resolve(
        &self,
        profile: &TargetProfile,
    ) -> Result<TargetCapabilities<'_>, CapabilityError> {
        self.records
            .iter()
            .find(|record| &record.profile == profile)
            .map(|record| TargetCapabilities { record })
            .ok_or(CapabilityError::ProfileNotReviewed)
    }

    /// Resolve exact build, release, three API dimensions, and mode. The
    /// returned capabilities expose the matched immutable evidence key.
    pub fn resolve_identity(
        &self,
        identity: &TargetProfileIdentity,
    ) -> Result<TargetCapabilities<'_>, CapabilityError> {
        self.records
            .iter()
            .find(|record| record.profile.identity() == identity)
            .map(|record| TargetCapabilities { record })
            .ok_or(CapabilityError::ProfileNotReviewed)
    }
}

/// Capabilities resolved from an exact reviewed catalog entry, not live facts.
pub struct TargetCapabilities<'a> {
    record: &'a TargetCapabilityRecord,
}

impl TargetCapabilities<'_> {
    #[must_use]
    pub fn profile(&self) -> &TargetProfile {
        &self.record.profile
    }

    #[must_use]
    pub fn evidence_key(&self) -> &CapabilityEvidenceKey {
        self.record.profile.evidence_key()
    }

    /// Source run and candidate of the admitted native record.
    #[must_use]
    pub fn evidence(&self) -> &NativeEvidenceReference {
        &self.record.evidence
    }

    #[must_use]
    pub fn supports(&self, capability: Capability) -> bool {
        self.record
            .capabilities
            .iter()
            .any(|fact| fact.capability == capability && fact.state == CapabilityState::Available)
    }
}

/// Internally validated observation claims. External callers cannot construct
/// this planning source by labeling their own facts as native conformance.
/// Native integration may expose a reviewed path after independent evidence.
///
/// ```compile_fail
/// use docker_lens::version::{DaemonFacts, ValidatedCapabilities};
/// fn fabricate(facts: &DaemonFacts) {
///     let _ = ValidatedCapabilities::new(facts);
/// }
/// ```
pub struct ValidatedCapabilities<'a> {
    facts: &'a DaemonFacts,
}

impl<'a> ValidatedCapabilities<'a> {
    #[cfg(test)]
    pub(crate) fn new(facts: &'a DaemonFacts) -> Result<Self, CapabilityError> {
        let (Some(release), Some(api_version)) = (&facts.release, facts.api_version) else {
            return Err(CapabilityError::MissingDaemonIdentity);
        };
        if facts.mode == DaemonMode::Unknown {
            return Err(CapabilityError::MissingDaemonIdentity);
        }
        if facts
            .minimum_api_version
            .is_some_and(|minimum| minimum > api_version)
        {
            return Err(CapabilityError::InvalidApiRange);
        }
        let mut seen = HashSet::new();
        for fact in &facts.capabilities {
            if !seen.insert(fact.capability) {
                return Err(CapabilityError::DuplicateCapability);
            }
            match (fact.state, fact.provenance) {
                (CapabilityState::Available, FactProvenance::NativeConformance)
                | (CapabilityState::Unavailable, FactProvenance::NativeConformance)
                | (CapabilityState::Unavailable, FactProvenance::DaemonResponse)
                | (CapabilityState::Unknown, FactProvenance::Unknown) => {}
                _ => return Err(CapabilityError::InvalidProvenance),
            }
            match (&fact.scope, fact.state) {
                (None, CapabilityState::Unknown) => {}
                (Some(scope), CapabilityState::Available | CapabilityState::Unavailable)
                    if scope.observation_id == facts.observation_id
                        && scope.release == *release
                        && scope.api_version == api_version
                        && scope.mode == facts.mode => {}
                _ => return Err(CapabilityError::ScopeMismatch),
            }
        }
        Ok(Self { facts })
    }

    #[must_use]
    pub fn supports(&self, capability: Capability) -> bool {
        self.facts
            .capabilities
            .iter()
            .any(|fact| fact.capability == capability && fact.state == CapabilityState::Available)
    }

    #[must_use]
    pub fn facts(&self) -> &'a DaemonFacts {
        self.facts
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn synthetic_evidence(
        lane: NativeEvidenceLane,
        key: &CapabilityEvidenceKey,
    ) -> NativeEvidenceReference {
        NativeEvidenceReference::new(
            lane,
            "https://github.com/Strukturpiloten/docker-lens/actions/runs/123/attempts/1".into(),
            "0123456789abcdef0123456789abcdef01234567".into(),
            lane.artifact_name().into(),
            key.clone(),
            key.clone(),
        )
        .unwrap()
    }

    fn facts() -> DaemonFacts {
        DaemonFacts {
            observation_id: ObservationId::fresh().unwrap(),
            release: EngineRelease::new("20.10.24".to_string()),
            api_version: Some(ApiVersion::new(NonZeroU16::new(1).unwrap(), 41)),
            minimum_api_version: None,
            mode: DaemonMode::Rootless,
            capabilities: vec![],
        }
    }

    #[test]
    fn available_capability_requires_native_provenance_and_exact_scope() {
        let mut daemon = facts();
        let scope = CapabilityScope {
            observation_id: daemon.observation_id,
            release: daemon.release.clone().unwrap(),
            api_version: daemon.api_version.unwrap(),
            mode: daemon.mode,
        };
        daemon.capabilities.push(CapabilityFact {
            capability: Capability::NamedVolume,
            state: CapabilityState::Available,
            provenance: FactProvenance::DaemonResponse,
            scope: Some(scope.clone()),
        });
        assert!(matches!(
            ValidatedCapabilities::new(&daemon),
            Err(CapabilityError::InvalidProvenance)
        ));
        daemon.capabilities[0].provenance = FactProvenance::NativeConformance;
        daemon.capabilities[0].scope.as_mut().unwrap().mode = DaemonMode::Rootful;
        assert!(matches!(
            ValidatedCapabilities::new(&daemon),
            Err(CapabilityError::ScopeMismatch)
        ));
        daemon.capabilities[0].scope = Some(scope);
        assert!(
            ValidatedCapabilities::new(&daemon)
                .unwrap()
                .supports(Capability::NamedVolume)
        );
        daemon.capabilities.push(daemon.capabilities[0].clone());
        assert!(matches!(
            ValidatedCapabilities::new(&daemon),
            Err(CapabilityError::DuplicateCapability)
        ));
    }

    #[test]
    fn incomplete_daemon_identity_cannot_be_planning_context() {
        let mut daemon = facts();
        daemon.mode = DaemonMode::Unknown;
        assert!(matches!(
            ValidatedCapabilities::new(&daemon),
            Err(CapabilityError::MissingDaemonIdentity)
        ));
    }

    #[test]
    fn same_version_daemons_cannot_exchange_capability_claims() {
        let first = facts();
        let mut second = facts();
        assert_ne!(first.observation_id, second.observation_id);
        assert_eq!(first.release, second.release);
        assert_eq!(first.api_version, second.api_version);
        assert_eq!(first.mode, second.mode);
        second.capabilities.push(CapabilityFact {
            capability: Capability::NamedVolume,
            state: CapabilityState::Available,
            provenance: FactProvenance::NativeConformance,
            scope: Some(CapabilityScope {
                observation_id: first.observation_id,
                release: first.release.clone().unwrap(),
                api_version: first.api_version.unwrap(),
                mode: first.mode,
            }),
        });
        assert!(matches!(
            ValidatedCapabilities::new(&second),
            Err(CapabilityError::ScopeMismatch)
        ));
    }

    #[test]
    fn offline_target_needs_exact_reviewed_catalog_entry() {
        let api = ApiVersion::new(NonZeroU16::new(1).unwrap(), 41);
        let release = EngineRelease::new("20.10.5+dfsg1".into()).unwrap();
        assert_eq!(
            CapabilityEvidenceKey::sha256([0; 32]),
            Err(CapabilityError::EmptyEvidenceKey)
        );
        let key = CapabilityEvidenceKey::sha256([1; 32]).unwrap();
        let build = EngineBuild::DebianPackage(
            DebianPackageRevision::new("20.10.5+dfsg1-1+deb11u2".into()).unwrap(),
        );
        assert_eq!(
            TargetProfileIdentity::new(
                build.clone(),
                release.clone(),
                api,
                api,
                api,
                DaemonMode::Unknown,
            ),
            Err(CapabilityError::UnknownTargetMode)
        );
        let identity = TargetProfileIdentity::new(
            build.clone(),
            release.clone(),
            api,
            api,
            api,
            DaemonMode::Rootless,
        )
        .unwrap();
        let profile = TargetProfile::new(identity.clone(), key.clone());
        let catalog = TargetCapabilityCatalog::from_test_records(vec![TargetCapabilityRecord {
            profile: profile.clone(),
            evidence: synthetic_evidence(NativeEvidenceLane::Debian11Rootless, &key),
            capabilities: vec![TargetCapabilityFact {
                capability: Capability::PortPublish,
                state: CapabilityState::Available,
            }],
            admitted_shapes: NativeCapabilityShape::required_for(Capability::PortPublish)
                .unwrap()
                .to_vec(),
        }])
        .unwrap();
        assert_eq!(catalog.profiles().len(), 1);
        assert_eq!(catalog.profiles().next(), Some(&profile));
        assert_eq!(
            catalog.resolve_identity(&identity).unwrap().evidence_key(),
            &key
        );
        assert_eq!(
            catalog
                .resolve_identity(&identity)
                .unwrap()
                .evidence()
                .lane(),
            NativeEvidenceLane::Debian11Rootless
        );
        assert!(
            catalog
                .resolve(&profile)
                .unwrap()
                .supports(Capability::PortPublish)
        );
        assert!(
            !catalog
                .resolve(&profile)
                .unwrap()
                .supports(Capability::NamedVolume)
        );
        let other_mode = TargetProfile::new(
            TargetProfileIdentity::new(
                build.clone(),
                release.clone(),
                api,
                api,
                api,
                DaemonMode::Rootful,
            )
            .unwrap(),
            key.clone(),
        );
        assert!(matches!(
            catalog.resolve(&other_mode),
            Err(CapabilityError::ProfileNotReviewed)
        ));
        let api_42 = ApiVersion::new(NonZeroU16::new(1).unwrap(), 42);
        assert_eq!(
            TargetProfileIdentity::new(
                build.clone(),
                release.clone(),
                api,
                api,
                api_42,
                DaemonMode::Rootless,
            ),
            Err(CapabilityError::InvalidTargetApiRange)
        );
        let other_api = TargetProfile::new(
            TargetProfileIdentity::new(
                build.clone(),
                release.clone(),
                api_42,
                api,
                api,
                DaemonMode::Rootless,
            )
            .unwrap(),
            key.clone(),
        );
        assert!(matches!(
            catalog.resolve(&other_api),
            Err(CapabilityError::ProfileNotReviewed)
        ));
        let other_release = TargetProfile::new(
            TargetProfileIdentity::new(
                build.clone(),
                EngineRelease::new("20.10.25".into()).unwrap(),
                api,
                api,
                api,
                DaemonMode::Rootless,
            )
            .unwrap(),
            key.clone(),
        );
        assert!(matches!(
            catalog.resolve(&other_release),
            Err(CapabilityError::ProfileNotReviewed)
        ));
        let other_key = TargetProfile::new(
            identity.clone(),
            CapabilityEvidenceKey::sha256([2; 32]).unwrap(),
        );
        assert!(matches!(
            catalog.resolve(&other_key),
            Err(CapabilityError::ProfileNotReviewed)
        ));
        assert!(matches!(
            TargetCapabilityCatalog::reviewed().resolve(&profile),
            Err(CapabilityError::ProfileNotReviewed)
        ));
        assert_eq!(TargetCapabilityCatalog::reviewed().profiles().len(), 4);
        let other_build = TargetProfileIdentity::new(
            EngineBuild::Upstream,
            release.clone(),
            api,
            api,
            api,
            DaemonMode::Rootless,
        )
        .unwrap();
        assert!(matches!(
            catalog.resolve_identity(&other_build),
            Err(CapabilityError::ProfileNotReviewed)
        ));
        let other_revision = TargetProfileIdentity::new(
            EngineBuild::DebianPackage(
                DebianPackageRevision::new("20.10.5+dfsg1-1+deb11u3".into()).unwrap(),
            ),
            release.clone(),
            api,
            api,
            api,
            DaemonMode::Rootless,
        )
        .unwrap();
        assert!(matches!(
            catalog.resolve_identity(&other_revision),
            Err(CapabilityError::ProfileNotReviewed)
        ));
        assert!(!format!("{profile:?}").contains("20.10.5+dfsg1"));
        assert!(!format!("{profile:?}").contains("deb11u2"));
    }

    #[test]
    fn catalog_rejects_duplicate_profile_and_capability() {
        let identity = TargetProfileIdentity::new(
            EngineBuild::Upstream,
            EngineRelease::new("29.8.1".into()).unwrap(),
            ApiVersion::new(NonZeroU16::new(1).unwrap(), 41),
            ApiVersion::new(NonZeroU16::new(1).unwrap(), 41),
            ApiVersion::new(NonZeroU16::new(1).unwrap(), 41),
            DaemonMode::Rootful,
        )
        .unwrap();
        let profile = TargetProfile::new(
            identity.clone(),
            CapabilityEvidenceKey::sha256([3; 32]).unwrap(),
        );
        let record = || TargetCapabilityRecord {
            profile: profile.clone(),
            evidence: synthetic_evidence(
                NativeEvidenceLane::UpstreamRootful,
                profile.evidence_key(),
            ),
            capabilities: vec![],
            admitted_shapes: vec![],
        };
        assert!(matches!(
            TargetCapabilityCatalog::from_test_records(vec![record(), record()]),
            Err(CapabilityError::DuplicateProfile)
        ));
        assert!(matches!(
            TargetCapabilityCatalog::from_test_records(vec![
                record(),
                TargetCapabilityRecord {
                    profile: TargetProfile::new(
                        identity,
                        CapabilityEvidenceKey::sha256([4; 32]).unwrap()
                    ),
                    evidence: synthetic_evidence(
                        NativeEvidenceLane::UpstreamRootful,
                        profile.evidence_key(),
                    ),
                    capabilities: vec![],
                    admitted_shapes: vec![],
                }
            ]),
            Err(CapabilityError::DuplicateProfile)
        ));
        assert!(matches!(
            TargetCapabilityCatalog::from_test_records(vec![TargetCapabilityRecord {
                profile,
                evidence: synthetic_evidence(
                    NativeEvidenceLane::UpstreamRootful,
                    &CapabilityEvidenceKey::sha256([3; 32]).unwrap(),
                ),
                capabilities: vec![
                    TargetCapabilityFact {
                        capability: Capability::BindMount,
                        state: CapabilityState::Available
                    },
                    TargetCapabilityFact {
                        capability: Capability::BindMount,
                        state: CapabilityState::Unavailable
                    },
                ],
                admitted_shapes: vec![],
            }]),
            Err(CapabilityError::DuplicateCapability)
        ));
    }

    #[test]
    fn native_evidence_reference_requires_exact_run_attempt_and_candidate_sha() {
        let key = CapabilityEvidenceKey::sha256([8; 32]).unwrap();
        let run = "https://github.com/Strukturpiloten/docker-lens/actions/runs/123/attempts/2";
        let sha = "0123456789abcdef0123456789abcdef01234567";
        let evidence = NativeEvidenceReference::new(
            NativeEvidenceLane::UpstreamRootful,
            run.into(),
            sha.into(),
            NativeEvidenceLane::UpstreamRootful.artifact_name().into(),
            key.clone(),
            key.clone(),
        )
        .unwrap();
        assert_eq!(evidence.run_url(), run);
        assert_eq!(evidence.candidate_sha(), sha);
        assert_eq!(
            evidence.artifact_name(),
            NativeEvidenceLane::UpstreamRootful.artifact_name()
        );
        assert_eq!(evidence.record_key(), &key);
        for invalid in [
            "https://github.com/other/docker-lens/actions/runs/123/attempts/2",
            "https://github.com/Strukturpiloten/docker-lens/actions/runs/123",
            "https://github.com/Strukturpiloten/docker-lens/actions/runs/0/attempts/2",
            "https://github.com/Strukturpiloten/docker-lens/actions/runs/123/attempts/2?x=1",
        ] {
            assert_eq!(
                NativeEvidenceReference::new(
                    NativeEvidenceLane::UpstreamRootful,
                    invalid.into(),
                    sha.into(),
                    NativeEvidenceLane::UpstreamRootful.artifact_name().into(),
                    key.clone(),
                    key.clone(),
                ),
                Err(CapabilityError::InvalidEvidenceRunUrl)
            );
        }
        for invalid in ["abc", "0123456789ABCDEF0123456789abcdef01234567"] {
            assert_eq!(
                NativeEvidenceReference::new(
                    NativeEvidenceLane::UpstreamRootful,
                    run.into(),
                    invalid.into(),
                    NativeEvidenceLane::UpstreamRootful.artifact_name().into(),
                    key.clone(),
                    key.clone(),
                ),
                Err(CapabilityError::InvalidEvidenceCandidateSha)
            );
        }
        assert_eq!(
            NativeEvidenceReference::new(
                NativeEvidenceLane::UpstreamRootful,
                run.into(),
                sha.into(),
                "../other-lane".into(),
                key.clone(),
                key.clone(),
            ),
            Err(CapabilityError::InvalidEvidenceArtifactName)
        );
        assert_eq!(
            NativeEvidenceReference::new(
                NativeEvidenceLane::UpstreamRootful,
                run.into(),
                sha.into(),
                NativeEvidenceLane::UpstreamRootless.artifact_name().into(),
                key.clone(),
                key,
            ),
            Err(CapabilityError::InvalidEvidenceArtifactName)
        );
    }

    #[test]
    fn catalog_rejects_evidence_with_wrong_lane_or_record_digest() {
        let identity = TargetProfileIdentity::new(
            EngineBuild::Upstream,
            EngineRelease::new("29.8.1".into()).unwrap(),
            ApiVersion::new(NonZeroU16::new(1).unwrap(), 41),
            ApiVersion::new(NonZeroU16::new(1).unwrap(), 41),
            ApiVersion::new(NonZeroU16::new(1).unwrap(), 41),
            DaemonMode::Rootful,
        )
        .unwrap();
        let key = CapabilityEvidenceKey::sha256([8; 32]).unwrap();
        let record = |lane, evidence_key| TargetCapabilityRecord {
            profile: TargetProfile::new(identity.clone(), key.clone()),
            evidence: synthetic_evidence(lane, &evidence_key),
            capabilities: vec![],
            admitted_shapes: vec![],
        };
        assert!(matches!(
            TargetCapabilityCatalog::from_test_records(vec![record(
                NativeEvidenceLane::UpstreamRootless,
                key.clone(),
            )]),
            Err(CapabilityError::EvidenceLaneMismatch)
        ));
        assert!(matches!(
            TargetCapabilityCatalog::from_test_records(vec![record(
                NativeEvidenceLane::UpstreamRootful,
                CapabilityEvidenceKey::sha256([9; 32]).unwrap(),
            )]),
            Err(CapabilityError::EvidenceKeyMismatch)
        ));
    }

    #[test]
    fn debian11_lane_rejects_other_or_unspecified_distributions() {
        let key = CapabilityEvidenceKey::sha256([10; 32]).unwrap();
        let api_41 = ApiVersion::new(NonZeroU16::new(1).unwrap(), 41);
        for revision in [
            "20.10.5+dfsg1-1+deb12u1",
            "20.10.5+dfsg1-1",
            "20.10.5+dfsg1-1+deb11u3",
        ] {
            let identity = TargetProfileIdentity::new(
                EngineBuild::DebianPackage(DebianPackageRevision::new(revision.into()).unwrap()),
                EngineRelease::new("20.10.5+dfsg1".into()).unwrap(),
                api_41,
                api_41,
                api_41,
                DaemonMode::Rootful,
            )
            .unwrap();
            assert!(matches!(
                TargetCapabilityCatalog::from_test_records(vec![TargetCapabilityRecord {
                    profile: TargetProfile::new(identity, key.clone()),
                    evidence: synthetic_evidence(NativeEvidenceLane::Debian11Rootful, &key),
                    capabilities: vec![],
                    admitted_shapes: vec![],
                }]),
                Err(CapabilityError::EvidenceLaneMismatch)
            ));
        }
        for (release, advertised) in [
            ("20.10.6", api_41),
            (
                "20.10.5+dfsg1",
                ApiVersion::new(NonZeroU16::new(1).unwrap(), 42),
            ),
        ] {
            let identity = TargetProfileIdentity::new(
                EngineBuild::DebianPackage(
                    DebianPackageRevision::new("20.10.5+dfsg1-1+deb11u2".into()).unwrap(),
                ),
                EngineRelease::new(release.into()).unwrap(),
                advertised,
                api_41,
                api_41,
                DaemonMode::Rootful,
            )
            .unwrap();
            assert!(matches!(
                TargetCapabilityCatalog::from_test_records(vec![TargetCapabilityRecord {
                    profile: TargetProfile::new(identity, key.clone()),
                    evidence: synthetic_evidence(NativeEvidenceLane::Debian11Rootful, &key),
                    capabilities: vec![],
                    admitted_shapes: vec![],
                }]),
                Err(CapabilityError::EvidenceLaneMismatch)
            ));
        }
    }

    #[test]
    fn positive_port_publish_requires_both_fixed_protocol_shapes() {
        let key = CapabilityEvidenceKey::sha256([11; 32]).unwrap();
        let identity = TargetProfileIdentity::new(
            EngineBuild::Upstream,
            EngineRelease::new("29.8.1".into()).unwrap(),
            ApiVersion::new(NonZeroU16::new(1).unwrap(), 41),
            ApiVersion::new(NonZeroU16::new(1).unwrap(), 41),
            ApiVersion::new(NonZeroU16::new(1).unwrap(), 41),
            DaemonMode::Rootful,
        )
        .unwrap();
        let record = |admitted_shapes| TargetCapabilityRecord {
            profile: TargetProfile::new(identity.clone(), key.clone()),
            evidence: synthetic_evidence(NativeEvidenceLane::UpstreamRootful, &key),
            capabilities: vec![TargetCapabilityFact {
                capability: Capability::PortPublish,
                state: CapabilityState::Available,
            }],
            admitted_shapes,
        };
        assert!(matches!(
            TargetCapabilityCatalog::from_test_records(vec![record(vec![
                NativeCapabilityShape::FixedTcpPort,
            ])]),
            Err(CapabilityError::IncompleteEvidenceShapes)
        ));
        assert!(
            TargetCapabilityCatalog::from_test_records(vec![record(vec![
                NativeCapabilityShape::FixedTcpPort,
                NativeCapabilityShape::FixedUdpPort,
            ])])
            .unwrap()
            .resolve_identity(&identity)
            .unwrap()
            .supports(Capability::PortPublish)
        );
        assert!(matches!(
            TargetCapabilityCatalog::from_test_records(vec![record(vec![
                NativeCapabilityShape::FixedTcpPort,
                NativeCapabilityShape::FixedTcpPort,
            ])]),
            Err(CapabilityError::DuplicateEvidenceShape)
        ));
        assert!(matches!(
            TargetCapabilityCatalog::from_test_records(vec![record(vec![
                NativeCapabilityShape::FixedTcpPort,
                NativeCapabilityShape::FixedUdpPort,
                NativeCapabilityShape::ExecCommand,
            ])]),
            Err(CapabilityError::EvidenceShapeMismatch)
        ));
    }

    #[test]
    fn reviewed_identity_lookup_distinguishes_acquisition_and_rendering_apis() {
        let release = EngineRelease::new("29.8.1".into()).unwrap();
        let identity = TargetProfileIdentity::new(
            EngineBuild::Upstream,
            release.clone(),
            ApiVersion::new(NonZeroU16::new(1).unwrap(), 50),
            ApiVersion::new(NonZeroU16::new(1).unwrap(), 49),
            ApiVersion::new(NonZeroU16::new(1).unwrap(), 48),
            DaemonMode::Rootful,
        )
        .unwrap();
        let key = CapabilityEvidenceKey::sha256([5; 32]).unwrap();
        let catalog = TargetCapabilityCatalog::from_test_records(vec![TargetCapabilityRecord {
            profile: TargetProfile::new(identity.clone(), key.clone()),
            evidence: synthetic_evidence(NativeEvidenceLane::UpstreamRootful, &key),
            capabilities: vec![],
            admitted_shapes: vec![],
        }])
        .unwrap();
        assert_eq!(
            catalog.resolve_identity(&identity).unwrap().evidence_key(),
            &key
        );
        for (advertised, acquisition, rendering) in [(51, 49, 48), (50, 48, 48), (50, 49, 49)] {
            let mismatch = TargetProfileIdentity::new(
                EngineBuild::Upstream,
                release.clone(),
                ApiVersion::new(NonZeroU16::new(1).unwrap(), advertised),
                ApiVersion::new(NonZeroU16::new(1).unwrap(), acquisition),
                ApiVersion::new(NonZeroU16::new(1).unwrap(), rendering),
                DaemonMode::Rootful,
            )
            .unwrap();
            assert!(matches!(
                catalog.resolve_identity(&mismatch),
                Err(CapabilityError::ProfileNotReviewed)
            ));
        }
    }
}
