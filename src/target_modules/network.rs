//! Authored standalone bridge networks and container endpoints.
//! Observed addresses are never promoted to these types automatically.

use super::{IntentError, TargetIdentity};
use crate::evidence::ProtectedValue;
use crate::observation::ResourceRef;
use std::net::IpAddr;
use std::num::NonZeroU32;

/// A Compose-style default is still given an explicit target identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NetworkRole {
    Declared,
    ApplicationDefault,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NetworkDriver {
    Bridge,
    Host,
    Overlay,
    Macvlan,
}

/// Existing networks are requirements, not create operations or proof of existence.
#[derive(Debug)]
pub enum NetworkSource {
    Create(NetworkCreate),
    External {
        expected_driver: NetworkDriver,
        /// Optional consumer preflight requirement, not an observed fact.
        /// `None` leaves internal-network behavior unconstrained; explicit false
        /// and true require separate reviewed external-expectation evidence.
        expected_internal: Option<bool>,
    },
}

#[derive(Debug)]
pub struct NetworkIntent {
    pub reference: ResourceRef,
    pub identity: TargetIdentity,
    pub role: NetworkRole,
    pub source: NetworkSource,
}

#[derive(Debug)]
pub struct NetworkCreate {
    pub driver: NetworkDriver,
    pub internal: bool,
    pub enable_ipv6: bool,
    pub ipam: Option<NetworkIpam>,
    pub options: Vec<BridgeOption>,
    pub labels: Vec<NetworkLabel>,
}

impl NetworkCreate {
    #[must_use]
    pub fn bridge() -> Self {
        Self {
            driver: NetworkDriver::Bridge,
            internal: false,
            enable_ipv6: false,
            ipam: None,
            options: Vec::new(),
            labels: Vec::new(),
        }
    }
}

/// Only reviewed bridge-driver options have typed renderer branches.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BridgeOption {
    Mtu(NonZeroU32),
    InterContainerCommunication(bool),
    IpMasquerade(bool),
    HostBindingIp(NetworkAddress),
}

pub struct NetworkLabel {
    key: ProtectedValue,
    value: ProtectedValue,
}

impl NetworkLabel {
    pub fn new(key: Vec<u8>, value: Vec<u8>) -> Result<Self, IntentError> {
        if key.is_empty()
            || key.contains(&0)
            || value.contains(&0)
            || std::str::from_utf8(&key).is_err()
            || std::str::from_utf8(&value).is_err()
        {
            return Err(IntentError::InvalidNetworkLabel);
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

impl std::fmt::Debug for NetworkLabel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("NetworkLabel([redacted])")
    }
}

/// Addresses are validated at construction and redacted from Debug output.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct NetworkAddress(IpAddr);

impl NetworkAddress {
    pub fn new(text: &str) -> Result<Self, IntentError> {
        text.parse()
            .map(Self)
            .map_err(|_| IntentError::InvalidNetworkAddress)
    }

    #[must_use]
    pub const fn value(self) -> IpAddr {
        self.0
    }

    #[must_use]
    pub const fn is_ipv6(self) -> bool {
        self.0.is_ipv6()
    }
}

impl std::fmt::Debug for NetworkAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("NetworkAddress([redacted])")
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct NetworkSubnet {
    address: NetworkAddress,
    prefix: u8,
}

impl NetworkSubnet {
    pub fn new(address: NetworkAddress, prefix: u8) -> Result<Self, IntentError> {
        let bits = if address.is_ipv6() { 128 } else { 32 };
        if prefix > bits || !address_is_network(address.value(), prefix) {
            return Err(IntentError::InvalidNetworkSubnet);
        }
        Ok(Self { address, prefix })
    }

    #[must_use]
    pub const fn address(self) -> NetworkAddress {
        self.address
    }

    #[must_use]
    pub const fn prefix(self) -> u8 {
        self.prefix
    }

    #[must_use]
    pub fn contains(self, address: NetworkAddress) -> bool {
        match (self.address.value(), address.value()) {
            (IpAddr::V4(base), IpAddr::V4(value)) => {
                let mask = u32::MAX
                    .checked_shl(32 - u32::from(self.prefix))
                    .unwrap_or(0);
                u32::from(base) & mask == u32::from(value) & mask
            }
            (IpAddr::V6(base), IpAddr::V6(value)) => {
                let mask = u128::MAX
                    .checked_shl(128 - u32::from(self.prefix))
                    .unwrap_or(0);
                u128::from(base) & mask == u128::from(value) & mask
            }
            _ => false,
        }
    }

    /// Reject ordinary IPv4 subnet/broadcast slots and the IPv6 subnet base.
    /// IPv4 /31 and /32 have no distinct broadcast slot; native Engine support
    /// for those pool sizes still requires separate capability evidence.
    #[must_use]
    pub fn contains_usable_host(self, address: NetworkAddress) -> bool {
        if !self.contains(address) {
            return false;
        }
        match (self.address.value(), address.value()) {
            (IpAddr::V4(base), IpAddr::V4(value)) if self.prefix <= 30 => {
                let host_mask = u32::MAX
                    .checked_shr(u32::from(self.prefix))
                    .unwrap_or(u32::MAX);
                let base = u32::from(base);
                let value = u32::from(value);
                value != base && value != base | host_mask
            }
            (IpAddr::V4(_), IpAddr::V4(_)) => true,
            (IpAddr::V6(base), IpAddr::V6(value)) => value != base,
            _ => false,
        }
    }

    #[must_use]
    pub fn overlaps(self, other: Self) -> bool {
        self.contains(other.address()) || other.contains(self.address())
    }
}

impl std::fmt::Debug for NetworkSubnet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("NetworkSubnet([redacted])")
    }
}

fn address_is_network(address: IpAddr, prefix: u8) -> bool {
    match address {
        IpAddr::V4(value) => {
            let mask = u32::MAX.checked_shl(32 - u32::from(prefix)).unwrap_or(0);
            u32::from(value) & !mask == 0
        }
        IpAddr::V6(value) => {
            let mask = u128::MAX.checked_shl(128 - u32::from(prefix)).unwrap_or(0);
            u128::from(value) & !mask == 0
        }
    }
}

pub struct NetworkAlias(ProtectedValue);

impl NetworkAlias {
    pub fn new(bytes: Vec<u8>) -> Result<Self, IntentError> {
        if !bytes.first().is_some_and(u8::is_ascii_alphanumeric)
            || !bytes[1..]
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(*byte, b'_' | b'-' | b'.'))
        {
            return Err(IntentError::InvalidNetworkAlias);
        }
        Ok(Self(ProtectedValue::new(bytes)))
    }

    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl std::fmt::Debug for NetworkAlias {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("NetworkAlias([redacted])")
    }
}

#[derive(Debug)]
pub struct NetworkAuxAddress {
    pub name: NetworkAlias,
    pub address: NetworkAddress,
}

#[derive(Debug)]
pub struct NetworkIpamPool {
    pub subnet: NetworkSubnet,
    pub gateway: Option<NetworkAddress>,
    pub ip_range: Option<NetworkSubnet>,
    pub auxiliary_addresses: Vec<NetworkAuxAddress>,
}

#[derive(Debug)]
pub struct NetworkIpam {
    pub driver: Option<NetworkIpamDriver>,
    pub pools: Vec<NetworkIpamPool>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NetworkIpamDriver {
    Default,
}

#[derive(Debug)]
pub struct NetworkAttachmentIntent {
    pub network: ResourceRef,
    pub aliases: Vec<NetworkAlias>,
    pub ipv4_address: Option<NetworkAddress>,
    pub ipv6_address: Option<NetworkAddress>,
}
