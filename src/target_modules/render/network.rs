use super::json_string;
use crate::target::{
    BridgeOption, NetworkAddress, NetworkCreate, NetworkIntent, NetworkIpamDriver, NetworkIpamPool,
    NetworkSource, NetworkSubnet,
};

pub(super) fn render_network(network: &NetworkIntent) -> String {
    let NetworkSource::Create(create) = &network.source else {
        unreachable!("external networks never have a create operation")
    };
    let mut body = String::from("{\"Name\":");
    json_string(&mut body, network.identity.bytes());
    body.push_str(",\"Driver\":\"bridge\"");
    render_create_options(&mut body, create);
    body.push('}');
    body
}

fn render_create_options(body: &mut String, create: &NetworkCreate) {
    if create.internal {
        body.push_str(",\"Internal\":true");
    }
    if create.enable_ipv6 {
        body.push_str(",\"EnableIPv6\":true");
    }
    if let Some(ipam) = &create.ipam {
        body.push_str(",\"IPAM\":{");
        if let Some(driver) = ipam.driver {
            let name = match driver {
                NetworkIpamDriver::Default => "default",
            };
            body.push_str("\"Driver\":");
            json_string(body, name.as_bytes());
            body.push(',');
        }
        body.push_str("\"Config\":[");
        for (index, pool) in ipam.pools.iter().enumerate() {
            if index != 0 {
                body.push(',');
            }
            render_pool(body, pool);
        }
        body.push_str("]}");
    }
    if !create.options.is_empty() {
        body.push_str(",\"Options\":{");
        for (index, option) in create.options.iter().enumerate() {
            if index != 0 {
                body.push(',');
            }
            let (name, value) = match option {
                BridgeOption::Mtu(mtu) => ("com.docker.network.driver.mtu", mtu.to_string()),
                BridgeOption::InterContainerCommunication(enabled) => {
                    ("com.docker.network.bridge.enable_icc", enabled.to_string())
                }
                BridgeOption::IpMasquerade(enabled) => (
                    "com.docker.network.bridge.enable_ip_masquerade",
                    enabled.to_string(),
                ),
                BridgeOption::HostBindingIp(address) => (
                    "com.docker.network.bridge.host_binding_ipv4",
                    address.value().to_string(),
                ),
            };
            json_string(body, name.as_bytes());
            body.push(':');
            json_string(body, value.as_bytes());
        }
        body.push('}');
    }
    if !create.labels.is_empty() {
        body.push_str(",\"Labels\":{");
        for (index, label) in create.labels.iter().enumerate() {
            if index != 0 {
                body.push(',');
            }
            json_string(body, label.key());
            body.push(':');
            json_string(body, label.value());
        }
        body.push('}');
    }
}

fn render_pool(body: &mut String, pool: &NetworkIpamPool) {
    body.push_str("{\"Subnet\":");
    json_string(body, subnet_text(pool.subnet).as_bytes());
    if let Some(range) = pool.ip_range {
        body.push_str(",\"IPRange\":");
        json_string(body, subnet_text(range).as_bytes());
    }
    if let Some(gateway) = pool.gateway {
        body.push_str(",\"Gateway\":");
        json_string(body, address_text(gateway).as_bytes());
    }
    if !pool.auxiliary_addresses.is_empty() {
        body.push_str(",\"AuxiliaryAddresses\":{");
        for (index, auxiliary) in pool.auxiliary_addresses.iter().enumerate() {
            if index != 0 {
                body.push(',');
            }
            json_string(body, auxiliary.name.bytes());
            body.push(':');
            json_string(body, address_text(auxiliary.address).as_bytes());
        }
        body.push('}');
    }
    body.push('}');
}

pub(super) fn address_text(address: NetworkAddress) -> String {
    address.value().to_string()
}

fn subnet_text(subnet: NetworkSubnet) -> String {
    format!("{}/{}", subnet.address().value(), subnet.prefix())
}
