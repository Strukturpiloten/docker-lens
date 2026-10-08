use super::{RenderError, json_string, percent_encode};
use crate::observation::ResourceRef;
use crate::target::{
    Argument, ContainerIntent, HealthTest, ImageCommand, LogDriver, MemoryLimit, MountSource,
    NetworkAttachmentIntent, PidsLimit, PortHostIp, PortHostPort, PortPublication, Protocol,
    RestartPolicy, SecurityOption, TargetResource, UlimitValue, UserNamespaceMode,
};
use std::collections::HashMap;

pub(super) fn render_container(
    container: &ContainerIntent,
    resources: &HashMap<ResourceRef, &TargetResource>,
) -> Result<String, RenderError> {
    let mut body = String::from("{\"Image\":");
    json_string(&mut body, container.image.bytes());
    if !container.environment.is_empty() {
        body.push_str(",\"Env\":[");
        for (index, assignment) in container.environment.iter().enumerate() {
            if index != 0 {
                body.push(',');
            }
            let mut pair = assignment.key().to_vec();
            pair.push(b'=');
            pair.extend_from_slice(assignment.value());
            json_string(&mut body, &pair);
        }
        body.push(']');
    }
    render_image_command(&mut body, "Entrypoint", &container.entrypoint);
    render_image_command(&mut body, "Cmd", &container.command);
    if let Some(health) = &container.healthcheck {
        body.push_str(",\"Healthcheck\":{\"Test\":[");
        match health.test() {
            HealthTest::Exec(arguments) => {
                body.push_str("\"CMD\",");
                json_arguments(&mut body, arguments);
            }
            HealthTest::Shell(command) => {
                body.push_str("\"CMD-SHELL\",");
                json_string(&mut body, command.bytes());
            }
            HealthTest::Disabled => body.push_str("\"NONE\""),
        }
        body.push(']');
        if let Some(value) = health.interval_ns() {
            body.push_str(&format!(",\"Interval\":{}", value.get()));
        }
        if let Some(value) = health.timeout_ns() {
            body.push_str(&format!(",\"Timeout\":{}", value.get()));
        }
        if let Some(value) = health.retries() {
            body.push_str(&format!(",\"Retries\":{}", value.get()));
        }
        if let Some(value) = health.start_period_ns() {
            body.push_str(&format!(",\"StartPeriod\":{value}"));
        }
        if let Some(value) = health.start_interval_ns() {
            body.push_str(&format!(",\"StartInterval\":{value}"));
        }
        body.push_str(" }");
    }
    if !container.settings.labels.is_empty() {
        body.push_str(",\"Labels\":{");
        for (index, label) in container.settings.labels.iter().enumerate() {
            if index != 0 {
                body.push(',');
            }
            json_string(&mut body, label.key());
            body.push(':');
            json_string(&mut body, label.value());
        }
        body.push('}');
    }
    if let Some(user) = &container.settings.user {
        body.push_str(",\"User\":");
        json_string(&mut body, user.bytes());
    }
    if let Some(directory) = &container.settings.working_dir {
        body.push_str(",\"WorkingDir\":");
        json_string(&mut body, directory.bytes());
    }
    if let Some(hostname) = &container.settings.hostname {
        body.push_str(",\"Hostname\":");
        json_string(&mut body, hostname.bytes());
    }
    if let Some(signal) = &container.settings.stop_signal {
        body.push_str(",\"StopSignal\":");
        json_string(&mut body, signal.bytes());
    }
    if let Some(timeout) = container.settings.stop_timeout_seconds {
        body.push_str(&format!(",\"StopTimeout\":{timeout}"));
    }
    if !container.ports.is_empty() {
        body.push_str(",\"ExposedPorts\":{");
        for (index, port) in container.ports.iter().enumerate() {
            if index != 0 {
                body.push(',');
            }
            json_string(&mut body, port_key(port).as_bytes());
            body.push_str(":{}");
        }
        body.push('}');
    }
    body.push_str(",\"HostConfig\":{");
    let mut host_field = false;
    if container
        .ports
        .iter()
        .any(|port| !port.bindings().is_empty())
    {
        body.push_str("\"PortBindings\":{");
        let mut emitted = false;
        for port in &container.ports {
            if port.bindings().is_empty() {
                continue;
            }
            if emitted {
                body.push(',');
            }
            emitted = true;
            json_string(&mut body, port_key(port).as_bytes());
            body.push_str(":[");
            for (index, binding) in port.bindings().iter().enumerate() {
                if index != 0 {
                    body.push(',');
                }
                body.push('{');
                if let PortHostIp::Address(address) = binding.host_ip {
                    body.push_str("\"HostIp\":");
                    json_string(&mut body, address.to_string().as_bytes());
                    body.push(',');
                }
                body.push_str("\"HostPort\":");
                match binding.host_port {
                    PortHostPort::Fixed(port) => {
                        json_string(&mut body, port.to_string().as_bytes())
                    }
                    PortHostPort::Ephemeral => json_string(&mut body, b""),
                }
                body.push('}');
            }
            body.push(']');
        }
        body.push('}');
        host_field = true;
    }
    if container
        .mounts
        .iter()
        .any(|mount| mount.bind_relabel().is_some())
    {
        if host_field {
            body.push(',');
        }
        body.push_str("\"Binds\":[");
        for (index, mount) in container
            .mounts
            .iter()
            .filter(|mount| mount.bind_relabel().is_some())
            .enumerate()
        {
            if index != 0 {
                body.push(',');
            }
            let MountSource::Bind(source) = mount.source() else {
                return Err(RenderError::InvalidGraph);
            };
            let mut binding = source.as_bytes().to_vec();
            binding.push(b':');
            binding.extend_from_slice(mount.target());
            binding.extend_from_slice(if mount.read_only() { b":ro," } else { b":rw," });
            binding.extend_from_slice(match mount.bind_relabel() {
                Some(super::super::BindRelabel::Shared) => b"z",
                Some(super::super::BindRelabel::Private) => b"Z",
                None => return Err(RenderError::InvalidGraph),
            });
            json_string(&mut body, &binding);
        }
        body.push(']');
        host_field = true;
    }
    if container
        .mounts
        .iter()
        .any(|mount| mount.bind_relabel().is_none())
    {
        if host_field {
            body.push(',');
        }
        body.push_str("\"Mounts\":[");
        for (index, mount) in container
            .mounts
            .iter()
            .filter(|mount| mount.bind_relabel().is_none())
            .enumerate()
        {
            if index != 0 {
                body.push(',');
            }
            let (kind, source): (&str, Option<&[u8]>) = match mount.source() {
                MountSource::Bind(path) => ("bind", Some(path.as_bytes())),
                MountSource::Volume(reference) => match resources.get(reference) {
                    Some(
                        TargetResource::Volume { identity, .. }
                        | TargetResource::ExternalVolume { identity, .. },
                    ) => ("volume", Some(identity.bytes())),
                    _ => return Err(RenderError::InvalidGraph),
                },
                MountSource::Tmpfs(_) => ("tmpfs", None),
            };
            body.push_str("{\"Type\":");
            json_string(&mut body, kind.as_bytes());
            if let Some(source) = source {
                body.push_str(",\"Source\":");
                json_string(&mut body, source);
            }
            body.push_str(",\"Target\":");
            json_string(&mut body, mount.target());
            body.push_str(if mount.read_only() {
                ",\"ReadOnly\":true"
            } else {
                ",\"ReadOnly\":false"
            });
            if let MountSource::Tmpfs(options) = mount.source() {
                if options.size_bytes.is_some() || options.mode.is_some() {
                    body.push_str(",\"TmpfsOptions\":{");
                    let mut option_field = false;
                    if let Some(size) = options.size_bytes {
                        body.push_str(&format!("\"SizeBytes\":{}", size.get()));
                        option_field = true;
                    }
                    if let Some(mode) = options.mode {
                        if option_field {
                            body.push(',');
                        }
                        body.push_str(&format!("\"Mode\":{mode}"));
                    }
                    body.push('}');
                }
            }
            body.push('}');
        }
        body.push(']');
        host_field = true;
    }
    if let Some(attachment) = container.networks.first() {
        let Some(TargetResource::Network(network)) = resources.get(&attachment.network) else {
            return Err(RenderError::InvalidGraph);
        };
        if host_field {
            body.push(',');
        }
        body.push_str("\"NetworkMode\":");
        json_string(&mut body, network.identity.bytes());
        host_field = true;
    }
    if let Some(restart) = container.restart {
        if host_field {
            body.push(',');
        }
        body.push_str("\"RestartPolicy\":{\"Name\":");
        let (name, maximum_retries) = match restart {
            RestartPolicy::No => ("no", 0),
            RestartPolicy::Always => ("always", 0),
            RestartPolicy::UnlessStopped => ("unless-stopped", 0),
            RestartPolicy::OnFailure { maximum_retries } => ("on-failure", maximum_retries),
        };
        json_string(&mut body, name.as_bytes());
        body.push_str(&format!(",\"MaximumRetryCount\":{maximum_retries}}}"));
        host_field = true;
    }
    if let Some(read_only) = container.settings.read_only_rootfs {
        if host_field {
            body.push(',');
        }
        body.push_str(if read_only {
            "\"ReadonlyRootfs\":true"
        } else {
            "\"ReadonlyRootfs\":false"
        });
        host_field = true;
    }
    if let Some(init) = container.settings.init {
        if host_field {
            body.push(',');
        }
        body.push_str(if init {
            "\"Init\":true"
        } else {
            "\"Init\":false"
        });
        host_field = true;
    }
    if let Some(memory) = container.settings.memory_limit {
        host_field_prefix(&mut body, &mut host_field);
        let value = match memory {
            MemoryLimit::Unlimited => 0,
            MemoryLimit::Bytes(value) => value.get(),
        };
        body.push_str(&format!("\"Memory\":{value}"));
    }
    if let Some(pids) = container.settings.pids_limit {
        host_field_prefix(&mut body, &mut host_field);
        let value = match pids {
            PidsLimit::Unlimited => -1,
            PidsLimit::Count(value) => value.get() as i64,
        };
        body.push_str(&format!("\"PidsLimit\":{value}"));
    }
    if let Some(size) = container.settings.shm_size_bytes {
        host_field_prefix(&mut body, &mut host_field);
        body.push_str(&format!("\"ShmSize\":{}", size.get()));
    }
    if !container.settings.ulimits.is_empty() {
        host_field_prefix(&mut body, &mut host_field);
        body.push_str("\"Ulimits\":[");
        for (index, limit) in container.settings.ulimits.iter().enumerate() {
            if index != 0 {
                body.push(',');
            }
            body.push_str("{\"Name\":");
            json_string(&mut body, limit.name.bytes());
            let number = |value| match value {
                UlimitValue::Unlimited => -1,
                UlimitValue::Value(value) => value as i64,
            };
            body.push_str(&format!(
                ",\"Soft\":{},\"Hard\":{}}}",
                number(limit.soft),
                number(limit.hard)
            ));
        }
        body.push(']');
    }
    if !container.settings.devices.is_empty() {
        host_field_prefix(&mut body, &mut host_field);
        body.push_str("\"Devices\":[");
        for (index, device) in container.settings.devices.iter().enumerate() {
            if index != 0 {
                body.push(',');
            }
            body.push_str("{\"PathOnHost\":");
            json_string(&mut body, device.host_path.bytes());
            body.push_str(",\"PathInContainer\":");
            json_string(&mut body, device.container_path.bytes());
            body.push_str(",\"CgroupPermissions\":");
            let permissions = format!(
                "{}{}{}",
                if device.permissions.read { "r" } else { "" },
                if device.permissions.write { "w" } else { "" },
                if device.permissions.create { "m" } else { "" }
            );
            json_string(&mut body, permissions.as_bytes());
            body.push('}');
        }
        body.push(']');
    }
    for (key, tokens) in [
        ("CapAdd", &container.settings.cap_add),
        ("CapDrop", &container.settings.cap_drop),
    ] {
        if !tokens.is_empty() {
            host_field_prefix(&mut body, &mut host_field);
            body.push('"');
            body.push_str(key);
            body.push_str("\":[");
            for (index, token) in tokens.iter().enumerate() {
                if index != 0 {
                    body.push(',');
                }
                json_string(&mut body, token.bytes());
            }
            body.push(']');
        }
    }
    if !container.settings.security_options.is_empty() {
        host_field_prefix(&mut body, &mut host_field);
        body.push_str("\"SecurityOpt\":[");
        for (index, option) in container.settings.security_options.iter().enumerate() {
            if index != 0 {
                body.push(',');
            }
            let text = match option {
                SecurityOption::NoNewPrivileges(true) => "no-new-privileges:true",
                SecurityOption::NoNewPrivileges(false) => "no-new-privileges:false",
            };
            json_string(&mut body, text.as_bytes());
        }
        body.push(']');
    }
    if !container.settings.sysctls.is_empty() {
        host_field_prefix(&mut body, &mut host_field);
        body.push_str("\"Sysctls\":{");
        for (index, setting) in container.settings.sysctls.iter().enumerate() {
            if index != 0 {
                body.push(',');
            }
            json_string(&mut body, setting.key());
            body.push(':');
            json_string(&mut body, setting.value());
        }
        body.push('}');
    }
    if !container.settings.group_add.is_empty() {
        host_field_prefix(&mut body, &mut host_field);
        body.push_str("\"GroupAdd\":[");
        for (index, group) in container.settings.group_add.iter().enumerate() {
            if index != 0 {
                body.push(',');
            }
            json_string(&mut body, group.bytes());
        }
        body.push(']');
    }
    if !container.settings.dns.is_empty() {
        host_field_prefix(&mut body, &mut host_field);
        body.push_str("\"Dns\":[");
        for (index, address) in container.settings.dns.iter().enumerate() {
            if index != 0 {
                body.push(',');
            }
            json_string(&mut body, address.to_string().as_bytes());
        }
        body.push(']');
    }
    if !container.settings.extra_hosts.is_empty() {
        host_field_prefix(&mut body, &mut host_field);
        body.push_str("\"ExtraHosts\":[");
        for (index, host) in container.settings.extra_hosts.iter().enumerate() {
            if index != 0 {
                body.push(',');
            }
            let mut text = host.name.bytes().to_vec();
            text.push(b':');
            text.extend_from_slice(host.address.to_string().as_bytes());
            json_string(&mut body, &text);
        }
        body.push(']');
    }
    if let Some(log) = &container.settings.log_config {
        host_field_prefix(&mut body, &mut host_field);
        body.push_str("\"LogConfig\":{\"Type\":");
        let driver = match log.driver {
            LogDriver::JsonFile => "json-file",
            LogDriver::Local => "local",
            LogDriver::None => "none",
        };
        json_string(&mut body, driver.as_bytes());
        body.push_str(",\"Config\":{");
        for (index, option) in log.options.iter().enumerate() {
            if index != 0 {
                body.push(',');
            }
            json_string(&mut body, option.key());
            body.push(':');
            json_string(&mut body, option.value());
        }
        body.push_str("}}");
    }
    if let Some(mode) = container.settings.userns_mode {
        host_field_prefix(&mut body, &mut host_field);
        body.push_str("\"UsernsMode\":");
        let value = match mode {
            UserNamespaceMode::Host => "host",
        };
        json_string(&mut body, value.as_bytes());
    }
    body.push('}');
    if let Some(attachment) = container.networks.first() {
        let Some(TargetResource::Network(network)) = resources.get(&attachment.network) else {
            return Err(RenderError::InvalidGraph);
        };
        body.push_str(",\"NetworkingConfig\":{\"EndpointsConfig\":{");
        json_string(&mut body, network.identity.bytes());
        body.push(':');
        render_endpoint(&mut body, attachment);
        body.push_str("}}");
    }
    body.push('}');
    Ok(body)
}

pub(super) fn render_secondary_connection(
    container: &ContainerIntent,
    attachment: &NetworkAttachmentIntent,
    resources: &HashMap<ResourceRef, &TargetResource>,
) -> Result<(String, String), RenderError> {
    let Some(TargetResource::Network(network)) = resources.get(&attachment.network) else {
        return Err(RenderError::InvalidGraph);
    };
    let path = format!(
        "networks/{}/connect",
        percent_encode(network.identity.bytes())
    );
    let mut body = String::from("{\"Container\":");
    json_string(&mut body, container.identity.bytes());
    body.push_str(",\"EndpointConfig\":");
    render_endpoint(&mut body, attachment);
    body.push('}');
    Ok((path, body))
}

fn render_endpoint(body: &mut String, attachment: &NetworkAttachmentIntent) {
    body.push('{');
    let mut field = false;
    if !attachment.aliases.is_empty() {
        body.push_str("\"Aliases\":[");
        for (index, alias) in attachment.aliases.iter().enumerate() {
            if index != 0 {
                body.push(',');
            }
            json_string(body, alias.bytes());
        }
        body.push(']');
        field = true;
    }
    if attachment.ipv4_address.is_some() || attachment.ipv6_address.is_some() {
        if field {
            body.push(',');
        }
        body.push_str("\"IPAMConfig\":{");
        let mut address_field = false;
        if let Some(address) = attachment.ipv4_address {
            body.push_str("\"IPv4Address\":");
            json_string(body, address.value().to_string().as_bytes());
            address_field = true;
        }
        if let Some(address) = attachment.ipv6_address {
            if address_field {
                body.push(',');
            }
            body.push_str("\"IPv6Address\":");
            json_string(body, address.value().to_string().as_bytes());
        }
        body.push('}');
    }
    body.push('}');
}

fn port_key(port: &PortPublication) -> String {
    let protocol = match port.protocol {
        Protocol::Tcp => "tcp",
        Protocol::Udp => "udp",
    };
    format!("{}/{protocol}", port.container)
}

fn render_image_command(body: &mut String, key: &str, command: &ImageCommand) {
    match command {
        ImageCommand::Inherit => {}
        ImageCommand::Clear => body.push_str(&format!(",\"{key}\":[]")),
        ImageCommand::Exec(arguments) => {
            body.push_str(&format!(",\"{key}\":["));
            json_arguments(body, arguments);
            body.push(']');
        }
    }
}

fn host_field_prefix(body: &mut String, has_field: &mut bool) {
    if *has_field {
        body.push(',');
    }
    *has_field = true;
}

fn json_arguments(output: &mut String, arguments: &[Argument]) {
    for (index, argument) in arguments.iter().enumerate() {
        if index != 0 {
            output.push(',');
        }
        json_string(output, argument.bytes());
    }
}
