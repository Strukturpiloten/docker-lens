use super::{RenderError, json_string};
use crate::observation::ResourceRef;
use crate::target::{
    Argument, ContainerIntent, MountSource, PortBinding, Protocol, RestartPolicy, TargetResource,
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
    if let Some(entrypoint) = &container.entrypoint {
        body.push_str(",\"Entrypoint\":[");
        json_arguments(&mut body, entrypoint);
        body.push(']');
    }
    if let Some(command) = &container.command {
        body.push_str(",\"Cmd\":[");
        json_arguments(&mut body, command);
        body.push(']');
    }
    if let Some(health) = &container.healthcheck {
        body.push_str(",\"Healthcheck\":{\"Test\":[\"CMD\",");
        json_arguments(&mut body, health.command());
        body.push_str(&format!(
            "],\"Interval\":{},\"Timeout\":{},\"Retries\":{} }}",
            health.interval_ns(),
            health.timeout_ns(),
            health.retries()
        ));
    }
    if !container.ports.is_empty() {
        body.push_str(",\"ExposedPorts\":{");
        for (index, port) in container.ports.iter().enumerate() {
            if index != 0 {
                body.push(',');
            }
            json_string(&mut body, port_key(*port).as_bytes());
            body.push_str(":{}");
        }
        body.push('}');
    }
    body.push_str(",\"HostConfig\":{");
    let mut host_field = false;
    if !container.ports.is_empty() {
        body.push_str("\"PortBindings\":{");
        for (index, port) in container.ports.iter().enumerate() {
            if index != 0 {
                body.push(',');
            }
            json_string(&mut body, port_key(*port).as_bytes());
            body.push_str(":[{\"HostPort\":");
            json_string(&mut body, port.host.to_string().as_bytes());
            body.push_str("}]");
        }
        body.push('}');
        host_field = true;
    }
    if !container.mounts.is_empty() {
        if host_field {
            body.push(',');
        }
        body.push_str("\"Mounts\":[");
        for (index, mount) in container.mounts.iter().enumerate() {
            if index != 0 {
                body.push(',');
            }
            let (kind, source): (&str, &[u8]) = match mount.source() {
                MountSource::Bind(path) => ("bind", path.as_bytes()),
                MountSource::Volume(reference) => match resources.get(reference) {
                    Some(TargetResource::Volume { identity, .. }) => ("volume", identity.bytes()),
                    _ => return Err(RenderError::InvalidGraph),
                },
            };
            body.push_str("{\"Type\":");
            json_string(&mut body, kind.as_bytes());
            body.push_str(",\"Source\":");
            json_string(&mut body, source);
            body.push_str(",\"Target\":");
            json_string(&mut body, mount.target());
            body.push_str(if mount.read_only() {
                ",\"ReadOnly\":true}"
            } else {
                ",\"ReadOnly\":false}"
            });
        }
        body.push(']');
        host_field = true;
    }
    if let Some(network) = container.network {
        let Some(TargetResource::Network { identity, .. }) = resources.get(&network) else {
            return Err(RenderError::InvalidGraph);
        };
        if host_field {
            body.push(',');
        }
        body.push_str("\"NetworkMode\":");
        json_string(&mut body, identity.bytes());
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
    }
    body.push('}');
    if let Some(network) = container.network {
        let Some(TargetResource::Network { identity, .. }) = resources.get(&network) else {
            return Err(RenderError::InvalidGraph);
        };
        body.push_str(",\"NetworkingConfig\":{\"EndpointsConfig\":{");
        json_string(&mut body, identity.bytes());
        body.push_str(":{}}}");
    }
    body.push('}');
    Ok(body)
}

fn port_key(port: PortBinding) -> String {
    let protocol = match port.protocol {
        Protocol::Tcp => "tcp",
        Protocol::Udp => "udp",
    };
    format!("{}/{protocol}", port.container)
}

fn json_arguments(output: &mut String, arguments: &[Argument]) {
    for (index, argument) in arguments.iter().enumerate() {
        if index != 0 {
            output.push(',');
        }
        json_string(output, argument.bytes());
    }
}
