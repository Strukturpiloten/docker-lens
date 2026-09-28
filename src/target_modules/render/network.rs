use super::json_string;
use crate::target::TargetIdentity;

pub(super) fn render_network(identity: &TargetIdentity) -> String {
    let mut body = String::from("{\"Name\":");
    json_string(&mut body, identity.bytes());
    body.push_str(",\"Driver\":\"bridge\"}");
    body
}
