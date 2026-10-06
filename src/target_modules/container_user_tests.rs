use super::*;
use crate::target::{TargetIntent, TargetResource};

fn with_groups(groups: Vec<ContainerUser>) -> Result<TargetIntent, IntentError> {
    TargetIntent::new(vec![TargetResource::Container(Box::new(ContainerIntent {
        reference: ResourceRef::new(1),
        identity: TargetIdentity::new(b"app".to_vec()).unwrap(),
        image: ImageReference::new(b"busybox:fixture".to_vec()).unwrap(),
        environment: Vec::new(),
        ports: Vec::new(),
        mounts: Vec::new(),
        networks: Vec::new(),
        entrypoint: ImageCommand::Inherit,
        command: ImageCommand::Inherit,
        healthcheck: None,
        restart: None,
        settings: ContainerSettings {
            group_add: groups,
            ..ContainerSettings::default()
        },
    }))])
}

fn invalid_principals() -> Vec<Vec<u8>> {
    let mut values = vec![
        Vec::new(),
        b"00".to_vec(),
        b"01".to_vec(),
        b"0000000000".to_vec(),
        b"2147483648".to_vec(),
        b"9999999999".to_vec(),
        b"10000000000".to_vec(),
        b"+1".to_vec(),
        b"-1".to_vec(),
        b"1name".to_vec(),
        b"0x10".to_vec(),
        b".name".to_vec(),
        b"-name".to_vec(),
        b" name".to_vec(),
        b"name ".to_vec(),
        b"name group".to_vec(),
        b"name/group".to_vec(),
        b"name$".to_vec(),
        b"name\\group".to_vec(),
        "nämé".as_bytes().to_vec(),
        "１２".as_bytes().to_vec(),
        vec![0xff],
        vec![b'a'; 33],
    ];
    for control in (0..=31).chain(std::iter::once(127)) {
        values.push(vec![b'n', control, b'g']);
    }
    values
}

#[test]
fn accepts_six_user_forms_without_normalizing_bytes() {
    for value in [
        "1000",
        "app",
        "1000:1000",
        "app:staff",
        "app:1000",
        "1000:staff",
    ] {
        let user = ContainerUser::new(value.as_bytes().to_vec()).unwrap();
        assert_eq!(user.bytes(), value.as_bytes());
        assert_eq!(format!("{user:?}"), "ContainerUser([redacted])");
    }
}

#[test]
fn accepts_id_and_name_boundaries_in_both_components() {
    let principals = [
        "0".to_owned(),
        "1".to_owned(),
        "2147483647".to_owned(),
        "_".to_owned(),
        "a".to_owned(),
        "Z_09.-".to_owned(),
        "a".repeat(31),
        "a".repeat(32),
    ];
    for principal in &principals {
        let user = ContainerUser::new(principal.as_bytes().to_vec()).unwrap();
        assert_eq!(user.bytes(), principal.as_bytes());
        for other in &principals {
            let value = format!("{principal}:{other}");
            let user = ContainerUser::new(value.as_bytes().to_vec()).unwrap();
            assert_eq!(user.bytes(), value.as_bytes());
        }
    }
}

#[test]
fn rejects_invalid_principals_in_either_component_with_value_free_errors() {
    for principal in invalid_principals() {
        let mut user_component = principal.clone();
        user_component.extend_from_slice(b":staff");
        let mut group_component = b"app:".to_vec();
        group_component.extend_from_slice(&principal);
        for value in [principal, user_component, group_component] {
            let error = ContainerUser::new(value).unwrap_err();
            assert_eq!(error, IntentError::InvalidContainerUser);
            assert_eq!(format!("{error:?}"), "InvalidContainerUser");
        }
    }
}

#[test]
fn rejects_empty_and_extra_colon_components() {
    for value in [
        ":",
        ":staff",
        "app:",
        "app::staff",
        "app:staff:",
        "app:staff:extra",
    ] {
        assert_eq!(
            ContainerUser::new(value.as_bytes().to_vec()).unwrap_err(),
            IntentError::InvalidContainerUser
        );
    }
}

#[test]
fn supplementary_groups_accept_single_principals_and_keep_duplicate_error() {
    let groups = ["0", "2147483647", "_staff", "Staff_09.-"]
        .into_iter()
        .chain(["a".repeat(31), "a".repeat(32)].iter().map(String::as_str))
        .map(|value| ContainerUser::new(value.as_bytes().to_vec()).unwrap())
        .collect();
    assert!(with_groups(groups).is_ok());
    for value in ["0", "2147483647", "staff"] {
        let error = with_groups(vec![
            ContainerUser::new(value.as_bytes().to_vec()).unwrap(),
            ContainerUser::new(value.as_bytes().to_vec()).unwrap(),
        ])
        .unwrap_err();
        assert_eq!(error, IntentError::DuplicateContainerSetting);
        assert_eq!(format!("{error:?}"), "DuplicateContainerSetting");
    }
}

#[test]
fn supplementary_groups_reject_user_group_pairs_with_value_free_errors() {
    for value in ["1000:1000", "app:staff", "app:1000", "1000:staff"] {
        let user = ContainerUser::new(value.as_bytes().to_vec()).unwrap();
        let error = with_groups(vec![user]).unwrap_err();
        assert_eq!(error, IntentError::InvalidContainerSetting);
        assert_eq!(format!("{error:?}"), "InvalidContainerSetting");
    }
}

#[test]
fn supplementary_group_validation_independently_rejects_invalid_principals() {
    for value in invalid_principals() {
        // Exercise the intent guard independently of the constructor guard.
        let user = ContainerUser(ProtectedValue::new(value));
        let error = with_groups(vec![user]).unwrap_err();
        assert_eq!(error, IntentError::InvalidContainerSetting);
        assert_eq!(format!("{error:?}"), "InvalidContainerSetting");
    }
}

#[test]
fn user_validation_does_not_narrow_shared_absolute_path_values() {
    for value in ["/", "/private/work", "/device path/é"] {
        let path = WorkingDirectory::new(value.as_bytes().to_vec()).unwrap();
        assert_eq!(path.bytes(), value.as_bytes());
        assert_eq!(format!("{path:?}"), "WorkingDirectory([redacted])");
    }
}
