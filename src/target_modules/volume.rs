//! Protected authored labels for a created named volume only.

use super::IntentError;
use crate::evidence::ProtectedValue;

pub(crate) const MAX_VOLUME_LABEL_COUNT: usize = 64;
pub(crate) const MAX_VOLUME_LABEL_TOTAL_BYTES: usize = 16 * 1024;
const MAX_VOLUME_LABEL_KEY_BYTES: usize = 128;
const MAX_VOLUME_LABEL_VALUE_BYTES: usize = 4096;

/// One explicitly authored Docker named-volume label.
///
/// Values remain protected in `Debug` and closed errors. Only a caller's
/// explicit byte access or inert artifact read reveals them.
pub struct VolumeLabel {
    key: ProtectedValue,
    value: ProtectedValue,
}

impl VolumeLabel {
    pub fn new(key: Vec<u8>, value: Vec<u8>) -> Result<Self, IntentError> {
        if key.is_empty()
            || key.len() > MAX_VOLUME_LABEL_KEY_BYTES
            || value.len() > MAX_VOLUME_LABEL_VALUE_BYTES
            || key.contains(&0)
            || value.contains(&0)
            || std::str::from_utf8(&key).is_err()
            || std::str::from_utf8(&value).is_err()
        {
            return Err(IntentError::InvalidVolumeLabel);
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

impl std::fmt::Debug for VolumeLabel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("VolumeLabel([redacted])")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::observation::ResourceRef;
    use crate::target::{TargetIdentity, TargetIntent, TargetResource};

    fn volume(labels: Vec<VolumeLabel>) -> TargetResource {
        TargetResource::Volume {
            reference: ResourceRef::new(1),
            identity: TargetIdentity::new(b"task_volume".to_vec()).unwrap(),
            labels,
        }
    }

    fn label(key: &[u8], value: &[u8]) -> VolumeLabel {
        VolumeLabel::new(key.to_vec(), value.to_vec()).unwrap()
    }

    #[test]
    fn volume_label_byte_boundaries_and_private_errors() {
        assert!(VolumeLabel::new(vec![b'k'; 128], vec![b'v'; 4096]).is_ok());
        for (key, value) in [
            (vec![], vec![]),
            (vec![b'k'; 129], vec![]),
            (b"key".to_vec(), vec![b'v'; 4097]),
            (b"private\0key".to_vec(), vec![]),
            (b"private".to_vec(), b"value\0private".to_vec()),
            (vec![0xff], vec![]),
            (b"key".to_vec(), vec![0xff]),
        ] {
            let error = VolumeLabel::new(key, value).unwrap_err();
            assert_eq!(error, IntentError::InvalidVolumeLabel);
            assert!(!format!("{error:?}").contains("private"));
        }
        assert_eq!(label(b"empty", b"").value(), b"");
        assert!(!format!("{:?}", label(b"private-key", b"private-value")).contains("private"));
    }

    #[test]
    fn volume_label_count_total_and_duplicates_fail_before_planning() {
        let labels = (0..64)
            .map(|index| label(format!("key-{index}").as_bytes(), b""))
            .collect();
        assert!(TargetIntent::new(vec![volume(labels)]).is_ok());
        let labels = (0..65)
            .map(|index| label(format!("key-{index}").as_bytes(), b""))
            .collect();
        assert_eq!(
            TargetIntent::new(vec![volume(labels)]).unwrap_err(),
            IntentError::InvalidVolumeLabel
        );
        let labels = (0..4)
            .map(|index| label(format!("{index}").as_bytes(), &vec![b'v'; 4095]))
            .collect();
        assert!(TargetIntent::new(vec![volume(labels)]).is_ok());
        let labels = (0..4)
            .map(|index| {
                label(
                    format!("{index}").as_bytes(),
                    &vec![b'v'; 4095 + usize::from(index == 3)],
                )
            })
            .collect();
        assert_eq!(
            TargetIntent::new(vec![volume(labels)]).unwrap_err(),
            IntentError::InvalidVolumeLabel
        );
        assert_eq!(
            TargetIntent::new(vec![volume(vec![
                label(b"private-key", b"one"),
                label(b"private-key", b"two")
            ])])
            .unwrap_err(),
            IntentError::DuplicateVolumeLabel
        );
    }
}
