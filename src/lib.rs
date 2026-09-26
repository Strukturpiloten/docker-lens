//! Native Docker Engine contracts.
//!
//! This crate decodes bounded captures and plans inert standalone targets but does
//! not connect to a daemon or apply a plan. Native conformance evidence is required
//! before a release can pass.
//!
//! The public contract can be assembled without contacting a daemon:
//!
//! ```
//! use docker_lens::acquisition::{Endpoint, Limits, NativeId, Selector};
//! use docker_lens::observation::ResourceRef;
//! use docker_lens::target::{ContainerIntent, ImageReference, TargetIdentity, TargetIntent, TargetResource};
//! use std::time::Duration;
//!
//! let endpoint = Endpoint::unix_socket("/run/user/1000/docker.sock".into());
//! let selector = Selector::ContainerIds(vec![NativeId::new("example-id".into()).unwrap()]);
//! let limits = Limits {
//!     max_requests: 8, max_selected_resources: 2, max_expansions: 2,
//!     max_response_bytes: 1024, max_total_bytes: 4096,
//!     max_elapsed: Duration::from_secs(5),
//! }.validate().unwrap();
//! let intent = TargetIntent::new(vec![TargetResource::Container(Box::new(ContainerIntent {
//!     reference: ResourceRef::new(1),
//!     identity: TargetIdentity::new(b"example".to_vec()).unwrap(),
//!     image: ImageReference::new(b"example:1".to_vec()).unwrap(),
//!     environment: vec![],
//!     ports: vec![],
//!     mounts: vec![],
//!     network: None,
//!     entrypoint: None,
//!     command: None,
//!     healthcheck: None,
//!     restart: None,
//! }))]).unwrap();
//! assert!(endpoint.path().is_absolute());
//! assert!(matches!(selector, Selector::ContainerIds(_)));
//! assert_eq!(limits.max_requests, 8);
//! assert_eq!(intent.resources().len(), 1);
//! ```

#![forbid(unsafe_code)]

pub mod acquisition;
pub mod decoder;
pub mod evidence;
pub mod finding;
pub mod observation;
pub mod target;
pub mod version;
