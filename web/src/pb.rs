//! Generated gRPC clients, reconstructed into the proto package module tree so
//! prost's cross-package references (e.g. lore.repository.v1 -> lore.model.v1)
//! resolve.
#![allow(clippy::all)]
#![allow(dead_code)]

pub mod lore {
    pub mod model {
        pub mod v1 {
            include!(concat!(env!("OUT_DIR"), "/lore.model.v1.rs"));
        }
    }
    pub mod repository {
        pub mod v1 {
            include!(concat!(env!("OUT_DIR"), "/lore.repository.v1.rs"));
        }
    }
    pub mod revision {
        pub mod v1 {
            include!(concat!(env!("OUT_DIR"), "/lore.revision.v1.rs"));
        }
    }
    pub mod thin_client {
        pub mod v1 {
            include!(concat!(env!("OUT_DIR"), "/lore.thin_client.v1.rs"));
        }
    }
    pub mod storage {
        pub mod v1 {
            include!(concat!(env!("OUT_DIR"), "/lore.storage.v1.rs"));
        }
    }
}

pub mod epic_urc {
    include!(concat!(env!("OUT_DIR"), "/epic_urc.rs"));
}
