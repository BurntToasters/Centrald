#![forbid(unsafe_code)]

pub mod v1 {
    // Prost and tonic own the generated source shape; lint hand-written code at
    // workspace strictness while exempting only this generated module.
    #![allow(clippy::all, clippy::pedantic)]
    tonic::include_proto!("centrald.v1");
}

pub const PROTOCOL_MAJOR: u32 = 1;
pub const PROTOCOL_MINOR: u32 = 1;
