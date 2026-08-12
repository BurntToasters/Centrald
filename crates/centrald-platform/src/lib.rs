#![forbid(unsafe_code)]

pub mod broker;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceKind {
    ClientDaemon,
    PrivilegedBroker,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MachineAction {
    Restart,
}
