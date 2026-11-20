//! Hard bounds shared by both ends of the agent connection.

/// Largest WebSocket message either side accepts.
pub const MAX_MESSAGE_BYTES: usize = 256 * 1024;

/// Largest chunk of command or terminal output carried by one message.
pub const MAX_CHUNK_BYTES: usize = 32 * 1024;

/// Longest command line an operator may submit.
pub const MAX_COMMAND_BYTES: usize = 16 * 1024;

/// Command timeout bounds, in seconds.
pub const MIN_TIMEOUT_SECONDS: u32 = 1;
pub const DEFAULT_TIMEOUT_SECONDS: u32 = 300;
pub const MAX_TIMEOUT_SECONDS: u32 = 6 * 60 * 60;

/// Concurrent work one agent accepts.
pub const MAX_CONCURRENT_EXECS: usize = 8;
pub const MAX_CONCURRENT_TERMINALS: usize = 4;

/// Terminal geometry bounds.
pub const MAX_TERMINAL_COLUMNS: u16 = 500;
pub const MAX_TERMINAL_ROWS: u16 = 200;

/// Bounds applied to every agent-reported status before it is stored.
pub const MAX_TEXT_BYTES: usize = 256;
pub const MAX_DISKS: usize = 64;
pub const MAX_ADDRESSES: usize = 32;
pub const MAX_FAILED_UNITS: usize = 64;

/// Seconds between agent status reports.
pub const STATUS_INTERVAL_SECONDS: u32 = 15;
