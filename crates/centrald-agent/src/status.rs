//! Machine facts and health: OS, CPU, memory, disks, addresses, failed
//! services, and pending updates.

use std::net::IpAddr;
use std::path::Path;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use centrald_proto::limits::{MAX_ADDRESSES, MAX_DISKS, MAX_FAILED_UNITS};
use centrald_proto::wire::{Disk, OsInfo, Status, Updates, Usage};
use sysinfo::{Disks, Networks, System};

use crate::process::run_capture;

pub fn os_info() -> OsInfo {
    OsInfo {
        family: std::env::consts::OS.to_owned(),
        id: System::distribution_id(),
        name: System::long_os_version()
            .or_else(System::name)
            .unwrap_or_default(),
        version: System::os_version().unwrap_or_default(),
        kernel: System::kernel_version().unwrap_or_default(),
        arch: std::env::consts::ARCH.to_owned(),
    }
}

pub fn hostname() -> String {
    System::host_name().unwrap_or_default()
}

/// Pending-update facts shared between the periodic checker and actions.
pub type SharedUpdates = Arc<Mutex<Option<Updates>>>;

#[derive(Debug)]
pub struct Collector {
    system: System,
    disks: Disks,
    networks: Networks,
    failed_units: Option<Vec<String>>,
    failed_checked: Option<Instant>,
    updates: SharedUpdates,
}

const PSEUDO_FILESYSTEMS: &[&str] = &[
    "tmpfs",
    "devtmpfs",
    "overlay",
    "squashfs",
    "proc",
    "sysfs",
    "efivarfs",
    "ramfs",
    "autofs",
    "devpts",
    "cgroup",
    "cgroup2",
    "fuse.lxcfs",
    "nsfs",
    "tracefs",
];

impl Collector {
    pub fn new(updates: SharedUpdates) -> Self {
        let mut system = System::new();
        system.refresh_cpu_usage();
        Self {
            system,
            disks: Disks::new_with_refreshed_list(),
            networks: Networks::new_with_refreshed_list(),
            failed_units: None,
            failed_checked: None,
            updates,
        }
    }

    /// Takes one sample. Blocking: call from the blocking pool.
    pub fn sample(&mut self) -> Status {
        self.system.refresh_cpu_usage();
        self.system.refresh_memory();
        self.disks.refresh(true);
        self.networks.refresh(true);

        let mut disks: Vec<Disk> = Vec::new();
        for disk in &self.disks {
            let filesystem = disk.file_system().to_string_lossy().into_owned();
            let mount = disk.mount_point().to_string_lossy().into_owned();
            if disk.total_space() == 0
                || PSEUDO_FILESYSTEMS.contains(&filesystem.as_str())
                || disk.is_read_only()
                || mount.starts_with("/snap/")
                || disks.iter().any(|d| d.mount == mount)
            {
                continue;
            }
            disks.push(Disk {
                mount,
                filesystem,
                total_bytes: disk.total_space(),
                used_bytes: disk.total_space().saturating_sub(disk.available_space()),
            });
        }
        disks.sort_by(|a, b| a.mount.cmp(&b.mount));
        disks.truncate(MAX_DISKS);

        let mut addresses: Vec<String> = Vec::new();
        for (_, network) in &self.networks {
            for ip in network.ip_networks() {
                let usable = match ip.addr {
                    IpAddr::V4(v4) => !v4.is_loopback() && !v4.is_link_local(),
                    IpAddr::V6(v6) => !v6.is_loopback() && (v6.segments()[0] & 0xffc0) != 0xfe80,
                };
                let text = ip.addr.to_string();
                if usable && !addresses.contains(&text) {
                    addresses.push(text);
                }
            }
        }
        // IPv4 first: that is what people type.
        addresses.sort_by_key(|a| a.contains(':'));
        addresses.truncate(MAX_ADDRESSES);

        let refresh_units = self
            .failed_checked
            .is_none_or(|at| at.elapsed() > Duration::from_secs(60));
        if refresh_units {
            self.failed_units = failed_units();
            self.failed_checked = Some(Instant::now());
        }

        let load = if cfg!(windows) {
            None
        } else {
            let average = System::load_average();
            #[allow(clippy::cast_possible_truncation)]
            Some([
                average.one as f32,
                average.five as f32,
                average.fifteen as f32,
            ])
        };

        Status {
            uptime_seconds: System::uptime(),
            cpu_percent: self.system.global_cpu_usage(),
            cpu_count: u32::try_from(self.system.cpus().len()).unwrap_or(u32::MAX),
            load,
            memory: Usage {
                total_bytes: self.system.total_memory(),
                used_bytes: self.system.used_memory(),
            },
            swap: Usage {
                total_bytes: self.system.total_swap(),
                used_bytes: self.system.used_swap(),
            },
            disks,
            addresses,
            updates: self
                .updates
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone(),
            failed_units: self.failed_units.clone(),
        }
    }
}

fn systemctl() -> Option<&'static str> {
    ["/usr/bin/systemctl", "/bin/systemctl"]
        .into_iter()
        .find(|path| Path::new(path).exists())
}

/// Failed systemd units, or `None` where systemd is not running.
fn failed_units() -> Option<Vec<String>> {
    if !Path::new("/run/systemd/system").exists() {
        return None;
    }
    let output = run_capture(
        systemctl()?,
        &[
            "list-units",
            "--state=failed",
            "--plain",
            "--no-legend",
            "--no-pager",
        ],
        Duration::from_secs(10),
    )?;
    let mut units: Vec<String> = output
        .stdout
        .lines()
        .filter_map(|line| line.split_whitespace().next())
        .filter(|unit| unit.contains('.'))
        .map(str::to_owned)
        .collect();
    units.truncate(MAX_FAILED_UNITS);
    Some(units)
}

pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Package manager detected on this machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Manager {
    Apt,
    Dnf,
    Pacman,
}

impl Manager {
    pub fn detect() -> Option<Self> {
        if Path::new("/usr/bin/apt-get").exists() {
            Some(Self::Apt)
        } else if Path::new("/usr/bin/dnf").exists() {
            Some(Self::Dnf)
        } else if Path::new("/usr/bin/pacman").exists() {
            Some(Self::Pacman)
        } else {
            None
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Apt => "apt",
            Self::Dnf => "dnf",
            Self::Pacman => "pacman",
        }
    }
}

/// Counts pending updates from the package manager's existing metadata
/// (no network refresh). Blocking.
pub fn check_updates() -> Option<Updates> {
    let manager = Manager::detect()?;
    let timeout = Duration::from_secs(300);
    let pending = match manager {
        Manager::Apt => {
            let output = run_capture(
                "/usr/bin/apt-get",
                &["-s", "-o", "Debug::NoLocking=1", "upgrade"],
                timeout,
            )?;
            output
                .stdout
                .lines()
                .filter(|l| l.starts_with("Inst "))
                .count()
        }
        Manager::Dnf => {
            let output = run_capture(
                "/usr/bin/dnf",
                &["-q", "--cacheonly", "check-update"],
                timeout,
            )?;
            // Exit 100 means updates are available; 0 means none.
            match output.code {
                Some(100) => output
                    .stdout
                    .lines()
                    .take_while(|l| !l.starts_with("Obsoleting"))
                    .filter(|l| l.split_whitespace().count() == 3 && !l.starts_with(' '))
                    .count(),
                Some(0) => 0,
                _ => return None,
            }
        }
        Manager::Pacman => {
            let output = run_capture("/usr/bin/pacman", &["-Qu"], timeout)?;
            output
                .stdout
                .lines()
                .filter(|l| !l.trim().is_empty())
                .count()
        }
    };
    Some(Updates {
        manager: manager.name().to_owned(),
        pending: u32::try_from(pending).unwrap_or(u32::MAX),
        reboot_required: reboot_required(manager),
        checked_at: unix_now(),
    })
}

fn reboot_required(manager: Manager) -> bool {
    match manager {
        Manager::Apt => Path::new("/var/run/reboot-required").exists(),
        Manager::Dnf => {
            Path::new("/usr/bin/needs-restarting").exists()
                && run_capture(
                    "/usr/bin/needs-restarting",
                    &["-r"],
                    Duration::from_secs(60),
                )
                .is_some_and(|o| o.code == Some(1))
        }
        Manager::Pacman => {
            // Arch removes the running kernel's modules when it upgrades.
            System::kernel_version()
                .is_some_and(|kernel| !Path::new("/usr/lib/modules").join(kernel).exists())
        }
    }
}
