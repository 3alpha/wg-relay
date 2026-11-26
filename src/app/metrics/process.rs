//! The standard `process_*` metrics, read from `/proc` on Linux.

use std::time::Duration;

use super::encoder::Encoder;

/// The process's resource use at one instant.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(in crate::app) struct Process {
    cpu: Duration,
    resident_bytes: u64,
    virtual_bytes: u64,
    open_fds: usize,
    /// The soft limit on open files, unless unlimited.
    max_fds: Option<u64>,
}

impl Process {
    /// Read the calling process's resource use; `None` where the platform does not tell it.
    pub(in crate::app) fn read() -> Option<Self> {
        #[cfg(target_os = "linux")]
        match linux::read() {
            Ok(p) => return Some(p),
            Err(e) => tracing::debug!(error = %e, "reading process metrics failed"),
        }
        None
    }
}

/// Encode the process metrics; the start time is known on every platform.
pub(super) fn encode(enc: &mut Encoder, process: Option<&Process>, started: Duration) {
    enc.gauge("process_start_time_seconds", "Start time of the process since the Unix epoch.")
        .value(started);
    let Some(p) = process else { return };
    enc.counter("process_cpu_seconds_total", "User and system CPU time spent.").value(p.cpu);
    enc.gauge("process_resident_memory_bytes", "Resident memory size.").value(p.resident_bytes);
    enc.gauge("process_virtual_memory_bytes", "Virtual memory size.").value(p.virtual_bytes);
    enc.gauge("process_open_fds", "Open file descriptors.").value(p.open_fds);
    if let Some(max) = p.max_fds {
        enc.gauge("process_max_fds", "Most open file descriptors allowed.").value(max);
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::io;
    use std::time::Duration;

    use super::Process;

    // Positions in /proc/self/stat after the parenthesised command name,
    // counted from the state field (field 3 in proc(5)).
    const UTIME: usize = 11;
    const STIME: usize = 12;
    const VSIZE: usize = 20;
    const RSS_PAGES: usize = 21;

    pub(super) fn read() -> io::Result<Process> {
        let stat = std::fs::read_to_string("/proc/self/stat")?;
        let fields = parse_stat(&stat)?;
        let field = |i: usize| fields.get(i).copied().ok_or_else(|| invalid("/proc/self/stat"));
        let ticks = rustix::param::clock_ticks_per_second().max(1);
        let cpu_ticks = field(UTIME)?.saturating_add(field(STIME)?);
        let page_bytes = rustix::param::page_size() as u64;
        Ok(Process {
            cpu: Duration::from_secs_f64(cpu_ticks as f64 / ticks as f64),
            resident_bytes: field(RSS_PAGES)?.saturating_mul(page_bytes),
            virtual_bytes: field(VSIZE)?,
            open_fds: std::fs::read_dir("/proc/self/fd")?.count(),
            max_fds: parse_max_open_files(&std::fs::read_to_string("/proc/self/limits")?),
        })
    }

    /// The numeric fields after the command name, which may itself hold spaces
    /// and parentheses; the state letter and other non-numbers read as 0.
    fn parse_stat(stat: &str) -> io::Result<Vec<u64>> {
        let (_, rest) = stat.rsplit_once(')').ok_or_else(|| invalid("/proc/self/stat"))?;
        Ok(rest.split_whitespace().map(|f| f.parse().unwrap_or(0)).collect())
    }

    /// The soft limit on the "Max open files" line of `/proc/self/limits`.
    fn parse_max_open_files(limits: &str) -> Option<u64> {
        let line = limits.lines().find(|l| l.starts_with("Max open files"))?;
        line.split_whitespace().nth(3)?.parse().ok()
    }

    fn invalid(what: &str) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidData, format!("unexpected format of {what}"))
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn parses_stat_fields_after_a_command_name_with_parentheses() {
            let stat = "42 (wg (relay)) S 1 42 42 0 -1 4194560 100 0 0 0 250 50 0 0 20 0 3 0 \
                        12345 104857600 2560 18446744073709551615";
            let fields = parse_stat(stat).unwrap();
            let get = |i: usize| fields[i];
            assert_eq!(
                (get(UTIME), get(STIME), get(VSIZE), get(RSS_PAGES)),
                (250, 50, 104857600, 2560)
            );
        }

        #[test]
        fn parses_the_soft_open_files_limit() {
            let limits = "Limit                     Soft Limit           Hard Limit           Units\n\
                          Max open files            1024                 524288               files\n";
            assert_eq!(parse_max_open_files(limits), Some(1024));
            let unlimited =
                "Max open files            unlimited            unlimited            files";
            assert_eq!(parse_max_open_files(unlimited), None);
        }

        #[test]
        fn reads_this_process() {
            let p = read().unwrap();
            assert!(p.resident_bytes > 0 && p.virtual_bytes >= p.resident_bytes, "{p:?}");
            assert!(p.open_fds > 0, "{p:?}");
        }
    }
}
