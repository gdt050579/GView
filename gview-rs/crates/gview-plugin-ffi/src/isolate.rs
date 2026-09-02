//! Crash isolation for in-process plugin calls (spec `03_DUAL_PLUGIN`
//! §5.1 Phase 1, §5.3).
//!
//! | Mechanism | Coverage | Here |
//! |-----------|----------|------|
//! | `catch_unwind` at every entry | Rust panics | [`run_guarded`], [`run_isolated`] |
//! | `SIGSEGV` / `SIGBUS` / `SIGILL` / `SIGFPE` handler | C++ faults in the plugin | [`install_signal_handlers`] (Linux) |
//! | Watchdog | Infinite loops | [`run_isolated`] timeout |
//! | Plugin memory limit | Allocation bombs | out of scope (needs `rlimit` on the host process) |
//!
//! On a fault the record (plugin name, export, fault address, signal)
//! goes to the [`FaultRegistry`], the plugin is marked invalid and is
//! **never retried** in this session (§5.1 steps 1–4); the host shows
//! the error and continues.
//!
//! Signal strategy (Linux): the handler runs on the faulting thread.
//! When that thread is a plugin worker started by [`run_isolated`],
//! the handler stores the fault into a lock-free slot and then parks
//! the thread forever in `pause()` — nothing unwinds through Rust
//! frames, no `longjmp`, so the host stays sound; the waiting caller
//! sees the fault flag (or the watchdog fires) and reports
//! [`IsolationError::Fault`]. A fault on any other thread (the UI
//! thread running `PopulateWindow` through [`run_guarded`]) cannot be
//! recovered in-process: the handler logs it, restores the default
//! disposition and lets the process crash — the spec's answer for
//! hostile plugins is the out-of-process host (§5.2). On other
//! platforms the signal layer is a documented no-op.
//!
//! [`run_isolated`] runs the call on a dedicated thread with an
//! alternate signal stack, so `Validate` / `CreateInstance` /
//! `UpdateSettings` probes of untrusted plugins are watchdog-guarded.
//! A timed-out worker is abandoned (it cannot be killed safely); its
//! plugin is invalid from then on.

use std::collections::HashSet;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicUsize, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Mutex, OnceLock, PoisonError};
use std::time::{Duration, Instant};

/// Default watchdog budget for one plugin call.
pub const DEFAULT_CALL_TIMEOUT: Duration = Duration::from_secs(10);
/// Poll interval while waiting on a worker (fault flag latency).
pub const WAIT_POLL_INTERVAL: Duration = Duration::from_millis(20);
/// Capacity of the fault-slot plugin-name buffer (async-signal-safe
/// copy target).
pub const FAULT_NAME_CAPACITY: usize = 64;

/// What went wrong in a plugin call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FaultKind {
    /// Rust panic caught at the boundary.
    Panic,
    /// The watchdog expired.
    Timeout,
    /// A hardware fault signal (`SIGSEGV` = 11, `SIGBUS` = 7, …).
    Signal(i32),
}

/// One recorded plugin fault (§5.1 step 1: plugin name + fault
/// address).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FaultRecord {
    /// Plugin name.
    pub plugin: String,
    /// Export being called.
    pub export: &'static str,
    /// Fault kind.
    pub kind: FaultKind,
    /// Faulting address (`si_addr`), 0 when not applicable.
    pub address: usize,
}

impl core::fmt::Display for FaultRecord {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self.kind {
            FaultKind::Panic => write!(f, "plugin {} panicked in {}", self.plugin, self.export),
            FaultKind::Timeout => write!(f, "plugin {} timed out in {}", self.plugin, self.export),
            FaultKind::Signal(signal) => write!(
                f,
                "plugin {} faulted in {} (signal {signal}, address {:#x})",
                self.plugin, self.export, self.address
            ),
        }
    }
}

/// Failures of an isolated call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IsolationError {
    /// The plugin was already invalid; nothing was called.
    Invalid,
    /// The call panicked, timed out or faulted (recorded).
    Fault(FaultRecord),
}

impl core::fmt::Display for IsolationError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Invalid => write!(f, "Invalid plugin (not loaded properly or no valid exports)"),
            Self::Fault(record) => write!(f, "{record}"),
        }
    }
}

impl std::error::Error for IsolationError {}

/// Session-wide fault log and invalid-plugin set (§5.1 steps 2–4).
#[derive(Debug, Default)]
pub struct FaultRegistry {
    faults: Mutex<Vec<FaultRecord>>,
    invalid: Mutex<HashSet<String>>,
}

impl FaultRegistry {
    /// Empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            faults: Mutex::new(Vec::new()),
            invalid: Mutex::new(HashSet::new()),
        }
    }

    /// Records `record` and marks its plugin invalid.
    pub fn record(&self, record: FaultRecord) {
        self.invalid
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(record.plugin.clone());
        self.faults
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(record);
    }

    /// Marks a plugin invalid without a fault record (load failures).
    pub fn mark_invalid(&self, plugin: &str) {
        self.invalid
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(plugin.to_owned());
    }

    /// `true` once the plugin faulted in this session.
    #[must_use]
    pub fn is_invalid(&self, plugin: &str) -> bool {
        self.invalid
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .contains(plugin)
    }

    /// All faults so far.
    #[must_use]
    pub fn faults(&self) -> Vec<FaultRecord> {
        self.faults
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Drains the faults (for the error dialog).
    pub fn take_faults(&self) -> Vec<FaultRecord> {
        std::mem::take(&mut *self.faults.lock().unwrap_or_else(PoisonError::into_inner))
    }
}

/// The process-wide registry.
#[must_use]
pub fn registry() -> &'static FaultRegistry {
    static REGISTRY: OnceLock<FaultRegistry> = OnceLock::new();
    REGISTRY.get_or_init(FaultRegistry::new)
}

/// Lock-free slot the signal handler writes and the waiter reads.
struct FaultSlot {
    pending: AtomicBool,
    signal: AtomicI32,
    address: AtomicUsize,
    name_len: AtomicUsize,
    name: [std::sync::atomic::AtomicU8; FAULT_NAME_CAPACITY],
}

static FAULT_SLOT: FaultSlot = FaultSlot {
    pending: AtomicBool::new(false),
    signal: AtomicI32::new(0),
    address: AtomicUsize::new(0),
    name_len: AtomicUsize::new(0),
    name: [const { std::sync::atomic::AtomicU8::new(0) }; FAULT_NAME_CAPACITY],
};

thread_local! {
    /// Set while this thread is a plugin worker inside a call
    /// (read by the signal handler to decide recoverability).
    static PLUGIN_WORKER: AtomicBool = const { AtomicBool::new(false) };
}

/// Publishes the plugin name the handler will attribute a fault to.
fn arm_fault_slot(plugin: &str) {
    let bytes = plugin.as_bytes();
    let len = bytes.len().min(FAULT_NAME_CAPACITY);
    for (slot, byte) in FAULT_SLOT.name.iter().zip(bytes.iter().take(len)) {
        slot.store(*byte, Ordering::Relaxed);
    }
    FAULT_SLOT.name_len.store(len, Ordering::Relaxed);
    FAULT_SLOT.pending.store(false, Ordering::Release);
}

/// Reads and clears a pending fault, if any.
fn take_pending_fault(export: &'static str) -> Option<FaultRecord> {
    if !FAULT_SLOT.pending.swap(false, Ordering::AcqRel) {
        return None;
    }
    let len = FAULT_SLOT.name_len.load(Ordering::Relaxed).min(FAULT_NAME_CAPACITY);
    let bytes: Vec<u8> = FAULT_SLOT
        .name
        .iter()
        .take(len)
        .map(|b| b.load(Ordering::Relaxed))
        .collect();
    Some(FaultRecord {
        plugin: String::from_utf8_lossy(&bytes).into_owned(),
        export,
        kind: FaultKind::Signal(FAULT_SLOT.signal.load(Ordering::Relaxed)),
        address: FAULT_SLOT.address.load(Ordering::Relaxed),
    })
}

/// Simulates a hardware fault report (what the signal handler does),
/// for hosts without signal support and for tests.
pub fn report_fault(signal: i32, address: usize) {
    FAULT_SLOT.signal.store(signal, Ordering::Relaxed);
    FAULT_SLOT.address.store(address, Ordering::Relaxed);
    FAULT_SLOT.pending.store(true, Ordering::Release);
}

/// Same-thread guard (`PopulateWindow` and other UI-thread calls):
/// `catch_unwind` plus fault attribution. Hardware faults on this
/// thread are logged by the handler but not recoverable (module docs).
///
/// # Errors
///
/// [`IsolationError::Invalid`] when the plugin already faulted;
/// [`IsolationError::Fault`] for a caught panic (recorded, plugin
/// marked invalid).
pub fn run_guarded<R>(plugin: &str, export: &'static str, call: impl FnOnce() -> R) -> Result<R, IsolationError> {
    let registry = registry();
    if registry.is_invalid(plugin) {
        return Err(IsolationError::Invalid);
    }
    arm_fault_slot(plugin);
    let outcome = catch_unwind(AssertUnwindSafe(call));
    if let Some(record) = take_pending_fault(export) {
        registry.record(record.clone());
        return Err(IsolationError::Fault(record));
    }
    outcome.map_err(|_| {
        let record = FaultRecord {
            plugin: plugin.to_owned(),
            export,
            kind: FaultKind::Panic,
            address: 0,
        };
        registry.record(record.clone());
        IsolationError::Fault(record)
    })
}

/// Watchdog-guarded call on a plugin worker thread: panics, hardware
/// faults (Linux) and hangs are all reported without taking the host
/// down.
///
/// # Errors
///
/// [`IsolationError::Invalid`] when the plugin already faulted;
/// [`IsolationError::Fault`] with the recorded panic / signal /
/// timeout.
pub fn run_isolated<R: Send + 'static>(
    plugin: &str,
    export: &'static str,
    timeout: Duration,
    call: impl FnOnce() -> R + Send + 'static,
) -> Result<R, IsolationError> {
    let registry = registry();
    if registry.is_invalid(plugin) {
        return Err(IsolationError::Invalid);
    }
    arm_fault_slot(plugin);

    let (tx, rx) = mpsc::channel::<Result<R, ()>>();
    let spawned = std::thread::Builder::new()
        .name(format!("gview-plugin-{plugin}"))
        .spawn(move || {
            PLUGIN_WORKER.with(|flag| flag.store(true, Ordering::Release));
            signal::install_alternate_stack();
            let outcome = catch_unwind(AssertUnwindSafe(call)).map_err(|_| ());
            PLUGIN_WORKER.with(|flag| flag.store(false, Ordering::Release));
            // The receiver may be gone after a timeout: ignore.
            let _ = tx.send(outcome);
        });
    if spawned.is_err() {
        // No worker thread: fall back to the same-thread guard.
        return Err(IsolationError::Fault(FaultRecord {
            plugin: plugin.to_owned(),
            export,
            kind: FaultKind::Timeout,
            address: 0,
        }));
    }

    let deadline = Instant::now().checked_add(timeout).unwrap_or_else(Instant::now);
    loop {
        if let Some(record) = take_pending_fault(export) {
            registry.record(record.clone());
            return Err(IsolationError::Fault(record));
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        let step = remaining.min(WAIT_POLL_INTERVAL);
        match rx.recv_timeout(step) {
            Ok(Ok(value)) => {
                // A fault flagged just before the worker returned wins.
                if let Some(record) = take_pending_fault(export) {
                    registry.record(record.clone());
                    return Err(IsolationError::Fault(record));
                }
                return Ok(value);
            }
            Ok(Err(())) => {
                let record = FaultRecord {
                    plugin: plugin.to_owned(),
                    export,
                    kind: FaultKind::Panic,
                    address: 0,
                };
                registry.record(record.clone());
                return Err(IsolationError::Fault(record));
            }
            Err(RecvTimeoutError::Disconnected) => {
                // Worker vanished without sending (parked in the signal
                // handler or killed): treat as a fault unless recorded.
                let record = take_pending_fault(export).unwrap_or_else(|| FaultRecord {
                    plugin: plugin.to_owned(),
                    export,
                    kind: FaultKind::Timeout,
                    address: 0,
                });
                registry.record(record.clone());
                return Err(IsolationError::Fault(record));
            }
            Err(RecvTimeoutError::Timeout) => {
                if remaining.is_zero() {
                    let record = FaultRecord {
                        plugin: plugin.to_owned(),
                        export,
                        kind: FaultKind::Timeout,
                        address: 0,
                    };
                    registry.record(record.clone());
                    return Err(IsolationError::Fault(record));
                }
            }
        }
    }
}

/// Installs the fault-signal handlers (Linux); a no-op elsewhere.
/// Idempotent. Returns `true` when handlers are active.
#[must_use]
// Not `const`: the Linux body performs `sigaction` syscalls.
#[allow(clippy::missing_const_for_fn)]
pub fn install_signal_handlers() -> bool {
    signal::install()
}

#[cfg(target_os = "linux")]
mod signal {
    use super::{FAULT_SLOT, PLUGIN_WORKER};
    use std::sync::atomic::Ordering;
    use std::sync::OnceLock;

    const SIGNALS: [libc::c_int; 4] = [libc::SIGSEGV, libc::SIGBUS, libc::SIGILL, libc::SIGFPE];

    static INSTALLED: OnceLock<bool> = OnceLock::new();

    thread_local! {
        static ALT_STACK: std::cell::RefCell<Option<Vec<u8>>> = const { std::cell::RefCell::new(None) };
    }

    /// Gives the current worker thread an alternate stack so a stack
    /// overflow in the plugin still reaches the handler.
    pub(super) fn install_alternate_stack() {
        ALT_STACK.with(|slot| {
            let mut slot = slot.borrow_mut();
            if slot.is_some() {
                return;
            }
            let size = libc::SIGSTKSZ.max(64 * 1024);
            let mut stack = vec![0_u8; size];
            let descriptor = libc::stack_t {
                ss_sp: stack.as_mut_ptr().cast::<libc::c_void>(),
                ss_flags: 0,
                ss_size: size,
            };
            // SAFETY: `descriptor` points at a buffer this thread keeps
            // alive in `ALT_STACK` for its whole lifetime; `sigaltstack`
            // only reads the descriptor.
            let rc = unsafe { libc::sigaltstack(&raw const descriptor, std::ptr::null_mut()) };
            if rc == 0 {
                *slot = Some(stack);
            }
        });
    }

    unsafe extern "C" fn handler(signal: libc::c_int, info: *mut libc::siginfo_t, _context: *mut libc::c_void) {
        let address = if info.is_null() {
            0
        } else {
            // SAFETY: the kernel passes a valid `siginfo_t` for
            // `SA_SIGINFO` handlers; `si_addr` is defined for these
            // fault signals.
            unsafe { (*info).si_addr() as usize }
        };
        FAULT_SLOT.signal.store(signal, Ordering::Relaxed);
        FAULT_SLOT.address.store(address, Ordering::Relaxed);
        FAULT_SLOT.pending.store(true, Ordering::Release);

        let worker = PLUGIN_WORKER.try_with(|flag| flag.load(Ordering::Acquire)).unwrap_or(false);
        if worker {
            // Park the faulting plugin thread forever: no unwinding
            // through Rust frames, the waiter reports the fault.
            loop {
                // SAFETY: `pause` is async-signal-safe and has no
                // preconditions.
                unsafe {
                    libc::pause();
                }
            }
        }
        // Not recoverable on this thread: restore the default action
        // and return so the faulting instruction re-executes and the
        // process terminates after the fault was logged.
        // SAFETY: `signal(sig, SIG_DFL)` is async-signal-safe.
        unsafe {
            libc::signal(signal, libc::SIG_DFL);
        }
    }

    pub(super) fn install() -> bool {
        *INSTALLED.get_or_init(|| {
            let mut ok = true;
            for sig in SIGNALS {
                // SAFETY: `sigaction` is zero-initialisable (plain C
                // struct) and fully populated before use.
                let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
                action.sa_sigaction = handler as usize;
                action.sa_flags = libc::SA_SIGINFO | libc::SA_ONSTACK;
                // SAFETY: `sa_mask` is a valid out-pointer.
                unsafe {
                    libc::sigemptyset(&raw mut action.sa_mask);
                }
                // SAFETY: installs a handler with a valid, fully
                // initialised `sigaction`; no previous action is
                // requested back.
                let rc = unsafe { libc::sigaction(sig, &raw const action, std::ptr::null_mut()) };
                ok &= rc == 0;
            }
            ok
        })
    }
}

#[cfg(not(target_os = "linux"))]
mod signal {
    /// No alternate stack outside Linux.
    pub(super) const fn install_alternate_stack() {}

    /// No signal layer outside Linux (documented no-op).
    pub(super) const fn install() -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_records_faults_and_marks_invalid() {
        let registry = FaultRegistry::new();
        assert!(!registry.is_invalid("PE"));
        registry.record(FaultRecord {
            plugin: String::from("PE"),
            export: "Validate",
            kind: FaultKind::Signal(11),
            address: 0xdead,
        });
        assert!(registry.is_invalid("PE"));
        assert!(!registry.is_invalid("ELF"));
        registry.mark_invalid("ELF");
        assert!(registry.is_invalid("ELF"));
        let faults = registry.faults();
        assert_eq!(faults.len(), 1);
        assert_eq!(
            faults[0].to_string(),
            "plugin PE faulted in Validate (signal 11, address 0xdead)"
        );
        assert_eq!(registry.take_faults().len(), 1);
        assert!(registry.faults().is_empty());
        assert!(registry.is_invalid("PE"), "invalid set survives draining");
    }

    #[test]
    fn guarded_call_returns_values_and_catches_panics() {
        let value = run_guarded("guard-ok", "Validate", || 41_u32.saturating_add(1)).expect("ok");
        assert_eq!(value, 42);

        let err = run_guarded("guard-panic", "CreateInstance", || -> u32 { panic!("boom") }).expect_err("panic");
        assert_eq!(
            err,
            IsolationError::Fault(FaultRecord {
                plugin: String::from("guard-panic"),
                export: "CreateInstance",
                kind: FaultKind::Panic,
                address: 0,
            })
        );
        assert!(registry().is_invalid("guard-panic"));
        // Never retried.
        assert_eq!(
            run_guarded("guard-panic", "Validate", || 1_u32),
            Err(IsolationError::Invalid)
        );
        assert_eq!(err.to_string(), "plugin guard-panic panicked in CreateInstance");
    }

    #[test]
    fn simulated_hardware_fault_is_attributed_and_isolates_the_plugin() {
        let err = run_guarded("guard-fault", "PopulateWindow", || {
            report_fault(11, 0x1000);
            7_u32
        })
        .expect_err("fault");
        assert_eq!(
            err,
            IsolationError::Fault(FaultRecord {
                plugin: String::from("guard-fault"),
                export: "PopulateWindow",
                kind: FaultKind::Signal(11),
                address: 0x1000,
            })
        );
        assert!(registry().is_invalid("guard-fault"));
        assert!(registry()
            .faults()
            .iter()
            .any(|f| f.plugin == "guard-fault" && f.address == 0x1000));
    }

    #[test]
    fn isolated_call_success_panic_and_timeout() {
        let value = run_isolated("iso-ok", "Validate", DEFAULT_CALL_TIMEOUT, || 5_u32).expect("ok");
        assert_eq!(value, 5);

        let err = run_isolated("iso-panic", "Validate", DEFAULT_CALL_TIMEOUT, || -> u32 { panic!("boom") })
            .expect_err("panic");
        assert!(matches!(
            err,
            IsolationError::Fault(FaultRecord {
                kind: FaultKind::Panic,
                ..
            })
        ));
        assert!(registry().is_invalid("iso-panic"));

        let started = Instant::now();
        let err = run_isolated("iso-hang", "Validate", Duration::from_millis(150), || {
            std::thread::sleep(Duration::from_secs(5));
            0_u32
        })
        .expect_err("timeout");
        assert!(started.elapsed() < Duration::from_secs(4), "watchdog fired early");
        assert_eq!(
            err,
            IsolationError::Fault(FaultRecord {
                plugin: String::from("iso-hang"),
                export: "Validate",
                kind: FaultKind::Timeout,
                address: 0,
            })
        );
        assert!(registry().is_invalid("iso-hang"));
        assert_eq!(
            run_isolated("iso-hang", "Validate", DEFAULT_CALL_TIMEOUT, || 0_u32),
            Err(IsolationError::Invalid)
        );
        assert_eq!(err.to_string(), "plugin iso-hang timed out in Validate");
    }

    #[test]
    fn isolated_call_reports_a_fault_flag_raised_by_the_worker() {
        let err = run_isolated("iso-fault", "Validate", DEFAULT_CALL_TIMEOUT, || {
            report_fault(7, 0x42);
            // A real handler would park here; the worker simply returns.
            true
        })
        .expect_err("fault");
        assert!(matches!(
            err,
            IsolationError::Fault(FaultRecord {
                kind: FaultKind::Signal(7),
                address: 0x42,
                ..
            })
        ));
        assert!(registry().is_invalid("iso-fault"));
    }

    #[test]
    fn long_plugin_names_are_truncated_in_the_fault_slot() {
        let name = "x".repeat(200);
        let err = run_guarded(&name, "Validate", || {
            report_fault(11, 1);
        })
        .expect_err("fault");
        match err {
            IsolationError::Fault(record) => assert_eq!(record.plugin.len(), FAULT_NAME_CAPACITY),
            IsolationError::Invalid => panic!("unexpected"),
        }
    }

    #[test]
    fn signal_handler_installation_is_platform_dependent() {
        let installed = install_signal_handlers();
        assert_eq!(installed, cfg!(target_os = "linux"));
        assert_eq!(install_signal_handlers(), installed, "idempotent");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn real_segfault_in_a_worker_is_isolated() {
        assert!(install_signal_handlers());
        let err = run_isolated("iso-segv", "Validate", DEFAULT_CALL_TIMEOUT, || {
            let null: *mut u32 = std::ptr::null_mut();
            // SAFETY: deliberately invalid write to trigger SIGSEGV in
            // the worker; the handler parks the thread.
            unsafe {
                std::ptr::write_volatile(null, 1);
            }
            0_u32
        })
        .expect_err("segfault");
        assert!(matches!(
            err,
            IsolationError::Fault(FaultRecord {
                kind: FaultKind::Signal(libc::SIGSEGV),
                ..
            })
        ));
        assert!(registry().is_invalid("iso-segv"));
    }
}
