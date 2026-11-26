//! Test-only PID-1 fork witness. Never invoke on the development host.
//! The separate collector, not this program, establishes controller authority.

#[cfg(target_os = "linux")]
#[path = "native-pids-controller/mod.rs"]
mod controller;

#[cfg(target_os = "linux")]
mod linux {
    use std::fs::File;
    use std::io::Read;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
    use std::sync::atomic::{AtomicBool, Ordering};

    const CLEANUP_NS: u64 = 46_000_000_000;
    const MAX_RUN_NS: u64 = 180_000_000_000;
    const LINE_MAX: usize = 4096;
    const MAX_CHILDREN: usize = 32;
    static CANCELLED: AtomicBool = AtomicBool::new(false);
    type Result<T> = std::result::Result<T, &'static str>;

    extern "C" fn cancel(_: libc::c_int) {
        CANCELLED.store(true, Ordering::Relaxed);
    }

    fn now() -> Result<u64> {
        let mut ts = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // SAFETY: ts is writable for the duration of the call.
        if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) } != 0 {
            return Err("clock");
        }
        u64::try_from(ts.tv_sec)
            .ok()
            .and_then(|s| s.checked_mul(1_000_000_000))
            .and_then(|s| s.checked_add(u64::try_from(ts.tv_nsec).ok()?))
            .ok_or("clock")
    }

    #[derive(Clone, Debug, PartialEq)]
    struct Config {
        case: String,
        nonce: String,
        deadline: u64,
        finite16: bool,
    }

    fn config(args: &[String], current: u64) -> Result<Config> {
        if args.len() != 3
            || !matches!(
                args[0].as_str(),
                "cli16"
                    | "cli64"
                    | "cli_unlimited"
                    | "rendered16"
                    | "rendered64"
                    | "rendered_unlimited"
            )
        {
            return Err("arguments");
        }
        if args[1].len() != 32
            || !args[1]
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            return Err("arguments");
        }
        let deadline: u64 = args[2].parse().map_err(|_| "arguments")?;
        if deadline
            .checked_sub(current)
            .is_none_or(|left| left <= CLEANUP_NS || left > MAX_RUN_NS)
        {
            return Err("deadline");
        }
        Ok(Config {
            case: args[0].clone(),
            nonce: args[1].clone(),
            deadline,
            finite16: matches!(args[0].as_str(), "cli16" | "rendered16"),
        })
    }

    fn bounded_file(path: &str) -> Result<Vec<u8>> {
        let mut bytes = Vec::new();
        File::open(path)
            .map_err(|_| "identity")?
            .take(8193)
            .read_to_end(&mut bytes)
            .map_err(|_| "identity")?;
        if bytes.len() > 8192 {
            return Err("identity");
        }
        Ok(bytes)
    }

    fn single_threaded() -> Result<()> {
        let status = bounded_file("/proc/self/status")?;
        let text = std::str::from_utf8(&status).map_err(|_| "identity")?;
        if text
            .lines()
            .filter(|s| s.starts_with("Threads:"))
            .collect::<Vec<_>>()
            != ["Threads:\t1"]
        {
            return Err("identity");
        }
        Ok(())
    }

    fn stat(fd: RawFd) -> Result<libc::stat> {
        // SAFETY: zero is valid initial storage for stat; fstat initializes it.
        let mut value: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(fd, &mut value) } != 0 {
            return Err("custody");
        }
        Ok(value)
    }

    fn owned_fd(fd: RawFd) -> Result<OwnedFd> {
        if fd < 0 {
            return Err("custody");
        }
        // SAFETY: only fresh successful descriptors are passed here.
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }

    struct Channel {
        dir: OwnedFd,
        commands: OwnedFd,
        events: OwnedFd,
    }

    impl Channel {
        fn open() -> Result<Self> {
            let dir = owned_fd(unsafe {
                libc::open(
                    c"/dl-pids-control".as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            })?;
            let ds = stat(dir.as_raw_fd())?;
            if ds.st_mode & libc::S_IFMT != libc::S_IFDIR
                || ds.st_mode & 0o7777 != 0o700
                || ds.st_uid != unsafe { libc::geteuid() }
            {
                return Err("custody");
            }
            let commands = owned_fd(unsafe {
                libc::openat(
                    dir.as_raw_fd(),
                    c"commands".as_ptr(),
                    libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            })?;
            // The independently owned harness must already hold the event reader.
            let events = owned_fd(unsafe {
                libc::openat(
                    dir.as_raw_fd(),
                    c"events".as_ptr(),
                    libc::O_WRONLY | libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            })?;
            let channel = Self {
                dir,
                commands,
                events,
            };
            channel.recheck()?;
            Ok(channel)
        }

        fn recheck(&self) -> Result<()> {
            let ds = stat(self.dir.as_raw_fd())?;
            let fresh_dir = owned_fd(unsafe {
                libc::open(
                    c"/dl-pids-control".as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            })?;
            let current = stat(fresh_dir.as_raw_fd())?;
            if ds.st_dev != current.st_dev
                || ds.st_ino != current.st_ino
                || ds.st_nlink == 0
                || ds.st_mode & 0o7777 != 0o700
                || ds.st_uid != unsafe { libc::geteuid() }
            {
                return Err("custody");
            }
            for (fd, name) in [
                (self.commands.as_raw_fd(), c"commands"),
                (self.events.as_raw_fd(), c"events"),
            ] {
                let held = stat(fd)?;
                let mut named: libc::stat = unsafe { std::mem::zeroed() };
                if unsafe {
                    libc::fstatat(
                        self.dir.as_raw_fd(),
                        name.as_ptr(),
                        &mut named,
                        libc::AT_SYMLINK_NOFOLLOW,
                    )
                } != 0
                    || held.st_dev != named.st_dev
                    || held.st_ino != named.st_ino
                    || held.st_mode & libc::S_IFMT != libc::S_IFIFO
                    || held.st_mode & 0o7777 != 0o600
                    || held.st_nlink != 1
                    || named.st_nlink != 1
                    || held.st_uid != ds.st_uid
                {
                    return Err("custody");
                }
            }
            let a = stat(self.commands.as_raw_fd())?;
            let b = stat(self.events.as_raw_fd())?;
            if a.st_dev == b.st_dev && a.st_ino == b.st_ino {
                return Err("custody");
            }
            Ok(())
        }

        fn event(
            &self,
            config: &Config,
            phase: &'static str,
            ledger: &Ledger,
            witness: Option<(i32, i32)>,
            deadline: u64,
        ) -> Result<()> {
            self.recheck()?;
            let mut value = serde_json::json!({"schema":"dockerlens-pids-worker-v1", "case":config.case, "nonce":config.nonce, "phase":phase, "pid":1, "threads":1, "children":ledger.live(), "child_count":ledger.count(), "fork_return":null, "errno":null, "eagain":libc::EAGAIN});
            if let Some((ret, errno)) = witness {
                value["fork_return"] = ret.into();
                value["errno"] = errno.into();
            }
            let mut line = serde_json::to_vec(&value).map_err(|_| "protocol")?;
            line.push(b'\n');
            if line.len() > LINE_MAX {
                return Err("protocol");
            }
            loop {
                if now()? >= deadline {
                    return Err("deadline");
                }
                let write = || {
                    let written = unsafe {
                        libc::write(self.events.as_raw_fd(), line.as_ptr().cast(), line.len())
                    };
                    let errno = if written < 0 {
                        unsafe { *libc::__errno_location() }
                    } else {
                        0
                    };
                    Ok((written, errno))
                };
                let (written, errno) = if phase == "finished" {
                    publish_finished(write)?
                } else {
                    write()?
                };
                if written == line.len() as isize {
                    return Ok(());
                }
                if written >= 0 || (errno != libc::EINTR && errno != libc::EAGAIN) {
                    return Err("protocol");
                }
                pause(self.events.as_raw_fd(), libc::POLLOUT)?;
            }
        }

        fn command(&self, config: &Config, expected: &str, ledger: &mut Ledger) -> Result<()> {
            let mut bytes = [0_u8; LINE_MAX];
            let mut used = 0;
            ledger.held()?;
            loop {
                active(config)?;
                let mut byte = 0;
                let read = unsafe {
                    libc::read(self.commands.as_raw_fd(), (&mut byte as *mut u8).cast(), 1)
                };
                if read == 1 {
                    if used == LINE_MAX - 1 {
                        return Err("protocol");
                    }
                    if byte == b'\n' {
                        self.recheck()?;
                        ledger.held()?;
                        return command(&bytes[..used], expected, &config.nonce);
                    }
                    bytes[used] = byte;
                    used += 1;
                } else {
                    let errno = if read < 0 {
                        unsafe { *libc::__errno_location() }
                    } else {
                        0
                    };
                    if read < 0 && errno != libc::EINTR && errno != libc::EAGAIN {
                        return Err("protocol");
                    }
                    if read == 0 {
                        // A FIFO with no current writer reports HUP immediately;
                        // retain a bounded wait instead of spinning on that HUP.
                        pause(-1, 0)?;
                    } else {
                        pause(self.commands.as_raw_fd(), libc::POLLIN)?;
                    }
                }
            }
        }
    }

    fn command(bytes: &[u8], expected: &str, nonce: &str) -> Result<()> {
        // Parsing into a Value would silently accept duplicate keys. Deserialize a
        // closed struct instead, which rejects duplicates and additional fields.
        struct Command {
            command: String,
            nonce: String,
        }
        // Use the existing serde dependency without enabling derive or changing
        // dependency features. The map visitor enforces duplicate-key refusal.
        impl<'de> serde::Deserialize<'de> for Command {
            fn deserialize<D: serde::Deserializer<'de>>(
                deserializer: D,
            ) -> std::result::Result<Self, D::Error> {
                struct Closed;
                impl<'de> serde::de::Visitor<'de> for Closed {
                    type Value = Command;
                    fn expecting(
                        &self,
                        formatter: &mut std::fmt::Formatter<'_>,
                    ) -> std::fmt::Result {
                        formatter.write_str("a closed worker command")
                    }
                    fn visit_map<M: serde::de::MapAccess<'de>>(
                        self,
                        mut map: M,
                    ) -> std::result::Result<Command, M::Error> {
                        use serde::de::Error;
                        let mut command = None;
                        let mut nonce = None;
                        while let Some(key) = map.next_key::<String>()? {
                            match key.as_str() {
                                "command" if command.is_none() => {
                                    command = Some(map.next_value::<String>()?)
                                }
                                "nonce" if nonce.is_none() => {
                                    nonce = Some(map.next_value::<String>()?)
                                }
                                _ => return Err(M::Error::custom("closed command")),
                            }
                        }
                        Ok(Command {
                            command: command.ok_or_else(|| M::Error::custom("closed command"))?,
                            nonce: nonce.ok_or_else(|| M::Error::custom("closed command"))?,
                        })
                    }
                }
                deserializer.deserialize_map(Closed)
            }
        }
        let c: Command = serde_json::from_slice(bytes).map_err(|_| "protocol")?;
        if c.command != expected || c.nonce != nonce {
            return Err("protocol");
        }
        Ok(())
    }

    fn pause(fd: RawFd, events: i16) -> Result<()> {
        let mut pfd = libc::pollfd {
            fd,
            events,
            revents: 0,
        };
        if unsafe { libc::poll(&mut pfd, 1, 20) } < 0
            && unsafe { *libc::__errno_location() } != libc::EINTR
        {
            return Err("protocol");
        }
        if pfd.revents & (libc::POLLERR | libc::POLLNVAL) != 0 {
            return Err("protocol");
        }
        Ok(())
    }

    fn active(config: &Config) -> Result<()> {
        if CANCELLED.load(Ordering::Relaxed) {
            return Err("cancelled");
        }
        if now()? >= config.deadline - CLEANUP_NS {
            return Err("deadline");
        }
        Ok(())
    }

    fn finished_stop(current: u64, deadline: u64, cancelled: bool) -> Result<bool> {
        if current >= deadline {
            return Err("deadline");
        }
        Ok(cancelled)
    }

    fn completion_transition<T>(
        cancelled_before: bool,
        publish: impl FnOnce() -> Result<T>,
    ) -> Result<T> {
        if cancelled_before {
            return Err("cancelled");
        }
        // Successful publication commits completion. Do not reinterpret a later
        // intentional owner signal as cancellation of the completed experiment.
        publish()
    }

    fn publish_finished<T>(publish: impl FnOnce() -> Result<T>) -> Result<T> {
        let mut blocked: libc::sigset_t = unsafe { std::mem::zeroed() };
        let mut previous: libc::sigset_t = unsafe { std::mem::zeroed() };
        if unsafe { libc::sigemptyset(&mut blocked) } != 0
            || unsafe { libc::sigaddset(&mut blocked, libc::SIGTERM) } != 0
            || unsafe { libc::sigaddset(&mut blocked, libc::SIGINT) } != 0
            || unsafe { libc::sigprocmask(libc::SIG_BLOCK, &blocked, &mut previous) } != 0
        {
            return Err("signals");
        }
        // The FIFO write is nonblocking and <= PIPE_BUF. Mask only this one
        // check/write, including failed attempts; polling never masks signals.
        let result = completion_transition(CANCELLED.load(Ordering::Relaxed), publish);
        if unsafe { libc::sigprocmask(libc::SIG_SETMASK, &previous, std::ptr::null_mut()) } != 0 {
            return Err("signals");
        }
        result
    }

    fn pipe() -> Result<(OwnedFd, OwnedFd)> {
        let mut fds = [-1; 2];
        if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
            return Err("pipe");
        }
        Ok((owned_fd(fds[0])?, owned_fd(fds[1])?))
    }

    struct Ledger {
        pids: [libc::pid_t; MAX_CHILDREN],
    }
    impl Ledger {
        fn new() -> Self {
            Self {
                pids: [0; MAX_CHILDREN],
            }
        }
        fn count(&self) -> usize {
            self.pids.iter().filter(|&&p| p > 0).count()
        }
        fn live(&self) -> Vec<libc::pid_t> {
            self.pids.iter().copied().filter(|&p| p > 0).collect()
        }
        fn insert(&mut self, pid: libc::pid_t) -> Result<()> {
            if pid <= 1 || self.pids.contains(&pid) {
                return Err("ledger");
            }
            let slot = self.pids.iter_mut().find(|p| **p == 0).ok_or("ledger")?;
            *slot = pid;
            Ok(())
        }
        fn held(&mut self) -> Result<()> {
            for pid in &mut self.pids {
                if *pid == 0 {
                    continue;
                }
                let mut status = 0;
                let ret = unsafe { libc::waitpid(*pid, &mut status, libc::WNOHANG) };
                if ret == *pid {
                    *pid = 0;
                    return Err("early-exit");
                }
                if ret < 0 && unsafe { *libc::__errno_location() } != libc::EINTR {
                    return Err("ledger");
                }
            }
            single_threaded()?;
            let bytes = bounded_file("/proc/self/task/1/children")?;
            let mut actual = std::str::from_utf8(&bytes)
                .map_err(|_| "ledger")?
                .split_ascii_whitespace()
                .map(|p| p.parse::<libc::pid_t>().map_err(|_| "ledger"))
                .collect::<Result<Vec<_>>>()?;
            let mut expected = self.live();
            actual.sort_unstable();
            expected.sort_unstable();
            if actual != expected {
                return Err("ledger");
            }
            Ok(())
        }
        fn reap(&mut self, deadline: u64) -> Result<()> {
            let mut valid = true;
            while self.count() != 0 {
                if now()? >= deadline {
                    return Err("cleanup");
                }
                for pid in &mut self.pids {
                    if *pid == 0 {
                        continue;
                    }
                    let mut status = 0;
                    let ret = unsafe { libc::waitpid(*pid, &mut status, libc::WNOHANG) };
                    if ret == *pid {
                        *pid = 0;
                        valid &= libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0;
                    } else if ret < 0 && unsafe { *libc::__errno_location() } != libc::EINTR {
                        valid = false;
                        // ECHILD is uncertainty, never a successful reap.
                        *pid = 0;
                    }
                }
                if self.count() != 0 {
                    pause(-1, 0)?;
                }
            }
            self.held()?;
            if !valid {
                return Err("cleanup");
            }
            Ok(())
        }
    }

    // Child branch: no Rust allocation, panic, destructors or std I/O. Every
    // called libc operation is async-signal-safe. Never return into Rust main.
    unsafe fn child(
        hold_read: RawFd,
        hold_write: RawFd,
        ready_read: RawFd,
        ready_write: RawFd,
        reset: &libc::sigaction,
    ) -> ! {
        unsafe {
            if libc::sigaction(libc::SIGTERM, reset, std::ptr::null_mut()) != 0
                || libc::sigaction(libc::SIGINT, reset, std::ptr::null_mut()) != 0
                || libc::sigaction(libc::SIGPIPE, reset, std::ptr::null_mut()) != 0
            {
                libc::_exit(110);
            }
            libc::close(hold_write);
            libc::close(ready_read);
            let byte = 1_u8;
            if libc::write(ready_write, (&byte as *const u8).cast(), 1) != 1 {
                libc::_exit(111);
            }
            libc::close(ready_write);
            let mut byte = 0_u8;
            loop {
                let ret = libc::read(hold_read, (&mut byte as *mut u8).cast(), 1);
                if ret == 0 {
                    libc::_exit(0);
                }
                if ret < 0 && *libc::__errno_location() == libc::EINTR {
                    continue;
                }
                libc::_exit(112);
            }
        }
    }

    fn fork_child(
        ledger: &mut Ledger,
        hold: &(OwnedFd, OwnedFd),
        ready: &(OwnedFd, OwnedFd),
        reset: &libc::sigaction,
    ) -> Result<(i32, i32)> {
        if ledger.count() == MAX_CHILDREN {
            return Err("ledger");
        }
        // Capture errno immediately after -1, before formatting or any other call.
        let pid = unsafe { libc::fork() };
        let errno = if pid == -1 {
            unsafe { *libc::__errno_location() }
        } else {
            0
        };
        if pid == 0 {
            unsafe {
                child(
                    hold.0.as_raw_fd(),
                    hold.1.as_raw_fd(),
                    ready.0.as_raw_fd(),
                    ready.1.as_raw_fd(),
                    reset,
                )
            }
        }
        if pid > 0 {
            ledger.insert(pid)?;
        }
        Ok((pid, errno))
    }

    fn ready_count(config: &Config, ledger: &mut Ledger, fd: RawFd, target: usize) -> Result<()> {
        let mut received = 0;
        while received < target {
            active(config)?;
            ledger.held()?;
            let mut byte = 0_u8;
            let ret = unsafe { libc::read(fd, (&mut byte as *mut u8).cast(), 1) };
            if ret == 1 && byte == 1 {
                received += 1;
            } else if ret < 0
                && matches!(
                    unsafe { *libc::__errno_location() },
                    libc::EINTR | libc::EAGAIN
                )
            {
                pause(fd, libc::POLLIN)?;
            } else {
                return Err("barrier");
            }
        }
        Ok(())
    }

    fn experiment(
        config: &Config,
        channel: &Channel,
        ledger: &mut Ledger,
        hold: &(OwnedFd, OwnedFd),
        ready: &(OwnedFd, OwnedFd),
        reset: &libc::sigaction,
    ) -> Result<()> {
        channel.command(config, "baseline", ledger)?;
        channel.event(
            config,
            "baseline",
            ledger,
            None,
            config.deadline - CLEANUP_NS,
        )?;
        channel.command(config, "attempt", ledger)?;
        for _ in 0..if config.finite16 { 15 } else { 32 } {
            active(config)?;
            let (pid, _) = fork_child(ledger, hold, ready, reset)?;
            if pid <= 0 {
                return Err("unexpected-fork");
            }
        }
        ready_count(config, ledger, ready.0.as_raw_fd(), ledger.count())?;
        channel.event(
            config,
            "attempt",
            ledger,
            None,
            config.deadline - CLEANUP_NS,
        )?;
        let witness = if config.finite16 {
            channel.command(config, "hold-failure", ledger)?;
            active(config)?;
            let result = fork_child(ledger, hold, ready, reset)?;
            if result != (-1, libc::EAGAIN) {
                return Err("unexpected-fork");
            }
            Some(result)
        } else {
            channel.command(config, "hold-control", ledger)?;
            None
        };
        ledger.held()?;
        channel.event(
            config,
            if config.finite16 {
                "hold-failure"
            } else {
                "hold-control"
            },
            ledger,
            witness,
            config.deadline - CLEANUP_NS,
        )?;
        channel.command(config, "release", ledger)
    }

    fn run() -> Result<()> {
        let args: Vec<_> = std::env::args_os()
            .skip(1)
            .take(4)
            .map(|arg| {
                if arg.len() > 80 {
                    return Err("arguments");
                }
                arg.into_string().map_err(|_| "arguments")
            })
            .collect::<Result<_>>()?;
        let config = config(&args, now()?)?;
        if unsafe { libc::getpid() } != 1 || unsafe { libc::getppid() } != 0 {
            return Err("identity");
        }
        single_threaded()?;
        let mut handler: libc::sigaction = unsafe { std::mem::zeroed() };
        handler.sa_sigaction = cancel as *const () as usize;
        unsafe {
            libc::sigemptyset(&mut handler.sa_mask);
        }
        for signal in [libc::SIGTERM, libc::SIGINT] {
            if unsafe { libc::sigaction(signal, &handler, std::ptr::null_mut()) } != 0 {
                return Err("signals");
            }
        }
        // SIGPIPE must be an ordinary fixed protocol error in PID1.
        let mut reset: libc::sigaction = unsafe { std::mem::zeroed() };
        reset.sa_sigaction = libc::SIG_DFL;
        unsafe {
            libc::sigemptyset(&mut reset.sa_mask);
        }
        if unsafe { libc::sigaction(libc::SIGCHLD, &reset, std::ptr::null_mut()) } != 0
            || unsafe { libc::sigprocmask(libc::SIG_SETMASK, &reset.sa_mask, std::ptr::null_mut()) }
                != 0
        {
            return Err("signals");
        }
        let mut ignored = reset;
        ignored.sa_sigaction = libc::SIG_IGN;
        if unsafe { libc::sigaction(libc::SIGPIPE, &ignored, std::ptr::null_mut()) } != 0 {
            return Err("signals");
        }
        let channel = Channel::open()?;
        let mut limits: libc::rlimit = unsafe { std::mem::zeroed() };
        let mut kernel: libc::utsname = unsafe { std::mem::zeroed() };
        if unsafe { libc::getrlimit(libc::RLIMIT_NPROC, &mut limits) } != 0
            || unsafe { libc::uname(&mut kernel) } != 0
        {
            return Err("identity");
        }
        let kernel_string = |bytes: &[libc::c_char]| -> Result<String> {
            let raw: Vec<u8> = bytes
                .iter()
                .take_while(|&&b| b != 0)
                .map(|&b| b as u8)
                .collect();
            String::from_utf8(raw).map_err(|_| "identity")
        };
        let identity = serde_json::json!({"schema":"dockerlens-pids-worker-v1", "case":config.case, "nonce":config.nonce,"phase":"identity", "pid":1,"threads":1,"rlimit_nproc_soft":limits.rlim_cur,"rlimit_nproc_hard":limits.rlim_max,"kernel_sysname":kernel_string(&kernel.sysname)?,"kernel_release":kernel_string(&kernel.release)?,"kernel_version":kernel_string(&kernel.version)?,"kernel_machine":kernel_string(&kernel.machine)?});
        let mut line = serde_json::to_vec(&identity).map_err(|_| "protocol")?;
        line.push(b'\n');
        if line.len() > LINE_MAX
            || unsafe { libc::write(channel.events.as_raw_fd(), line.as_ptr().cast(), line.len()) }
                != line.len() as isize
        {
            return Err("protocol");
        }
        let mut ledger = Ledger::new();
        ledger.held()?;
        let hold = pipe()?;
        let ready = pipe()?;
        if unsafe { libc::fcntl(ready.0.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK) } != 0 {
            return Err("pipe");
        }
        let result = experiment(&config, &channel, &mut ledger, &hold, &ready, &reset);
        // Always release and reap every exact known PID, including error paths.
        drop(hold.1);
        let cleanup = ledger.reap(config.deadline);
        if let Err(phase) = result.and(cleanup) {
            let _ = channel.event(&config, phase, &ledger, None, config.deadline);
            return Err(phase);
        }
        active(&config)?;
        channel.event(
            &config,
            "release",
            &ledger,
            None,
            config.deadline - CLEANUP_NS,
        )?;
        channel.command(&config, "reuse", &mut ledger)?;
        let reuse_hold = pipe()?;
        active(&config)?;
        let reuse_result = fork_child(&mut ledger, &reuse_hold, &ready, &reset);
        drop(reuse_hold.1);
        let reaped = ledger.reap(config.deadline);
        let (pid, errno) = reuse_result?;
        reaped?;
        if pid <= 1 || errno != 0 {
            return Err("reuse");
        }
        channel.event(
            &config,
            "reuse",
            &ledger,
            Some((pid, errno)),
            config.deadline - CLEANUP_NS,
        )?;
        channel.command(&config, "finish", &mut ledger)?;
        active(&config)?;
        ledger.held()?;
        channel.event(
            &config,
            "finished",
            &ledger,
            None,
            config.deadline - CLEANUP_NS,
        )?;
        // The root collector seals all six original init identities together.
        // Keep PID1 alive after completion; never accept another operation.
        // The native owner stops/removes this known fixture after its seal.
        loop {
            if finished_stop(now()?, config.deadline, CANCELLED.load(Ordering::Relaxed))? {
                return Ok(());
            }
            pause(-1, 0)?;
        }
    }

    pub fn main() {
        if run().is_err() {
            eprintln!("native-pids-worker: refused");
            std::process::exit(1);
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        #[test]
        fn closed_config_and_original_deadline() {
            let base = vec![
                "cli16".into(),
                "0123456789abcdef0123456789abcdef".into(),
                "100000000000".into(),
            ];
            assert!(config(&base, 0).unwrap().finite16);
            for name in [
                "cli64",
                "cli_unlimited",
                "rendered16",
                "rendered64",
                "rendered_unlimited",
            ] {
                let mut args = base.clone();
                args[0] = name.into();
                assert!(config(&args, 0).is_ok());
            }
            assert!(config(&base, 54_000_000_000).is_err());
            assert!(config(&base, 100_000_000_001).is_err());
            let mut args = base.clone();
            args[0] = "cli-unlimited".into();
            assert!(config(&args, 0).is_err());
            let mut args = base;
            args[1] = "A".repeat(32);
            assert!(config(&args, 0).is_err());
        }
        #[test]
        fn commands_reject_replay_extra_and_duplicate_fields() {
            assert!(command(br#"{"command":"attempt","nonce":"n"}"#, "attempt", "n").is_ok());
            for bytes in [
                br#"{"command":"release","nonce":"n"}"#.as_slice(),
                br#"{"command":"attempt","nonce":"old"}"#,
                br#"{"command":"attempt","nonce":"n","extra":1}"#,
                br#"{"command":"attempt","command":"attempt","nonce":"n"}"#,
            ] {
                assert!(command(bytes, "attempt", "n").is_err());
            }
        }
        #[test]
        fn bounded_exact_ledger_without_forking() {
            let mut ledger = Ledger::new();
            assert!(ledger.insert(1).is_err());
            for pid in 2..34 {
                ledger.insert(pid).unwrap();
            }
            assert_eq!(ledger.count(), 32);
            assert!(ledger.insert(34).is_err());
            assert!(ledger.insert(2).is_err());
            assert_eq!(ledger.live(), (2..34).collect::<Vec<_>>());
        }
        #[test]
        fn finished_idle_preserves_original_deadline_without_forking() {
            assert_eq!(finished_stop(99, 100, false), Ok(false));
            assert_eq!(finished_stop(99, 100, true), Ok(true));
            assert_eq!(finished_stop(100, 100, false), Err("deadline"));
            assert_eq!(finished_stop(100, 100, true), Err("deadline"));
        }
        #[test]
        fn completion_publication_commits_before_owner_stop_without_forking() {
            let cancelled = std::cell::Cell::new(false);
            let committed = completion_transition(cancelled.get(), || {
                // Deterministically model the owner receiving the committed line
                // and signalling before the publisher gets another instruction.
                cancelled.set(true);
                Ok(())
            });
            assert_eq!(committed, Ok(()));
            assert_eq!(finished_stop(99, 100, cancelled.get()), Ok(true));
            let called = std::cell::Cell::new(false);
            assert_eq!(
                completion_transition(true, || {
                    called.set(true);
                    Ok(())
                }),
                Err("cancelled")
            );
            assert!(!called.get());
            assert_eq!(
                completion_transition(false, || Err::<(), _>("protocol")),
                Err("protocol")
            );
        }
    }
}

#[cfg(target_os = "linux")]
fn serve_arguments(
    args: impl IntoIterator<Item = std::ffi::OsString>,
) -> Result<Vec<String>, &'static str> {
    let args = args
        .into_iter()
        .take(6)
        .map(|arg| {
            if arg.len() > 80 {
                return Err("arguments");
            }
            arg.into_string().map_err(|_| "arguments")
        })
        .collect::<Result<Vec<_>, _>>()?;
    if args.len() != 5 || args[0] != "serve" {
        return Err("arguments");
    }
    Ok(args)
}

#[cfg(target_os = "linux")]
fn main() {
    if std::env::args_os().nth(1).as_deref() == Some(std::ffi::OsStr::new("serve")) {
        let result =
            serve_arguments(std::env::args_os().skip(1)).and_then(|args| controller::run(&args));
        if result.is_err() {
            eprintln!("native-pids-worker: refused");
            std::process::exit(1);
        }
    } else {
        linux::main();
    }
}

#[cfg(all(test, target_os = "linux"))]
mod dispatch_tests {
    use super::*;
    #[test]
    fn serve_dispatch_arguments_are_closed_without_executing_controller() {
        let args = [
            "serve",
            "Run12345",
            "upstream-rootless",
            "0123456789abcdef0123456789abcdef",
            "100000000000",
        ]
        .map(std::ffi::OsString::from);
        assert!(serve_arguments(args.clone()).is_ok());
        assert!(serve_arguments(args[..4].iter().cloned()).is_err());
        let mut extra = args.to_vec();
        extra.push("extra".into());
        assert!(serve_arguments(extra).is_err());
        let mut wrong = args.clone();
        wrong[0] = "cli16".into();
        assert!(serve_arguments(wrong).is_err());
        let mut oversized = args.clone();
        oversized[1] = "x".repeat(81).into();
        assert!(serve_arguments(oversized).is_err());
        use std::os::unix::ffi::OsStringExt;
        let mut invalid = args;
        invalid[1] = std::ffi::OsString::from_vec(vec![0xff]);
        assert!(serve_arguments(invalid).is_err());
    }
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("native-pids-worker: refused");
    std::process::exit(1);
}
