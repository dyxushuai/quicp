//! Host-driven runtime for synchronous and FFI integrations.

use std::collections::VecDeque;
use std::fmt;
use std::future::Future;
use std::io;
use std::num::NonZeroUsize;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, Weak};
use std::task::{Context, Poll, Wake, Waker};
use std::time::{Duration, Instant};

use noq::{AsyncTimer, AsyncUdpSocket, Runtime};
use thiserror::Error;

/// A bounded executor advanced by the host's monotonic clock.
///
/// The host calls [`Self::drive`] after external I/O becomes ready and at [`Self::next_timer`],
/// then calls [`Self::shutdown`] before releasing the owning engine.
pub struct HostRuntime {
    inner: Arc<RuntimeInner>,
}

impl HostRuntime {
    /// Creates a runtime without a host wake callback.
    #[must_use]
    pub fn new() -> Self {
        Self::new_with_wake_callback(None)
    }

    /// Creates a runtime and optionally notifies the host when work becomes ready.
    ///
    /// The callback is best-effort and is never allowed to unwind into the protocol runtime. The
    /// host must still call [`Self::drive`] and must not use this callback as a replacement for
    /// timer or I/O integration.
    #[must_use]
    pub fn new_with_wake_callback(callback: Option<Arc<dyn Fn() + Send + Sync + 'static>>) -> Self {
        Self {
            inner: Arc::new(RuntimeInner::new(callback)),
        }
    }

    /// Schedules one host-owned task for a future [`Self::drive`] call.
    #[track_caller]
    ///
    /// # Errors
    ///
    /// Returns [`HostRuntimeError::Closed`] when shutdown has started.
    pub fn spawn(
        &self,
        future: Pin<Box<dyn Future<Output = ()> + Send>>,
    ) -> Result<(), HostRuntimeError> {
        self.spawn_boxed(future)
    }

    /// Processes at most `max_tasks` ready-queue entries after advancing the monotonic clock.
    ///
    /// `elapsed` is measured from this runtime's creation and must never decrease.
    ///
    /// # Errors
    ///
    /// Returns an error for overlapping drives, decreasing time, an elapsed duration outside the
    /// platform clock range, a closed runtime, or a panicking task.
    pub fn drive(
        &self,
        elapsed: Duration,
        max_tasks: NonZeroUsize,
    ) -> Result<usize, HostRuntimeError> {
        let _driving = DriveGuard::acquire(&self.inner.driving)?;
        if self.inner.stopped.load(Ordering::Acquire) {
            return Err(HostRuntimeError::Closed);
        }
        let now = self.inner.advance(elapsed)?;
        self.inner.wake_due_timers(now);

        let mut processed = 0;
        while processed < max_tasks.get() {
            let Some(task) = self.inner.pop_ready() else {
                break;
            };
            task.poll()?;
            processed += 1;
        }
        if processed == max_tasks.get() && !lock_recover(&self.inner.ready).is_empty() {
            self.inner.notify_host();
        }
        Ok(processed)
    }

    /// Returns the earliest live timer as elapsed time from runtime creation.
    #[must_use]
    pub fn next_timer(&self) -> Option<Duration> {
        if self.inner.stopped.load(Ordering::Acquire) {
            return None;
        }
        let epoch = lock_recover(&self.inner.clock).epoch;
        let mut timers = lock_recover(&self.inner.timers);
        timers.retain(|timer| timer.strong_count() != 0);
        timers
            .iter()
            .filter_map(Weak::upgrade)
            .filter_map(|timer| {
                let data = lock_recover(&timer.data);
                data.waker.as_ref().map(|_| {
                    data.deadline
                        .checked_duration_since(epoch)
                        .unwrap_or(Duration::ZERO)
                })
            })
            .min()
    }

    /// Returns whether shutdown has started or completed.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.inner.stopped.load(Ordering::Acquire)
    }

    pub(crate) fn shutdown_signal(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.inner.stopped)
    }

    /// Cancels every spawned task and releases runtime-owned protocol state.
    ///
    /// Calling this method more than once is allowed.
    ///
    /// # Errors
    ///
    /// Returns an error when a drive call is active or a task destructor panics during cleanup.
    pub fn shutdown(&self) -> Result<(), HostRuntimeError> {
        let _driving = DriveGuard::acquire(&self.inner.driving)?;
        if self.inner.stopped.swap(true, Ordering::AcqRel) {
            return Ok(());
        }
        lock_recover(&self.inner.ready).clear();
        lock_recover(&self.inner.timers).clear();
        let tasks = std::mem::take(&mut *lock_recover(&self.inner.tasks));
        let mut panicked = false;
        for task in tasks {
            task.queued.store(false, Ordering::Release);
            let future = lock_recover(&task.future).take();
            panicked |= drop_catching_panic(future).is_err();
        }
        if panicked {
            return Err(HostRuntimeError::TaskPanicked);
        }
        Ok(())
    }

    fn spawn_boxed(
        &self,
        future: Pin<Box<dyn Future<Output = ()> + Send>>,
    ) -> Result<(), HostRuntimeError> {
        let task = Task::new(future, &self.inner);
        let rejected = {
            let mut tasks = lock_recover(&self.inner.tasks);
            if self.inner.stopped.load(Ordering::Acquire) {
                true
            } else {
                tasks.push(Arc::clone(&task));
                false
            }
        };
        if rejected {
            let future = lock_recover(&task.future).take();
            if drop_catching_panic(future).is_err() {
                return Err(HostRuntimeError::TaskPanicked);
            }
            return Err(HostRuntimeError::Closed);
        }
        task.schedule();
        Ok(())
    }
}

impl Default for HostRuntime {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for HostRuntime {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HostRuntime")
            .finish_non_exhaustive()
    }
}

impl Runtime for HostRuntime {
    fn new_timer(&self, deadline: Instant) -> Pin<Box<dyn AsyncTimer>> {
        let state = Arc::new(TimerState {
            runtime: Arc::downgrade(&self.inner),
            data: Mutex::new(TimerData {
                deadline,
                waker: None,
            }),
        });
        lock_recover(&self.inner.timers).push(Arc::downgrade(&state));
        Box::pin(HostTimer { state })
    }

    fn spawn(&self, future: Pin<Box<dyn Future<Output = ()> + Send>>) {
        let _ = self.spawn_boxed(future);
    }

    fn wrap_udp_socket(&self, _socket: std::net::UdpSocket) -> io::Result<Box<dyn AsyncUdpSocket>> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "HostRuntime requires a host-driven AsyncUdpSocket",
        ))
    }

    fn now(&self) -> Instant {
        lock_recover(&self.inner.clock).now
    }
}

/// Host clock, drive-ownership, shutdown, and task-containment errors.
#[derive(Debug, Error, Eq, PartialEq)]
#[non_exhaustive]
pub enum HostRuntimeError {
    /// A drive call supplied elapsed time earlier than the previous call.
    #[error("host runtime time moved backwards")]
    TimeWentBackwards,
    /// Elapsed time cannot be represented by the platform monotonic clock.
    #[error("host runtime time is outside the platform Instant range")]
    TimeOutsideRange,
    /// Two drive or shutdown calls overlapped.
    #[error("host runtime drive calls must not overlap")]
    ConcurrentDrive,
    /// Shutdown has started or completed.
    #[error("host runtime is closed")]
    Closed,
    /// A task or task destructor panicked and was contained.
    #[error("a host runtime task panicked")]
    TaskPanicked,
}

struct RuntimeInner {
    clock: Mutex<Clock>,
    ready: Mutex<VecDeque<Arc<Task>>>,
    tasks: Mutex<Vec<Arc<Task>>>,
    timers: Mutex<Vec<Weak<TimerState>>>,
    driving: AtomicBool,
    stopped: Arc<AtomicBool>,
    wake_callback: Option<Arc<dyn Fn() + Send + Sync + 'static>>,
}

impl RuntimeInner {
    fn new(wake_callback: Option<Arc<dyn Fn() + Send + Sync + 'static>>) -> Self {
        let now = Instant::now();
        Self {
            clock: Mutex::new(Clock {
                epoch: now,
                elapsed: Duration::ZERO,
                now,
            }),
            ready: Mutex::new(VecDeque::new()),
            tasks: Mutex::new(Vec::new()),
            timers: Mutex::new(Vec::new()),
            driving: AtomicBool::new(false),
            stopped: Arc::new(AtomicBool::new(false)),
            wake_callback,
        }
    }

    fn advance(&self, elapsed: Duration) -> Result<Instant, HostRuntimeError> {
        let mut clock = lock_recover(&self.clock);
        if elapsed < clock.elapsed {
            return Err(HostRuntimeError::TimeWentBackwards);
        }
        let now = clock
            .epoch
            .checked_add(elapsed)
            .ok_or(HostRuntimeError::TimeOutsideRange)?;
        clock.elapsed = elapsed;
        clock.now = now;
        Ok(now)
    }

    fn wake_due_timers(&self, now: Instant) {
        let timers = {
            let mut registered = lock_recover(&self.timers);
            let timers = registered
                .iter()
                .filter_map(Weak::upgrade)
                .collect::<Vec<_>>();
            registered.retain(|timer| timer.strong_count() != 0);
            timers
        };
        for timer in timers {
            timer.wake_if_due(now);
        }
    }

    fn notify_host(&self) {
        if let Some(callback) = self.wake_callback.as_ref() {
            let _ = catch_unwind(AssertUnwindSafe(|| callback()));
        }
    }

    fn pop_ready(&self) -> Option<Arc<Task>> {
        let mut ready = lock_recover(&self.ready);
        let task = ready.pop_front()?;
        task.queued.store(false, Ordering::Release);
        Some(task)
    }

    fn remove_task(&self, completed: &Arc<Task>) {
        lock_recover(&self.tasks).retain(|task| !Arc::ptr_eq(task, completed));
    }
}

struct Clock {
    epoch: Instant,
    elapsed: Duration,
    now: Instant,
}

struct DriveGuard<'a>(&'a AtomicBool);

impl<'a> DriveGuard<'a> {
    fn acquire(driving: &'a AtomicBool) -> Result<Self, HostRuntimeError> {
        driving
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| HostRuntimeError::ConcurrentDrive)?;
        Ok(Self(driving))
    }
}

impl Drop for DriveGuard<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

struct Task {
    future: Mutex<Option<Pin<Box<dyn Future<Output = ()> + Send>>>>,
    runtime: Weak<RuntimeInner>,
    queued: AtomicBool,
}

impl Task {
    fn new(
        future: Pin<Box<dyn Future<Output = ()> + Send>>,
        runtime: &Arc<RuntimeInner>,
    ) -> Arc<Self> {
        Arc::new(Self {
            future: Mutex::new(Some(future)),
            runtime: Arc::downgrade(runtime),
            queued: AtomicBool::new(false),
        })
    }

    fn schedule(self: Arc<Self>) {
        if self.queued.swap(true, Ordering::AcqRel) {
            return;
        }
        let Some(runtime) = self.runtime.upgrade() else {
            return;
        };
        let mut ready = lock_recover(&runtime.ready);
        if runtime.stopped.load(Ordering::Acquire) {
            self.queued.store(false, Ordering::Release);
            return;
        }
        let was_empty = ready.is_empty();
        ready.push_back(self);
        drop(ready);
        if was_empty {
            runtime.notify_host();
        }
    }

    fn poll(self: &Arc<Self>) -> Result<(), HostRuntimeError> {
        let mut slot = lock_recover(&self.future);
        let Some(future) = slot.as_mut() else {
            return Ok(());
        };
        let waker = Waker::from(Arc::clone(self));
        let mut context = Context::from_waker(&waker);
        let outcome = catch_unwind(AssertUnwindSafe(|| future.as_mut().poll(&mut context)));
        match outcome {
            Ok(Poll::Pending) => Ok(()),
            Ok(Poll::Ready(())) => {
                let future = slot.take();
                drop(slot);
                if let Some(runtime) = self.runtime.upgrade() {
                    runtime.remove_task(self);
                }
                drop_catching_panic(future)
            }
            Err(_) => {
                let future = slot.take();
                drop(slot);
                if let Some(runtime) = self.runtime.upgrade() {
                    runtime.remove_task(self);
                }
                let _ = drop_catching_panic(future);
                Err(HostRuntimeError::TaskPanicked)
            }
        }
    }
}

impl Wake for Task {
    fn wake(self: Arc<Self>) {
        self.schedule();
    }
}

struct HostTimer {
    state: Arc<TimerState>,
}

impl fmt::Debug for HostTimer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("HostTimer").finish_non_exhaustive()
    }
}

impl AsyncTimer for HostTimer {
    fn reset(self: Pin<&mut Self>, deadline: Instant) {
        let runtime = self.state.runtime.upgrade();
        let clock = runtime.as_ref().map(|runtime| lock_recover(&runtime.clock));
        let now = clock.as_ref().map(|clock| clock.now);
        let wake = {
            let mut data = lock_recover(&self.state.data);
            data.deadline = deadline;
            now.filter(|now| *now >= deadline)
                .and_then(|_| data.waker.take())
        };
        if let Some(waker) = wake {
            waker.wake();
        }
    }

    fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<()> {
        let Some(runtime) = self.state.runtime.upgrade() else {
            return Poll::Ready(());
        };
        if runtime.stopped.load(Ordering::Acquire) {
            return Poll::Ready(());
        }
        let clock = lock_recover(&runtime.clock);
        let now = clock.now;
        let mut data = lock_recover(&self.state.data);
        if now >= data.deadline {
            Poll::Ready(())
        } else {
            match &mut data.waker {
                Some(waker) => waker.clone_from(context.waker()),
                None => data.waker = Some(context.waker().clone()),
            }
            Poll::Pending
        }
    }
}

struct TimerState {
    runtime: Weak<RuntimeInner>,
    data: Mutex<TimerData>,
}

impl TimerState {
    fn wake_if_due(&self, now: Instant) {
        let wake = {
            let mut data = lock_recover(&self.data);
            (now >= data.deadline).then(|| data.waker.take()).flatten()
        };
        if let Some(waker) = wake {
            waker.wake();
        }
    }
}

struct TimerData {
    deadline: Instant,
    waker: Option<Waker>,
}

fn lock_recover<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

fn drop_catching_panic(
    future: Option<Pin<Box<dyn Future<Output = ()> + Send>>>,
) -> Result<(), HostRuntimeError> {
    catch_unwind(AssertUnwindSafe(|| drop(future))).map_err(|_| HostRuntimeError::TaskPanicked)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shutdown_signal_only_changes_on_shutdown() {
        let runtime = HostRuntime::new();
        let stopped = runtime.shutdown_signal();
        assert!(!stopped.load(Ordering::Acquire));
        runtime.shutdown().unwrap();
        assert!(stopped.load(Ordering::Acquire));
    }
}
