use std::future::{Future, poll_fn};
use std::num::NonZeroUsize;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use noq::Runtime;
use quicp::{HostRuntime, HostRuntimeError};

struct DropPanic(bool);

impl Future for DropPanic {
    type Output = ();

    fn poll(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<()> {
        if self.0 {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    }
}

impl Drop for DropPanic {
    fn drop(&mut self) {
        panic!("drop panic");
    }
}

#[test]
fn host_runtime_drives_tasks_and_timers_with_a_bounded_tick() {
    let runtime = HostRuntime::new();
    let completed = Arc::new(AtomicUsize::new(0));
    for _ in 0..2 {
        let completed = Arc::clone(&completed);
        runtime
            .spawn(Box::pin(async move {
                completed.fetch_add(1, Ordering::Relaxed);
            }))
            .expect("spawn");
    }

    let one = NonZeroUsize::MIN;
    assert_eq!(runtime.drive(Duration::ZERO, one), Ok(1));
    assert_eq!(completed.load(Ordering::Relaxed), 1);
    assert_eq!(runtime.drive(Duration::ZERO, one), Ok(1));
    assert_eq!(completed.load(Ordering::Relaxed), 2);

    let fired = Arc::new(AtomicBool::new(false));
    let deadline = runtime.now() + Duration::from_millis(10);
    let mut timer = runtime.new_timer(deadline);
    let task_fired = Arc::clone(&fired);
    runtime
        .spawn(Box::pin(async move {
            poll_fn(|cx| timer.as_mut().poll(cx)).await;
            task_fired.store(true, Ordering::Release);
        }))
        .expect("spawn");

    assert_eq!(runtime.next_timer(), None);
    assert_eq!(runtime.drive(Duration::ZERO, one), Ok(1));
    assert!(!fired.load(Ordering::Acquire));
    assert_eq!(runtime.next_timer(), Some(Duration::from_millis(10)));
    assert_eq!(runtime.drive(Duration::from_millis(9), one), Ok(0));
    assert_eq!(runtime.drive(Duration::from_millis(10), one), Ok(1));
    assert!(fired.load(Ordering::Acquire));
    assert_eq!(runtime.next_timer(), None);
    assert_eq!(
        runtime.drive(Duration::from_millis(9), one),
        Err(HostRuntimeError::TimeWentBackwards)
    );
}

#[test]
fn host_runtime_shutdown_releases_pending_tasks() {
    struct DropProbe(Arc<AtomicBool>);

    impl Drop for DropProbe {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Release);
        }
    }

    let runtime = HostRuntime::new();
    let (waiter, waiter_result) = std::sync::mpsc::channel::<()>();
    let dropped = Arc::new(AtomicBool::new(false));
    let probe = DropProbe(Arc::clone(&dropped));
    let mut timer = runtime.new_timer(runtime.now() + Duration::from_secs(60));
    runtime
        .spawn(Box::pin(async move {
            std::hint::black_box(&waiter);
            std::hint::black_box(&probe);
            poll_fn(|cx| timer.as_mut().poll(cx)).await;
        }))
        .expect("spawn");
    runtime.drive(Duration::ZERO, NonZeroUsize::MIN).unwrap();

    assert_eq!(runtime.shutdown(), Ok(()));
    assert!(dropped.load(Ordering::Acquire));
    assert!(matches!(
        waiter_result.try_recv(),
        Err(std::sync::mpsc::TryRecvError::Disconnected)
    ));
    assert_eq!(runtime.shutdown(), Ok(()));
    assert_eq!(
        runtime.drive(Duration::ZERO, NonZeroUsize::MIN),
        Err(HostRuntimeError::Closed)
    );
    assert_eq!(
        runtime.spawn(Box::pin(async {})),
        Err(HostRuntimeError::Closed)
    );
    assert_eq!(
        runtime.spawn(Box::pin(DropPanic(false))),
        Err(HostRuntimeError::TaskPanicked)
    );
}

#[test]
fn host_runtime_contains_task_panics() {
    let runtime = HostRuntime::new();
    runtime
        .spawn(Box::pin(async { panic!("test panic") }))
        .expect("spawn");

    assert_eq!(
        runtime.drive(Duration::ZERO, NonZeroUsize::MIN),
        Err(HostRuntimeError::TaskPanicked)
    );
    assert_eq!(runtime.drive(Duration::ZERO, NonZeroUsize::MIN), Ok(0));

    let runtime = HostRuntime::new();
    runtime.spawn(Box::pin(DropPanic(true))).expect("spawn");
    assert_eq!(
        runtime.drive(Duration::ZERO, NonZeroUsize::MIN),
        Err(HostRuntimeError::TaskPanicked)
    );
    assert_eq!(runtime.drive(Duration::ZERO, NonZeroUsize::MIN), Ok(0));

    let runtime = HostRuntime::new();
    runtime.spawn(Box::pin(DropPanic(false))).expect("spawn");
    assert_eq!(runtime.drive(Duration::ZERO, NonZeroUsize::MIN), Ok(1));
    assert_eq!(runtime.shutdown(), Err(HostRuntimeError::TaskPanicked));
    assert_eq!(runtime.shutdown(), Ok(()));
}

#[test]
fn host_runtime_wakes_the_host_when_work_becomes_ready() {
    let wakes = Arc::new(AtomicUsize::new(0));
    let callback_wakes = Arc::clone(&wakes);
    let runtime = HostRuntime::new_with_wake_callback(Some(Arc::new(move || {
        callback_wakes.fetch_add(1, Ordering::Relaxed);
    })));

    runtime.spawn(Box::pin(async {})).expect("spawn");
    runtime.spawn(Box::pin(async {})).expect("spawn");
    assert_eq!(wakes.load(Ordering::Relaxed), 1);
    assert_eq!(runtime.drive(Duration::ZERO, NonZeroUsize::MIN), Ok(1));
    assert_eq!(wakes.load(Ordering::Relaxed), 2);
    assert_eq!(runtime.drive(Duration::ZERO, NonZeroUsize::MIN), Ok(1));

    runtime.spawn(Box::pin(async {})).expect("spawn");
    assert_eq!(wakes.load(Ordering::Relaxed), 3);
}
