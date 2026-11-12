//! The storage engine: one writer thread with group commit, and a pool of
//! read only connections.
//!
//! Every write runs on the single writer connection, so "check then act"
//! sequences (single use receipts, velocity limits, the audit chain) cannot
//! race. Durability costs one disk sync per commit, so the writer commits in
//! batches: all operations that arrived while the previous sync was running
//! share the next transaction and the next sync. Each operation runs inside
//! its own savepoint, so one failing does not undo its neighbours, and no
//! caller gets an answer before its data is on disk.
//!
//! Reads never wait for a sync: SQLite in WAL mode lets readers proceed on
//! their own connections while the writer works.

use crate::error::{Error, Result};
use rusqlite::{Connection, OpenFlags};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::Notify;

/// Upper bound of operations sharing one transaction.
const MAX_BATCH: usize = 256;
const MAX_READERS: usize = 8;
const BUSY_TIMEOUT: Duration = Duration::from_secs(10);

struct Job {
    /// Runs the operation. Returns whether it succeeded.
    run: Box<dyn FnOnce(&Connection) -> bool + Send>,
    /// Delivers the result to the caller, told whether the batch committed.
    finish: Box<dyn FnOnce(bool) + Send>,
}

pub(crate) struct Store {
    jobs: Sender<Job>,
    readers: Vec<Mutex<Connection>>,
    next_reader: AtomicUsize,
    /// Woken after every commit, for long polling.
    pub changed: Arc<Notify>,
}

fn stopped() -> Error {
    Error::Internal("the database writer has stopped".into())
}

impl Store {
    /// Opens the database. `None` is a private in-memory database, where
    /// reads share the writer connection.
    pub fn open(path: Option<&Path>, schema: &str) -> Result<Self> {
        let writer = match path {
            Some(path) => Connection::open(path)?,
            None => Connection::open_in_memory()?,
        };
        writer.busy_timeout(BUSY_TIMEOUT)?;
        if path.is_some() {
            writer.pragma_update(None, "journal_mode", "WAL")?;
        }
        // FULL: a commit is on disk before anyone hears about it.
        writer.pragma_update(None, "synchronous", "FULL")?;
        writer.pragma_update(None, "foreign_keys", "ON")?;
        writer.set_prepared_statement_cache_capacity(128);
        writer.execute_batch(schema)?;

        let mut readers = Vec::new();
        if let Some(path) = path {
            let count = std::thread::available_parallelism()
                .map_or(2, |n| n.get())
                .min(MAX_READERS);
            for _ in 0..count {
                let reader = Connection::open_with_flags(
                    path,
                    OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
                )?;
                reader.busy_timeout(BUSY_TIMEOUT)?;
                reader.set_prepared_statement_cache_capacity(128);
                readers.push(Mutex::new(reader));
            }
        }

        let changed = Arc::new(Notify::new());
        let (jobs, queue) = mpsc::channel();
        let notify = changed.clone();
        std::thread::Builder::new()
            .name("twof-writer".into())
            .spawn(move || writer_loop(writer, queue, notify))
            .map_err(|e| Error::Internal(format!("cannot start the writer thread: {e}")))?;
        Ok(Store {
            jobs,
            readers,
            next_reader: AtomicUsize::new(0),
            changed,
        })
    }

    /// Runs `op` in the next write batch and returns once it is durable.
    /// An `Err` from `op` rolls back only what `op` itself did.
    pub fn write<T, F>(&self, op: F) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce(&Connection) -> Result<T> + Send + 'static,
    {
        let slot: Arc<Mutex<Option<Result<T>>>> = Arc::new(Mutex::new(None));
        let (answer, wait) = mpsc::sync_channel(1);
        let run_slot = slot.clone();
        let job = Job {
            run: Box::new(move |conn| {
                let result = op(conn);
                let ok = result.is_ok();
                *run_slot.lock().unwrap_or_else(|p| p.into_inner()) = Some(result);
                ok
            }),
            finish: Box::new(move |committed| {
                let result = slot.lock().unwrap_or_else(|p| p.into_inner()).take();
                let _ = answer.send(match result {
                    // The operation refused: its savepoint was rolled back and
                    // the refusal stands whatever happened to the batch.
                    Some(Err(e)) => Err(e),
                    Some(Ok(value)) if committed => Ok(value),
                    _ => Err(Error::Internal(
                        "the transaction could not be committed".into(),
                    )),
                });
            }),
        };
        self.jobs.send(job).map_err(|_| stopped())?;
        wait.recv().map_err(|_| stopped())?
    }

    /// Runs a read on a pooled connection, inside one consistent snapshot.
    pub fn read<T, F>(&self, op: F) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce(&Connection) -> Result<T> + Send + 'static,
    {
        if self.readers.is_empty() {
            return self.write(op);
        }
        // Prefer an idle connection; otherwise wait for one in turn.
        let guard = self
            .readers
            .iter()
            .find_map(|reader| reader.try_lock().ok())
            .unwrap_or_else(|| {
                let turn = self.next_reader.fetch_add(1, Ordering::Relaxed) % self.readers.len();
                self.readers[turn].lock().unwrap_or_else(|p| p.into_inner())
            });
        let snapshot = guard.unchecked_transaction()?;
        op(&snapshot)
    }
}

fn writer_loop(conn: Connection, queue: Receiver<Job>, changed: Arc<Notify>) {
    while let Ok(first) = queue.recv() {
        let mut healthy = conn.execute_batch("BEGIN IMMEDIATE").is_ok();
        let mut finishes = Vec::new();
        let mut next = Some(first);
        while let Some(job) = next.take() {
            if healthy {
                let step = catch_unwind(AssertUnwindSafe(|| -> rusqlite::Result<()> {
                    conn.execute_batch("SAVEPOINT op")?;
                    if (job.run)(&conn) {
                        conn.execute_batch("RELEASE op")
                    } else {
                        conn.execute_batch("ROLLBACK TO op; RELEASE op")
                    }
                }));
                // A panic or a failing savepoint leaves the batch in an
                // unknown state: nothing in it is committed.
                healthy = matches!(step, Ok(Ok(())));
            }
            finishes.push(job.finish);
            if finishes.len() < MAX_BATCH {
                next = queue.try_recv().ok();
            }
        }
        let committed = healthy && conn.execute_batch("COMMIT").is_ok();
        if !committed {
            let _ = conn.execute_batch("ROLLBACK");
        }
        for finish in finishes {
            finish(committed);
        }
        if committed {
            changed.notify_waiters();
        }
    }
}
