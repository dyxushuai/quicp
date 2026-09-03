//! Bounded scalar GF(256) sliding-window repair used by QUICP.

#[cfg(test)]
use std::collections::BTreeMap;
use std::collections::{HashSet, VecDeque};
use std::mem::size_of;
use std::sync::Arc;

use bytes::Bytes;
use thiserror::Error;

use crate::config::MAX_REPAIR_SPAN;
use crate::recovery::{RecoveryCharge, RecoveryMemoryBudget};
use crate::wire::{SourceRecord, decode_source_padded};

const REDUCTION: u8 = 0x1d;
const MAX_DECODED_SOURCE_RECORDS: usize = 32;

#[derive(Clone, Debug, Eq, PartialEq)]
struct Row {
    coefficients: Vec<(u32, u8)>,
    data: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct KnownSource {
    symbol_id: u32,
    bytes: Bytes,
    retained_bytes: usize,
}

#[derive(Debug)]
struct ScratchReservation {
    charge: RecoveryCharge,
}

impl ScratchReservation {
    fn new(budget: Arc<RecoveryMemoryBudget>, bytes: usize) -> Result<Self, FecError> {
        Ok(Self {
            charge: RecoveryCharge::reserve(budget, bytes).map_err(|_| FecError::MemoryCapacity)?,
        })
    }

    fn transfer(&mut self, bytes: usize) {
        self.charge
            .transfer(bytes)
            .expect("transferred bytes were reserved before state mutation");
    }

    fn ensure(&mut self, bytes: usize) -> Result<(), FecError> {
        self.charge
            .grow(bytes)
            .map_err(|_| FecError::MemoryCapacity)
    }

    fn shrink(&mut self, bytes: usize) {
        self.charge.shrink(bytes);
    }

    fn take(&mut self, bytes: usize) -> Result<RecoveryCharge, FecError> {
        self.charge
            .split(bytes)
            .map_err(|_| FecError::MemoryCapacity)
    }
}

#[derive(Debug)]
pub(crate) struct RecoveredSource {
    pub(crate) symbol_id: u32,
    pub(crate) bytes: Bytes,
    pub(crate) retained_bytes: usize,
}

#[derive(Debug)]
pub(crate) struct RecoveredBatch {
    items: Vec<RecoveredSource>,
    retained_bytes: usize,
    scratch: ScratchReservation,
}

impl RecoveredBatch {
    fn empty(memory_budget: Arc<RecoveryMemoryBudget>) -> Self {
        Self {
            items: Vec::new(),
            retained_bytes: 0,
            scratch: ScratchReservation {
                charge: RecoveryCharge::reserve(memory_budget, 0)
                    .expect("zero-byte reservation succeeds"),
            },
        }
    }

    fn new(
        items: Vec<RecoveredSource>,
        mut scratch: ScratchReservation,
        committed_bytes: usize,
    ) -> Result<Self, FecError> {
        let retained_bytes = items.iter().try_fold(
            items
                .capacity()
                .checked_mul(size_of::<RecoveredSource>())
                .ok_or(FecError::MemoryCapacity)?,
            |bytes, source| {
                bytes
                    .checked_add(source.retained_bytes)
                    .ok_or(FecError::MemoryCapacity)
            },
        )?;
        let required = retained_bytes
            .checked_add(committed_bytes)
            .ok_or(FecError::MemoryCapacity)?;
        scratch.ensure(required)?;
        scratch.transfer(committed_bytes);
        Ok(Self {
            items,
            retained_bytes,
            scratch,
        })
    }

    pub(crate) fn reserve_dispatch(&mut self, bytes: usize) -> Result<(), FecError> {
        let required = self
            .retained_bytes
            .checked_add(bytes)
            .ok_or(FecError::MemoryCapacity)?;
        self.scratch.ensure(required)
    }

    fn shrink_after_state_transition(&mut self) {
        self.scratch.shrink(self.retained_bytes);
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    pub(crate) fn iter(&self) -> std::slice::Iter<'_, RecoveredSource> {
        self.items.iter()
    }

    pub(crate) fn pop(&mut self) -> Option<RecoveredSource> {
        self.items.pop()
    }

    pub(crate) fn take_retained_charge(
        &mut self,
        bytes: usize,
    ) -> Result<RecoveryCharge, FecError> {
        let retained_bytes = self
            .retained_bytes
            .checked_sub(bytes)
            .ok_or(FecError::MemoryCapacity)?;
        let charge = self.scratch.take(bytes)?;
        self.retained_bytes = retained_bytes;
        Ok(charge)
    }

    pub(crate) fn take_dispatch_charge(
        &mut self,
        bytes: usize,
    ) -> Result<RecoveryCharge, FecError> {
        self.scratch.take(bytes)
    }
}

/// Bounded decoder errors. Peer input is rejected before committed state changes.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub(crate) enum FecError {
    #[error("repair span must be between 1 and {MAX_REPAIR_SPAN}")]
    InvalidSpan,
    #[error("repair symbol has an invalid size")]
    InvalidSymbolSize,
    #[error("decoder row capacity is exhausted")]
    RowCapacity,
    #[error("endpoint recovery memory capacity is exhausted")]
    MemoryCapacity,
    #[error("decoder operation budget is exhausted")]
    WorkBudget,
    #[error("repair equation contradicts known source data")]
    ContradictoryRepair,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SourceStatus {
    New,
    Duplicate,
}

pub(crate) fn repair_symbol(
    first_symbol_id: u32,
    repair_id: u32,
    seed: u32,
    sources: &[Bytes],
) -> Result<Vec<u8>, FecError> {
    if sources.is_empty() || sources.len() > usize::from(MAX_REPAIR_SPAN) {
        return Err(FecError::InvalidSpan);
    }
    let symbol_size = sources.iter().map(Bytes::len).max().unwrap_or(0);
    if symbol_size == 0 || symbol_size > usize::from(u16::MAX) {
        return Err(FecError::InvalidSymbolSize);
    }
    let mut output = vec![0; symbol_size];
    for (ordinal, source) in sources.iter().enumerate() {
        let id = first_symbol_id.wrapping_add(u32::try_from(ordinal).expect("repair span is u16"));
        let coefficient = coefficient(seed, repair_id, id);
        for (target, byte) in output.iter_mut().zip(source.iter().copied()) {
            *target ^= multiply(byte, coefficient);
        }
    }
    Ok(output)
}

/// Incremental bounded repair decoder.
#[derive(Debug)]
pub(crate) struct Decoder {
    known: VecDeque<KnownSource>,
    known_ids: HashSet<u32>,
    rows: Vec<Row>,
    max_symbols: usize,
    max_rows: usize,
    max_symbol_bytes: usize,
    row_bytes: usize,
    memory_budget: Arc<RecoveryMemoryBudget>,
}

impl Decoder {
    #[cfg(any(test, fuzzing))]
    pub(crate) fn new(max_symbols: usize, max_rows: usize, max_symbol_bytes: usize) -> Self {
        Self::with_budget(
            max_symbols,
            max_rows,
            max_symbol_bytes,
            Arc::new(RecoveryMemoryBudget::new(u32::MAX)),
        )
    }

    pub(crate) fn with_budget(
        max_symbols: usize,
        max_rows: usize,
        max_symbol_bytes: usize,
        memory_budget: Arc<RecoveryMemoryBudget>,
    ) -> Self {
        Self {
            known: VecDeque::with_capacity(max_symbols),
            known_ids: HashSet::with_capacity(max_symbols),
            rows: Vec::new(),
            max_symbols,
            max_rows,
            max_symbol_bytes,
            row_bytes: 0,
            memory_budget,
        }
    }

    pub(crate) fn add_source(
        &mut self,
        symbol_id: u32,
        source: Bytes,
        work_budget: usize,
    ) -> Result<RecoveredBatch, FecError> {
        if source.is_empty() || source.len() > self.max_symbol_bytes {
            return Err(FecError::InvalidSymbolSize);
        }
        if self.source_status(symbol_id, &source)? == SourceStatus::Duplicate {
            return Ok(RecoveredBatch::empty(Arc::clone(&self.memory_budget)));
        }
        if self.rows.is_empty() {
            if !source.is_unique() && self.try_reuse_oldest_source(symbol_id, &source) {
                return Ok(RecoveredBatch::empty(Arc::clone(&self.memory_budget)));
            }
            let mut scratch =
                ScratchReservation::new(Arc::clone(&self.memory_budget), source.len())?;
            let source = normalize_source_storage(symbol_id, source);
            let (reserved, released) = self.known_memory_delta(source.retained_bytes);
            scratch.ensure(reserved)?;
            scratch.transfer(reserved);
            self.insert_known(symbol_id, source, released);
            return Ok(RecoveredBatch::empty(Arc::clone(&self.memory_budget)));
        }

        let mut work = matrix_clone_work(&self.rows)?;
        if work > work_budget {
            return Err(FecError::WorkBudget);
        }
        let scratch = ScratchReservation::new(
            Arc::clone(&self.memory_budget),
            self.scratch_memory_bytes(0, 0, source.len())?,
        )?;
        let mut rows = clone_rows_bounded(&self.rows, 0, 0, self.max_symbol_bytes)?;
        for row in &mut rows {
            let Ok(index) = row
                .coefficients
                .binary_search_by_key(&symbol_id, |(id, _)| *id)
            else {
                continue;
            };
            let factor = row.coefficients.remove(index).1;
            xor_scaled(&mut row.data, &source, factor, &mut work, work_budget)?;
        }
        let recovered = canonical_recovered(
            reduce(
                &mut rows,
                self.max_symbol_bytes,
                work_budget.saturating_sub(work),
            )?,
            self.max_symbol_bytes,
        )?;
        validate_recovered(&self.known, &recovered)?;

        rows.retain(|row| row.coefficients.len() > 1);
        let next_row_bytes = row_storage_bytes(&rows)?;
        let row_growth = next_row_bytes.saturating_sub(self.row_bytes);
        let source = normalize_source_storage(symbol_id, source);
        let (source_growth, source_release) = self.known_memory_delta(source.retained_bytes);
        let reservation = source_growth
            .checked_add(row_growth)
            .ok_or(FecError::MemoryCapacity)?;
        let mut batch = RecoveredBatch::new(recovered, scratch, reservation)?;
        let released = self.row_bytes.saturating_sub(next_row_bytes);
        self.rows = rows;
        self.row_bytes = next_row_bytes;
        self.memory_budget.release(released);
        self.insert_known(symbol_id, source, source_release);
        batch.shrink_after_state_transition();
        Ok(batch)
    }

    pub(crate) fn add_repair(
        &mut self,
        first_symbol_id: u32,
        span: u16,
        repair_id: u32,
        seed: u32,
        coded: &[u8],
        work_budget: usize,
    ) -> Result<RecoveredBatch, FecError> {
        if span == 0 || span > MAX_REPAIR_SPAN {
            return Err(FecError::InvalidSpan);
        }
        if coded.is_empty() || coded.len() > self.max_symbol_bytes {
            return Err(FecError::InvalidSymbolSize);
        }
        if self.rows.len() == self.max_rows {
            return Err(FecError::RowCapacity);
        }

        let mut work = matrix_clone_work(&self.rows)?
            .checked_add(coded.len())
            .and_then(|work| work.checked_add(usize::from(span)))
            .ok_or(FecError::WorkBudget)?;
        if work > work_budget {
            return Err(FecError::WorkBudget);
        }
        let scratch = ScratchReservation::new(
            Arc::clone(&self.memory_budget),
            self.scratch_memory_bytes(1, usize::from(span), 0)?,
        )?;
        let coefficient_capacity = matrix_coefficient_count(&self.rows, usize::from(span))?;
        let mut row = Row {
            coefficients: bounded_vec(coefficient_capacity)?,
            data: {
                let mut data = bounded_vec(self.max_symbol_bytes)?;
                data.extend_from_slice(coded);
                data
            },
        };
        for ordinal in 0..u32::from(span) {
            let id = first_symbol_id.wrapping_add(ordinal);
            let value = coefficient(seed, repair_id, id);
            if let Some(source) = self.known_source(id) {
                xor_scaled(&mut row.data, &source.bytes, value, &mut work, work_budget)?;
            } else {
                row.coefficients.push((id, value));
            }
        }
        row.coefficients.sort_unstable_by_key(|(id, _)| *id);
        if row.coefficients.is_empty() {
            return if row.data.iter().all(|byte| *byte == 0) {
                Ok(RecoveredBatch::empty(Arc::clone(&self.memory_budget)))
            } else {
                Err(FecError::ContradictoryRepair)
            };
        }

        let mut rows = clone_rows_bounded(&self.rows, 1, usize::from(span), self.max_symbol_bytes)?;
        rows.push(row);
        let recovered = canonical_recovered(
            reduce(
                &mut rows,
                self.max_symbol_bytes,
                work_budget.saturating_sub(work),
            )?,
            self.max_symbol_bytes,
        )?;
        validate_recovered(&self.known, &recovered)?;
        rows.retain(|row| row.coefficients.len() > 1);
        let next_row_bytes = row_storage_bytes(&rows)?;
        let growth = next_row_bytes.saturating_sub(self.row_bytes);
        let mut batch = RecoveredBatch::new(recovered, scratch, growth)?;
        let released = self.row_bytes.saturating_sub(next_row_bytes);
        self.rows = rows;
        self.row_bytes = next_row_bytes;
        self.memory_budget.release(released);
        batch.shrink_after_state_transition();
        Ok(batch)
    }

    #[cfg(test)]
    pub(crate) fn commit_recovered(
        &mut self,
        symbol_id: u32,
        source: Bytes,
    ) -> Result<(), FecError> {
        let charge = RecoveryCharge::reserve(Arc::clone(&self.memory_budget), source.len())
            .map_err(|_| FecError::MemoryCapacity)?;
        self.commit_recovered_precharged(symbol_id, source, charge)
    }

    pub(crate) fn commit_recovered_precharged(
        &mut self,
        symbol_id: u32,
        source: Bytes,
        mut charge: RecoveryCharge,
    ) -> Result<(), FecError> {
        if source.is_empty() || source.len() > self.max_symbol_bytes {
            return Err(FecError::InvalidSymbolSize);
        }
        if !charge.belongs_to(&self.memory_budget) || charge.bytes() < source.len() {
            return Err(FecError::MemoryCapacity);
        }
        if let Some(existing) = self.known_source(symbol_id) {
            return if existing.bytes == source {
                Ok(())
            } else {
                Err(FecError::ContradictoryRepair)
            };
        }
        let source = normalize_source_storage(symbol_id, source);
        charge
            .grow(source.retained_bytes)
            .map_err(|_| FecError::MemoryCapacity)?;
        charge
            .transfer(source.retained_bytes)
            .map_err(|_| FecError::MemoryCapacity)?;
        let released = self.evicted_known_bytes();
        self.insert_known(symbol_id, source, released);
        Ok(())
    }

    #[cfg(all(
        test,
        feature = "runtime-tokio",
        any(target_os = "linux", target_os = "macos", windows)
    ))]
    pub(crate) fn state_counts(&self) -> (usize, usize) {
        (self.known.len(), self.rows.len())
    }

    fn known_memory_delta(&self, source_bytes: usize) -> (usize, usize) {
        let evicted_bytes = self.evicted_known_bytes();
        (
            source_bytes.saturating_sub(evicted_bytes),
            evicted_bytes.saturating_sub(source_bytes),
        )
    }

    fn evicted_known_bytes(&self) -> usize {
        (self.known.len() >= self.max_symbols)
            .then(|| self.known.front())
            .flatten()
            .map_or(0, |source| source.retained_bytes)
    }

    fn scratch_memory_bytes(
        &self,
        additional_rows: usize,
        additional_coefficients: usize,
        source_bytes: usize,
    ) -> Result<usize, FecError> {
        let rows = self
            .rows
            .len()
            .checked_add(additional_rows)
            .ok_or(FecError::MemoryCapacity)?;
        let columns = matrix_coefficient_count(&self.rows, additional_coefficients)?;
        let coefficient_bytes = columns
            .checked_mul(size_of::<(u32, u8)>())
            .ok_or(FecError::MemoryCapacity)?;
        let matrix_row_bytes = size_of::<Row>()
            .checked_add(self.max_symbol_bytes)
            .and_then(|bytes| bytes.checked_add(coefficient_bytes))
            .ok_or(FecError::MemoryCapacity)?;
        let matrix_bytes = rows
            .checked_mul(matrix_row_bytes)
            .ok_or(FecError::MemoryCapacity)?;
        let pivot_bytes = size_of::<Row>()
            .checked_add(self.max_symbol_bytes)
            .and_then(|bytes| bytes.checked_add(coefficient_bytes))
            .ok_or(FecError::MemoryCapacity)?;
        let source_record_bytes = MAX_DECODED_SOURCE_RECORDS
            .checked_mul(size_of::<SourceRecord<'static>>())
            .ok_or(FecError::MemoryCapacity)?;
        let recovered_bytes = rows
            .checked_mul(
                self.max_symbol_bytes
                    .checked_mul(2)
                    .and_then(|bytes| {
                        bytes
                            .checked_add(size_of::<(u32, Bytes)>())
                            .and_then(|bytes| bytes.checked_add(size_of::<RecoveredSource>()))
                            .and_then(|bytes| bytes.checked_add(source_record_bytes))
                    })
                    .ok_or(FecError::MemoryCapacity)?,
            )
            .ok_or(FecError::MemoryCapacity)?;
        matrix_bytes
            .checked_add(pivot_bytes)
            .and_then(|bytes| bytes.checked_add(recovered_bytes))
            .and_then(|bytes| bytes.checked_add(source_bytes))
            .ok_or(FecError::MemoryCapacity)
    }

    fn insert_known(&mut self, symbol_id: u32, source: KnownSource, released: usize) {
        debug_assert_eq!(source.symbol_id, symbol_id);
        self.known_ids.insert(symbol_id);
        self.known.push_back(source);
        while self.known.len() > self.max_symbols {
            if let Some(source) = self.known.pop_front() {
                self.known_ids.remove(&source.symbol_id);
            }
        }
        self.memory_budget.release(released);
    }

    fn try_reuse_oldest_source(&mut self, symbol_id: u32, source: &[u8]) -> bool {
        if self.known.len() < self.max_symbols {
            return false;
        }
        let Some(oldest) = self.known.pop_front() else {
            return false;
        };
        self.known_ids.remove(&oldest.symbol_id);
        if oldest.retained_bytes < source.len() {
            self.known_ids.insert(oldest.symbol_id);
            self.known.push_front(oldest);
            return false;
        }
        let previous_retained_bytes = oldest.retained_bytes;
        let mut storage = match oldest.bytes.try_into_mut() {
            Ok(storage) => storage,
            Err(bytes) => {
                self.known_ids.insert(oldest.symbol_id);
                self.known.push_front(KnownSource {
                    symbol_id: oldest.symbol_id,
                    bytes,
                    retained_bytes: previous_retained_bytes,
                });
                return false;
            }
        };
        storage.clear();
        storage.extend_from_slice(source);
        let retained_bytes = storage.capacity();
        debug_assert!(retained_bytes <= previous_retained_bytes);
        self.memory_budget
            .release(previous_retained_bytes - retained_bytes);
        self.known_ids.insert(symbol_id);
        self.known.push_back(KnownSource {
            symbol_id,
            bytes: storage.freeze(),
            retained_bytes,
        });
        true
    }

    fn known_source(&self, symbol_id: u32) -> Option<&KnownSource> {
        // ponytail: Decoder windows are bounded; add an index only if loss-path profiles justify it.
        self.known
            .iter()
            .find(|source| source.symbol_id == symbol_id)
    }

    pub(crate) fn source_status(
        &self,
        symbol_id: u32,
        source: &[u8],
    ) -> Result<SourceStatus, FecError> {
        if !self.known_ids.contains(&symbol_id) {
            return Ok(SourceStatus::New);
        }
        let Some(existing) = self.known_source(symbol_id) else {
            unreachable!("known source index is consistent");
        };
        if existing.bytes == source {
            Ok(SourceStatus::Duplicate)
        } else {
            Err(FecError::ContradictoryRepair)
        }
    }
}

impl Drop for Decoder {
    fn drop(&mut self) {
        let known_bytes = self
            .known
            .iter()
            .map(|source| source.retained_bytes)
            .sum::<usize>();
        self.memory_budget.release(known_bytes + self.row_bytes);
    }
}

fn normalize_source_storage(symbol_id: u32, source: Bytes) -> KnownSource {
    match source.try_into_mut() {
        Ok(source) => {
            let retained_bytes = source.capacity();
            KnownSource {
                symbol_id,
                bytes: source.freeze(),
                retained_bytes,
            }
        }
        Err(source) => {
            let bytes = Bytes::copy_from_slice(&source);
            KnownSource {
                symbol_id,
                retained_bytes: bytes.len(),
                bytes,
            }
        }
    }
}

fn row_storage_bytes(rows: &Vec<Row>) -> Result<usize, FecError> {
    rows.iter().try_fold(
        rows.capacity()
            .checked_mul(size_of::<Row>())
            .ok_or(FecError::MemoryCapacity)?,
        |bytes, row| {
            bytes
                .checked_add(row.data.capacity())
                .and_then(|bytes| {
                    row.coefficients
                        .capacity()
                        .checked_mul(size_of::<(u32, u8)>())
                        .and_then(|coefficients| bytes.checked_add(coefficients))
                })
                .ok_or(FecError::MemoryCapacity)
        },
    )
}

fn bounded_vec<T>(capacity: usize) -> Result<Vec<T>, FecError> {
    if size_of::<T>() == 0 {
        return Err(FecError::MemoryCapacity);
    }
    let values = Vec::with_capacity(capacity);
    if values.capacity() != capacity {
        return Err(FecError::MemoryCapacity);
    }
    Ok(values)
}

fn clone_rows_bounded(
    rows: &[Row],
    additional_rows: usize,
    additional_coefficients: usize,
    max_symbol_bytes: usize,
) -> Result<Vec<Row>, FecError> {
    let coefficient_capacity = matrix_coefficient_count(rows, additional_coefficients)?;
    let mut cloned = bounded_vec(
        rows.len()
            .checked_add(additional_rows)
            .ok_or(FecError::MemoryCapacity)?,
    )?;
    for row in rows {
        let mut coefficients = bounded_vec(coefficient_capacity)?;
        coefficients.extend_from_slice(&row.coefficients);
        let mut data = bounded_vec(max_symbol_bytes)?;
        data.extend_from_slice(&row.data);
        cloned.push(Row { coefficients, data });
    }
    Ok(cloned)
}

fn matrix_coefficient_count(rows: &[Row], additional: usize) -> Result<usize, FecError> {
    rows.iter().try_fold(additional, |count, row| {
        count
            .checked_add(row.coefficients.len())
            .ok_or(FecError::MemoryCapacity)
    })
}

fn matrix_clone_work(rows: &[Row]) -> Result<usize, FecError> {
    rows.iter().try_fold(0usize, |work, row| {
        work.checked_add(row.coefficients.len())
            .and_then(|work| work.checked_add(row.data.len()))
            .ok_or(FecError::WorkBudget)
    })
}

fn canonical_recovered(
    recovered: Vec<(u32, Bytes)>,
    max_symbol_bytes: usize,
) -> Result<Vec<RecoveredSource>, FecError> {
    let mut canonical = bounded_vec(recovered.len())?;
    for (symbol_id, source) in recovered {
        let (decoded, consumed) =
            decode_source_padded(&source, MAX_DECODED_SOURCE_RECORDS, max_symbol_bytes)
                .map_err(|_| FecError::ContradictoryRepair)?;
        if decoded.records.capacity() != decoded.records.len() {
            return Err(FecError::MemoryCapacity);
        }
        if decoded.symbol_id != symbol_id {
            return Err(FecError::ContradictoryRepair);
        }
        let mut storage = bounded_vec(consumed)?;
        storage.extend_from_slice(&source[..consumed]);
        let retained_bytes = storage.capacity();
        canonical.push(RecoveredSource {
            symbol_id,
            bytes: Bytes::from(storage),
            retained_bytes,
        });
    }
    Ok(canonical)
}

fn validate_recovered(
    known: &VecDeque<KnownSource>,
    recovered: &[RecoveredSource],
) -> Result<(), FecError> {
    for source in recovered {
        if let Some(existing) = known
            .iter()
            .find(|known| known.symbol_id == source.symbol_id)
            && existing.bytes != source.bytes
        {
            return Err(FecError::ContradictoryRepair);
        }
    }
    Ok(())
}

fn reduce(
    rows: &mut [Row],
    max_symbol_bytes: usize,
    work_budget: usize,
) -> Result<Vec<(u32, Bytes)>, FecError> {
    let mut work = 0usize;
    let mut pivot = 0usize;
    while pivot < rows.len() {
        let Some(candidate) = (pivot..rows.len())
            .filter(|index| !rows[*index].coefficients.is_empty())
            .min_by_key(|index| rows[*index].coefficients[0].0)
        else {
            break;
        };
        rows.swap(pivot, candidate);
        let pivot_id = rows[pivot].coefficients[0].0;
        let inverse = inverse(rows[pivot].coefficients[0].1);
        scale_row(&mut rows[pivot], inverse, &mut work, work_budget)?;
        let source = clone_rows_bounded(&rows[pivot..=pivot], 0, 0, max_symbol_bytes)?
            .pop()
            .expect("one row cloned");

        for (index, row) in rows.iter_mut().enumerate() {
            if index == pivot {
                continue;
            }
            let Some((_, factor)) = row
                .coefficients
                .iter()
                .find(|(id, _)| *id == pivot_id)
                .copied()
            else {
                continue;
            };
            subtract_row(row, &source, factor, &mut work, work_budget)?;
        }
        pivot += 1;
    }

    let mut recovered = bounded_vec(rows.len())?;
    for row in rows.iter() {
        if row.coefficients.is_empty() {
            if row.data.iter().any(|byte| *byte != 0) {
                return Err(FecError::ContradictoryRepair);
            }
            continue;
        }
        if let [(id, coefficient)] = row.coefficients.as_slice() {
            let mut data = bounded_vec(max_symbol_bytes)?;
            data.extend_from_slice(&row.data);
            if *coefficient != 1 {
                for byte in &mut data {
                    *byte = multiply(*byte, inverse(*coefficient));
                }
            }
            recovered.push((*id, Bytes::from(data)));
        }
    }
    recovered.sort_unstable_by_key(|(id, _)| *id);
    for duplicate in recovered.windows(2) {
        if duplicate[0].0 == duplicate[1].0 && duplicate[0].1 != duplicate[1].1 {
            return Err(FecError::ContradictoryRepair);
        }
    }
    recovered.dedup_by_key(|(id, _)| *id);
    Ok(recovered)
}

fn scale_row(row: &mut Row, factor: u8, work: &mut usize, budget: usize) -> Result<(), FecError> {
    for (_, value) in &mut row.coefficients {
        spend(work, budget)?;
        *value = multiply(*value, factor);
    }
    for byte in &mut row.data {
        spend(work, budget)?;
        *byte = multiply(*byte, factor);
    }
    Ok(())
}

fn subtract_row(
    target: &mut Row,
    source: &Row,
    factor: u8,
    work: &mut usize,
    budget: usize,
) -> Result<(), FecError> {
    if target.data.len() < source.data.len() {
        target.data.resize(source.data.len(), 0);
    }
    for (id, coefficient) in &source.coefficients {
        spend(work, budget)?;
        let scaled = multiply(*coefficient, factor);
        match target.coefficients.binary_search_by_key(id, |(id, _)| *id) {
            Ok(index) => {
                target.coefficients[index].1 ^= scaled;
                if target.coefficients[index].1 == 0 {
                    target.coefficients.remove(index);
                }
            }
            Err(index) => target.coefficients.insert(index, (*id, scaled)),
        }
    }
    for (target, source) in target.data.iter_mut().zip(&source.data) {
        spend(work, budget)?;
        *target ^= multiply(*source, factor);
    }
    Ok(())
}

fn spend(work: &mut usize, budget: usize) -> Result<(), FecError> {
    *work = work.saturating_add(1);
    if *work > budget {
        Err(FecError::WorkBudget)
    } else {
        Ok(())
    }
}

fn xor_scaled(
    target: &mut [u8],
    source: &[u8],
    factor: u8,
    work: &mut usize,
    budget: usize,
) -> Result<(), FecError> {
    if source.len() > target.len() {
        return Err(FecError::InvalidSymbolSize);
    }
    for (target, source) in target.iter_mut().zip(source.iter().copied()) {
        spend(work, budget)?;
        *target ^= multiply(source, factor);
    }
    Ok(())
}

fn coefficient(seed: u32, repair_id: u32, symbol_id: u32) -> u8 {
    let mut value =
        seed ^ repair_id.wrapping_mul(0x9e37_79b9) ^ symbol_id.wrapping_mul(0x85eb_ca6b);
    value ^= value >> 16;
    value = value.wrapping_mul(0x7feb_352d);
    value ^= value >> 15;
    value = value.wrapping_mul(0x846c_a68b);
    value ^= value >> 16;
    let coefficient = value.to_le_bytes()[0];
    if coefficient == 0 { 1 } else { coefficient }
}

fn multiply(mut left: u8, mut right: u8) -> u8 {
    let mut output = 0;
    while right != 0 {
        if right & 1 != 0 {
            output ^= left;
        }
        let carry = left & 0x80 != 0;
        left <<= 1;
        if carry {
            left ^= REDUCTION;
        }
        right >>= 1;
    }
    output
}

fn inverse(value: u8) -> u8 {
    debug_assert_ne!(value, 0);
    let mut base = value;
    let mut exponent = 254u8;
    let mut output = 1;
    while exponent != 0 {
        if exponent & 1 != 0 {
            output = multiply(output, base);
        }
        base = multiply(base, base);
        exponent >>= 1;
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{SourceRecord, encode_source};

    fn source(symbol_id: u32, payload: &[u8]) -> Bytes {
        let mut encoded = Vec::new();
        encode_source(
            symbol_id,
            &[SourceRecord {
                flow_id: 1,
                offset: u64::from(symbol_id),
                fin: false,
                data: payload,
            }],
            &mut encoded,
        )
        .unwrap();
        Bytes::from(encoded)
    }

    #[test]
    fn field_inverse_round_trips_every_nonzero_value() {
        for value in 1..=u8::MAX {
            assert_eq!(multiply(value, inverse(value)), 1);
        }
    }

    #[test]
    fn coefficient_vectors_are_pinned() {
        assert_eq!(coefficient(0, 0, 0), 0x01);
        assert_eq!(coefficient(7, 100, 10), 0xef);
        assert_eq!(coefficient(7, 100, 11), 0x2c);
        assert_eq!(coefficient(7, 101, 10), 0x91);
        assert_eq!(coefficient(7, 101, 11), 0x8d);
        assert_eq!(coefficient(u32::MAX, u32::MAX, u32::MAX), 0x30);
    }

    #[test]
    fn decoder_recovers_two_missing_sources() {
        let sources = [source(10, b"one!"), source(11, b"two!")];
        let repair_a = repair_symbol(10, 100, 7, &sources).unwrap();
        let repair_b = repair_symbol(10, 101, 7, &sources).unwrap();
        let mut decoder = Decoder::new(512, 512, 1200);
        assert!(
            decoder
                .add_repair(10, 2, 100, 7, &repair_a, 20_000)
                .unwrap()
                .is_empty()
        );
        let recovered = decoder
            .add_repair(10, 2, 101, 7, &repair_b, 20_000)
            .unwrap();
        assert_eq!(
            recovered
                .iter()
                .map(|source| (source.symbol_id, source.bytes.clone()))
                .collect::<Vec<_>>(),
            [(10, sources[0].clone()), (11, sources[1].clone())]
        );
    }

    #[test]
    fn decoder_rejects_over_span_and_budget_without_mutating_rows() {
        let mut decoder = Decoder::new(512, 2, 1200);
        assert!(matches!(
            decoder.add_repair(0, 257, 1, 1, &[1], 10),
            Err(FecError::InvalidSpan)
        ));
        assert!(matches!(
            decoder.add_repair(0, 2, 1, 1, &[1; 64], 1),
            Err(FecError::WorkBudget)
        ));
        assert_eq!(decoder.rows, []);

        decoder.add_repair(0, 2, 1, 1, &[1; 64], 20_000).unwrap();
        let rows = decoder.rows.clone();
        assert!(matches!(
            decoder.add_source(0, source(0, b"source"), 1),
            Err(FecError::WorkBudget)
        ));
        assert_eq!(decoder.rows, rows);
    }

    #[test]
    fn decoder_rejects_a_repair_beyond_row_capacity() {
        let mut decoder = Decoder::new(2, 1, 32);
        decoder.add_repair(0, 2, 1, 1, &[1; 8], 2_000).unwrap();
        assert!(matches!(
            decoder.add_repair(2, 2, 2, 1, &[2; 8], 2_000),
            Err(FecError::RowCapacity)
        ));
        assert_eq!(decoder.rows.len(), 1);
    }

    #[test]
    fn decoder_source_memory_is_bounded_reused_and_released() {
        let first = source(1, b"first");
        let second = source(2, b"second");
        let limit = u32::try_from(first.len().max(second.len())).unwrap();
        let budget = Arc::new(RecoveryMemoryBudget::new(limit));
        let mut decoder = Decoder::with_budget(1, 1, 64, Arc::clone(&budget));
        decoder.add_source(1, first, 2_000).unwrap();
        decoder.add_source(2, second.clone(), 2_000).unwrap();
        assert_eq!(budget.used(), second.len() as u64);

        let retained = decoder.known.clone();
        assert!(matches!(
            decoder.add_source(3, source(3, b"payload-too-large"), 2_000),
            Err(FecError::MemoryCapacity)
        ));
        assert_eq!(decoder.known, retained);
        drop(decoder);
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn decoder_exact_scratch_budget_succeeds_and_minus_one_is_atomic() {
        let measured = Decoder::new(4, 4, 32);
        let exact = measured.scratch_memory_bytes(1, 2, 0).unwrap();

        let budget = Arc::new(RecoveryMemoryBudget::new(u32::try_from(exact).unwrap()));
        let mut decoder = Decoder::with_budget(4, 4, 32, Arc::clone(&budget));
        decoder.add_repair(0, 2, 1, 1, &[1; 8], 2_000).unwrap();
        drop(decoder);
        assert_eq!(budget.used(), 0);

        let budget = Arc::new(RecoveryMemoryBudget::new(u32::try_from(exact - 1).unwrap()));
        let mut decoder = Decoder::with_budget(4, 4, 32, Arc::clone(&budget));
        assert!(matches!(
            decoder.add_repair(0, 2, 1, 1, &[1; 8], 2_000),
            Err(FecError::MemoryCapacity)
        ));
        assert!(decoder.rows.is_empty());
        assert_eq!(budget.used(), 0);
        drop(decoder);
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn recovered_batch_holds_transition_credit_until_state_is_replaced() {
        let budget = Arc::new(RecoveryMemoryBudget::new(100));
        let old_state = RecoveryCharge::reserve(Arc::clone(&budget), 30).unwrap();
        let scratch = ScratchReservation::new(Arc::clone(&budget), 70).unwrap();
        let mut batch = RecoveredBatch::new(Vec::new(), scratch, 0).unwrap();
        assert_eq!(budget.used(), 100);

        let mut competing = Decoder::with_budget(1, 1, 1, Arc::clone(&budget));
        assert!(matches!(
            competing.add_source(1, Bytes::from_static(b"x"), 16),
            Err(FecError::MemoryCapacity)
        ));

        drop(old_state);
        batch.shrink_after_state_transition();
        competing
            .add_source(1, Bytes::from_static(b"x"), 16)
            .unwrap();
        drop(batch);
        drop(competing);
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn recovered_batch_holds_the_shared_budget_until_consumed() {
        let sources = [source(10, b"one!"), source(11, b"two!")];
        let repair_a = repair_symbol(10, 100, 7, &sources).unwrap();
        let repair_b = repair_symbol(10, 101, 7, &sources).unwrap();
        let recover = |budget: Arc<RecoveryMemoryBudget>| {
            let mut decoder = Decoder::with_budget(8, 8, 1_200, budget);
            assert!(
                decoder
                    .add_repair(10, 2, 100, 7, &repair_a, 20_000)
                    .unwrap()
                    .is_empty()
            );
            let recovered = decoder
                .add_repair(10, 2, 101, 7, &repair_b, 20_000)
                .unwrap();
            (decoder, recovered)
        };

        let measured_budget = Arc::new(RecoveryMemoryBudget::new(u32::MAX));
        let mut measured_decoder = Decoder::with_budget(8, 8, 1_200, Arc::clone(&measured_budget));
        measured_decoder
            .add_repair(10, 2, 100, 7, &repair_a, 20_000)
            .unwrap();
        let limit = u32::try_from(
            measured_budget.used()
                + u64::try_from(measured_decoder.scratch_memory_bytes(1, 2, 0).unwrap()).unwrap(),
        )
        .unwrap();
        drop(measured_decoder);
        assert_eq!(measured_budget.used(), 0);

        let budget = Arc::new(RecoveryMemoryBudget::new(limit));
        let (decoder, recovered) = recover(Arc::clone(&budget));
        let blocked_bytes = usize::try_from(u64::from(limit) - budget.used() + 1).unwrap();
        let mut competing = Decoder::with_budget(1, 1, blocked_bytes, Arc::clone(&budget));
        assert!(matches!(
            competing.add_source(99, Bytes::from(vec![1; blocked_bytes]), 2_000),
            Err(FecError::MemoryCapacity)
        ));
        drop(recovered);
        competing
            .add_source(99, Bytes::from(vec![1; blocked_bytes]), 2_000)
            .unwrap();
        drop(competing);
        drop(decoder);
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn recovered_charge_transfer_releases_exactly_once() {
        let sources = [source(10, b"one!"), source(11, b"two!")];
        let repair_a = repair_symbol(10, 100, 7, &sources).unwrap();
        let repair_b = repair_symbol(10, 101, 7, &sources).unwrap();
        let budget = Arc::new(RecoveryMemoryBudget::new(u32::MAX));
        let mut decoder = Decoder::with_budget(8, 8, 1_200, Arc::clone(&budget));
        decoder
            .add_repair(10, 2, 100, 7, &repair_a, 20_000)
            .unwrap();
        let mut recovered = decoder
            .add_repair(10, 2, 101, 7, &repair_b, 20_000)
            .unwrap();

        while let Some(source) = recovered.pop() {
            let charge = recovered
                .take_retained_charge(source.retained_bytes)
                .unwrap();
            decoder
                .commit_recovered_precharged(source.symbol_id, source.bytes, charge)
                .unwrap();
        }
        drop(recovered);
        drop(decoder);
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn recovered_source_does_not_retain_padded_repair_storage() {
        let encoded = source(7, b"short");
        let mut padded = encoded.to_vec();
        padded.resize(1_200, 0);
        let padded = Bytes::from(padded);
        let recovered = canonical_recovered(vec![(7, padded.clone())], 1_200).unwrap();
        assert_eq!(recovered[0].bytes, encoded);
        assert_ne!(recovered[0].bytes.as_ptr(), padded.as_ptr());
    }

    #[test]
    fn direct_source_does_not_retain_shared_packet_storage() {
        let encoded = source(8, b"short");
        let mut packet = encoded.to_vec();
        packet.resize(1_200, 0);
        let packet = Bytes::from(packet);
        let source = packet.slice(..encoded.len());
        let source_pointer = source.as_ptr();
        let mut decoder = Decoder::new(4, 4, 1_200);
        decoder.add_source(8, source, 2_000).unwrap();
        assert_ne!(
            decoder.known_source(8).unwrap().bytes.as_ptr(),
            source_pointer
        );
    }

    #[test]
    fn direct_source_reuses_unique_storage_and_accounts_its_capacity() {
        let encoded = source(8, b"short");
        let mut packet = Vec::with_capacity(1_200);
        packet.extend_from_slice(&encoded);
        let source = Bytes::from(packet);
        let source_pointer = source.as_ptr();
        let budget = Arc::new(RecoveryMemoryBudget::new(1_200));
        let mut decoder = Decoder::with_budget(4, 4, 1_200, Arc::clone(&budget));
        decoder.add_source(8, source, 2_000).unwrap();
        assert_eq!(
            decoder.known_source(8).unwrap().bytes.as_ptr(),
            source_pointer
        );
        assert_eq!(budget.used(), 1_200);
        drop(decoder);
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn decoder_recycles_evicted_storage_for_shared_sources() {
        let first = source(1, b"first");
        let recycled_pointer = first.as_ptr();
        let second = source(2, b"other");
        let mut decoder = Decoder::new(1, 1, 64);
        decoder.add_source(1, first, 2_000).unwrap();
        decoder.add_source(2, second.clone(), 2_000).unwrap();
        assert_eq!(
            decoder.known_source(2).unwrap().bytes.as_ptr(),
            recycled_pointer
        );
        assert_eq!(decoder.known_source(2).unwrap().bytes, second);
    }

    #[test]
    fn source_after_repair_recovers_a_shorter_missing_symbol() {
        let sources = [source(7, b"short"), source(8, b"much-longer")];
        let repair = repair_symbol(7, 42, 9, &sources).unwrap();
        let mut decoder = Decoder::new(512, 512, 1200);
        assert!(
            decoder
                .add_repair(7, 2, 42, 9, &repair, 20_000)
                .unwrap()
                .is_empty()
        );
        let recovered = decoder.add_source(8, sources[1].clone(), 20_000).unwrap();
        assert_eq!(recovered.items.len(), 1);
        assert_eq!(recovered.items[0].symbol_id, 7);
        assert_eq!(recovered.items[0].bytes, sources[0]);
        for source in recovered.iter() {
            decoder
                .commit_recovered(source.symbol_id, source.bytes.clone())
                .unwrap();
        }
        let short_repair = repair_symbol(7, 43, 9, &sources[..1]).unwrap();
        assert!(
            decoder
                .add_repair(7, 1, 43, 9, &short_repair, 20_000)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn known_window_evicts_by_arrival_across_identifier_wrap() {
        let mut decoder = Decoder::new(2, 2, 32);
        for id in [u32::MAX, 0, 1] {
            decoder.add_source(id, source(id, b"x"), 2_000).unwrap();
        }
        assert!(decoder.known_source(u32::MAX).is_none());
        assert!(decoder.known_source(0).is_some());
        assert!(decoder.known_source(1).is_some());
    }

    #[test]
    fn apparent_wrap_does_not_bypass_duplicate_validation() {
        let mut decoder = Decoder::new(4, 4, 32);
        decoder.add_source(0, source(0, b"first"), 2_000).unwrap();
        decoder
            .add_source(u32::MAX, source(u32::MAX, b"last"), 2_000)
            .unwrap();
        assert!(matches!(
            decoder.add_source(0, source(0, b"other"), 2_000),
            Err(FecError::ContradictoryRepair)
        ));
        assert_eq!(decoder.known.len(), 2);
    }

    #[test]
    fn duplicate_source_is_classified_before_delivery_reservation() {
        let encoded = source(7, b"source");
        let mut decoder = Decoder::new(4, 4, 64);
        assert_eq!(decoder.source_status(7, &encoded), Ok(SourceStatus::New));
        decoder.add_source(7, encoded.clone(), 2_000).unwrap();
        assert_eq!(
            decoder.source_status(7, &encoded),
            Ok(SourceStatus::Duplicate)
        );
        assert_eq!(
            decoder.source_status(7, &source(7, b"changed")),
            Err(FecError::ContradictoryRepair)
        );
        assert_eq!(
            decoder.source_status(8, &source(8, b"later")),
            Ok(SourceStatus::New)
        );
    }

    #[test]
    fn unadmitted_recovery_does_not_evict_known_history() {
        let sources = [source(1, b"known"), source(2, b"recovered")];
        let repair = repair_symbol(1, 7, 3, &sources).unwrap();
        let mut decoder = Decoder::new(1, 2, 1200);
        decoder.add_source(1, sources[0].clone(), 20_000).unwrap();
        let recovered = decoder.add_repair(1, 2, 7, 3, &repair, 20_000).unwrap();
        assert_eq!(recovered.items[0].symbol_id, 2);
        assert_eq!(recovered.items[0].bytes, sources[1]);
        assert!(decoder.known_source(1).is_some());
        assert!(decoder.known_source(2).is_none());
    }

    #[test]
    fn decoder_recovers_across_identifier_wrap() {
        let sources = [source(u32::MAX, b"last"), source(0, b"first")];
        let repair_a = repair_symbol(u32::MAX, 100, 7, &sources).unwrap();
        let repair_b = repair_symbol(u32::MAX, 101, 7, &sources).unwrap();
        let mut decoder = Decoder::new(512, 512, 1200);
        assert!(
            decoder
                .add_repair(u32::MAX, 2, 100, 7, &repair_a, 20_000)
                .unwrap()
                .is_empty()
        );
        let mut recovered = decoder
            .add_repair(u32::MAX, 2, 101, 7, &repair_b, 20_000)
            .unwrap();
        recovered
            .items
            .sort_unstable_by_key(|source| source.symbol_id);
        assert_eq!(
            recovered
                .iter()
                .map(|source| (source.symbol_id, source.bytes.clone()))
                .collect::<Vec<_>>(),
            [(0, sources[1].clone()), (u32::MAX, sources[0].clone())]
        );
    }

    #[test]
    fn reordered_sources_and_repairs_recover_a_burst_gap() {
        let sources = (0..8u8)
            .map(|id| source(40 + u32::from(id), &vec![id; usize::from(id) + 3]))
            .collect::<Vec<_>>();
        let repairs = (100..104)
            .map(|repair_id| repair_symbol(40, repair_id, 17, &sources).unwrap())
            .collect::<Vec<_>>();
        let mut decoder = Decoder::new(512, 512, 1200);
        for (repair_id, repair) in (100..104).zip(&repairs) {
            decoder
                .add_repair(40, 8, repair_id, 17, repair, 200_000)
                .unwrap();
        }

        let mut recovered = Vec::new();
        for index in [7usize, 0, 5, 2, 1, 6] {
            let mut batch = decoder
                .add_source(
                    40 + u32::try_from(index).unwrap(),
                    sources[index].clone(),
                    200_000,
                )
                .unwrap();
            for source in batch.iter() {
                decoder
                    .commit_recovered(source.symbol_id, source.bytes.clone())
                    .unwrap();
            }
            recovered.extend(
                batch
                    .items
                    .drain(..)
                    .map(|source| (source.symbol_id, source.bytes)),
            );
        }
        recovered.sort_unstable_by_key(|(id, _)| *id);
        for (id, bytes) in &recovered {
            assert_eq!(bytes, &sources[usize::try_from(*id - 40).unwrap()]);
        }
        let recovered = recovered.into_iter().collect::<BTreeMap<_, _>>();
        for id in [43, 44] {
            assert_eq!(
                recovered.get(&id),
                Some(&sources[usize::try_from(id - 40).unwrap()])
            );
        }
    }

    #[test]
    fn deterministic_random_loss_recovers_despite_repair_loss() {
        let sources = (0..32u32)
            .map(|id| source(100 + id, &id.to_be_bytes()))
            .collect::<Vec<_>>();
        let mut random = 0x4d59_5df4_d0f3_3173u64;
        let mut missing = Vec::new();
        let mut decoder = Decoder::new(512, 512, 1200);
        for index in (0..sources.len()).rev() {
            random = random
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1);
            if random >> 61 == 0 {
                missing.push(index);
            } else {
                decoder
                    .add_source(
                        100 + u32::try_from(index).unwrap(),
                        sources[index].clone(),
                        200_000,
                    )
                    .unwrap();
            }
        }
        assert!(
            missing.len() >= 2,
            "fixed channel must erase multiple sources"
        );

        let mut recovered = Vec::new();
        for ordinal in 0..(missing.len() * 3) {
            if ordinal % 3 == 1 {
                continue;
            }
            let repair_id = 1_000 + u32::try_from(ordinal).unwrap();
            let repair = repair_symbol(100, repair_id, 17, &sources).unwrap();
            let mut batch = decoder
                .add_repair(100, 32, repair_id, 17, &repair, 500_000)
                .unwrap();
            for source in batch.iter() {
                decoder
                    .commit_recovered(source.symbol_id, source.bytes.clone())
                    .unwrap();
            }
            recovered.extend(
                batch
                    .items
                    .drain(..)
                    .map(|source| (source.symbol_id, source.bytes)),
            );
        }
        recovered.sort_unstable_by_key(|(id, _)| *id);
        missing.sort_unstable();
        assert_eq!(recovered.len(), missing.len());
        for ((id, bytes), index) in recovered.into_iter().zip(missing) {
            assert_eq!(id, 100 + u32::try_from(index).unwrap());
            assert_eq!(bytes, sources[index]);
        }
    }
}
