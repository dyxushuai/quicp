//! Minimal synchronous C ABI for the platform packet bridge.
//!
//! The ABI borrows foreign buffers only for the duration of each call. It does not expose Rust
//! futures, collections, callbacks, or platform descriptors.

#![allow(unsafe_code)]

use std::mem::{align_of, size_of};
use std::panic::{AssertUnwindSafe, catch_unwind};

use crate::{PlatformError, PlatformPacketBridge, PlatformPacketConfig};

/// Current version of the native QUICP ABI.
pub const ABI_VERSION: u32 = 1;
/// Maximum number of packets accepted by one batch call.
pub const MAX_BATCH_PACKETS: u32 = 64;

/// Stable status values returned by the C ABI.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum FfiStatus {
    /// The operation completed successfully.
    Ok = 0,
    /// The bounded bridge cannot currently make progress.
    WouldBlock = 1,
    /// A caller-owned output buffer is smaller than the next packet.
    BufferTooSmall = 2,
    /// A pointer, length, descriptor, or batch relationship is invalid.
    InvalidArgument = 3,
    /// The requested bridge state is not ready.
    NotReady = 4,
    /// The bridge is closed.
    Closed = 5,
    /// A panic was contained at the FFI boundary.
    Panic = 6,
}

/// Opaque packet-bridge handle owned by foreign code.
pub struct FfiBridge {
    bridge: PlatformPacketBridge,
}

impl FfiBridge {
    fn new() -> Result<Self, PlatformError> {
        Ok(Self {
            bridge: PlatformPacketBridge::new(PlatformPacketConfig::default())?,
        })
    }
}

/// One caller-owned input packet.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct FfiInputPacket {
    /// Pointer to caller-owned packet bytes, borrowed for one call.
    pub data: *const u8,
    /// Packet length in bytes.
    pub len: u32,
}

/// One caller-owned output packet buffer.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct FfiOutputPacket {
    /// Pointer to a caller-owned writable packet buffer, borrowed for one call.
    pub data: *mut u8,
    /// Writable buffer capacity in bytes.
    pub capacity: u32,
    /// Produced packet length, or required length when the buffer is too small.
    pub len: u32,
}

/// Progress made by one batch call.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(C)]
pub struct FfiBatchResult {
    /// Number of input descriptors consumed.
    pub inputs_consumed: u32,
    /// Number of output descriptors filled.
    pub outputs_written: u32,
}

const MAX_BATCH_RANGES: usize = 2 * MAX_BATCH_PACKETS as usize;

#[derive(Clone, Copy, Debug)]
struct AddressRange {
    start: usize,
    end: usize,
}

impl AddressRange {
    const EMPTY: Self = Self { start: 0, end: 0 };
}

fn checked_range<T>(pointer: *const T, count: usize) -> Option<AddressRange> {
    let bytes = count.checked_mul(size_of::<T>())?;
    if bytes == 0 {
        return Some(AddressRange::EMPTY);
    }
    if isize::try_from(bytes).is_err() {
        return None;
    }
    let start = pointer as usize;
    Some(AddressRange {
        start,
        end: start.checked_add(bytes)?,
    })
}

fn ranges_overlap(left: AddressRange, right: AddressRange) -> bool {
    left.start < left.end
        && right.start < right.end
        && left.start < right.end
        && right.start < left.end
}

fn ranges_are_disjoint(ranges: &[AddressRange]) -> bool {
    for (index, left) in ranges.iter().copied().enumerate() {
        if ranges[index + 1..]
            .iter()
            .copied()
            .any(|right| ranges_overlap(left, right))
        {
            return false;
        }
    }
    true
}

fn packet_range(pointer: *const u8, length: usize) -> Option<AddressRange> {
    if length != 0 && pointer.is_null() {
        return None;
    }
    checked_range(pointer, length)
}

fn is_aligned<T>(pointer: *const T) -> bool {
    (pointer as usize).is_multiple_of(align_of::<T>())
}

fn valid_array<T>(pointer: *const T, count: u32) -> bool {
    count <= MAX_BATCH_PACKETS
        && (count == 0 || (!pointer.is_null() && is_aligned(pointer)))
        && checked_range(pointer, count as usize).is_some()
}

fn validate_packet_ranges(
    fixed: &[AddressRange; 4],
    inputs: &[FfiInputPacket],
    outputs: &[FfiOutputPacket],
) -> bool {
    let mut packets = [AddressRange::EMPTY; MAX_BATCH_RANGES];
    for (range, packet) in packets.iter_mut().zip(inputs) {
        let Some(packet_range) = packet_range(packet.data, packet.len as usize) else {
            return false;
        };
        *range = packet_range;
    }
    for (range, packet) in packets[inputs.len()..].iter_mut().zip(outputs) {
        let Some(packet_range) = packet_range(packet.data.cast_const(), packet.capacity as usize)
        else {
            return false;
        };
        *range = packet_range;
    }

    if fixed.iter().copied().any(|fixed_range| {
        packets
            .iter()
            .copied()
            .any(|packet| ranges_overlap(fixed_range, packet))
    }) {
        return false;
    }
    ranges_are_disjoint(&packets[..inputs.len() + outputs.len()])
}

fn map_ingress(error: &PlatformError) -> FfiStatus {
    match error {
        PlatformError::PacketQueueFull => FfiStatus::WouldBlock,
        PlatformError::PacketOutsideMtu { .. } => FfiStatus::InvalidArgument,
        _ => FfiStatus::NotReady,
    }
}

fn boundary(operation: impl FnOnce() -> FfiStatus) -> FfiStatus {
    catch_unwind(AssertUnwindSafe(operation)).unwrap_or(FfiStatus::Panic)
}

/// Returns the native ABI version without allocating or taking a lock.
#[unsafe(no_mangle)]
pub const extern "C" fn quicp_abi_version() -> u32 {
    ABI_VERSION
}

/// Creates an opaque packet bridge using the bounded default configuration.
///
/// The returned bridge is single-owner. Calls using the same bridge, including close, must not
/// overlap on different threads.
///
/// # Safety
///
/// `out_bridge` must be non-null, aligned, and writable for one pointer. The caller must eventually
/// pass that same pointer variable to [`quicp_bridge_close`] exactly once.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn quicp_bridge_create(out_bridge: *mut *mut FfiBridge) -> FfiStatus {
    boundary(|| {
        if out_bridge.is_null() || !is_aligned(out_bridge) {
            return FfiStatus::InvalidArgument;
        }
        // SAFETY: The caller contract guarantees one writable, aligned pointer.
        unsafe { out_bridge.write(std::ptr::null_mut()) };
        let Ok(bridge) = FfiBridge::new() else {
            return FfiStatus::NotReady;
        };
        // SAFETY: The pointer was validated above and remains borrowed for this call only.
        unsafe { out_bridge.write(Box::into_raw(Box::new(bridge))) };
        FfiStatus::Ok
    })
}

fn validate_inputs(bridge: &FfiBridge, inputs: &[FfiInputPacket]) -> bool {
    inputs.iter().all(|packet| {
        !packet.data.is_null()
            && bridge
                .bridge
                .validate_packet_length(packet.len as usize)
                .is_ok()
    })
}

fn validate_outputs(outputs: &mut [FfiOutputPacket]) -> bool {
    for packet in &mut *outputs {
        packet.len = 0;
    }
    outputs
        .iter()
        .all(|packet| packet.capacity == 0 || !packet.data.is_null())
}

fn ingress_batch(
    bridge: &FfiBridge,
    inputs: &[FfiInputPacket],
    result: &mut FfiBatchResult,
) -> FfiStatus {
    let _guard = bridge.bridge.lock_ingress_producer();
    for packet in inputs {
        // SAFETY: All descriptors were validated before any packet was consumed, and the caller
        // keeps every input buffer readable for the duration of this call.
        let bytes = unsafe { std::slice::from_raw_parts(packet.data, packet.len as usize) };
        match bridge
            .bridge
            .ingress_ip_borrowed_validated_while_locked(bytes)
        {
            Ok(()) => result.inputs_consumed += 1,
            Err(error) => return map_ingress(&error),
        }
    }
    FfiStatus::Ok
}

fn egress_batch(
    bridge: &FfiBridge,
    outputs: &mut [FfiOutputPacket],
    result: &mut FfiBatchResult,
) -> FfiStatus {
    let _guard = bridge.bridge.lock_egress_consumer();
    for packet in outputs {
        let output = if packet.capacity == 0 {
            &mut []
        } else {
            // SAFETY: All descriptors were validated before processing. Each mutable slice exists
            // only for this iteration and is not retained by the bridge.
            unsafe { std::slice::from_raw_parts_mut(packet.data, packet.capacity as usize) }
        };
        match bridge.bridge.poll_egress_ip_into_while_locked(output) {
            Ok(Some(len)) => {
                let Ok(len) = u32::try_from(len) else {
                    return FfiStatus::NotReady;
                };
                packet.len = len;
                result.outputs_written += 1;
            }
            Ok(None) => break,
            Err(PlatformError::BufferTooSmall { required, .. }) => {
                let Ok(required) = u32::try_from(required) else {
                    return FfiStatus::NotReady;
                };
                packet.len = required;
                return FfiStatus::BufferTooSmall;
            }
            Err(_) => return FfiStatus::NotReady,
        }
    }
    FfiStatus::Ok
}

/// Enqueues and drains batches of complete IP packets in one nonblocking call.
///
/// All descriptor ranges are validated before the bridge consumes input. After the bridge,
/// descriptor, and result ranges are proven disjoint, `result` and every output length are cleared
/// before packet-buffer and semantic validation. An `OK` result may report partial progress when a
/// bounded queue becomes full; callers retry the unconsumed suffix. `BUFFER_TOO_SMALL` leaves that
/// packet queued and puts its required length in the first unwritten output descriptor. Structural
/// pointer, count, or fixed descriptor/bridge/result overlap errors return before touching
/// caller-owned result or output memory. Packet-buffer range and semantic errors occur after that
/// structural boundary and return with the result and output lengths cleared.
///
/// # Safety
///
/// `bridge` must be a live pointer returned by [`quicp_bridge_create`]. Calls for one bridge must
/// not overlap. Descriptor arrays must be readable/writable for their declared counts, input data
/// must be readable for each length, and output data must be writable for each capacity. Output
/// buffers, descriptor arrays, `result`, and the bridge allocation must not overlap.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn quicp_bridge_process_batch(
    bridge: *mut FfiBridge,
    inputs: *const FfiInputPacket,
    input_count: u32,
    outputs: *mut FfiOutputPacket,
    output_count: u32,
    result: *mut FfiBatchResult,
) -> FfiStatus {
    boundary(|| {
        if bridge.is_null()
            || !is_aligned(bridge)
            || result.is_null()
            || !is_aligned(result)
            || !valid_array(inputs, input_count)
            || !valid_array(outputs, output_count)
        {
            return FfiStatus::InvalidArgument;
        }

        let (Some(bridge_range), Some(input_range), Some(output_range), Some(result_range)) = (
            checked_range(bridge, 1),
            checked_range(inputs, input_count as usize),
            checked_range(outputs, output_count as usize),
            checked_range(result, 1),
        ) else {
            return FfiStatus::InvalidArgument;
        };
        let fixed_ranges = [bridge_range, input_range, output_range, result_range];
        if !ranges_are_disjoint(&fixed_ranges) {
            return FfiStatus::InvalidArgument;
        }

        // SAFETY: The fixed ranges were validated, aligned, and proven disjoint above.
        let result = unsafe { &mut *result };
        *result = FfiBatchResult::default();

        // SAFETY: The caller contract and validation above provide live, aligned values.
        let bridge = unsafe { &*bridge };
        // SAFETY: A null pointer is represented by an empty slice without dereferencing it.
        let inputs = if input_count == 0 {
            &[]
        } else {
            unsafe { std::slice::from_raw_parts(inputs, input_count as usize) }
        };
        // SAFETY: A null pointer is represented by an empty slice without dereferencing it.
        let outputs = if output_count == 0 {
            &mut []
        } else {
            unsafe { std::slice::from_raw_parts_mut(outputs, output_count as usize) }
        };
        for packet in &mut *outputs {
            packet.len = 0;
        }
        if !validate_packet_ranges(&fixed_ranges, inputs, outputs) {
            return FfiStatus::InvalidArgument;
        }

        let inputs_valid = validate_inputs(bridge, inputs);
        let outputs_valid = validate_outputs(outputs);
        if !inputs_valid || !outputs_valid {
            return FfiStatus::InvalidArgument;
        }

        let ingress_status = ingress_batch(bridge, inputs, result);
        if matches!(
            ingress_status,
            FfiStatus::InvalidArgument | FfiStatus::NotReady
        ) {
            return ingress_status;
        }
        let egress_status = egress_batch(bridge, outputs, result);
        if egress_status != FfiStatus::Ok {
            return egress_status;
        }
        if result.inputs_consumed != 0 || result.outputs_written != 0 {
            FfiStatus::Ok
        } else {
            FfiStatus::WouldBlock
        }
    })
}

/// Closes a bridge and clears the caller's pointer.
///
/// # Safety
///
/// `bridge` must point to the live pointer variable written by [`quicp_bridge_create`]. No call may
/// overlap close. Copies of the raw bridge pointer become invalid when this function returns.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn quicp_bridge_close(bridge: *mut *mut FfiBridge) -> FfiStatus {
    boundary(|| {
        if bridge.is_null() || !is_aligned(bridge) {
            return FfiStatus::InvalidArgument;
        }
        // SAFETY: The caller provides a live, aligned pointer variable.
        let raw = unsafe { bridge.read() };
        if raw.is_null() {
            return FfiStatus::Closed;
        }
        if !is_aligned(raw) {
            return FfiStatus::InvalidArgument;
        }
        // Clear the foreign owner before running destructors, making repeated close through the
        // same variable deterministic.
        // SAFETY: The caller provides a writable pointer variable.
        unsafe { bridge.write(std::ptr::null_mut()) };
        // SAFETY: `raw` came from Box::into_raw in create and ownership is consumed exactly once.
        unsafe { drop(Box::from_raw(raw)) };
        FfiStatus::Ok
    })
}

#[cfg(test)]
mod tests {
    use smoltcp::phy::{Device, TxToken};
    use smoltcp::time::Instant;

    use super::*;
    use crate::smolstack::SmoltcpConfig;

    fn len_u32(len: usize) -> u32 {
        u32::try_from(len).expect("test buffer length fits u32")
    }

    #[test]
    fn c_abi_batches_packets_and_preserves_caller_buffers() {
        let mut bridge = std::ptr::null_mut();
        // SAFETY: All pointers below refer to live, correctly sized Rust values.
        assert_eq!(
            unsafe { quicp_bridge_create(&raw mut bridge) },
            FfiStatus::Ok
        );
        assert!(!bridge.is_null());
        assert_eq!(quicp_abi_version(), ABI_VERSION);

        let first = [0x45; 64];
        let second = [0x46; 64];
        let inputs = [
            FfiInputPacket {
                data: first.as_ptr(),
                len: len_u32(first.len()),
            },
            FfiInputPacket {
                data: second.as_ptr(),
                len: len_u32(second.len()),
            },
        ];
        let mut result = FfiBatchResult::default();
        // SAFETY: The bridge and descriptor buffers remain live for the complete call.
        assert_eq!(
            unsafe {
                quicp_bridge_process_batch(
                    bridge,
                    inputs.as_ptr(),
                    len_u32(inputs.len()),
                    std::ptr::null_mut(),
                    0,
                    &raw mut result,
                )
            },
            FfiStatus::Ok
        );
        assert_eq!(result.inputs_consumed, 2);

        // SAFETY: The opaque pointer remains live and exclusively owned by this test.
        let bridge_ref = unsafe { &*bridge };
        assert_eq!(bridge_ref.bridge.ingress_len(), 2);
        let mut device = bridge_ref
            .bridge
            .smoltcp_device(SmoltcpConfig::default())
            .expect("device");
        device
            .transmit(Instant::ZERO)
            .expect("tx")
            .consume(4, |bytes| bytes.copy_from_slice(&[1, 2, 3, 4]));

        let mut small = [0; 3];
        let mut small_output = [FfiOutputPacket {
            data: small.as_mut_ptr(),
            capacity: len_u32(small.len()),
            len: 99,
        }];
        // SAFETY: The bridge and output descriptor remain live and writable.
        assert_eq!(
            unsafe {
                quicp_bridge_process_batch(
                    bridge,
                    std::ptr::null(),
                    0,
                    small_output.as_mut_ptr(),
                    len_u32(small_output.len()),
                    &raw mut result,
                )
            },
            FfiStatus::BufferTooSmall
        );
        assert_eq!(small_output[0].len, 4);
        assert_eq!(bridge_ref.bridge.egress_len(), 1);

        let mut output = [0; 4];
        let mut outputs = [FfiOutputPacket {
            data: output.as_mut_ptr(),
            capacity: len_u32(output.len()),
            len: 99,
        }];
        // SAFETY: The bridge and output descriptor remain live and writable.
        assert_eq!(
            unsafe {
                quicp_bridge_process_batch(
                    bridge,
                    std::ptr::null(),
                    0,
                    outputs.as_mut_ptr(),
                    len_u32(outputs.len()),
                    &raw mut result,
                )
            },
            FfiStatus::Ok
        );
        assert_eq!(outputs[0].len, 4);
        assert_eq!(result.outputs_written, 1);
        assert_eq!(output, [1, 2, 3, 4]);

        drop(device);
        // SAFETY: `bridge` is the live owner variable returned by create.
        assert_eq!(
            unsafe { quicp_bridge_close(&raw mut bridge) },
            FfiStatus::Ok
        );
        assert!(bridge.is_null());
        // SAFETY: Repeated close through the cleared owner variable is supported.
        assert_eq!(
            unsafe { quicp_bridge_close(&raw mut bridge) },
            FfiStatus::Closed
        );
    }

    #[test]
    fn c_abi_rejects_null_boundary_pointers() {
        // SAFETY: Null is intentionally supplied to verify boundary validation.
        assert_eq!(
            unsafe { quicp_bridge_create(std::ptr::null_mut()) },
            FfiStatus::InvalidArgument
        );
        let mut result = FfiBatchResult::default();
        // SAFETY: Null is intentionally supplied to verify boundary validation.
        assert_eq!(
            unsafe {
                quicp_bridge_process_batch(
                    std::ptr::null_mut(),
                    std::ptr::null(),
                    0,
                    std::ptr::null_mut(),
                    0,
                    &raw mut result,
                )
            },
            FfiStatus::InvalidArgument
        );
    }

    #[test]
    fn c_abi_validates_a_complete_batch_before_consuming_it() {
        let mut bridge = std::ptr::null_mut();
        // SAFETY: `bridge` is a live, writable pointer variable.
        assert_eq!(
            unsafe { quicp_bridge_create(&raw mut bridge) },
            FfiStatus::Ok
        );

        let valid = [0x45; 64];
        let oversized = [0x45; 1501];
        let inputs = [
            FfiInputPacket {
                data: valid.as_ptr(),
                len: len_u32(valid.len()),
            },
            FfiInputPacket {
                data: oversized.as_ptr(),
                len: len_u32(oversized.len()),
            },
        ];
        let mut result = FfiBatchResult {
            inputs_consumed: 99,
            outputs_written: 99,
        };
        // SAFETY: Every descriptor points to live memory; the oversized packet is intentionally
        // rejected before the valid prefix can be consumed.
        assert_eq!(
            unsafe {
                quicp_bridge_process_batch(
                    bridge,
                    inputs.as_ptr(),
                    len_u32(inputs.len()),
                    std::ptr::null_mut(),
                    0,
                    &raw mut result,
                )
            },
            FfiStatus::InvalidArgument
        );
        assert_eq!(result, FfiBatchResult::default());
        // SAFETY: The bridge remains live and exclusively owned by this test.
        assert_eq!(unsafe { &*bridge }.bridge.ingress_len(), 0);

        let mut invalid_output = [FfiOutputPacket {
            data: std::ptr::null_mut(),
            capacity: 1,
            len: 99,
        }];
        result = FfiBatchResult {
            inputs_consumed: 9,
            outputs_written: 9,
        };
        // SAFETY: Descriptor and result ranges are valid and disjoint; the packet buffer is
        // deliberately invalid to verify the post-structure clearing contract.
        assert_eq!(
            unsafe {
                quicp_bridge_process_batch(
                    bridge,
                    std::ptr::null(),
                    0,
                    invalid_output.as_mut_ptr(),
                    1,
                    &raw mut result,
                )
            },
            FfiStatus::InvalidArgument
        );
        assert_eq!(result, FfiBatchResult::default());
        assert_eq!(invalid_output[0].len, 0);

        // The count guard runs before constructing a descriptor slice.
        // SAFETY: The intentionally excessive count is rejected without reading the array.
        assert_eq!(
            unsafe {
                quicp_bridge_process_batch(
                    bridge,
                    inputs.as_ptr(),
                    MAX_BATCH_PACKETS + 1,
                    std::ptr::null_mut(),
                    0,
                    &raw mut result,
                )
            },
            FfiStatus::InvalidArgument
        );

        // SAFETY: `bridge` is the live owner variable returned by create.
        assert_eq!(
            unsafe { quicp_bridge_close(&raw mut bridge) },
            FfiStatus::Ok
        );
    }

    #[test]
    fn c_abi_rejects_overlapping_descriptor_ranges() {
        let mut bridge = std::ptr::null_mut();
        // SAFETY: `bridge` is a live, writable pointer variable.
        assert_eq!(
            unsafe { quicp_bridge_create(&raw mut bridge) },
            FfiStatus::Ok
        );

        let payload = [0x45; 64];
        let mut input = FfiInputPacket {
            data: payload.as_ptr(),
            len: len_u32(payload.len()),
        };
        let mut result = FfiBatchResult {
            inputs_consumed: 9,
            outputs_written: 9,
        };
        // SAFETY: The output pointer is deliberately aliased with a live descriptor. The ABI
        // must reject the overlap before constructing a mutable output slice or touching state.
        assert_eq!(
            unsafe {
                quicp_bridge_process_batch(
                    bridge,
                    &raw const input,
                    1,
                    (&raw mut input).cast::<FfiOutputPacket>(),
                    1,
                    &raw mut result,
                )
            },
            FfiStatus::InvalidArgument
        );
        assert_eq!(
            result,
            FfiBatchResult {
                inputs_consumed: 9,
                outputs_written: 9,
            }
        );
        // SAFETY: The bridge remains live and exclusively owned by this test.
        assert_eq!(unsafe { (&*bridge).bridge.ingress_len() }, 0);
        // SAFETY: `bridge` is the live owner variable returned by create.
        assert_eq!(
            unsafe { quicp_bridge_close(&raw mut bridge) },
            FfiStatus::Ok
        );
    }
}
