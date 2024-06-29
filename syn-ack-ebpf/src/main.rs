#![no_std]
#![no_main]

use aya_ebpf::{bindings::xdp_action, macros::xdp, programs::XdpContext};
use core::mem;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
};

#[derive(Debug)]
enum ExecutionError {
    PointerOverflow,
    PointerOutOfBounds,
}

#[inline(always)]
fn get_ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ExecutionError> {
    // Get the start and end of the packet data and the size of the type we're trying to access
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    // Ensure the pointer doesn't overflow to prevent undefined behavior and ensure the pointer is not out of bounds
    let new_ptr = start
        .checked_add(offset)
        .ok_or(ExecutionError::PointerOverflow)?;

    if new_ptr
        .checked_add(len)
        .ok_or(ExecutionError::PointerOverflow)?
        > end
    {
        return Err(ExecutionError::PointerOutOfBounds);
    }

    Ok((start + offset) as *const T)
}

#[inline(always)]
fn get_mut_ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*mut T, ExecutionError> {
    let ptr: *const T = get_ptr_at(ctx, offset)?;
    Ok(ptr as *mut T)
}

#[xdp]
pub fn syn_ack(ctx: XdpContext) -> u32 {
    match try_syn_ack(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn try_syn_ack(ctx: XdpContext) -> Result<u32, ExecutionError> {
    // Use pointer arithmetic to obtain a raw pointer to the Ethernet header at the start of the XdpContext data.
    let eth_hdr: *mut EthHdr = get_mut_ptr_at(&ctx, 0)?;

    // Check the EtherType of the packet. If it's not an IPv4 packet, pass it along without further processing
    // We have to use unsafe here because we're dereferencing a raw pointer
    match unsafe { (*eth_hdr).ether_type } {
        EtherType::Ipv4 => {}
        _ => return Ok(xdp_action::XDP_PASS),
    }

    // Using Ethernet header length, obtain a pointer to the IPv4 header which immediately follows the Ethernet header
    let ip_hdr: *mut Ipv4Hdr = get_mut_ptr_at(&ctx, EthHdr::LEN)?;

    // Check the protocol of the IPv4 packet. If it's not TCP, pass it along without further processing
    match unsafe { (*ip_hdr).proto } {
        IpProto::Tcp => {}
        _ => return Ok(xdp_action::XDP_PASS),
    }

    // Using the IPv4 header length, obtain a pointer to the TCP header which immediately follows the IPv4 header
    let tcp_hdr: *mut TcpHdr = get_mut_ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;

    // Check the destination port of the TCP packet. If it's not in the range 9000-9500, pass it along without further processing
    let port = unsafe { u16::from_be((*tcp_hdr).dest) };
    match port {
        9000..=9500 => {}
        _ => return Ok(xdp_action::XDP_PASS),
    }

    // Check if it's a SYN packet
    let is_syn_packet = unsafe {
        match ((*tcp_hdr).syn() != 0, (*tcp_hdr).ack() == 0) {
            (true, true) => true,
            _ => false,
        }
    };

    if !is_syn_packet {
        return Ok(xdp_action::XDP_PASS);
    }

    // Swap Ethernet addresses
    unsafe { core::mem::swap(&mut (*eth_hdr).src_addr, &mut (*eth_hdr).dst_addr) }

    // Swap IP addresses
    unsafe {
        core::mem::swap(&mut (*ip_hdr).src_addr, &mut (*ip_hdr).dst_addr);
    }

    // Modify TCP header for SYN-ACK
    unsafe {
        core::mem::swap(&mut (*tcp_hdr).source, &mut (*tcp_hdr).dest);
        (*tcp_hdr).set_ack(1);
        (*tcp_hdr).ack_seq = (*tcp_hdr).seq.to_be() + 1;
        (*tcp_hdr).seq = 1u32.to_be();
    }

    Ok(xdp_action::XDP_TX)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
