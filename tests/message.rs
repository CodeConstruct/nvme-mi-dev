// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2025 Code Construct
 */
use mctp::MsgIC;
mod common;

use common::DeviceType;

use crate::common::NeverRespChannel;
use crate::common::new_device;
use crate::common::setup;

#[test]
fn invalid_ic_bit() {
    common::setup();

    let (mut mep, mut subsys) = new_device(DeviceType::P1p1tC1aNS0a0a);
    let resp = NeverRespChannel::new("Response sent for request with bad IC bit");

    smol::block_on(async { mep.handle_async(&mut subsys, &[], MsgIC(false), resp).await });
}

#[test]
fn invalid_ic_object() {
    setup();

    let (mut mep, mut subsys) = new_device(DeviceType::P1p1tC1aNS0a0a);
    let resp = NeverRespChannel::new("Response sent for request with invalid IC object");

    const REQ: [u8; 3] = [0x00, 0x00, 0x00];
    smol::block_on(async { mep.handle_async(&mut subsys, &REQ, MsgIC(true), resp).await });
}

#[test]
fn invalid_ic_value() {
    setup();

    let (mut mep, mut subsys) = new_device(DeviceType::P1p1tC1aNS0a0a);
    let resp = NeverRespChannel::new("Response sent for request with invalid IC value");

    const REQ: [u8; 4] = [!0x36, !0xff, !0x11, !0x17];
    smol::block_on(async { mep.handle_async(&mut subsys, &REQ, MsgIC(true), resp).await });
}

#[test]
fn invalid_message_header_object() {
    setup();

    let (mut mep, mut subsys) = new_device(DeviceType::P1p1tC1aNS0a0a);
    let resp =
        NeverRespChannel::new("Response sent for request with invalid message header object");

    #[rustfmt::skip]
    const REQ: [u8; 6] = [
        0x00, 0x00,
        0x23, 0x70, 0x9d, 0x75
    ];
    smol::block_on(async { mep.handle_async(&mut subsys, &REQ, MsgIC(true), resp).await });
}

#[test]
fn invalid_message_header_ror() {
    setup();

    let (mut mep, mut subsys) = new_device(DeviceType::P1p1tC1aNS0a0a);
    let resp =
        NeverRespChannel::new("Response sent for request with invalid message header ROR value");

    #[rustfmt::skip]
    const REQ: [u8; 7] = [
        0x80, 0x00, 0x00,
        0x48, 0xc4, 0xc2, 0xea
    ];
    smol::block_on(async { mep.handle_async(&mut subsys, &REQ, MsgIC(true), resp).await });
}
