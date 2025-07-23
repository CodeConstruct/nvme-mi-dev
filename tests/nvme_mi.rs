// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2025 Code Construct
 */
use mctp::MsgIC;
mod common;

use common::DeviceType;
use common::ExpectedRespChannel;
use common::new_device;
use common::setup;

#[rustfmt::skip]
pub const RESP_INVALID_PARAMETER: [u8; 11] = [
    0x88, 0x00, 0x00,
    0x04, 0x00, 0x00, 0x00,
    0xd7, 0x64, 0x55, 0x59
];

#[rustfmt::skip]
pub const RESP_INVALID_COMMAND_SIZE: [u8; 11] = [
    0x88, 0x00, 0x00,
    0x05, 0x00, 0x00, 0x00,
    0x6f, 0xce, 0x10, 0x84
];

#[rustfmt::skip]
pub const RESP_INVALID_COMMAND_INPUT_DATA_SIZE: [u8; 11] = [
    0x88, 0x00, 0x00,
    0x06, 0x00, 0x00, 0x00,
    0x56, 0x47, 0x32, 0xe6
];

#[test]
fn short_header_object() {
    setup();

    let (mut mep, mut subsys) = new_device(DeviceType::P1p1tC1aN0a0a);

    #[rustfmt::skip]
    const REQ: [u8; 10] = [
        0x08, 0x00, 0x00,
        0x00, 0x00, 0x00, // Shortened header
        0x57, 0xb9, 0xb6, 0x8b
    ];

    let resp = ExpectedRespChannel::new(&RESP_INVALID_COMMAND_SIZE);
    smol::block_on(async { mep.handle_async(&mut subsys, &REQ, MsgIC(true), resp).await });
}

mod read_nvme_mi_data_structure {
    use mctp::MsgIC;
    use nvme_mi_dev::nvme::ManagementEndpoint;
    use nvme_mi_dev::nvme::PciePort;
    use nvme_mi_dev::nvme::PortType;
    use nvme_mi_dev::nvme::Subsystem;
    use nvme_mi_dev::nvme::SubsystemInfo;
    use nvme_mi_dev::nvme::TwoWirePort;

    use super::RESP_INVALID_COMMAND_INPUT_DATA_SIZE;
    use super::RESP_INVALID_COMMAND_SIZE;
    use super::RESP_INVALID_PARAMETER;
    use crate::common::DeviceType;
    use crate::common::ExpectedRespChannel;
    use crate::common::RelaxedRespChannel;
    use crate::common::new_device;
    use crate::common::setup;

    #[test]
    fn short_request() {
        setup();

        let (mut mep, mut subsys) = new_device(DeviceType::P1p1tC1aN0a0a);

        #[rustfmt::skip]
        const REQ: [u8; 15] = [
            0x08, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            // Missing DWORD1
            0xc9, 0x40, 0xd7, 0x8b
        ];

        let resp = ExpectedRespChannel::new(&RESP_INVALID_COMMAND_SIZE);
        smol::block_on(async { mep.handle_async(&mut subsys, &REQ, MsgIC(true), resp).await });
    }

    #[test]
    fn long_request() {
        setup();

        let (mut mep, mut subsys) = new_device(DeviceType::P1p1tC1aN0a0a);

        #[rustfmt::skip]
        const REQ: [u8; 23] = [
            0x08, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, // Unnecessary request data
            0xcc, 0xdf, 0x26, 0x64
        ];

        let resp = ExpectedRespChannel::new(&RESP_INVALID_COMMAND_INPUT_DATA_SIZE);
        smol::block_on(async { mep.handle_async(&mut subsys, &REQ, MsgIC(true), resp).await });
    }

    #[test]
    fn nvm_subsystem_information() {
        setup();

        let (mut mep, mut subsys) = new_device(DeviceType::P1p1tC1aN0a0a);

        #[rustfmt::skip]
        const REQ: [u8; 19] = [
            0x08, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0xe2, 0x00, 0x06, 0x07
        ];

        #[rustfmt::skip]
        const RESP: [u8; 43] = [
            0x88, 0x00, 0x00,
            0x00, 0x20, 0x00, 0x00,
            0x01, 0x01, 0x02, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x3c, 0xf8, 0xdb, 0x52
        ];

        let resp = ExpectedRespChannel::new(&RESP);
        smol::block_on(async { mep.handle_async(&mut subsys, &REQ, MsgIC(true), resp).await });
    }

    #[test]
    fn port_information_invalid() {
        setup();

        let (mut mep, mut subsys) = new_device(DeviceType::P1p1tC1aN0a0a);

        #[rustfmt::skip]
        const REQ: [u8; 19] = [
            0x08, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x02, 0x01,
            0x00, 0x00, 0x00, 0x00,
            0x8d, 0xcf, 0x9b, 0xe4
        ];

        let resp = ExpectedRespChannel::new(&RESP_INVALID_PARAMETER);
        smol::block_on(async { mep.handle_async(&mut subsys, &REQ, MsgIC(true), resp).await })
    }

    #[test]
    fn port_information_pcie() {
        setup();

        let (mut mep, mut subsys) = new_device(DeviceType::P1p1tC1aN0a0a);

        #[rustfmt::skip]
        const REQ: [u8; 19] = [
            0x08, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x00,
            0x4e, 0x6f, 0x17, 0x3f
        ];

        #[rustfmt::skip]
        const RESP: [u8; 43] = [
            0x88, 0x00, 0x00,
            0x00, 0x20, 0x00, 0x00,
            0x01, 0x00, 0x40, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x3f, 0x01, 0x02,
            0x01, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x76, 0x6e, 0x77, 0x2d
        ];

        let resp = ExpectedRespChannel::new(&RESP);
        smol::block_on(async { mep.handle_async(&mut subsys, &REQ, MsgIC(true), resp).await })
    }

    #[test]
    fn port_information_twowire() {
        setup();

        let (mut mep, mut subsys) = new_device(DeviceType::P1p1tC1aN0a0a);

        #[rustfmt::skip]
        const REQ: [u8; 19] = [
            0x08, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x01, 0x01,
            0x00, 0x00, 0x00, 0x00,
            0x57, 0x04, 0x27, 0xd0
        ];

        #[rustfmt::skip]
        const RESP: [u8; 43] = [
            0x88, 0x00, 0x00,
            0x00, 0x20, 0x00, 0x00,
            0x02, 0x00, 0x40, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x1d, 0x01,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0xc4, 0x05, 0xbc, 0x27
        ];

        let resp = ExpectedRespChannel::new(&RESP);
        smol::block_on(async { mep.handle_async(&mut subsys, &REQ, MsgIC(true), resp).await })
    }

    #[test]
    fn controller_list_all() {
        setup();

        let (mut mep, mut subsys) = new_device(DeviceType::P1p1tC1aN0a0a);

        #[rustfmt::skip]
        const REQ: [u8; 19] = [
            0x08, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x02,
            0x00, 0x00, 0x00, 0x00,
            0xba, 0xdf, 0x24, 0x77
        ];

        #[rustfmt::skip]
        const RESP: [u8; 15] = [
            0x88, 0x00, 0x00,
            0x00, 0x04, 0x00, 0x00,
            0x01, 0x00, 0x00, 0x00,
            0x0a, 0x29, 0x2f, 0x14
        ];

        let resp = ExpectedRespChannel::new(&RESP);
        smol::block_on(async { mep.handle_async(&mut subsys, &REQ, MsgIC(true), resp).await })
    }

    #[test]
    fn controller_list_single_partial_empty() {
        setup();

        let (mut mep, mut subsys) = new_device(DeviceType::P1p1tC1aN0a0a);

        #[rustfmt::skip]
        const REQ: [u8; 19] = [
            0x08, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x01, 0x00, 0x00, 0x02,
            0x00, 0x00, 0x00, 0x00,
            0x9d, 0xa2, 0x18, 0x3e
        ];

        #[rustfmt::skip]
        const RESP: [u8; 13] = [
            0x88, 0x00, 0x00,
            0x00, 0x02, 0x00, 0x00,
            0x00, 0x00,
            0xec, 0xc6, 0x96, 0xd4
        ];

        let resp = ExpectedRespChannel::new(&RESP);
        smol::block_on(async { mep.handle_async(&mut subsys, &REQ, MsgIC(true), resp).await })
    }

    #[test]
    fn controller_list_multiple() {
        setup();
        let mut subsys = Subsystem::new(SubsystemInfo::invalid());
        let ppid = subsys.add_port(PortType::Pcie(PciePort::new())).unwrap();
        subsys.add_controller(ppid).unwrap();
        subsys.add_controller(ppid).unwrap();
        let twpid = subsys
            .add_port(PortType::TwoWire(TwoWirePort::new()))
            .unwrap();
        let mut mep = ManagementEndpoint::new(twpid);

        #[rustfmt::skip]
        const REQ: [u8; 19] = [
            0x08, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x02,
            0x00, 0x00, 0x00, 0x00,
            0xba, 0xdf, 0x24, 0x77
        ];

        #[rustfmt::skip]
        const RESP: [u8; 17] = [
            0x88, 0x00, 0x00,
            0x00, 0x06, 0x00, 0x00,
            0x02, 0x00, 0x00, 0x00,
            0x01, 0x00,
            0x75, 0x4c, 0xb0, 0xd9
        ];

        let resp = ExpectedRespChannel::new(&RESP);
        smol::block_on(async { mep.handle_async(&mut subsys, &REQ, MsgIC(true), resp).await })
    }

    #[test]
    fn controller_list_multiple_partial_populated() {
        setup();

        let mut subsys = Subsystem::new(SubsystemInfo::invalid());
        let ppid = subsys.add_port(PortType::Pcie(PciePort::new())).unwrap();
        subsys.add_controller(ppid).unwrap();
        subsys.add_controller(ppid).unwrap();
        let twpid = subsys
            .add_port(PortType::TwoWire(TwoWirePort::new()))
            .unwrap();
        let mut mep = ManagementEndpoint::new(twpid);

        #[rustfmt::skip]
        const REQ: [u8; 19] = [
            0x08, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x01, 0x00, 0x00, 0x02,
            0x00, 0x00, 0x00, 0x00,
            0x9d, 0xa2, 0x18, 0x3e
        ];

        #[rustfmt::skip]
        const RESP: [u8; 15] = [
            0x88, 0x00, 0x00,
            0x00, 0x04, 0x00, 0x00,
            0x01, 0x00, 0x01, 0x00,
            0x7d, 0xb1, 0x8d, 0x07
        ];

        let resp = ExpectedRespChannel::new(&RESP);
        smol::block_on(async { mep.handle_async(&mut subsys, &REQ, MsgIC(true), resp).await })
    }

    #[test]
    fn controller_information_single_valid() {
        setup();

        let (mut mep, mut subsys) = new_device(DeviceType::P1p1tC1aN0a0a);

        #[rustfmt::skip]
        const REQ: [u8; 19] = [
            0x08, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x03,
            0x00, 0x00, 0x00, 0x00,
            0x16, 0xb0, 0x35, 0x4f
        ];

        // Make sure we get a valid response of size 0x20. PCI data will be
        // vendor-specific
        let resp_data: Vec<(usize, &[u8])> = vec![(0, &[0x88, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00])];

        let resp = RelaxedRespChannel::new(resp_data);
        smol::block_on(async { mep.handle_async(&mut subsys, &REQ, MsgIC(true), resp).await })
    }

    #[test]
    fn controller_information_single_invalid() {
        setup();

        let (mut mep, mut subsys) = new_device(DeviceType::P1p1tC1aN0a0a);

        #[rustfmt::skip]
        const REQ: [u8; 19] = [
            0x08, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x01, 0x00, 0x00, 0x03,
            0x00, 0x00, 0x00, 0x00,
            0x31, 0xcd, 0x09, 0x06
        ];

        let resp = ExpectedRespChannel::new(&RESP_INVALID_PARAMETER);
        smol::block_on(async { mep.handle_async(&mut subsys, &REQ, MsgIC(true), resp).await })
    }
}

mod nvm_subsystem_status_health_poll {
    use mctp::MsgIC;
    use nvme_mi_dev::nvme::{
        ManagementEndpoint, PciePort, PortType, Subsystem, SubsystemInfo, Temperature, TwoWirePort,
    };

    use super::RESP_INVALID_COMMAND_SIZE;
    use crate::common::{DeviceType, ExpectedRespChannel, new_device, setup};

    #[test]
    fn short_request() {
        setup();

        let (mut mep, mut subsys) = new_device(DeviceType::P1p1tC1aN0a0a);
        #[rustfmt::skip]
        const REQ: [u8; 15] = [
            0x08, 0x00, 0x00,
            0x01, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0xee, 0x3d, 0xeb, 0xc2
        ];

        let resp = ExpectedRespChannel::new(&RESP_INVALID_COMMAND_SIZE);
        smol::block_on(async { mep.handle_async(&mut subsys, &REQ, MsgIC(true), resp).await })
    }

    #[test]
    fn long_request() {
        setup();

        let (mut mep, mut subsys) = new_device(DeviceType::P1p1tC1aN0a0a);

        #[rustfmt::skip]
        const REQ: [u8; 23] = [
            0x08, 0x00, 0x00,
            0x01, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x32, 0xd2, 0x2a, 0x96
        ];

        let resp = ExpectedRespChannel::new(&RESP_INVALID_COMMAND_SIZE);
        smol::block_on(async { mep.handle_async(&mut subsys, &REQ, MsgIC(true), resp).await });
    }

    #[test]
    fn clear_status() {
        setup();

        let (mut mep, mut subsys) = new_device(DeviceType::P1p1tC1aN0a0a);

        #[rustfmt::skip]
        const REQ: [u8; 19] = [
            0x08, 0x00, 0x00,
            0x01, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x80,
            0xaa, 0xef, 0x81, 0xb4
        ];

        #[rustfmt::skip]
        const RESP: [u8; 19] = [
            0x88, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x38, 0x3d, 0x14, 0x26,
            0x00, 0x00, 0x00, 0x00,
            0x11, 0x7c, 0xb0, 0x3d
        ];

        let resp = ExpectedRespChannel::new(&RESP);
        smol::block_on(async { mep.handle_async(&mut subsys, &REQ, MsgIC(true), resp).await });
    }

    #[test]
    fn ctemp_excursion_saturate_low() {
        setup();

        let mut subsys = Subsystem::new(SubsystemInfo::invalid());
        let ppid = subsys.add_port(PortType::Pcie(PciePort::new())).unwrap();
        let ctlrid = subsys.add_controller(ppid).unwrap();
        let twpid = subsys
            .add_port(PortType::TwoWire(TwoWirePort::new()))
            .unwrap();
        let mut mep = ManagementEndpoint::new(twpid);
        let ctlr = subsys.controller_mut(ctlrid);
        ctlr.set_temperature(Temperature::Kelvin(212));

        #[rustfmt::skip]
        const REQ: [u8; 19] = [
            0x08, 0x00, 0x00,
            0x01, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0xd2, 0xd4, 0x77, 0x36
        ];

        #[rustfmt::skip]
        const RESP: [u8; 19] = [
            0x88, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x38, 0x3f, 0xc4, 0x26,
            0x00, 0x00, 0x00, 0x00,
            0x82, 0xf9, 0xb6, 0x3f
        ];

        let resp = ExpectedRespChannel::new(&RESP);
        smol::block_on(async { mep.handle_async(&mut subsys, &REQ, MsgIC(true), resp).await });
    }

    #[test]
    fn ctemp_saturate_low() {
        setup();

        let mut subsys = Subsystem::new(SubsystemInfo::invalid());
        let ppid = subsys.add_port(PortType::Pcie(PciePort::new())).unwrap();
        let ctlrid = subsys.add_controller(ppid).unwrap();
        let twpid = subsys
            .add_port(PortType::TwoWire(TwoWirePort::new()))
            .unwrap();
        let mut mep = ManagementEndpoint::new(twpid);
        let ctlr = subsys.controller_mut(ctlrid);
        ctlr.set_temperature(Temperature::Kelvin(213));

        #[rustfmt::skip]
        const REQ: [u8; 19] = [
            0x08, 0x00, 0x00,
            0x01, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0xd2, 0xd4, 0x77, 0x36
        ];

        #[rustfmt::skip]
        const RESP: [u8; 19] = [
            0x88, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x38, 0x3d, 0xc4, 0x26,
            0x00, 0x00, 0x00, 0x00,
            0x12, 0xa0, 0xb0, 0xef
        ];

        let resp = ExpectedRespChannel::new(&RESP);
        smol::block_on(async { mep.handle_async(&mut subsys, &REQ, MsgIC(true), resp).await });
    }

    #[test]
    fn ctemp_low() {
        setup();

        let mut subsys = Subsystem::new(SubsystemInfo::invalid());
        let ppid = subsys.add_port(PortType::Pcie(PciePort::new())).unwrap();
        let ctlrid = subsys.add_controller(ppid).unwrap();
        let twpid = subsys
            .add_port(PortType::TwoWire(TwoWirePort::new()))
            .unwrap();
        let mut mep = ManagementEndpoint::new(twpid);
        let ctlr = subsys.controller_mut(ctlrid);
        ctlr.set_temperature(Temperature::Kelvin(214));

        #[rustfmt::skip]
        const REQ: [u8; 19] = [
            0x08, 0x00, 0x00,
            0x01, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0xd2, 0xd4, 0x77, 0x36
        ];

        #[rustfmt::skip]
        const RESP: [u8; 19] = [
            0x88, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x38, 0x3d, 0xc5, 0x26,
            0x00, 0x00, 0x00, 0x00,
            0x0b, 0xcb, 0x80, 0x00
        ];

        let resp = ExpectedRespChannel::new(&RESP);
        smol::block_on(async { mep.handle_async(&mut subsys, &REQ, MsgIC(true), resp).await });
    }

    #[test]
    fn ctemp_zero() {
        setup();

        let mut subsys = Subsystem::new(SubsystemInfo::invalid());
        let ppid = subsys.add_port(PortType::Pcie(PciePort::new())).unwrap();
        let ctlrid = subsys.add_controller(ppid).unwrap();
        let twpid = subsys
            .add_port(PortType::TwoWire(TwoWirePort::new()))
            .unwrap();
        let mut mep = ManagementEndpoint::new(twpid);
        let ctlr = subsys.controller_mut(ctlrid);
        ctlr.set_temperature(Temperature::Kelvin(273));

        #[rustfmt::skip]
        const REQ: [u8; 19] = [
            0x08, 0x00, 0x00,
            0x01, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0xd2, 0xd4, 0x77, 0x36
        ];

        #[rustfmt::skip]
        const RESP: [u8; 19] = [
            0x88, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x38, 0x3d, 0x00, 0x26,
            0x00, 0x00, 0x00, 0x00,
            0x58, 0x7b, 0x49, 0x4f
        ];

        let resp = ExpectedRespChannel::new(&RESP);
        smol::block_on(async { mep.handle_async(&mut subsys, &REQ, MsgIC(true), resp).await });
    }

    #[test]
    fn ctemp_high() {
        setup();

        let mut subsys = Subsystem::new(SubsystemInfo::invalid());
        let ppid = subsys.add_port(PortType::Pcie(PciePort::new())).unwrap();
        let ctlrid = subsys.add_controller(ppid).unwrap();
        let twpid = subsys
            .add_port(PortType::TwoWire(TwoWirePort::new()))
            .unwrap();
        let mut mep = ManagementEndpoint::new(twpid);
        let ctlr = subsys.controller_mut(ctlrid);
        ctlr.set_temperature(Temperature::Kelvin(399));

        #[rustfmt::skip]
        const REQ: [u8; 19] = [
            0x08, 0x00, 0x00,
            0x01, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0xd2, 0xd4, 0x77, 0x36
        ];

        #[rustfmt::skip]
        const RESP: [u8; 19] = [
            0x88, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x38, 0x3d, 0x7e, 0x26,
            0x00, 0x00, 0x00, 0x00,
            0xab, 0x89, 0xca, 0x0d
        ];

        let resp = ExpectedRespChannel::new(&RESP);
        smol::block_on(async { mep.handle_async(&mut subsys, &REQ, MsgIC(true), resp).await });
    }

    #[test]
    fn ctemp_saturate_high() {
        setup();

        let mut subsys = Subsystem::new(SubsystemInfo::invalid());
        let ppid = subsys.add_port(PortType::Pcie(PciePort::new())).unwrap();
        let ctlrid = subsys.add_controller(ppid).unwrap();
        let twpid = subsys
            .add_port(PortType::TwoWire(TwoWirePort::new()))
            .unwrap();
        let mut mep = ManagementEndpoint::new(twpid);
        let ctlr = subsys.controller_mut(ctlrid);
        ctlr.set_temperature(Temperature::Kelvin(400));

        #[rustfmt::skip]
        const REQ: [u8; 19] = [
            0x08, 0x00, 0x00,
            0x01, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0xd2, 0xd4, 0x77, 0x36
        ];

        #[rustfmt::skip]
        const RESP: [u8; 19] = [
            0x88, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x38, 0x3d, 0x7f, 0x26,
            0x00, 0x00, 0x00, 0x00,
            0xb2, 0xe2, 0xfa, 0xe2
        ];

        let resp = ExpectedRespChannel::new(&RESP);
        smol::block_on(async { mep.handle_async(&mut subsys, &REQ, MsgIC(true), resp).await });
    }

    #[test]
    fn ctemp_excursion_saturate_high() {
        setup();

        let mut subsys = Subsystem::new(SubsystemInfo::invalid());
        let ppid = subsys.add_port(PortType::Pcie(PciePort::new())).unwrap();
        let ctlrid = subsys.add_controller(ppid).unwrap();
        let twpid = subsys
            .add_port(PortType::TwoWire(TwoWirePort::new()))
            .unwrap();
        let mut mep = ManagementEndpoint::new(twpid);
        let ctlr = subsys.controller_mut(ctlrid);
        ctlr.set_temperature(Temperature::Kelvin(401));

        #[rustfmt::skip]
        const REQ: [u8; 19] = [
            0x08, 0x00, 0x00,
            0x01, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0xd2, 0xd4, 0x77, 0x36
        ];

        #[rustfmt::skip]
        const RESP: [u8; 19] = [
            0x88, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x38, 0x3f, 0x7f, 0x26,
            0x00, 0x00, 0x00, 0x00,
            0x22, 0xbb, 0xfc, 0x32
        ];

        let resp = ExpectedRespChannel::new(&RESP);
        smol::block_on(async { mep.handle_async(&mut subsys, &REQ, MsgIC(true), resp).await });
    }
}

mod configuration_get {
    use mctp::MsgIC;

    use crate::{
        RESP_INVALID_COMMAND_SIZE, RESP_INVALID_PARAMETER,
        common::{DeviceType, ExpectedRespChannel, new_device, setup},
    };

    #[test]
    fn short_request() {
        setup();

        let (mut mep, mut subsys) = new_device(DeviceType::P1p1tC1aN0a0a);

        #[rustfmt::skip]
        const REQ: [u8; 15] = [
            0x08, 0x00, 0x00,
            0x04, 0x00, 0x00, 0x00,
            0x01, 0x00, 0x00, 0x00,
            // Missing DWORD 1
            0x1c, 0x68, 0x8f, 0x77
        ];

        let resp = ExpectedRespChannel::new(&RESP_INVALID_COMMAND_SIZE);
        smol::block_on(async { mep.handle_async(&mut subsys, &REQ, MsgIC(true), resp).await })
    }

    #[test]
    fn long_request() {
        setup();

        let (mut mep, mut subsys) = new_device(DeviceType::P1p1tC1aN0a0a);

        #[rustfmt::skip]
        const REQ: [u8; 23] = [
            0x08, 0x00, 0x00,
            0x04, 0x00, 0x00, 0x00,
            0x01, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            // Unexpected data
            0x00, 0x00, 0x00, 0x00,
            0x17, 0xa7, 0x53, 0x93
        ];

        let resp = ExpectedRespChannel::new(&RESP_INVALID_COMMAND_SIZE);
        smol::block_on(async { mep.handle_async(&mut subsys, &REQ, MsgIC(true), resp).await })
    }

    #[test]
    fn reserved() {
        setup();

        let (mut mep, mut subsys) = new_device(DeviceType::P1p1tC1aN0a0a);

        #[rustfmt::skip]
        const REQ: [u8; 19] = [
            0x08, 0x00, 0x00,
            0x04, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x22, 0x50, 0xc1, 0xc2
        ];

        let resp = ExpectedRespChannel::new(&RESP_INVALID_PARAMETER);
        smol::block_on(async { mep.handle_async(&mut subsys, &REQ, MsgIC(true), resp).await })
    }

    #[test]
    fn smbus_i2c_frequency() {
        setup();

        let (mut mep, mut subsys) = new_device(DeviceType::P1p1tC1aN0a0a);

        #[rustfmt::skip]
        const REQ: [u8; 19] = [
            0x08, 0x00, 0x00,
            0x04, 0x00, 0x00, 0x00,
            0x01, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x00,
            0xa9, 0x42, 0xec, 0xb3
        ];

        #[rustfmt::skip]
        const RESP: [u8; 11] = [
            0x88, 0x00, 0x00,
            0x00, 0x01, 0x00, 0x00,
            0x5a, 0xc7, 0x36, 0x87
        ];

        let resp = ExpectedRespChannel::new(&RESP);
        smol::block_on(async { mep.handle_async(&mut subsys, &REQ, MsgIC(true), resp).await });
    }

    #[test]
    fn smbus_i2c_frequency_bad_port_type_for_index() {
        setup();

        let (mut mep, mut subsys) = new_device(DeviceType::P1p1tC1aN0a0a);

        #[rustfmt::skip]
        const REQ: [u8; 19] = [
            0x08, 0x00, 0x00,
            0x04, 0x00, 0x00, 0x00,
            0x01, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x05, 0x2d, 0xfd, 0x8b
        ];

        let resp = ExpectedRespChannel::new(&RESP_INVALID_PARAMETER);
        smol::block_on(async { mep.handle_async(&mut subsys, &REQ, MsgIC(true), resp).await });
    }

    #[test]
    fn smbus_i2c_frequency_bad_port_index() {
        setup();

        let (mut mep, mut subsys) = new_device(DeviceType::P1p1tC1aN0a0a);

        #[rustfmt::skip]
        const REQ: [u8; 19] = [
            0x08, 0x00, 0x00,
            0x04, 0x00, 0x00, 0x00,
            0x01, 0x00, 0x00, 0xff,
            0x00, 0x00, 0x00, 0x00,
            0xa6, 0x43, 0x95, 0x2b
        ];

        let resp = ExpectedRespChannel::new(&RESP_INVALID_PARAMETER);
        smol::block_on(async { mep.handle_async(&mut subsys, &REQ, MsgIC(true), resp).await });
    }

    #[test]
    fn mctp_transmission_unit_size() {
        setup();

        let (mut mep, mut subsys) = new_device(DeviceType::P1p1tC1aN0a0a);

        #[rustfmt::skip]
        const REQ: [u8; 19] = [
            0x08, 0x00, 0x00,
            0x04, 0x00, 0x00, 0x00,
            0x03, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x00,
            0xe7, 0xb8, 0x94, 0x21
        ];

        #[rustfmt::skip]
        const RESP: [u8; 11] = [
            0x88, 0x00, 0x00,
            0x00, 0x40, 0x00, 0x00,
            0xfd, 0xd5, 0x12, 0xe5
        ];

        let resp = ExpectedRespChannel::new(&RESP);
        smol::block_on(async { mep.handle_async(&mut subsys, &REQ, MsgIC(true), resp).await });
    }

    #[test]
    fn mctp_transmission_unit_size_long() {
        setup();

        let (mut mep, mut subsys) = new_device(DeviceType::P1p1tC1aN0a0a);

        #[rustfmt::skip]
        const REQ: [u8; 23] = [
            0x08, 0x00, 0x00,
            0x04, 0x00, 0x00, 0x00,
            0x03, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x77, 0x0f, 0xb0, 0xf1
        ];

        let resp = ExpectedRespChannel::new(&RESP_INVALID_COMMAND_SIZE);
        smol::block_on(async { mep.handle_async(&mut subsys, &REQ, MsgIC(true), resp).await });
    }

    #[test]
    fn mctp_transmission_unit_size_bad_port_index() {
        setup();

        let (mut mep, mut subsys) = new_device(DeviceType::P1p1tC1aN0a0a);

        #[rustfmt::skip]
        const REQ: [u8; 19] = [
            0x08, 0x00, 0x00,
            0x04, 0x00, 0x00, 0x00,
            0x03, 0x00, 0x00, 0xff,
            0x00, 0x00, 0x00, 0x00,
            0xe8, 0xb9, 0xed, 0xb9
        ];

        let resp = ExpectedRespChannel::new(&RESP_INVALID_PARAMETER);
        smol::block_on(async { mep.handle_async(&mut subsys, &REQ, MsgIC(true), resp).await });
    }
}
