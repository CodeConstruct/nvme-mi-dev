// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2025 Code Construct
 */
extern crate simplelog;

use log::LevelFilter;
use mctp::MsgIC;
use nvme_mi_dev::{
    ManagementEndpoint, PciePort, PortId, PortType, Subsystem, SubsystemInfo, TwoWirePort,
};
use simplelog::{ColorChoice, Config, TermLogger, TerminalMode};

pub struct MockNVMeMIAsyncReqChannel {}

impl mctp::AsyncReqChannel for MockNVMeMIAsyncReqChannel {
    async fn send_vectored(
        &mut self,
        _typ: mctp::MsgType,
        _integrity_check: MsgIC,
        _bufs: &[&[u8]],
    ) -> mctp::Result<()> {
        Result::Ok(())
    }

    async fn recv<'f>(
        &mut self,
        buf: &'f mut [u8],
    ) -> mctp::Result<(mctp::MsgType, MsgIC, &'f mut [u8])> {
        mctp::Result::Ok((mctp::MCTP_TYPE_NVME, MsgIC(true), buf))
    }

    fn remote_eid(&self) -> mctp::Eid {
        todo!()
    }
}

pub struct NeverRespChannel {
    msg: &'static str,
}

impl NeverRespChannel {
    #[allow(dead_code)]
    pub fn new(msg: &'static str) -> Self {
        NeverRespChannel { msg }
    }
}

impl mctp::AsyncRespChannel for NeverRespChannel {
    type ReqChannel<'a>
        = MockNVMeMIAsyncReqChannel
    where
        Self: 'a;

    async fn send_vectored(
        &mut self,
        _integrity_check: MsgIC,
        _bufs: &[&[u8]],
    ) -> mctp::Result<()> {
        unreachable!("{}", self.msg);
    }

    fn remote_eid(&self) -> mctp::Eid {
        mctp::Eid(9)
    }

    fn req_channel(&self) -> mctp::Result<Self::ReqChannel<'_>> {
        todo!()
    }
}

pub struct ExpectedRespChannel<'a> {
    resp: &'a [u8],
    sent: bool,
}

impl<'a> ExpectedRespChannel<'a> {
    #[allow(dead_code)]
    pub fn new(resp: &'a [u8]) -> Self {
        Self { resp, sent: false }
    }
}

impl Drop for ExpectedRespChannel<'_> {
    fn drop(&mut self) {
        assert!(
            self.sent,
            "Response never sent - expected {:02x?}",
            self.resp
        );
    }
}

impl mctp::AsyncRespChannel for ExpectedRespChannel<'_> {
    type ReqChannel<'a>
        = MockNVMeMIAsyncReqChannel
    where
        Self: 'a;

    async fn send_vectored(&mut self, _integrity_check: MsgIC, bufs: &[&[u8]]) -> mctp::Result<()> {
        self.sent = true;

        assert!(
            self.resp.is_empty() == bufs.iter().all(|b| b.is_empty()),
            "Failed emptiness consensus"
        );
        assert!(
            core::iter::zip(self.resp, bufs.iter().flat_map(|b| b.iter())).all(|(e, f)| e == f),
            "Expected: {:02x?}, found: {:02x?}",
            self.resp.to_vec(),
            bufs.iter()
                .flat_map(|b| b.iter())
                .copied()
                .collect::<Vec<u8>>()
        );
        Ok(())
    }

    fn remote_eid(&self) -> mctp::Eid {
        mctp::Eid(9)
    }

    fn req_channel(&self) -> mctp::Result<Self::ReqChannel<'_>> {
        todo!()
    }
}

/// A tuple of `(byte_offset, expected_slice)`
pub type ExpectedField<'a> = (usize, &'a [u8]);
pub struct RelaxedRespChannel<'a> {
    fields: Vec<ExpectedField<'a>>,
    sent: bool,
}

impl<'a> RelaxedRespChannel<'a> {
    #[allow(dead_code)]
    pub fn new(mut fields: Vec<ExpectedField<'a>>) -> Self {
        fields.sort_by(|a, b| Ord::cmp(&a.0, &b.0));
        Self {
            fields,
            sent: false,
        }
    }
}

impl Drop for RelaxedRespChannel<'_> {
    fn drop(&mut self) {
        assert!(self.sent);
    }
}

impl mctp::AsyncRespChannel for RelaxedRespChannel<'_> {
    type ReqChannel<'a>
        = MockNVMeMIAsyncReqChannel
    where
        Self: 'a;

    async fn send_vectored(&mut self, _integrity_check: MsgIC, bufs: &[&[u8]]) -> mctp::Result<()> {
        self.sent = true;
        let reified: Vec<u8> = bufs.iter().flat_map(|b| b.iter()).copied().collect();
        for (offset, data) in self.fields.iter() {
            assert!(
                reified.iter().skip(*offset).zip(*data).all(|p| p.0 == p.1),
                "Field match failed at offset {offset}: expected {data:x?} in response\n{reified:x?}"
            );
        }
        Ok(())
    }

    fn remote_eid(&self) -> mctp::Eid {
        todo!()
    }

    fn req_channel(&self) -> mctp::Result<Self::ReqChannel<'_>> {
        todo!()
    }
}

pub fn setup() {
    if true {
        let _ = TermLogger::init(
            LevelFilter::Debug,
            Config::default(),
            TerminalMode::Mixed,
            ColorChoice::Auto,
        );
    }
}

#[allow(dead_code)]
pub enum DeviceType {
    // Ports: 1 PCIe, 1 Two-wire
    // Controllers: 1 Admin
    // Namespaces: 0 Allocated, 0 Active
    P1p1tC1aN0a0a,

    // Ports: 1 PCIe, 1 Two-wire
    // Controllers: 1 Admin
    // Namespaces: 1 Allocated, 0 Active
    P1p1tC1aN1a0a,

    // Ports: 1 PCIe, 1 Two-wire
    // Controllers: 1 Admin
    // Namespaces: 1 Allocated, 1 Active
    P1p1tC1aN1a1a,
}

pub struct TestDevice {
    pub ppid: PortId,
    pub mep: ManagementEndpoint,
    pub subsys: Subsystem,
}

impl TestDevice {
    pub fn new() -> Self {
        let mut subsys = Subsystem::new(SubsystemInfo::invalid());
        let ppid = subsys.add_port(PortType::Pcie(PciePort::new())).unwrap();
        let twpid = subsys
            .add_port(PortType::TwoWire(TwoWirePort::new()))
            .unwrap();
        let mep = ManagementEndpoint::new(twpid);
        Self { ppid, mep, subsys }
    }
}

pub fn new_device(typ: DeviceType) -> (ManagementEndpoint, Subsystem) {
    let mut tdev = TestDevice::new();

    let ctlrid = tdev.subsys.add_controller(tdev.ppid).unwrap();
    match typ {
        DeviceType::P1p1tC1aN0a0a => {}
        DeviceType::P1p1tC1aN1a0a => {
            tdev.subsys.add_namespace(1024).unwrap();
        }
        DeviceType::P1p1tC1aN1a1a => {
            let nsid = tdev.subsys.add_namespace(1024).unwrap();
            tdev.subsys
                .controller_mut(ctlrid)
                .attach_namespace(nsid)
                .unwrap();
        }
    };
    (tdev.mep, tdev.subsys)
}
