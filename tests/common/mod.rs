extern crate simplelog;

use log::LevelFilter;
use nvme_mi_dev::nvme::{ManagementEndpoint, PCIePort, PortType, Subsystem, TwoWirePort};
use simplelog::{ColorChoice, Config, TermLogger, TerminalMode};

pub struct MockNVMeMIAsyncReqChannel {}

impl mctp::AsyncReqChannel for MockNVMeMIAsyncReqChannel {
    async fn send_vectored(
        &mut self,
        _typ: mctp::MsgType,
        _integrity_check: bool,
        _bufs: &[&[u8]],
    ) -> mctp::Result<()> {
        Result::Ok(())
    }

    async fn recv<'f>(
        &mut self,
        buf: &'f mut [u8],
    ) -> mctp::Result<(&'f mut [u8], mctp::MsgType, mctp::Tag, bool)> {
        mctp::Result::Ok((
            buf,
            mctp::MCTP_TYPE_NVME,
            mctp::Tag::Unowned(mctp::TagValue(0)),
            true,
        ))
    }

    fn remote_eid(&self) -> mctp::Eid {
        todo!()
    }
}

pub struct NeverRespChannel {
    msg: &'static str,
}

impl NeverRespChannel {
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
        _typ: mctp::MsgType,
        _integrity_check: bool,
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

    async fn send(&mut self, typ: mctp::MsgType, buf: &[u8]) -> mctp::Result<()> {
        self.send_vectored(typ, false, &[buf]).await
    }
}

pub struct ExpectedRespChannel<'a> {
    resp: &'a [u8],
    sent: bool,
}

impl<'a> ExpectedRespChannel<'a> {
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

    async fn send_vectored(
        &mut self,
        _typ: mctp::MsgType,
        _integrity_check: bool,
        bufs: &[&[u8]],
    ) -> mctp::Result<()> {
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

    async fn send(&mut self, typ: mctp::MsgType, buf: &[u8]) -> mctp::Result<()> {
        self.send_vectored(typ, false, &[buf]).await
    }
}

pub type ExpectedField<'a> = (usize, &'a [u8]);
pub struct RelaxedRespChannel<'a> {
    fields: Vec<ExpectedField<'a>>,
    sent: bool,
}

impl<'a> RelaxedRespChannel<'a> {
    pub fn new(mut fields: Vec<ExpectedField<'a>>) -> Self {
        fields.sort_by(|a, b| Ord::cmp(&a.0, &b.0));
        Self {
            fields,
            sent: false,
        }
    }
}

impl mctp::AsyncRespChannel for RelaxedRespChannel<'_> {
    type ReqChannel<'a>
        = MockNVMeMIAsyncReqChannel
    where
        Self: 'a;

    async fn send_vectored(
        &mut self,
        _typ: mctp::MsgType,
        _integrity_check: bool,
        bufs: &[&[u8]],
    ) -> mctp::Result<()> {
        self.sent = true;
        let reified: Vec<u8> = bufs.iter().flat_map(|b| b.iter()).copied().collect();
        for (offset, data) in self.fields.iter() {
            assert!(
                reified.iter().skip(*offset).zip(*data).all(|p| p.0 == p.1),
                "Field match failed at offset {}: expected {:x?} in response\n{:x?}",
                offset,
                data,
                reified
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

pub fn new_simple_subsystem() -> (ManagementEndpoint, Subsystem) {
    let mut subsys = Subsystem::new();
    let ppid = subsys.add_port(PortType::PCIe(PCIePort::new())).unwrap();
    subsys.add_controller(ppid).unwrap();
    let twpid = subsys
        .add_port(PortType::TwoWire(TwoWirePort::new()))
        .unwrap();
    let mep = ManagementEndpoint::new(twpid);
    (mep, subsys)
}

#[rustfmt::skip]
pub const RESP_INVALID_COMMAND: [u8; 11] = [
    0x80, 0x00, 0x00,
    0x03, 0x00, 0x00, 0x00,
    0x4e, 0x21, 0x78, 0x0e
];

#[rustfmt::skip]
pub const RESP_INVALID_PARAMETER: [u8; 11] = [
    0x80, 0x00, 0x00,
    0x04, 0x00, 0x00, 0x00,
    0x84, 0x99, 0x78, 0x17
];

#[rustfmt::skip]
pub const RESP_INVALID_COMMAND_SIZE: [u8; 11] = [
    0x80, 0x00, 0x00,
    0x05, 0x00, 0x00, 0x00,
    0x3c, 0x33, 0x3d, 0xca,
];

#[rustfmt::skip]
pub const RESP_INVALID_COMMAND_INPUT_DATA_SIZE: [u8; 11] = [
    0x80, 0x00, 0x00,
    0x06, 0x00, 0x00, 0x00,
    0x05, 0xba, 0x1f, 0xa8
];
