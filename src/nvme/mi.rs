// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2025 Code Construct
 */
use deku::ctx::Endian;
use deku::prelude::*;
use heapless::Vec;
use log::debug;
use mctp::{AsyncRespChannel, MsgIC};

use num_derive::{FromPrimitive, ToPrimitive};
use num_traits::ToPrimitive;

use crate::{
    nvme::{MAX_NAMESPACES, MAX_NIDTS, PCIeLinkSpeed, PortType, UnitKind},
    wire::{string::WireString, uuid::WireUuid, vec::WireVec},
};

const ISCSI: crc::Crc<u32> = crc::Crc::<u32>::new(&crc::CRC_32_ISCSI);
const MAX_FRAGMENTS: usize = 6;

#[allow(dead_code)]
#[derive(Clone, Copy, Debug, DekuRead, DekuWrite, Eq, FromPrimitive, PartialEq, ToPrimitive)]
#[deku(endian = "endian", ctx = "endian: Endian")]
#[deku(id_type = "u8")]
#[repr(u8)]
enum SMBusFrequency {
    FreqNotSupported = 0x00,
    Freq100kHz = 0x01,
    Freq400kHz = 0x02,
    Freq1MHz = 0x03,
}

impl From<super::SMBusFrequency> for SMBusFrequency {
    fn from(value: super::SMBusFrequency) -> Self {
        match value {
            super::SMBusFrequency::FreqNotSupported => Self::FreqNotSupported,
            super::SMBusFrequency::Freq100kHz => Self::Freq100kHz,
            super::SMBusFrequency::Freq400kHz => Self::Freq400kHz,
            super::SMBusFrequency::Freq1MHz => Self::Freq1MHz,
        }
    }
}

trait RequestHandler {
    async fn handle<A: AsyncRespChannel>(
        self,
        mep: &mut super::ManagementEndpoint,
        subsys: &mut super::Subsystem,
        rest: &[u8],
        resp: &mut A,
    ) -> Result<(), ResponseStatus>;
}

trait Encode<const S: usize>: DekuContainerWrite {
    fn encode(&self) -> Result<([u8; S], usize), DekuError> {
        let mut buf = [0u8; S];
        self.to_slice(&mut buf).map(|len| (buf, len))
    }
}

#[derive(Debug, DekuRead, DekuWrite, PartialEq, FromPrimitive, ToPrimitive)]
#[deku(endian = "endian", ctx = "endian: Endian", id_type = "u8")]
#[repr(u8)]
enum ResponseStatus {
    Success = 0x00,
    InternalError = 0x02,
    InvalidCommandOpcode = 0x03,
    InvalidParameter = 0x04,
    InvalidCommandSize = 0x05,
    InvalidCommandInputDataSize = 0x06,
}

impl From<DekuError> for ResponseStatus {
    fn from(err: DekuError) -> Self {
        debug!("Codec operation failed: {err}");
        Self::InternalError
    }
}

impl From<()> for ResponseStatus {
    fn from(_: ()) -> Self {
        ResponseStatus::InternalError
    }
}

#[derive(Debug, DekuRead, DekuWrite)]
#[deku(endian = "little")]
struct NVMeManagementResponse {
    #[deku(pad_bytes_after = "3")]
    status: ResponseStatus,
}
impl Encode<4> for NVMeManagementResponse {}

#[derive(Debug, DekuRead, DekuWrite)]
#[deku(endian = "little")]
struct MessageHeader {
    #[deku(pad_bytes_after = "2")]
    nmimt: u8,
}
impl Encode<3> for MessageHeader {}

impl MessageHeader {
    fn respond(nmimt: MessageType) -> Self {
        Self {
            nmimt: ((true as u8) << 7) | ((nmimt.id() & 0xf) << 3),
        }
    }

    fn nmimt(&self) -> Result<MessageType, u8> {
        ((self.nmimt >> 3) & 0xf).try_into()
    }

    fn csi(&self) -> bool {
        (self.nmimt & 0x01) != 0
    }

    fn ror(&self) -> bool {
        (self.nmimt & 0x80) != 0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
enum MessageType {
    ControlPrimitive = 0x00,
    NVMeMICommand = 0x01,
    NVMeAdminCommand = 0x02,
    PCIeCommand = 0x04,
    AsynchronousEvent = 0x05,
}

impl TryFrom<u8> for MessageType {
    type Error = u8;

    fn try_from(value: u8) -> Result<Self, u8> {
        match value {
            0x00 => Ok(Self::ControlPrimitive),
            0x01 => Ok(Self::NVMeMICommand),
            0x02 => Ok(Self::NVMeAdminCommand),
            0x04 => Ok(Self::PCIeCommand),
            0x05 => Ok(Self::AsynchronousEvent),
            _ => Err(value),
        }
    }
}

impl MessageType {
    fn id(&self) -> u8 {
        // https://doc.rust-lang.org/reference/items/enumerations.html#r-items.enum.discriminant.access-memory
        unsafe { *(self as *const Self as *const u8) }
    }
}

#[derive(Debug, DekuRead, DekuWrite)]
#[deku(endian = "little")]
struct NVMeMICommandHeader {
    #[deku(pad_bytes_after = "3")]
    opcode: CommandOpcode,
}
impl Encode<4> for NVMeMICommandHeader {}

#[derive(Debug, DekuRead, DekuWrite, PartialEq, Eq)]
#[deku(id_type = "u8", endian = "endian", ctx = "endian: Endian")]
#[repr(u8)]
enum CommandOpcode {
    ReadNVMeMIDataStructure = 0x00,
    NVMSubsystemHealthStatusPoll = 0x01,
    ControllerHealthStatusPoll = 0x02,
    ConfigurationSet = 0x03,
    ConfigurationGet = 0x04,
    VPDRead = 0x05,
    VPDWrite = 0x06,
    Reset = 0x07,
    SESReceive = 0x08,
    SESSend = 0x09,
    ManagementEndpointBufferRead = 0x0a,
    ManagementEndpointBufferWrite = 0x0b,
    Shutdown = 0x0c,
}

#[derive(Debug, DekuRead, DekuWrite)]
#[deku(endian = "little")]
struct NVMeMIDataStructure {
    ctrlid: u16,
    portid: u8,
    dtyp: NVMeMIDataStructureType,
    #[deku(pad_bytes_after = "3")]
    iocsi: u8,
}

#[derive(Debug, DekuRead, DekuWrite, PartialEq, Eq)]
#[deku(id_type = "u8", endian = "endian", ctx = "endian: Endian")]
#[repr(u8)]
enum NVMeMIDataStructureType {
    NVMSubsystemInformation = 0x00,
    PortInformation = 0x01,
    ControllerList = 0x02,
    ControllerInformation = 0x03,
    OptionallySupportedCommandList = 0x04,
    ManagementEndpointBufferCommandSupportList = 0x05,
}

#[derive(Debug, DekuRead, DekuWrite)]
#[deku(endian = "little")]
struct NVMeMIDataStructureManagementResponse {
    status: ResponseStatus,
    rdl: u16,
}
impl Encode<4> for NVMeMIDataStructureManagementResponse {}

#[derive(Debug, DekuWrite)]
#[deku(endian = "little")]
struct NVMSubsystemInformation {
    nump: u8,
    mjr: u8,
    mnr: u8,
    nnsc: u8,
}
impl Encode<32> for NVMSubsystemInformation {}

#[derive(Debug, DekuWrite)]
#[deku(endian = "little")]
struct PortInformation {
    prttyp: u8,
    prtcap: u8,
    mmtus: u16,
    mebs: u32,
}
impl Encode<8> for PortInformation {}

#[derive(Debug, DekuWrite)]
#[deku(endian = "little")]
struct PCIePortData {
    pciemps: u8,
    pcieslsv: u8,
    pciecls: u8,
    pciemlw: u8,
    pcienlw: u8,
    pciepn: u8,
}
impl Encode<24> for PCIePortData {}

#[derive(Debug, DekuWrite)]
#[deku(endian = "little")]
struct TwoWirePortData {
    cvpdaddr: u8,
    mvpdfreq: u8,
    cmeaddr: u8,
    twprt: u8,
    nvmebm: u8,
}
impl Encode<24> for TwoWirePortData {}

#[derive(Debug, DekuRead, DekuWrite)]
#[deku(endian = "little")]
struct ControllerList {
    #[deku(update = "self.ids.len()")]
    numids: u16,
    #[deku(count = "numids")]
    ids: WireVec<u16, 2047>,
}
impl Encode<4096> for ControllerList {}

impl ControllerList {
    fn new() -> Self {
        Self {
            numids: 0,
            ids: WireVec::new(),
        }
    }
}

#[derive(Debug, DekuRead, DekuWrite)]
#[deku(endian = "little")]
struct ControllerInformation {
    #[deku(pad_bytes_after = "4")]
    portid: u8,
    prii: u8,
    pri: u16,
    pcivid: u16,
    pcidid: u16,
    pcisvid: u16,
    pcisdid: u16,
    pciesn: u8,
}
impl Encode<32> for ControllerInformation {}

#[derive(Debug, DekuRead, DekuWrite)]
#[deku(endian = "little")]
struct NVMSubsystemHealthStatusPoll {
    dword0: u32,
    dword1: u32,
}
impl Encode<8> for NVMSubsystemHealthStatusPoll {}

#[derive(Debug, DekuRead, DekuWrite)]
#[deku(endian = "little")]
struct NVMSubsystemHealthDataStructure {
    nss: u8,
    sw: u8,
    ctemp: u8,
    pldu: u8,
}
impl Encode<4> for NVMSubsystemHealthDataStructure {}

#[derive(Debug, DekuRead, DekuWrite)]
#[deku(endian = "little")]
struct CompositeControllerStatusDataStructure {
    #[deku(pad_bytes_after = "2")]
    ccsf: u16,
}
impl Encode<4> for CompositeControllerStatusDataStructure {}

#[derive(Debug, DekuRead, DekuWrite, PartialEq)]
#[deku(id_type = "u8", endian = "little")]
#[repr(u8)]
enum NVMeMIConfigurationIdentifier {
    Reserved = 0x00,
    SMBusI2CFrequency = 0x01,
    HealthStatusChange = 0x02,
    MCTPTransmissionUnitSize = 0x03,
    AsyncronousEvent = 0x04,
}

#[derive(Debug, DekuRead, DekuWrite, PartialEq)]
#[deku(endian = "little")]
struct GetSMBusI2CFrequencyRequest {
    // Skip intermediate bytes in DWORD 0
    #[deku(seek_from_start = "2")]
    dw0_portid: u8,
    _dw1: u32,
}

#[derive(Debug, DekuWrite, PartialEq)]
#[deku(endian = "little")]
struct GetSMBusI2CFrequencyResponse {
    status: ResponseStatus,
    #[deku(pad_bytes_after = "2")]
    mr_sfreq: SMBusFrequency,
}
impl Encode<4> for GetSMBusI2CFrequencyResponse {}

#[derive(Debug, DekuRead, DekuWrite)]
#[deku(endian = "little")]
struct GetMCTPTransmissionUnitSizeRequest {
    #[deku(seek_from_start = "2")]
    dw0_portid: u8,
    _dw1: u32,
}

#[derive(Debug, DekuWrite)]
#[deku(endian = "little")]
struct GetMCTPTransmissionUnitSizeResponse {
    status: ResponseStatus,
    #[deku(pad_bytes_after = "1")]
    mr_mtus: u16,
}
impl Encode<4> for GetMCTPTransmissionUnitSizeResponse {}

#[derive(Clone, Copy, Debug, DekuRead, DekuWrite, PartialEq, Eq)]
#[deku(id_type = "u8", endian = "endian", ctx = "endian: Endian")]
#[repr(u8)]
enum AdminCommandOpcode {
    DeleteIOSubmissionQueue = 0x00,        // P
    CreateIOSubmissionQueue = 0x01,        // P
    GetLogPage = 0x02,                     // M
    DeleteIOCompletionQueue = 0x04,        // P
    CreateIOCompletionQueue = 0x05,        // P
    Identify = 0x06,                       // M
    Abort = 0x08,                          // P
    GetFeatures = 0x0a,                    // M
    AsynchronousEventRequest = 0x0c,       // P
    KeepAlive = 0x18,                      // P
    DirectiveSend = 0x19,                  // P
    DirectiveReceive = 0x1a,               // P
    NVMeMISend = 0x1d,                     // P
    NVMeMIReceive = 0x1e,                  // P
    DiscoveryInformationManagement = 0x21, // P
    FabricZoningReceive = 0x22,            // P
    FabricZoningLookup = 0x25,             // P
    FabricZoningSend = 0x29,               // P
    SendDiscoveryLogPage = 0x39,           // P
    TrackSend = 0x3d,                      // P
    TrackReceive = 0x3e,                   // P
    MigrationSend = 0x41,                  // P
    MigrationReceive = 0x42,               // P
    ControllerDataQueue = 0x45,            // P
    DoorbellBufferConfig = 0x7c,           // P
    FabricsCommands = 0x7f,                // P
    LoadProgram = 0x85,                    // P
    ProgramActivationManagement = 0x88,    // P
    MemoryRangeSetManagement = 0x89,       // P
}

#[derive(Debug, DekuRead, DekuWrite)]
#[deku(endian = "little")]
struct AdminCommandRequestHeader {
    opcode: AdminCommandOpcode,
    cflgs: u8,
    ctlid: u16,
}

#[derive(Clone, Copy, Debug, DekuRead, DekuWrite, Eq, PartialEq)]
#[deku(id_type = "u8", endian = "endian", ctx = "endian: Endian")]
#[repr(u8)]
enum ControllerOrNamespaceStructure {
    NVMIdentifyNamespace = 0x00,
    IdentifyController = 0x01,
    ActiveNamespaceIDList = 0x02,
    NamespaceIdentificationDescriptorList = 0x03,
    IOIdentifyNamespace = 0x05,
    IOIdentifyController = 0x06,
    IOActiveNamespaceIDList = 0x07,
    IdentifyNamespace = 0x08,
    AllocatedNamespaceIDList = 0x10,
    NVMSubsystemControllerList = 0x13,
    SecondaryControllerList = 0x15,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
enum StatusCodeType {
    GenericCommandStatus = 0x00,
    #[expect(dead_code)]
    CommandSpecificStatus = 0x01,
    #[expect(dead_code)]
    MediaAndDataIntegrityErrors = 0x02,
    #[expect(dead_code)]
    PathRelatedStatus = 0x03,
    #[expect(dead_code)]
    VendorSpecific = 0x07,
}

impl StatusCodeType {
    fn id(&self) -> u8 {
        // https://doc.rust-lang.org/reference/items/enumerations.html#r-items.enum.discriminant.access-memory
        unsafe { *(self as *const Self as *const u8) }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
enum GenericCommandStatus {
    SuccessfulCompletion = 0x00,
}

impl GenericCommandStatus {
    fn id(&self) -> u8 {
        // https://doc.rust-lang.org/reference/items/enumerations.html#r-items.enum.discriminant.access-memory
        unsafe { *(self as *const Self as *const u8) }
    }
}

#[derive(Debug, DekuRead, DekuWrite)]
#[deku(endian = "little")]
struct AdminCommandResponseHeader {
    status: ResponseStatus,
    #[deku(seek_from_start = "4")]
    cqedw0: u32,
    cqedw1: u32,
    cqedw3: u32,
}
impl Encode<16> for AdminCommandResponseHeader {}

#[derive(Debug, DekuRead, DekuWrite)]
#[deku(endian = "little")]
struct AdminIdentifyRequest {
    nsid: u32,
    #[deku(seek_from_start = "20")]
    dofst: u32,
    dlen: u32,
    #[deku(seek_from_start = "36")]
    cns: ControllerOrNamespaceStructure,
    #[deku(seek_from_start = "38")]
    cntid: u16,
    cnssid: u16,
    #[deku(seek_from_start = "43")]
    csi: u8,
    #[deku(seek_from_start = "52", pad_bytes_after = "7")]
    uidx: u8,
}

#[derive(Clone, Copy, Debug, DekuRead, DekuWrite, PartialEq)]
#[deku(id_type = "u8", endian = "endian", ctx = "endian: Endian")]
#[repr(u8)]
enum ControllerType {
    Reserved = 0x00,
    IOController = 0x01,
    DiscoveryController = 0x02,
    AdministrativeController = 0x03,
}

#[derive(Debug, DekuRead, DekuWrite)]
#[deku(endian = "little")]
struct AdminIdentifyControllerResponse {
    vid: u16,
    ssvid: u16,
    sn: WireString<20>,
    mn: WireString<40>,
    fr: WireString<8>,
    rab: u8,
    ieee: [u8; 3],
    cmic: u8,
    mdts: u8,
    cntlid: u16,
    ver: u32,
    rtd3r: u32,
    rtd3e: u32,
    oaes: u32,
    ctratt: u32,
    #[deku(seek_from_start = "111")]
    cntrltype: ControllerType,
    #[deku(seek_from_start = "253")]
    nvmsr: u8,
    vwci: u8,
    mec: u8,
    ocas: u16,
    acl: u8,
    aerl: u8,
    frmw: u8,
    lpa: u8,
    elpe: u8,
    npss: u8,
    avscc: u8,
    #[deku(seek_from_start = "266")]
    wctemp: u16,
    cctemp: u16,
    #[deku(seek_from_start = "319")]
    fwug: u8,
    kas: u16,
    #[deku(seek_from_start = "386")]
    cqt: u16,
    #[deku(seek_from_start = "512")]
    sqes: u8,
    cqes: u8,
    maxcmd: u16,
    nn: u32,
    oncs: u16,
    fuses: u16,
    fna: u8,
    vwc: u8,
    awun: u16,
    awupf: u16,
    icsvscc: u8,
    nwpc: u8,
    #[deku(seek_from_start = "540")]
    mnan: u32,
    #[deku(seek_from_start = "768")]
    subnqn: WireString<256>,
    #[deku(seek_from_start = "1802")]
    fcatt: u8,
    msdbd: u8,
    ofcs: u16,
}
impl Encode<4096> for AdminIdentifyControllerResponse {}

#[derive(Debug, Default, DekuRead, DekuWrite)]
#[deku(endian = "little")]
struct AdminIdentifyNVMIdentifyNamespaceResponse {
    nsze: u64,
    ncap: u64,
    nuse: u64,
    nsfeat: u8,
    nlbaf: u8,
    flbas: u8,
    mc: u8,
    dpc: u8,
    dps: u8,
    #[deku(seek_from_start = "48")]
    nvmcap: u128,
    #[deku(seek_from_start = "128")]
    // FIXME: use another struct
    lbaf0: u16,
    lbaf0_lbads: u8,
    lbaf0_rp: u8,
}
impl Encode<4096> for AdminIdentifyNVMIdentifyNamespaceResponse {}

#[derive(Debug, DekuRead, DekuWrite)]
#[deku(endian = "little")]
struct AdminIdentifyActiveNamespaceIDListResponse {
    nsid: WireVec<u32, 1024>,
}
impl Encode<4096> for AdminIdentifyActiveNamespaceIDListResponse {}

impl AdminIdentifyActiveNamespaceIDListResponse {
    fn new() -> Self {
        Self {
            nsid: WireVec::new(),
        }
    }
}

#[derive(Clone, Copy, Debug, DekuRead, DekuWrite)]
#[deku(id_type = "u8", endian = "endian", ctx = "endian: Endian")]
#[repr(u8)]
enum CommandSetIdentifier {
    Nvm = 0,
    KeyValue = 1,
    ZonedNamespace = 2,
    SubsystemLocalMemory = 3,
    ComputationalPrograms = 4,
}

impl From<super::CommandSetIdentifier> for CommandSetIdentifier {
    fn from(value: super::CommandSetIdentifier) -> Self {
        match value {
            super::CommandSetIdentifier::NVMCommandSet => Self::Nvm,
            super::CommandSetIdentifier::KeyValueCommandSet => Self::KeyValue,
            super::CommandSetIdentifier::ZonedNamespaceCommandSet => Self::ZonedNamespace,
            super::CommandSetIdentifier::SubsystemLocalMemoryCommandSet => {
                Self::SubsystemLocalMemory
            }
            super::CommandSetIdentifier::ComputationalProgramsCommandSet => {
                Self::ComputationalPrograms
            }
        }
    }
}

// NID: 5.1.13.2.3, Base v2.1
#[derive(Clone, Copy, Debug, DekuRead, DekuWrite)]
#[deku(id_type = "u8", endian = "endian", ctx = "endian: Endian")]
#[repr(u8)]
enum NamespaceIdentifierType {
    Reserved = 0,
    #[deku(id = 1)]
    Ieuid(u8, u16, [u8; 8]),
    #[deku(id = 2)]
    Nguid(u8, u16, [u8; 16]),
    #[deku(id = 3)]
    Nuuid(u8, u16, WireUuid),
    #[deku(id = 4)]
    Csi(u8, u16, CommandSetIdentifier),
}

impl From<super::NamespaceIdentifierType> for NamespaceIdentifierType {
    fn from(value: super::NamespaceIdentifierType) -> Self {
        match value {
            super::NamespaceIdentifierType::IEUID(v) => Self::Ieuid(v.len() as u8, 0, v),
            super::NamespaceIdentifierType::NGUID(v) => Self::Nguid(v.len() as u8, 0, v),
            super::NamespaceIdentifierType::NUUID(uuid) => Self::Nuuid(16, 0, WireUuid::new(uuid)),
            super::NamespaceIdentifierType::CSI(v) => Self::Csi(1, 0, v.into()),
        }
    }
}

#[derive(Debug)]
#[deku_derive(DekuRead, DekuWrite)]
#[deku(endian = "little")]
struct AdminIdentifyNamespaceIdentificationDescriptorListResponse {
    nids: WireVec<NamespaceIdentifierType, { MAX_NIDTS }>,
}
impl Encode<4096> for AdminIdentifyNamespaceIdentificationDescriptorListResponse {}

#[derive(Debug, DekuRead, DekuWrite)]
#[deku(endian = "little")]
struct AdminIdentifyAllocatedNamespaceIDListResponse {
    nsid: WireVec<u32, 1024>,
}
impl Encode<4096> for AdminIdentifyAllocatedNamespaceIDListResponse {}

async fn send_response(resp: &mut impl AsyncRespChannel, bufs: &[&[u8]]) {
    let mut digest = ISCSI.digest();
    digest.update(&[0x80 | 0x04]);

    for s in bufs {
        digest.update(s);
    }
    let icv = digest.finalize().to_le_bytes();

    let Ok(mut bufs) = Vec::<&[u8], MAX_FRAGMENTS>::from_slice(bufs) else {
        debug!("Failed to gather buffers into vec");
        return;
    };

    if bufs.push(icv.as_slice()).is_err() {
        debug!("Failed to apply integrity check to response");
        return;
    }

    if let Err(e) = resp.send_vectored(MsgIC(true), bufs.as_slice()).await {
        debug!("Failed to send NVMe-MI response: {e:?}");
    }
}

impl RequestHandler for MessageHeader {
    async fn handle<A: AsyncRespChannel>(
        self,
        mep: &mut super::ManagementEndpoint,
        subsys: &mut super::Subsystem,
        rest: &[u8],
        resp: &mut A,
    ) -> Result<(), ResponseStatus> {
        debug!("{self:x?}");
        // TODO: Command and Feature Lockdown handling
        // TODO: Handle subsystem reset, section 8.1, v2.0
        let Ok(nmimt) = self.nmimt() else {
            return Err(ResponseStatus::InvalidCommandOpcode);
        };

        match nmimt {
            MessageType::NVMeMICommand => {
                let Ok(((rest, _), ch)) = NVMeMICommandHeader::from_bytes((rest, 0)) else {
                    debug!("Message too short to extract NVMeMICommandHeader");
                    return Err(ResponseStatus::InvalidCommandSize);
                };

                ch.handle(mep, subsys, rest, resp).await
            }
            MessageType::NVMeAdminCommand => {
                let Ok(((rest, _), ch)) = AdminCommandRequestHeader::from_bytes((rest, 0)) else {
                    debug!("Message too short to extract AdminCommandHeader");
                    return Err(ResponseStatus::InvalidCommandSize);
                };

                ch.handle(mep, subsys, rest, resp).await
            }
            _ => {
                debug!("Unimplemented NMINT: {:?}", self.nmimt());
                Err(ResponseStatus::InternalError)
            }
        }
    }
}

impl RequestHandler for NVMeMICommandHeader {
    async fn handle<A: AsyncRespChannel>(
        self,
        mep: &mut super::ManagementEndpoint,
        subsys: &mut super::Subsystem,
        rest: &[u8],
        resp: &mut A,
    ) -> Result<(), ResponseStatus> {
        debug!("{self:x?}");
        match self.opcode {
            CommandOpcode::ReadNVMeMIDataStructure => {
                let Ok(((rest, _), ds)) = NVMeMIDataStructure::from_bytes((rest, 0)) else {
                    debug!("Message too short to extract NVMeMIDataStructure");
                    return Err(ResponseStatus::InvalidCommandSize);
                };
                ds.handle(mep, subsys, rest, resp).await
            }
            CommandOpcode::NVMSubsystemHealthStatusPoll => {
                // 5.6, Figure 108, v2.0
                let Ok(((rest, _), shsp)) = NVMSubsystemHealthStatusPoll::from_bytes((rest, 0))
                else {
                    debug!("Message too short to extract NVMSubsystemHealthStatusPoll");
                    return Err(ResponseStatus::InvalidCommandSize);
                };

                if !rest.is_empty() {
                    debug!("Lost coherence decoding {:?}", self.opcode);
                    return Err(ResponseStatus::InvalidCommandSize);
                }

                let mh = MessageHeader::respond(MessageType::NVMeMICommand).encode()?;

                let mr = NVMeManagementResponse {
                    status: ResponseStatus::Success,
                }
                .encode()?;

                // Implementation-specific strategy is to pick the first controller.
                let ctlr = subsys
                    .ctlrs
                    .first()
                    .expect("Device needs at least one controller");

                let Some(port) = subsys.ports.iter().find(|p| p.id == ctlr.port) else {
                    panic!(
                        "Inconsistent port association for controller {:?}: {:?}",
                        ctlr.id, ctlr.port
                    );
                };

                let PortType::PCIe(pprt) = port.typ else {
                    panic!("Non-PCIe port associated with controller {:?}", ctlr.id);
                };

                // Derive ASCBT from spare vs capacity
                if ctlr.spare > ctlr.capacity {
                    debug!(
                        "spare capacity {} exceeds drive capacity {}",
                        ctlr.spare, ctlr.capacity
                    );
                    return Err(ResponseStatus::InternalError);
                }

                // Derive TTC from operating range comparison
                assert!(ctlr.temp_range.kind == UnitKind::Kelvin);

                // Derive CTEMP from controller temperature via conversions
                // Clamp to Figure 108, NVMe MI v2.0 requirements
                let clamped = ctlr
                    .temp
                    .clamp(ctlr.temp_range.lower, ctlr.temp_range.upper);

                // Convert to celcius from kelvin
                let celcius: i32 = clamped as i32 - 273;

                // Convert to unsigned representation of two's-complement value
                let ctemp = if celcius < 0 {
                    celcius + u8::MAX as i32 + 1
                } else {
                    celcius
                };
                debug_assert!(ctemp <= u8::MAX.into());

                // Derive PLDU from write age and expected lifespan
                let pldu = core::cmp::min(255, 100 * ctlr.write_age / ctlr.write_lifespan);

                let nvmshds = NVMSubsystemHealthDataStructure {
                    nss: (subsys.health.nss.atf as u8) << 7
                        | (subsys.health.nss.sfm as u8) << 6
                        | (subsys.health.nss.df as u8) << 5
                        | (subsys.health.nss.rnr as u8) << 4
                        | ((pprt.cls != PCIeLinkSpeed::Inactive) as u8) << 3 // P0LA
                        | (false as u8) << 2, // P1LA
                    #[allow(clippy::nonminimal_bool)]
                    sw: (!false as u8) << 5 // PMRRO
                        | (!false as u8) << 4 // VMBF
                        | (!ctlr.ro as u8) << 3 // AMRO
                        | (!subsys.health.nss.rd as u8) << 2 // NDR
                        | (!(ctlr.temp_range.lower <= ctlr.temp && ctlr.temp <= ctlr.temp_range.upper) as u8) << 1 // TTC
                        | (!((100 * ctlr.spare / ctlr.capacity) < ctlr.spare_range.lower as u64) as u8),
                    ctemp: ctemp as u8,
                    pldu: pldu as u8,
                }
                .encode()?;

                let ccs = CompositeControllerStatusDataStructure {
                    ccsf: (mep.ccsf.tcida as u16) << 13
                        | (mep.ccsf.cwarn as u16) << 12
                        | (mep.ccsf.spare as u16) << 11
                        | (mep.ccsf.pdlu as u16) << 10
                        | (mep.ccsf.ctemp as u16) << 9
                        | (mep.ccsf.csts as u16) << 8
                        | (mep.ccsf.fa as u16) << 7
                        | (mep.ccsf.nac as u16) << 6
                        | (mep.ccsf.ceco as u16) << 5
                        | (mep.ccsf.nssro as u16) << 4
                        | (mep.ccsf.shst as u16) << 2
                        | (mep.ccsf.cfs as u16) << 1
                        | (mep.ccsf.rdy as u16),
                }
                .encode()?;

                // CS: See Figure 106, NVMe MI v2.0
                if (shsp.dword1 & (1u32 << 31)) != 0 {
                    mep.ccsf = super::CompositeControllerStatusFlags::default();
                }

                send_response(resp, &[&mh.0, &mr.0, &nvmshds.0, &ccs.0]).await;
                Ok(())
            }
            CommandOpcode::ConfigurationGet => {
                let Ok(((rest, _len), cid)) = NVMeMIConfigurationIdentifier::from_bytes((rest, 0))
                else {
                    debug!("Failed to extract NVMeConfigurationIdentifier");
                    return Err(ResponseStatus::InvalidCommandSize);
                };

                return cid.handle(mep, subsys, rest, resp).await;
            }
            _ => {
                debug!("Unimplemented OPCODE: {:?}", self.opcode);
                Err(ResponseStatus::InternalError)
            }
        }
    }
}

impl RequestHandler for NVMeMIConfigurationIdentifier {
    async fn handle<A: AsyncRespChannel>(
        self,
        _mep: &mut super::ManagementEndpoint,
        subsys: &mut super::Subsystem,
        rest: &[u8],
        resp: &mut A,
    ) -> Result<(), ResponseStatus> {
        match self {
            NVMeMIConfigurationIdentifier::Reserved => Err(ResponseStatus::InvalidParameter),
            NVMeMIConfigurationIdentifier::SMBusI2CFrequency => {
                let Ok(((_rest, len), gsifr)) = GetSMBusI2CFrequencyRequest::from_bytes((rest, 0))
                else {
                    debug!("Failed to extract GetSMBusI2CFrequencyRequest");
                    return Err(ResponseStatus::InvalidCommandSize);
                };

                if len != 0 {
                    debug!("Lost synchronisation when decoding ConfigurationGet SMBusI2CFrequency");
                    return Err(ResponseStatus::InvalidCommandSize);
                }

                let Some(port) = subsys.ports.get(gsifr.dw0_portid as usize) else {
                    debug!("Unrecognised port ID: {}", gsifr.dw0_portid);
                    return Err(ResponseStatus::InvalidParameter);
                };

                let PortType::TwoWire(twprt) = port.typ else {
                    debug!(
                        "Port {} is not a TwoWire port: {:?}",
                        gsifr.dw0_portid, port
                    );
                    return Err(ResponseStatus::InvalidParameter);
                };

                let mh = MessageHeader::respond(MessageType::NVMeMICommand).encode()?;

                let fr = GetSMBusI2CFrequencyResponse {
                    status: ResponseStatus::Success,
                    mr_sfreq: Into::<SMBusFrequency>::into(twprt.msmbfreq),
                }
                .encode()?;

                send_response(resp, &[&mh.0, &fr.0]).await;
                Ok(())
            }
            NVMeMIConfigurationIdentifier::HealthStatusChange => todo!(),
            NVMeMIConfigurationIdentifier::MCTPTransmissionUnitSize => {
                let Ok(((_rest, len), gmtusr)) =
                    GetMCTPTransmissionUnitSizeRequest::from_bytes((rest, 0))
                else {
                    debug!("Failed to extract GetMCTPTransmissionUnitSizeRequest");
                    return Err(ResponseStatus::InvalidCommandSize);
                };

                if len != 0 {
                    debug!(
                        "Lost synchronisation when decoding ConfigurationGet MCTPTransmissionUnitSize"
                    );
                    return Err(ResponseStatus::InvalidCommandSize);
                }

                let Some(port) = subsys.ports.get(gmtusr.dw0_portid as usize) else {
                    debug!("Unrecognised port ID: {}", gmtusr.dw0_portid);
                    return Err(ResponseStatus::InvalidParameter);
                };

                let mh = MessageHeader::respond(MessageType::NVMeMICommand).encode()?;

                let fr = GetMCTPTransmissionUnitSizeResponse {
                    status: ResponseStatus::Success,
                    mr_mtus: port.mmtus,
                }
                .encode()?;

                send_response(resp, &[&mh.0, &fr.0]).await;
                Ok(())
            }
            NVMeMIConfigurationIdentifier::AsyncronousEvent => todo!(),
        }
    }
}

impl RequestHandler for NVMeMIDataStructure {
    async fn handle<A: AsyncRespChannel>(
        self,
        _mep: &mut super::ManagementEndpoint,
        subsys: &mut super::Subsystem,
        rest: &[u8],
        resp: &mut A,
    ) -> Result<(), ResponseStatus> {
        debug!("{self:x?}");

        if !rest.is_empty() {
            debug!("Lost coherence decoding NVMe-MI message");
            return Err(ResponseStatus::InvalidCommandInputDataSize);
        }

        let mh = MessageHeader::respond(MessageType::NVMeMICommand).encode()?;

        match self.dtyp {
            NVMeMIDataStructureType::NVMSubsystemInformation => {
                assert!(!subsys.ports.is_empty(), "Need at least one port defined");
                // See 5.7.1, 5.1.1 of v2.0
                assert!(
                    subsys.ports.len() < u8::MAX as usize,
                    "Too many ports defined: {}",
                    subsys.ports.len()
                );
                // See 5.7.1 of v2.0
                let nvmsi = NVMSubsystemInformation {
                    nump: subsys.ports.len() as u8 - 1,
                    mjr: subsys.mi.mjr,
                    mnr: subsys.mi.mnr,
                    nnsc: subsys.caps.sre.into(),
                }
                .encode()?;

                debug_assert!(nvmsi.0.len() <= u16::MAX as usize);
                let dsmr = NVMeMIDataStructureManagementResponse {
                    status: ResponseStatus::Success,
                    rdl: nvmsi.0.len() as u16,
                }
                .encode()?;

                send_response(resp, &[&mh.0, &dsmr.0, &nvmsi.0]).await;
                Ok(())
            }
            NVMeMIDataStructureType::PortInformation => {
                let Some(port) = subsys.ports.iter().find(|p| p.id.0 == self.portid) else {
                    // TODO: Propagate PEL
                    return Err(ResponseStatus::InvalidParameter);
                };
                let pi = PortInformation {
                    prttyp: port.typ.id(),
                    prtcap: (port.caps.aems as u8) << 1 | (port.caps.ciaps as u8),
                    mmtus: port.mmtus,
                    mebs: port.mebs,
                }
                .encode()?;

                match port.typ {
                    PortType::PCIe(pprt) => {
                        let ppd = PCIePortData {
                            pciemps: pprt.mps.into(),
                            pcieslsv: 0x3fu8,
                            pciecls: pprt.cls.into(),
                            pciemlw: pprt.mlw.into(),
                            pcienlw: pprt.nlw.into(),
                            pciepn: port.id.0,
                        }
                        .encode()?;

                        debug_assert!(pi.0.len() + ppd.0.len() <= u16::MAX as usize);
                        let dsmr = NVMeMIDataStructureManagementResponse {
                            status: ResponseStatus::Success,
                            rdl: (pi.0.len() + ppd.0.len()) as u16,
                        }
                        .encode()?;

                        send_response(resp, &[&mh.0, &dsmr.0, &pi.0, &ppd.0]).await;
                        Ok(())
                    }
                    PortType::TwoWire(twprt) => {
                        let twpd = TwoWirePortData {
                            cvpdaddr: twprt.cvpdaddr,
                            mvpdfreq: Into::<SMBusFrequency>::into(twprt.mvpdfreq)
                                .to_u8()
                                .unwrap(),
                            cmeaddr: twprt.cmeaddr,
                            twprt: (twprt.i3csprt as u8) << 7
                                | Into::<SMBusFrequency>::into(twprt.msmbfreq)
                                    .to_u8()
                                    .unwrap()
                                    & 3,
                            nvmebm: twprt.nvmebms.into(),
                        }
                        .encode()?;

                        debug_assert!((pi.0.len() + twpd.0.len()) <= u16::MAX as usize);
                        let dsmr = NVMeMIDataStructureManagementResponse {
                            status: ResponseStatus::Success,
                            rdl: (pi.0.len() + twpd.0.len()) as u16,
                        }
                        .encode()?;

                        send_response(resp, &[&mh.0, &dsmr.0, &pi.0, &twpd.0]).await;
                        Ok(())
                    }
                    _ => {
                        debug!("Unimplemented port type: {:?}", port.typ);
                        Err(ResponseStatus::InternalError)
                    }
                }
            }
            NVMeMIDataStructureType::ControllerList => {
                assert!(
                    subsys.ctlrs.len() <= 2047,
                    "Invalid number of controllers in drive model: {}",
                    subsys.ctlrs.len()
                );

                let mut cl = ControllerList::new();
                for ctlr in subsys
                    .ctlrs
                    .iter()
                    // Section 5.7.3, NVMe MI v2.0
                    .filter(|c| c.id.0 >= self.ctrlid)
                {
                    if let Err(id) = cl.ids.push(ctlr.id.0) {
                        debug!("Failed to push controller ID {id}");
                        return Err(ResponseStatus::InternalError);
                    };
                }

                // NVMeSubsystemInformation and PortInformation are defined to
                // be a minimum of 32 bytes in v2.0 of the NVMe specification.
                // ControllerList in the NVMe MI v2.0 specification defers to
                // Figure 137 in v2.1 of the NVMe base specification, which
                // says "Unused entries are zero-filled". The motivation
                // for padding out to 32 bytes for NVMeSubsystemInformation
                // and PortInformation messages is unclear wrt whether
                // ControllerList should be similarly padded or dynamically
                // sized, given it can extend to 4096 bytes.
                //
                // Assume it's always dynamically sized appropriate for the
                // requested controllers for now. mi-mctp seems okay with this.
                //
                // Note that for zero or even numbers of controllers in the
                // response the MIC falls out of natural alignment.
                cl.update()?;
                let cl = cl.encode()?;
                let rdl = cl.1 as u16;

                let dsmr = NVMeMIDataStructureManagementResponse {
                    status: ResponseStatus::Success,
                    rdl,
                }
                .encode()?;

                send_response(resp, &[&mh.0, &dsmr.0, &cl.0[..cl.1]]).await;
                Ok(())
            }
            NVMeMIDataStructureType::ControllerInformation => {
                let Some(ctlr) = subsys.ctlrs.iter().find(|c| c.id.0 == self.ctrlid) else {
                    debug!("Unknown controller ID: {:?}", self.ctrlid);
                    return Err(ResponseStatus::InvalidParameter);
                };

                let Some(port) = subsys.ports.iter().find(|p| p.id == ctlr.port) else {
                    panic!(
                        "Inconsistent port association for controller {:?}: {:?}",
                        ctlr.id, ctlr.port
                    );
                };

                let PortType::PCIe(pprt) = port.typ else {
                    panic!("Non-PCIe port associated with controller {:?}", ctlr.id);
                };

                let ci = ControllerInformation {
                    portid: ctlr.port.0,
                    prii: 1,
                    pri: pprt.b << 8 | pprt.d << 4 | pprt.f,
                    pcivid: subsys.info.pci_vid,
                    pcidid: subsys.info.pci_did,
                    pcisvid: subsys.info.pci_svid,
                    pcisdid: subsys.info.pci_sdid,
                    pciesn: pprt.seg,
                }
                .encode()?;

                debug_assert!(ci.0.len() < u16::MAX as usize);
                let dsmr = NVMeMIDataStructureManagementResponse {
                    status: ResponseStatus::Success,
                    rdl: ci.0.len() as u16,
                }
                .encode()?;

                send_response(resp, &[&mh.0, &dsmr.0, &ci.0]).await;
                Ok(())
            }
            _ => {
                debug!("Unimplemented DTYP: {:?}", self.dtyp);
                Err(ResponseStatus::InternalError)
            }
        }
    }
}

const MI_PROHIBITED_ADMIN_COMMANDS: [AdminCommandOpcode; 26] = [
    AdminCommandOpcode::DeleteIOSubmissionQueue,
    AdminCommandOpcode::CreateIOSubmissionQueue,
    AdminCommandOpcode::DeleteIOCompletionQueue,
    AdminCommandOpcode::CreateIOCompletionQueue,
    AdminCommandOpcode::Abort,
    AdminCommandOpcode::AsynchronousEventRequest,
    AdminCommandOpcode::KeepAlive,
    AdminCommandOpcode::DirectiveSend,
    AdminCommandOpcode::DirectiveReceive,
    AdminCommandOpcode::NVMeMISend,
    AdminCommandOpcode::NVMeMIReceive,
    AdminCommandOpcode::DiscoveryInformationManagement,
    AdminCommandOpcode::FabricZoningReceive,
    AdminCommandOpcode::FabricZoningLookup,
    AdminCommandOpcode::FabricZoningSend,
    AdminCommandOpcode::SendDiscoveryLogPage,
    AdminCommandOpcode::TrackSend,
    AdminCommandOpcode::TrackReceive,
    AdminCommandOpcode::MigrationSend,
    AdminCommandOpcode::MigrationReceive,
    AdminCommandOpcode::ControllerDataQueue,
    AdminCommandOpcode::DoorbellBufferConfig,
    AdminCommandOpcode::FabricsCommands,
    AdminCommandOpcode::LoadProgram,
    AdminCommandOpcode::ProgramActivationManagement,
    AdminCommandOpcode::MemoryRangeSetManagement,
];

impl RequestHandler for AdminCommandRequestHeader {
    async fn handle<A: AsyncRespChannel>(
        self,
        mep: &mut super::ManagementEndpoint,
        subsys: &mut super::Subsystem,
        rest: &[u8],
        resp: &mut A,
    ) -> Result<(), ResponseStatus> {
        debug!("{self:x?}");

        // ISH
        if self.cflgs & 4 != 0 {
            debug!("Support ignore shutdown state");
            return Err(ResponseStatus::InternalError);
        }

        if self.ctlid > 0 {
            if subsys.ctlrs.len() > 1 {
                todo!("Support for selecting controllers via CTLID");
            }
            debug!("Invalid CTLID: {}", self.ctlid);
            return Err(ResponseStatus::InvalidParameter);
        }

        let opcode = self.opcode;
        match opcode {
            AdminCommandOpcode::Identify => {
                let Ok(((rest, _), id)) = AdminIdentifyRequest::from_bytes((rest, 0)) else {
                    debug!("Message too short to extract AdminIdentify request");
                    return Err(ResponseStatus::InvalidCommandSize);
                };
                id.handle(mep, subsys, rest, resp).await
            }
            opcode if MI_PROHIBITED_ADMIN_COMMANDS.contains(&opcode) => {
                debug!("Prohibited MI admin command opcode: {opcode:?}");
                Err(ResponseStatus::InvalidCommandOpcode)
            }
            _ => {
                debug!("Unimplemented OPCODE: {:?}", self.opcode);
                Err(ResponseStatus::InternalError)
            }
        }
    }
}

impl AdminIdentifyRequest {
    async fn send_constrained_response<A: AsyncRespChannel>(
        self,
        resp: &mut A,
        bufs: &[&[u8]],
        data: &[u8],
    ) -> Result<(), ResponseStatus> {
        // See Figure 136 in NVMe MI v2.0

        // Use send_response() instead
        assert!(!data.is_empty());

        // TODO: propagate PEL for all errors

        let dofst = self.dofst as usize;
        if dofst & 3 != 0 {
            debug!("Unnatural DOFST value: {dofst:?}");
            return Err(ResponseStatus::InvalidParameter);
        }

        if dofst >= data.len() {
            debug!("DOFST value exceeds unconstrained response length: {dofst:?}");
            return Err(ResponseStatus::InvalidParameter);
        }

        let dlen = self.dlen as usize;

        if dlen & 3 != 0 {
            debug!("Unnatural DLEN value: {dlen:?}");
            return Err(ResponseStatus::InvalidParameter);
        }

        if dlen > 4096 {
            debug!("DLEN too large: {dlen:?}");
            return Err(ResponseStatus::InvalidParameter);
        }

        if dlen > data.len() || data.len() - dlen < dofst {
            debug!(
                "Requested response data range beginning at {:?} for {:?} bytes exceeds bounds of unconstrained response length {:?}",
                dofst,
                dlen,
                data.len()
            );
            return Err(ResponseStatus::InvalidParameter);
        }

        if dlen == 0 {
            debug!("DLEN cleared for command with data response: {dlen:?}");
            return Err(ResponseStatus::InvalidParameter);
        }

        let end = dofst + dlen;

        let Ok(mut bufs) = Vec::<&[u8], MAX_FRAGMENTS>::from_slice(bufs) else {
            debug!("Failed to gather buffer slice into vec");
            return Err(ResponseStatus::InternalError);
        };

        if bufs.push(&data[dofst..end]).is_err() {
            debug!("Failed to append MIC buffer");
            return Err(ResponseStatus::InternalError);
        }

        send_response(resp, bufs.as_slice()).await;
        Ok(())
    }
}

impl RequestHandler for AdminIdentifyRequest {
    async fn handle<A: AsyncRespChannel>(
        self,
        _mep: &mut super::ManagementEndpoint,
        subsys: &mut super::Subsystem,
        rest: &[u8],
        resp: &mut A,
    ) -> Result<(), ResponseStatus> {
        debug!("{self:x?}");

        if !rest.is_empty() {
            debug!("Invalid request size for Admin Identify");
            return Err(ResponseStatus::InvalidCommandSize);
        }

        let mh = MessageHeader::respond(MessageType::NVMeAdminCommand).encode()?;

        let acrh = AdminCommandResponseHeader {
            status: ResponseStatus::Success,
            cqedw0: 0,
            cqedw1: 0,
            #[expect(clippy::identity_op, clippy::erasing_op)]
            cqedw3: ((false as u32) << 31) // DNR
                | ((false as u32) << 30) // M
                | (0u32 & 3) << 28 // CRD
                | (((StatusCodeType::GenericCommandStatus.id() as u32) & 7) << 25) // SCT
                | (((GenericCommandStatus::SuccessfulCompletion.id() as u32) & 0x1ff) << 17) // SC
                | ((true as u32) << 16) // P
                | (0u32 & 0xffff) << 0, // CID
        }
        .encode()?;

        match self.cns {
            ControllerOrNamespaceStructure::NVMIdentifyNamespace => {
                assert!(subsys.nss.len() <= u32::MAX.try_into().unwrap());

                if self.nsid == u32::MAX {
                    debug!("Support with broadcast NSID");
                    return Err(ResponseStatus::InternalError);
                }

                if self.nsid == 0 || self.nsid > subsys.nss.capacity() as u32 {
                    debug!("Invalid NSID: {}", self.nsid);
                    return Err(ResponseStatus::InvalidParameter);
                }

                let Some(ns) = subsys.nss.get(self.nsid as usize - 1) else {
                    debug!("Unallocated NSID: {}", self.nsid);
                    return Err(ResponseStatus::InvalidParameter);
                };

                // 4.1.5.1 NVM Command Set Spec, v1.0c
                // TODO: Ensure the associated controller is an IO controller
                // FIXME: Improve determination algo
                let active = subsys
                    .ctlrs
                    .iter()
                    .flat_map(|c| c.active_ns.iter())
                    .any(|&nsid| nsid.0 == self.nsid);
                let ainvminr = if active {
                    AdminIdentifyNVMIdentifyNamespaceResponse {
                        nsze: ns.size,
                        ncap: ns.capacity,
                        nuse: ns.used,
                        nsfeat: ((ns.size == ns.capacity) as u8),
                        nlbaf: 0,
                        flbas: 0,
                        mc: 0,
                        dpc: 0,
                        dps: 0,
                        nvmcap: 2_u128.pow(ns.block_order as u32) * ns.size as u128,
                        lbaf0: 0,
                        lbaf0_lbads: ns.block_order,
                        lbaf0_rp: 0,
                    }
                } else {
                    AdminIdentifyNVMIdentifyNamespaceResponse::default()
                }
                .encode()?;

                self.send_constrained_response(resp, &[&mh.0, &acrh.0], &ainvminr.0)
                    .await
            }
            ControllerOrNamespaceStructure::IdentifyController => {
                let ctlr = subsys
                    .ctlrs
                    .first()
                    .expect("Device needs at least one controller");

                let aicr = AdminIdentifyControllerResponse {
                    vid: subsys.info.pci_vid,
                    ssvid: subsys.info.pci_svid,
                    sn: WireString::from(subsys.sn)?,
                    mn: WireString::from(subsys.mn)?,
                    fr: WireString::from(subsys.fr)?,
                    rab: 0,
                    ieee: {
                        // 4.5.3, Base v2.1
                        let mut fixup = subsys.info.ieee_oui;
                        fixup.reverse();
                        fixup
                    },
                    cmic: ((subsys.ctlrs.len() > 1) as u8) << 1 // MCTRS
                        | ((subsys.ports.len() > 1) as u8), // MPORTS
                    mdts: 0,
                    cntlid: ctlr.id.0,
                    ver: 0,
                    rtd3r: 0,
                    rtd3e: 0,
                    oaes: 0,
                    // TODO: Tie to data model
                    ctratt: ((false as u32) << 14) // DNVMS
                        | ((false as u32) << 13) // DEG
                        | ((false as u32) << 4) // EGS
                        | ((false as u32) << 2), // NSETS
                    cntrltype: ControllerType::AdministrativeController,
                    // TODO: Tie to data model
                    nvmsr: ((false as u8) << 1) // NVMEE
                        | (true as u8), // NVMESD
                    vwci: 0,
                    mec: ((subsys.ports.iter().any(|p| matches!(p.typ, PortType::PCIe(_)))) as u8) << 1 // PCIEME
                        | (subsys.ports.iter().any(|p| matches!(p.typ, PortType::TwoWire(_)))) as u8, // TWPME
                    ocas: 0,
                    acl: 0,
                    aerl: 0,
                    frmw: 0,
                    lpa: 0,
                    elpe: 0,
                    npss: 0,
                    avscc: 0,
                    wctemp: 0x157,
                    cctemp: 0x157,
                    fwug: 0,
                    kas: 0,
                    cqt: 0,
                    sqes: 0,
                    cqes: 0,
                    maxcmd: 0,
                    nn: subsys
                        .nss
                        .capacity()
                        .try_into()
                        .expect("Too many namespaces"),
                    oncs: 0,
                    fuses: 0,
                    fna: 0,
                    vwc: 0,
                    awun: 0,
                    awupf: 0,
                    icsvscc: 0,
                    nwpc: 0,
                    mnan: 0,
                    subnqn: WireString::new(),
                    fcatt: 0,
                    msdbd: 0,
                    ofcs: 0,
                }
                .encode()?;

                self.send_constrained_response(resp, &[&mh.0, &acrh.0], &aicr.0)
                    .await
            }
            ControllerOrNamespaceStructure::ActiveNamespaceIDList => {
                // 5.1.13.2.2, Base v2.1
                let mut active: heapless::Vec<u32, MAX_NAMESPACES> = subsys
                    .ctlrs
                    .iter()
                    .flat_map(|c| c.active_ns.iter())
                    .map(|nsid| nsid.0)
                    .filter(|nsid| *nsid > self.nsid)
                    .collect();
                active.sort_unstable();
                // IndexSet iterator is insertion-order:
                // https://docs.rs/heapless/0.8.0/heapless/struct.IndexSet.html#method.iter
                let unique: heapless::FnvIndexSet<u32, MAX_NAMESPACES> =
                    active.iter().copied().collect();

                let mut aianidlr = AdminIdentifyActiveNamespaceIDListResponse::new();
                // TODO: Improve this with better iterator handling?
                for nsid in unique.iter() {
                    if aianidlr.nsid.push(*nsid).is_err() {
                        debug!("Failed to insert NSID {nsid}");
                        return Err(ResponseStatus::InternalError);
                    };
                }
                let aianidlr = aianidlr.encode()?;

                self.send_constrained_response(resp, &[&mh.0, &acrh.0], &aianidlr.0)
                    .await
            }
            ControllerOrNamespaceStructure::NamespaceIdentificationDescriptorList => {
                // 5.1.13.2.3, Base v2.1
                if self.nsid >= u32::MAX - 1 {
                    debug!("Unacceptable NSID for Namespace Identification Descriptor List");
                    return Err(ResponseStatus::InvalidParameter);
                }

                if self.nsid == 0 || self.nsid > subsys.nss.capacity() as u32 {
                    debug!("Invalid NSID: {}", self.nsid);
                    return Err(ResponseStatus::InvalidParameter);
                }

                let Some(ns) = subsys.nss.get(self.nsid as usize - 1) else {
                    debug!("Unallocated NSID: {}", self.nsid);
                    return Err(ResponseStatus::InvalidParameter);
                };

                let ainsidlr = AdminIdentifyNamespaceIdentificationDescriptorListResponse {
                    nids: {
                        let mut vec = WireVec::new();
                        for nid in &ns.nids {
                            if vec
                                .push(Into::<NamespaceIdentifierType>::into(*nid))
                                .is_err()
                            {
                                debug!("Failed to push NID {nid:?}");
                                return Err(ResponseStatus::InternalError);
                            }
                        }
                        vec
                    },
                }
                .encode()?;

                self.send_constrained_response(resp, &[&mh.0, &acrh.0], &ainsidlr.0)
                    .await
            }
            ControllerOrNamespaceStructure::AllocatedNamespaceIDList => {
                // 5.1.13.2.9, Base v2.1
                if self.nsid >= u32::MAX - 1 {
                    debug!("Invalid NSID");
                    return Err(ResponseStatus::InvalidParameter);
                }

                assert!(subsys.nss.len() < 4096 / core::mem::size_of::<u32>());
                let aiansidl = AdminIdentifyAllocatedNamespaceIDListResponse {
                    nsid: {
                        let start = self.nsid + 1;
                        let end = subsys.nss.len() as u32;
                        let mut vec = WireVec::new();
                        for nsid in start..=end {
                            if vec.push(nsid).is_err() {
                                debug!("Failed to inset NSID {nsid}");
                                return Err(ResponseStatus::InternalError);
                            };
                        }
                        vec
                    },
                }
                .encode()?;

                self.send_constrained_response(resp, &[&mh.0, &acrh.0], &aiansidl.0)
                    .await
            }
            ControllerOrNamespaceStructure::NVMSubsystemControllerList => {
                assert!(
                    subsys.ctlrs.len() <= 2047,
                    "Invalid number of controllers in drive model: {}",
                    subsys.ctlrs.len()
                );
                let mut cl = ControllerList::new();
                for ctlr in subsys.ctlrs.iter().filter(|v| v.id.0 >= self.cntid) {
                    if let Err(id) = cl.ids.push(ctlr.id.0) {
                        debug!("Failed to push controller ID {id}");
                        return Err(ResponseStatus::InternalError);
                    };
                }
                cl.update()?;
                let cl = cl.encode()?;
                self.send_constrained_response(resp, &[&mh.0, &acrh.0], &cl.0)
                    .await
            }
            ControllerOrNamespaceStructure::SecondaryControllerList => {
                let ctlr = subsys
                    .ctlrs
                    .first()
                    .expect("Device needs at least one controller");

                if !ctlr.secondaries.is_empty() {
                    todo!("Support listing secondary controllers");
                }

                self.send_constrained_response(resp, &[&mh.0, &acrh.0], &[0u8; 4096])
                    .await
            }
            _ => {
                debug!("Unimplemented CNS: {:?}", self.cns);
                Err(ResponseStatus::InternalError)
            }
        }
    }
}

impl super::ManagementEndpoint {
    pub async fn handle_async<A: AsyncRespChannel>(
        &mut self,
        subsys: &mut super::Subsystem,
        msg: &[u8],
        ic: MsgIC,
        mut resp: A,
    ) {
        if !ic.0 {
            debug!("NVMe-MI requires IC set for OOB messages");
            return;
        }

        if msg.len() < 4 {
            debug!("Message cannot contain a valid IC object");
            return;
        }

        let Some((msg, icv)) = msg.split_at_checked(msg.len() - 4) else {
            debug!("Message too short to extract integrity check");
            return;
        };

        let mut digest = ISCSI.digest();
        digest.update(&[0x80 | 0x04]);
        digest.update(msg);
        let calculated = digest.finalize().to_le_bytes();

        if icv != calculated {
            debug!("checksum mismatch: {icv:02x?}, {calculated:02x?}");
            return;
        }

        let Ok(((rest, _), mh)) = MessageHeader::from_bytes((msg, 0)) else {
            debug!("Message too short to extract NVMeMIMessageHeader");
            return;
        };

        if mh.csi() {
            debug!("Support second command slot");
            return;
        }

        if mh.ror() {
            debug!("NVMe-MI message was not a request: {:?}", mh.ror());
            return;
        }

        let Ok(nmimt) = mh.nmimt() else {
            debug!("Message contains unrecognised NMIMT: {mh:x?}");
            return;
        };

        if let Err(status) = mh.handle(self, subsys, rest, &mut resp).await {
            let mut digest = ISCSI.digest();
            digest.update(&[0x80 | 0x04]);

            let Ok(mh) = MessageHeader::respond(nmimt).encode() else {
                debug!("Failed to encode MessageHeader for error response");
                return;
            };
            digest.update(&mh.0);

            let ss: [u8; 4] = [status.to_u8().unwrap(), 0, 0, 0];
            digest.update(&ss);

            let icv = digest.finalize().to_le_bytes();
            let respv = [mh.0.as_slice(), ss.as_slice(), icv.as_slice()];
            if let Err(e) = resp.send_vectored(MsgIC(true), &respv).await {
                debug!("Failed to send NVMe-MI error response: {e:?}");
            }
        }
    }
}
