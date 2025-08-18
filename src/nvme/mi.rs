use deku::ctx::Endian;
use deku::{DekuError, DekuRead, DekuWrite};
use flagset::{FlagSet, flags};
use log::debug;

use crate::nvme::AdminNamespaceManagementSelect;
use crate::wire::{WireFlagSet, WireVec};
use crate::{CommandEffectError, Discriminant, Encode, MAX_CONTROLLERS};

use super::{AdminGetLogPageLidRequestType, AdminIdentifyCnsRequestType};

// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2025 Code Construct
 */
pub mod dev;

// MI v2.0, 3.1.1, Figure 20, NMIMT
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
enum MessageType {
    ControlPrimitive = 0x00,
    NvmeMiCommand = 0x01,
    NvmeAdminCommand = 0x02,
    PcieCommand = 0x04,
    AsynchronousEvent = 0x05,
}
unsafe impl Discriminant<u8> for MessageType {}

impl TryFrom<u8> for MessageType {
    type Error = u8;

    fn try_from(value: u8) -> Result<Self, u8> {
        match value {
            0x00 => Ok(Self::ControlPrimitive),
            0x01 => Ok(Self::NvmeMiCommand),
            0x02 => Ok(Self::NvmeAdminCommand),
            0x04 => Ok(Self::PcieCommand),
            0x05 => Ok(Self::AsynchronousEvent),
            _ => Err(value),
        }
    }
}

// MI v2.0, 3.1.1, Figure 20
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

// MI v2.0, 4.1.2, Figure 29
#[derive(Debug, DekuRead, DekuWrite, PartialEq)]
#[deku(endian = "endian", ctx = "endian: Endian", id_type = "u8")]
#[repr(u8)]
pub enum ResponseStatus {
    Success = 0x00,
    InternalError = 0x02,
    InvalidCommandOpcode = 0x03,
    InvalidParameter = 0x04,
    InvalidCommandSize = 0x05,
    InvalidCommandInputDataSize = 0x06,
}
unsafe impl Discriminant<u8> for ResponseStatus {}

impl From<DekuError> for ResponseStatus {
    fn from(err: DekuError) -> Self {
        debug!("Codec operation failed: {err}");
        Self::InternalError
    }
}

impl From<()> for ResponseStatus {
    fn from(_: ()) -> Self {
        Self::InternalError
    }
}

impl From<CommandEffectError> for ResponseStatus {
    fn from(value: CommandEffectError) -> Self {
        debug!("Failed to apply command effect: {value:?}");
        Self::InternalError
    }
}

// MI v2.0, 5, Figure 67
#[derive(Debug, DekuRead, DekuWrite)]
#[deku(endian = "little")]
struct NvmeMiCommandRequestHeader {
    #[deku(pad_bytes_after = "3")]
    #[deku(update = "self.body.id()")]
    opcode: u8,
    #[deku(ctx = "*opcode")]
    body: NvmeMiCommandRequestType,
}
impl Encode<4> for NvmeMiCommandRequestHeader {}

// MI v2.0, 5, Figure 68
#[derive(Debug, DekuRead, DekuWrite, PartialEq, Eq)]
#[deku(ctx = "endian: Endian, opcode: u8", id = "opcode", endian = "endian")]
#[repr(u8)]
enum NvmeMiCommandRequestType {
    #[deku(id = "0x00")]
    ReadNvmeMiDataStructure(NvmeMiDataStructureRequest),
    #[deku(id = "0x01")]
    NvmSubsystemHealthStatusPoll(NvmSubsystemHealthStatusPollRequest),
    #[deku(id = "0x02")]
    ControllerHealthStatusPoll(ControllerHealthStatusPollRequest),
    #[deku(id = "0x03")]
    ConfigurationSet(NvmeMiConfigurationSetRequest),
    #[deku(id = "0x04")]
    ConfigurationGet(NvmeMiConfigurationGetRequest),
    VpdRead = 0x05,
    VpdWrite = 0x06,
    Reset = 0x07,
    SesReceive = 0x08,
    SesSend = 0x09,
    ManagementEndpointBufferRead = 0x0a,
    ManagementEndpointBufferWrite = 0x0b,
    Shutdown = 0x0c,
}
unsafe impl Discriminant<u8> for NvmeMiCommandRequestType {}

// MI v2.0, 5, Figure 71
#[derive(Debug, DekuRead, DekuWrite)]
#[deku(endian = "little")]
struct NvmeManagementResponse {
    #[deku(pad_bytes_after = "3")]
    status: ResponseStatus,
}
impl Encode<4> for NvmeManagementResponse {}

// MI v2.0, 5, Figure 73
#[derive(Debug, DekuRead, DekuWrite, Eq, PartialEq)]
#[deku(ctx = "endian: Endian", endian = "endian")]
struct NvmeMiConfigurationGetRequest {
    body: NvmeMiConfigurationIdentifierRequestType,
}

// MI v2.0, 5, Figure 75
#[derive(Debug, DekuRead, DekuWrite, Eq, PartialEq)]
#[deku(id_type = "u8", ctx = "endian: Endian", endian = "endian")]
#[repr(u8)]
enum NvmeMiConfigurationIdentifierRequestType {
    Reserved = 0x00,
    #[deku(id = "0x01")]
    SmbusI2cFrequency(SmbusI2cFrequencyRequest),
    #[deku(id = "0x02")]
    HealthStatusChange(HealthStatusChangeRequest),
    #[deku(id = "0x03")]
    MctpTransmissionUnitSize(MctpTransmissionUnitSizeRequest),
    AsynchronousEvent = 0x04,
}

// MI v2.0, 5.1.1, Figure 77
#[derive(Debug, DekuWrite, PartialEq)]
#[deku(endian = "little")]
struct GetSmbusI2cFrequencyResponse {
    status: ResponseStatus,
    #[deku(pad_bytes_after = "2")]
    mr_sfreq: crate::nvme::mi::SmbusFrequency,
}
impl Encode<4> for GetSmbusI2cFrequencyResponse {}

// MI v2.0, 5.1.2
#[derive(Debug, DekuWrite)]
#[deku(endian = "little")]
struct GetHealthStatusChangeResponse {
    #[deku(pad_bytes_after = "3")]
    status: ResponseStatus,
}
impl Encode<4> for GetHealthStatusChangeResponse {}

// MI v2.0, 5.1.3, Figure 79
#[derive(Debug, DekuWrite)]
#[deku(endian = "little")]
struct GetMctpTransmissionUnitSizeResponse {
    status: ResponseStatus,
    #[deku(pad_bytes_after = "1")]
    mr_mtus: u16,
}
impl Encode<4> for GetMctpTransmissionUnitSizeResponse {}

// MI v2.0, 5.2, Figure 84
#[derive(Debug, DekuRead, DekuWrite, Eq, PartialEq)]
#[deku(ctx = "endian: Endian", endian = "endian")]
struct NvmeMiConfigurationSetRequest {
    body: NvmeMiConfigurationIdentifierRequestType,
}

// MI v2.0, 5.2.1, Figure 86
#[derive(Debug, DekuRead, DekuWrite, Eq, PartialEq)]
#[deku(ctx = "endian: Endian", endian = "endian")]
struct SmbusI2cFrequencyRequest {
    // XXX: This is inaccurate as SFREQ is specified as 4 bits, not 8
    // TODO: Support deku/bits feature without deku/alloc
    dw0_sfreq: crate::nvme::mi::SmbusFrequency,
    // Skip intermediate bytes in DWORD 0
    #[deku(seek_from_current = "1")]
    dw0_portid: u8,
    _dw1: u32,
}

// MI v2.0, 5.2.2, Figure 87
#[derive(Debug, DekuRead, DekuWrite, Eq, PartialEq)]
#[deku(ctx = "endian: Endian", endian = "endian")]
struct HealthStatusChangeRequest {
    // Skip intermediate bytes comprising DWORD 0
    #[deku(seek_from_current = "3")]
    dw1: u32,
}

// MI v2.0, 5.2.2, Figure 88
flags! {
    #[repr(u32)]
    enum HealthStatusChangeFlags: u32 {
        Rdy,
        Cfs,
        Shst,
        Nssro,
        Ceco,
        Nac,
        Fa,
        Csts,
        Ctemp,
        Pldu,
        Spare,
        Cwarn,
        Tcida,
    }
}

// MI v2.0, 5.2.3, Figure 89
#[derive(Debug, DekuRead, DekuWrite, Eq, PartialEq)]
#[deku(ctx = "endian: Endian", endian = "endian")]
struct MctpTransmissionUnitSizeRequest {
    #[deku(seek_from_current = "2")]
    dw0_portid: u8,
    #[deku(pad_bytes_after = "2")]
    dw1_mtus: u16,
}

// MI v2.0, 5.3, Figure 94
flags! {
    pub enum ControllerFunctionAndReportingFlags: u8 {
        Incf = 1 << 0,
        Incpf = 1 << 1,
        Incvf = 1 << 2,
        All = 1 << 7,
    }
}

// MI v2.0, 5.3, Figure 95
flags! {
    pub enum ControllerPropertyFlags: u32 {
        Csts = 1 << 0,
        Ctemp = 1 << 1,
        Pldu = 1 << 2,
        Spare = 1 << 3,
        Cwarn = 1 << 4,
        Ccf = 1 << 31,
    }
}

// MI v2.0, 5.3, Figures 94, 95
#[derive(Debug, DekuRead, DekuWrite, Eq, PartialEq)]
#[deku(ctx = "endian: Endian", endian = "endian")]
struct ControllerHealthStatusPollRequest {
    sctlid: u16,
    maxrent: u8,
    functions: WireFlagSet<ControllerFunctionAndReportingFlags>,
    properties: WireFlagSet<ControllerPropertyFlags>,
}

// MI v2.0, 5.3, Figure 96
#[derive(Debug, DekuRead, DekuWrite)]
#[deku(endian = "little")]
struct ControllerHealthStatusPollResponse {
    status: ResponseStatus,
    #[deku(pad_bytes_before = "2", update = "self.body.len() as u8")]
    rent: u8,
    body: WireVec<ControllerHealthDataStructure, MAX_CONTROLLERS>,
}
impl Encode<{ 4 + 16 * MAX_CONTROLLERS }> for ControllerHealthStatusPollResponse {}

// MI v2.0, 5.3, Figure 97, CSTS
flags! {
    pub enum ControllerStatusFlags: u16 {
        Rdy = 1 << 0,
        Cfs = 1 << 1,
        ShstInProgress = 1 << 2,
        ShstComplete = 1 << 3,
        ShstReserved = (ControllerStatusFlags::ShstInProgress | ControllerStatusFlags::ShstComplete).bits(),
        Nssro = 1 << 4,
        Ceco = 1 << 5,
        Nac = 1 << 6,
        Fa = 1 << 7,
        Tcida = 1 << 8,
    }
}

// XXX: Consider improving the data model to handle the incongruence of the two flag
// sets
impl From<FlagSet<super::ControllerStatusFlags>> for WireFlagSet<ControllerStatusFlags> {
    fn from(value: FlagSet<super::ControllerStatusFlags>) -> Self {
        use super::ControllerStatusFlags as F;
        use ControllerStatusFlags as T;

        let mut fs = FlagSet::empty();

        for f in value {
            fs |= match f {
                F::Rdy => T::Rdy,
                F::Cfs => T::Cfs,
                F::ShstInProgress => T::ShstInProgress,
                F::ShstComplete => T::ShstComplete,
                F::ShstReserved => T::ShstReserved,
                F::Nssro => T::Nssro,
                F::Pp => todo!(),
                F::St => todo!(),
            };
        }

        Self(fs)
    }
}

// MI v2.0, 5.3, Figure 97, CWARN
flags! {
    pub enum CriticalWarningFlags: u8 {
        St,
        Taut,
        Rd,
        Ro,
        Vmbf,
        Pmre
    }
}

// MI v2.0, 5.3, Figure 97
#[derive(Debug, DekuRead, DekuWrite)]
#[deku(ctx = "endian: Endian", endian = "endian")]
struct ControllerHealthDataStructure {
    ctlid: u16,
    csts: WireFlagSet<ControllerStatusFlags>,
    ctemp: u16,
    pdlu: u8,
    spare: u8,
    cwarn: WireFlagSet<CriticalWarningFlags>,
    #[deku(pad_bytes_after = "5")]
    chsc: WireFlagSet<ControllerHealthStatusChangedFlags>,
}

// MI v2.0, 5.3, Figure 98
flags! {
    // NOTE: These are the same as CompositeControllerStatusFlags
    pub enum ControllerHealthStatusChangedFlags: u16 {
        Rdy = 1 << 0,
        Cfs = 1 << 1,
        Shst = 1 << 2,
        Nssro = 1 << 4,
        Ceco = 1 << 5,
        Nac = 1 << 6,
        Fa = 1 << 7,
        Csts = 1 << 8,
        Ctemp = 1 << 9,
        Pdlu = 1 << 10,
        Spare = 1 << 11,
        Cwarn = 1 << 12,
        Tcida = 1 << 13,
    }
}

// MI v2.0, 5.6, Figure 106
#[derive(Debug, DekuRead, DekuWrite, Eq, PartialEq)]
#[deku(ctx = "endian: Endian", endian = "endian")]
struct NvmSubsystemHealthStatusPollRequest {
    dword0: u32,
    dword1: u32,
}

// MI v2.0, 5.6, Figure 107
flags! {
    #[repr(u16)]
    enum CompositeControllerStatusFlags: u16 {
        Rdy = 1 << 0,
        Cfs = 1 << 1,
        Shst = 1 << 2,
        Nssro = 1 << 4,
        Ceco = 1 << 5,
        Nac = 1 << 6,
        Fa = 1 << 7,
        Csts = 1 << 8,
        Ctemp = 1 << 9,
        Pdlu = 1 << 10,
        Spare = 1 << 11,
        Cwarn = 1 << 12,
        Tcida = 1 << 13,
    }
}

#[derive(Debug)]
pub struct CompositeControllerStatusFlagSet(FlagSet<CompositeControllerStatusFlags>);

impl CompositeControllerStatusFlagSet {
    pub fn empty() -> Self {
        Self(FlagSet::empty())
    }
}

impl From<FlagSet<HealthStatusChangeFlags>> for CompositeControllerStatusFlagSet {
    fn from(value: FlagSet<HealthStatusChangeFlags>) -> Self {
        use CompositeControllerStatusFlags as T;
        use HealthStatusChangeFlags as F;

        let mut converted = FlagSet::empty();
        for flag in value {
            converted |= match flag {
                F::Rdy => T::Rdy,
                F::Cfs => T::Cfs,
                F::Shst => T::Shst,
                F::Nssro => T::Nssro,
                F::Ceco => T::Ceco,
                F::Nac => T::Nac,
                F::Fa => T::Fa,
                F::Csts => T::Csts,
                F::Ctemp => T::Ctemp,
                F::Pldu => T::Pdlu,
                F::Spare => T::Spare,
                F::Cwarn => T::Cwarn,
                F::Tcida => T::Tcida,
            }
        }
        Self(converted)
    }
}

impl From<FlagSet<ControllerHealthStatusChangedFlags>> for CompositeControllerStatusFlagSet {
    fn from(value: FlagSet<ControllerHealthStatusChangedFlags>) -> Self {
        // SAFETY: Separate declarations have the equal definitions
        Self(FlagSet::new(value.bits()).expect("Divergent flag definitions"))
    }
}

// MI v2.0, 5.6, Figure 107, 108
#[derive(Debug, DekuRead, DekuWrite)]
#[deku(endian = "little")]
struct CompositeControllerStatusDataStructureResponse {
    #[deku(pad_bytes_after = "2")]
    ccsf: u16,
}
impl Encode<4> for CompositeControllerStatusDataStructureResponse {}

// MI v2.0, 5.6, Figure 108, NSS
// TODO: Convert to Flags/FlagSet
#[derive(Debug)]
pub struct NvmSubsystemStatus {
    atf: bool,
    sfm: bool,
    df: bool,
    rnr: bool,
    rd: bool,
}

impl Default for NvmSubsystemStatus {
    fn default() -> Self {
        Self::new()
    }
}

impl NvmSubsystemStatus {
    pub fn new() -> Self {
        Self {
            atf: false,
            sfm: false,
            df: true,
            rnr: true,
            rd: false,
        }
    }
}

// MI v2.0, 5.6, Figure 108
#[derive(Debug, DekuRead, DekuWrite)]
#[deku(endian = "little")]
struct NvmSubsystemHealthDataStructureResponse {
    nss: u8,
    sw: u8,
    ctemp: u8,
    pldu: u8,
}
impl Encode<4> for NvmSubsystemHealthDataStructureResponse {}

// MI v2.0, 5.7, Figure 109, DTYP
#[derive(Debug, DekuRead, DekuWrite, PartialEq, Eq)]
#[deku(ctx = "endian: Endian, dtyp: u8", endian = "endian", id = "dtyp")]
#[repr(u8)]
enum NvmeMiDataStructureRequestType {
    NvmSubsystemInformation = 0x00,
    PortInformation = 0x01,
    ControllerList = 0x02,
    ControllerInformation = 0x03,
    OptionallySupportedCommandList = 0x04,
    ManagementEndpointBufferCommandSupportList = 0x05,
}
unsafe impl Discriminant<u8> for NvmeMiDataStructureRequestType {}

// MI v2.0, 5.7, Figure 109
#[derive(Debug, DekuRead, DekuWrite, Eq, PartialEq)]
#[deku(ctx = "endian: Endian", endian = "endian")]
struct NvmeMiDataStructureRequest {
    ctrlid: u16,
    portid: u8,
    #[deku(update = "self.body.id()")]
    dtyp: u8,
    #[deku(pad_bytes_after = "3")]
    iocsi: u8,
    #[deku(ctx = "*dtyp")]
    body: NvmeMiDataStructureRequestType,
}

// MI v2.0, 5.7, Figure 111
#[derive(Debug, DekuRead, DekuWrite)]
#[deku(endian = "little")]
struct NvmeMiDataStructureManagementResponse {
    status: ResponseStatus,
    rdl: u16,
}
impl Encode<4> for NvmeMiDataStructureManagementResponse {}

// MI v2.0, 5.7.1, Figure 112, NNSC
// TODO: Convert to Flags/FlagSet
#[derive(Debug)]
pub struct SubsystemCapabilities {
    sre: bool,
}

impl SubsystemCapabilities {
    pub fn new() -> Self {
        Self { sre: false }
    }
}

impl Default for SubsystemCapabilities {
    fn default() -> Self {
        Self::new()
    }
}

// MI v2.0, 5.7.1, Figure 112
#[derive(Debug, DekuWrite)]
#[deku(endian = "little")]
struct NvmSubsystemInformationResponse {
    nump: u8,
    mjr: u8,
    mnr: u8,
    nnsc: u8,
}
impl Encode<32> for NvmSubsystemInformationResponse {}

// MI v2.0, 5.7.2, Figure 114, PRTTYP
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum PortType {
    Inactive = 0x00,
    Pcie = 0x01,
    TwoWire = 0x02,
}
unsafe impl Discriminant<u8> for PortType {}

impl From<&crate::PortType> for PortType {
    fn from(value: &crate::PortType) -> Self {
        match value {
            crate::PortType::Inactive => Self::Inactive,
            crate::PortType::Pcie(_) => Self::Pcie,
            crate::PortType::TwoWire(_) => Self::TwoWire,
        }
    }
}

// MI v2.0, 5.7.2, Figure 114
#[derive(Debug, DekuWrite)]
#[deku(endian = "little")]
struct PortInformationResponse {
    prttyp: u8,
    prtcap: u8,
    mmtus: u16,
    mebs: u32,
}
impl Encode<8> for PortInformationResponse {}

// MI v2.0, 5.7.2, Figure 115, PCIEMPS
#[allow(dead_code)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum PciePayloadSize {
    Payload128B = 0x00,
    Payload256B = 0x01,
    Payload512B = 0x02,
    Payload1Kb = 0x03,
    Payload2Kb = 0x04,
    Payload4Kb = 0x05,
}

impl From<PciePayloadSize> for u8 {
    fn from(pps: PciePayloadSize) -> Self {
        pps as Self
    }
}

// MI v2.0, 5.7.2, Figure 115, PCIECLS
#[allow(dead_code)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum PcieLinkSpeed {
    Inactive = 0x00,
    Gts2p5 = 0x01,
    Gts5 = 0x02,
    Gts8 = 0x03,
    Gts16 = 0x04,
    Gts32 = 0x05,
    Gts64 = 0x06,
}

impl From<PcieLinkSpeed> for u8 {
    fn from(pls: PcieLinkSpeed) -> Self {
        pls as Self
    }
}

// MI v2.0, 5.7.2, Figure 115, PCIEMLW
#[allow(dead_code)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum PcieLinkWidth {
    X1 = 1,
    X2 = 2,
    X4 = 4,
    X8 = 8,
    X12 = 12,
    X16 = 16,
    X32 = 32,
}

impl From<PcieLinkWidth> for u8 {
    fn from(plw: PcieLinkWidth) -> Self {
        plw as Self
    }
}

// MI v2.0, 5.7.2, Figure 115
#[derive(Debug, DekuWrite)]
#[deku(endian = "little")]
struct PciePortDataResponse {
    pciemps: u8,
    pcieslsv: u8,
    pciecls: u8,
    pciemlw: u8,
    pcienlw: u8,
    pciepn: u8,
}
impl Encode<24> for PciePortDataResponse {}

// MI v2.0, Figure 116, MVPDFREQ
#[allow(dead_code)]
#[derive(Clone, Copy, Debug, DekuRead, DekuWrite, Eq, Ord, PartialEq, PartialOrd)]
#[deku(endian = "endian", ctx = "endian: Endian")]
#[deku(id_type = "u8")]
#[repr(u8)]
pub enum SmbusFrequency {
    FreqNotSupported = 0x00,
    Freq100Khz = 0x01,
    Freq400Khz = 0x02,
    Freq1Mhz = 0x03,
}
unsafe impl Discriminant<u8> for SmbusFrequency {}

// MI v2.0, 5.7.2, Figure 116
#[derive(Debug, DekuWrite)]
#[deku(endian = "little")]
struct TwoWirePortDataResponse {
    cvpdaddr: u8,
    mvpdfreq: u8,
    cmeaddr: u8,
    twprt: u8,
    nvmebm: u8,
}
impl Encode<24> for TwoWirePortDataResponse {}

// MI v2.0, 5.7.4, Figure 117
#[derive(Debug, DekuRead, DekuWrite)]
#[deku(endian = "little")]
struct ControllerInformationResponse {
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
impl Encode<32> for ControllerInformationResponse {}

// MI v2.0, 6, Figure 134
#[derive(Debug, DekuRead, DekuWrite, PartialEq, Eq)]
#[deku(ctx = "endian: Endian, opcode: u8", id = "opcode", endian = "endian")]
#[repr(u8)]
enum AdminCommandRequestType {
    DeleteIoSubmissionQueue = 0x00, // P
    CreateIoSubmissionQueue = 0x01, // P
    #[deku(id = 0x02)]
    GetLogPage(AdminGetLogPageRequest), // M
    DeleteIoCompletionQueue = 0x04, // P
    CreateIoCompletionQueue = 0x05, // P
    #[deku(id = 0x06)]
    Identify(AdminIdentifyRequest), // M
    Abort = 0x08,                   // P
    GetFeatures = 0x0a,             // M
    AsynchronousEventRequest = 0x0c, // P
    #[deku(id = 0x0d)]
    NamespaceManagement(AdminNamespaceManagementRequest),
    KeepAlive = 0x18,                      // P
    DirectiveSend = 0x19,                  // P
    DirectiveReceive = 0x1a,               // P
    NvmeMiSend = 0x1d,                     // P
    NvmeMiReceive = 0x1e,                  // P
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
unsafe impl Discriminant<u8> for AdminCommandRequestType {}

// MI v2.0, 6, Figure 136
#[derive(Debug, DekuRead, DekuWrite)]
#[deku(endian = "little")]
struct AdminCommandRequestHeader {
    #[deku(update = "self.op.id()")]
    opcode: u8,
    cflgs: u8,
    ctlid: u16,
    #[deku(ctx = "*opcode")]
    op: AdminCommandRequestType,
}

// MI v2.0, 6, Figure 136
// Base v2.1, 5.1.12, Figures 197-201
#[derive(Debug, DekuRead, DekuWrite, Eq, PartialEq)]
#[deku(ctx = "endian: Endian", endian = "endian")]
struct AdminGetLogPageRequest {
    nsid: u32,
    #[deku(seek_from_current = "16")]
    dofst: u32,
    dlen: u32,
    #[deku(seek_from_current = "8")]
    #[deku(update = "self.req.id()")]
    lid: u8,
    lsp_rae: u8,
    numdw: u32, // Synthesised from NUMDL / NUMDU
    lsi: u16,
    lpo: u64, // Synthesised from LPOL / LPOU
    uidx: u8,
    #[deku(seek_from_current = "1")]
    ot: u8,
    csi: u8,
    #[deku(pad_bytes_after = "4")]
    #[deku(ctx = "*lid")]
    req: AdminGetLogPageLidRequestType,
}

// MI v2.0, 6, Figure 136
// Base v2.1, 5.1.13.1, Figures 306-309
#[derive(Debug, DekuRead, DekuWrite, Eq, PartialEq)]
#[deku(ctx = "endian: Endian", endian = "endian")]
struct AdminIdentifyRequest {
    nsid: u32,
    #[deku(seek_from_current = "16")]
    dofst: u32,
    dlen: u32,
    #[deku(seek_from_current = "8")]
    #[deku(update = "self.req.id()")]
    cns: u8,
    #[deku(seek_from_current = "1")]
    cntid: u16,
    cnssid: u16,
    #[deku(seek_from_current = "1")]
    csi: u8,
    #[deku(seek_from_current = "8")]
    uidx: u8,
    #[deku(pad_bytes_after = "7")]
    #[deku(ctx = "*cns")]
    req: AdminIdentifyCnsRequestType,
}

// MI v2.0, 6, Figure 136
// Base v2.1, 5.1.21, Figures 367-369
#[derive(Debug, DekuRead, DekuWrite, Eq, PartialEq)]
#[deku(ctx = "endian: Endian", endian = "endian")]
struct AdminNamespaceManagementRequest {
    nsid: u32,
    #[deku(seek_from_current = "16")]
    dofst: u32,
    dlen: u32,
    #[deku(seek_from_current = "8")]
    sel: u8, // NOTE: SEL is the bottom nibble
    #[deku(seek_from_current = "6")]
    csi: u8,
    #[deku(seek_from_current = "16")]
    #[deku(ctx = "*sel")]
    req: AdminNamespaceManagementSelect,
}

// MI v2.0, 6, Figure 138
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
