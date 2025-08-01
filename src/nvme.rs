// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2025 Code Construct
 */
pub mod mi;

use deku::ctx::Endian;
use deku::{DekuRead, DekuWrite, deku_derive};
use flagset::flags;

use crate::wire::WireFlagSet;
use crate::wire::WireString;
use crate::wire::WireUuid;
use crate::wire::WireVec;
use crate::{Discriminant, Encode};

// Base v2.1, 3.1.4, Figure 33
#[repr(usize)]
pub enum ControllerProperties {
    Cc(ControllerConfiguration) = 0x14,
}

// Base v2.1, 3.1.4.5, Figure 41
#[derive(Clone, Copy, Debug, Default)]
pub struct ControllerConfiguration {
    pub en: bool,
}

// Base v2.1, 3.1.4.6, Figure 42
flags! {
    #[repr(u32)]
    pub enum ControllerStatusFlags: u32 {
        Rdy = 1 << 0,
        Cfs = 1 << 1,
        ShstInProgress = 1 << 2,
        ShstComplete = 1 << 3,
        ShstReserved = (ControllerStatusFlags::ShstInProgress | ControllerStatusFlags::ShstComplete).bits(),
        Nssro = 1 << 4,
        Pp = 1 << 5,
        St = 1 << 6,
    }
}

// Base v2.1, 4.2.3, Figure 100, CRD
#[expect(dead_code)]
#[repr(u8)]
enum CommandRetryDelay {
    None = 0x00,
    Time1 = 0x01,
    Time2 = 0x02,
    Time3 = 0x03,
}
unsafe impl Discriminant<u8> for CommandRetryDelay {}

// Base v2.1, 4.2.1, Figure 98
struct AdminIoCqeStatus {
    cid: u16,
    p: bool,
    status: AdminIoCqeStatusType,
    crd: CommandRetryDelay,
    m: bool,
    dnr: bool,
}

impl From<AdminIoCqeStatus> for u32 {
    fn from(value: AdminIoCqeStatus) -> Self {
        let dnr: u32 = value.dnr.into();
        let m: u32 = value.m.into();
        let crd: u32 = value.crd.id().into();
        debug_assert_eq!((crd & !3), 0);
        let sct: u32 = value.status.id().into();
        debug_assert_eq!((sct & !7), 0);
        let sc: u32 = match value.status {
            AdminIoCqeStatusType::GenericCommandStatus(s) => s.id(),
            AdminIoCqeStatusType::CommandSpecificStatus => todo!(),
            AdminIoCqeStatusType::MediaAndDataIntegrityErrors => todo!(),
            AdminIoCqeStatusType::PathRelatedStatus => todo!(),
            AdminIoCqeStatusType::VendorSpecific => todo!(),
        }
        .into();
        debug_assert_eq!((sc & !0xff), 0);
        let p: u32 = value.p.into();
        let cid: u32 = value.cid.into();
        (dnr << 31) | (m << 30) | (crd << 28) | (sct << 25) | (sc << 17) | (p << 16) | cid
    }
}

// Base v2.1, 4.3.2, Figure 101
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
enum AdminIoCqeStatusType {
    GenericCommandStatus(AdminIoCqeGenericCommandStatus) = 0x00,
    #[expect(dead_code)]
    CommandSpecificStatus = 0x01,
    #[expect(dead_code)]
    MediaAndDataIntegrityErrors = 0x02,
    #[expect(dead_code)]
    PathRelatedStatus = 0x03,
    #[expect(dead_code)]
    VendorSpecific = 0x07,
}
unsafe impl Discriminant<u8> for AdminIoCqeStatusType {}

// Base v2.1, 4.2.3.1, Figure 102
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
enum AdminIoCqeGenericCommandStatus {
    SuccessfulCompletion = 0x00,
    InvalidFieldInCommand = 0x02,
}
unsafe impl Discriminant<u8> for AdminIoCqeGenericCommandStatus {}

// Base v2.1, 5.1.13.1, Figure 310
#[derive(Clone, Copy, Debug, DekuRead, DekuWrite, Eq, PartialEq)]
#[deku(ctx = "endian: Endian, cns: u8", id = "cns", endian = "endian")]
#[repr(u8)]
enum AdminIdentifyCnsRequestType {
    NvmIdentifyNamespace = 0x00,
    IdentifyController = 0x01,
    ActiveNamespaceIDList = 0x02,
    NamespaceIdentificationDescriptorList = 0x03,
    IoIdentifyNamespace = 0x05,
    IoIdentifyController = 0x06,
    IoActiveNamespaceIdList = 0x07,
    IdentifyNamespace = 0x08,
    AllocatedNamespaceIdList = 0x10,
    NvmSubsystemControllerList = 0x13,
    SecondaryControllerList = 0x15,
}
unsafe impl Discriminant<u8> for AdminIdentifyCnsRequestType {}

// Base v2.1, 5.1.13.1, Figure 310
// NVM Command Set v1.0c, 4.1.5.1, Figure 97
#[derive(Debug, Default, DekuRead, DekuWrite)]
#[deku(endian = "little")]
pub struct AdminIdentifyNvmIdentifyNamespaceResponse {
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
impl Encode<4096> for AdminIdentifyNvmIdentifyNamespaceResponse {}

// Base v2.1, 5.1.12, Figure 202
// MI v2.0, 6.3, Figure 141
#[derive(Debug, DekuRead, DekuWrite, Eq, PartialEq)]
#[deku(ctx = "endian: Endian, lid: u8", id = "lid", endian = "endian")]
#[repr(u8)]
pub enum AdminGetLogPageLidRequestType {
    SupportedLogPages = 0x00,
    ErrorInformation = 0x01,
    SmartHealthInformation = 0x02,
    FeatureIdentifiersSupportedAndEffects = 0x12,
}
unsafe impl Discriminant<u8> for AdminGetLogPageLidRequestType {}

// Base v2.1, 5.1.12.1.1, Figure 203
#[derive(Debug, DekuRead, DekuWrite)]
#[deku(endian = "little")]
pub struct AdminGetLogPageSupportedLogPagesResponse {
    lsids: WireVec<LidSupportedAndEffectsDataStructure, 256>,
}
impl Encode<1024> for AdminGetLogPageSupportedLogPagesResponse {}

// Base v2.1, 5.1.12.1.1, Figure 204
flags! {
    pub enum LidSupportedAndEffectsFlags: u8 {
        Lsupp,
        Ios,
    }
}

// Base v2.1, 5.1.12.1.1, Figure 204
#[derive(Clone, Copy, Debug, DekuRead, DekuWrite)]
#[deku(ctx = "endian: Endian", endian = "endian")]
pub struct LidSupportedAndEffectsDataStructure {
    flags: WireFlagSet<LidSupportedAndEffectsFlags>,
    #[deku(seek_from_current = "1")]
    lidsp: u16,
}

// Base v2.1, 5.1.12.1.3, Figure 206, CW
flags! {
    pub enum CriticalWarning: u8 {
        Ascbt,
        Ttc,
        Ndr,
        Amro,
        Vmbf,
        Pmrro,
    }
}

// Base v2.1, 5.1.12.1.3, Figure 206, EGCWS
flags! {
    pub enum EnduranceGroupCriticalWarningSummary: u8 {
        Egascbt = 1 << 0,
        Egdr = 1 << 2,
        Egro = 1 << 3,
    }
}

// Base v2.1, 5.1.12.1.3, Figure 206
#[derive(Debug, Default, DekuRead, DekuWrite)]
#[deku(endian = "little")]
pub struct SmartHealthInformationLogPageResponse {
    cw: WireFlagSet<CriticalWarning>,
    ctemp: u16,
    avsp: u8,
    avspt: u8,
    pused: u8,
    egcws: WireFlagSet<EnduranceGroupCriticalWarningSummary>,
    #[deku(seek_from_current = "25")]
    dur: u128,
    duw: u128,
    hrc: u128,
    hwc: u128,
    cbt: u128,
    pwrc: u128,
    poh: u128,
    upl: u128,
    mdie: u128,
    neile: u128,
    wctt: u32,
    cctt: u32,
    tsen: [u16; 8],
    tmttc: [u32; 2],
    #[deku(pad_bytes_after = "280")]
    tttmt: [u32; 2],
}
impl Encode<512> for SmartHealthInformationLogPageResponse {}

// Base v2.1, 5.1.13.1, Figure 311
#[derive(Clone, Copy, Debug, DekuRead, DekuWrite)]
#[deku(id_type = "u8", endian = "endian", ctx = "endian: Endian")]
#[repr(u8)]
pub enum CommandSetIdentifier {
    Nvm = 0x00,
    KeyValue = 0x01,
    ZonedNamespace = 0x02,
    SubsystemLocalMemory = 0x03,
    ComputationalPrograms = 0x04,
}

// Base v2.1, 5.1.13.2.1, Figure 312, CNTRLTYPE
#[derive(Clone, Copy, Debug, DekuRead, DekuWrite, PartialEq)]
#[deku(id_type = "u8", endian = "endian", ctx = "endian: Endian")]
#[repr(u8)]
enum ControllerType {
    Reserved = 0x00,
    IoController = 0x01,
    DiscoveryController = 0x02,
    AdministrativeController = 0x03,
}

// Base v2.1, 5.1.13.2.1, Figure 312, LPA
flags! {
    #[repr(u8)]
    pub enum LogPageAttributes: u8 {
        Smarts,
        Cses,
        Lpeds,
        Ts,
        Pes,
        Mlps,
        Da4s,
    }
}

// Base v2.1, 5.1.13.2.1, Figure 312
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
    cntrltype: crate::nvme::ControllerType,
    #[deku(seek_from_start = "253")]
    nvmsr: u8,
    vwci: u8,
    mec: u8,
    ocas: u16,
    acl: u8,
    aerl: u8,
    frmw: u8,
    lpa: WireFlagSet<LogPageAttributes>,
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

// Base v2.1, 5.1.13.2.2
#[derive(Debug, DekuRead, DekuWrite)]
#[deku(endian = "little")]
struct AdminIdentifyActiveNamespaceIdListResponse {
    nsid: WireVec<u32, 1024>,
}
impl Encode<4096> for AdminIdentifyActiveNamespaceIdListResponse {}

impl AdminIdentifyActiveNamespaceIdListResponse {
    fn new() -> Self {
        Self {
            nsid: WireVec::new(),
        }
    }
}

// Base v2.1, 5.1.13.2.3, Figure 315
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
    Csi(u8, u16, crate::nvme::CommandSetIdentifier),
}

impl From<crate::NamespaceIdentifierType> for NamespaceIdentifierType {
    fn from(value: crate::NamespaceIdentifierType) -> Self {
        match value {
            crate::NamespaceIdentifierType::Ieuid(v) => Self::Ieuid(v.len() as u8, 0, v),
            crate::NamespaceIdentifierType::Nguid(v) => Self::Nguid(v.len() as u8, 0, v),
            crate::NamespaceIdentifierType::Nuuid(uuid) => Self::Nuuid(16, 0, WireUuid::new(uuid)),
            crate::NamespaceIdentifierType::Csi(v) => Self::Csi(1, 0, v),
        }
    }
}

// Base v2.1, 5.1.13.2.3, Figure 315
#[derive(Debug)]
#[deku_derive(DekuRead, DekuWrite)]
#[deku(endian = "little")]
struct AdminIdentifyNamespaceIdentificationDescriptorListResponse {
    nids: WireVec<NamespaceIdentifierType, { crate::MAX_NIDTS }>,
}
impl Encode<4096> for AdminIdentifyNamespaceIdentificationDescriptorListResponse {}

// Base v2.1, 5.1.13.2.9
#[derive(Debug, DekuRead, DekuWrite)]
#[deku(endian = "little")]
struct AdminIdentifyAllocatedNamespaceIdListResponse {
    nsid: WireVec<u32, 1024>,
}
impl Encode<4096> for AdminIdentifyAllocatedNamespaceIdListResponse {}

// Base v2.1, Section 5.1.13.2.12
#[derive(Debug, DekuRead, DekuWrite)]
#[deku(endian = "little")]
struct ControllerListResponse {
    #[deku(update = "self.ids.len()")]
    numids: u16,
    #[deku(count = "numids")]
    ids: WireVec<u16, 2047>,
}
impl Encode<4096> for ControllerListResponse {}

impl ControllerListResponse {
    fn new() -> Self {
        Self {
            numids: 0,
            ids: WireVec::new(),
        }
    }
}
