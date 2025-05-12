use heapless::Vec;
use log::debug;
use mctp::{AsyncRespChannel, MCTP_TYPE_NVME};

use crate::nvme::{PCIeLinkSpeed, UnitKind};

use super::PortType;

const ISCSI: crc::Crc<u32> = crc::Crc::<u32>::new(&crc::CRC_32_ISCSI);
const MAX_FRAGMENTS: usize = 6;

trait RequestHandler {
    async fn handle<A: AsyncRespChannel>(
        self,
        mep: &mut super::ManagementEndpoint,
        subsys: &mut super::Subsystem,
        rest: &[u8],
        resp: &mut A,
    ) -> Result<(), ResponseStatus>;
}

#[derive(Debug)]
enum ResponseStatus {
    Success = 0x00,
    InternalError = 0x02,
    InvalidCommandOpcode = 0x03,
    InvalidParameter = 0x04,
    InvalidCommandSize = 0x05,
    InvalidCommandInputDataSize = 0x06,
    Unknown = 0x100,
}

impl From<u8> for ResponseStatus {
    fn from(num: u8) -> Self {
        match num {
            0x00 => Self::Success,
            _ => Self::Unknown,
        }
    }
}

impl From<ResponseStatus> for u8 {
    fn from(rs: ResponseStatus) -> Self {
        rs as Self
    }
}

bitfield! {
    struct NVMeManagementResponse([u8]);
    impl Debug;
    u8;
    from into ResponseStatus, status, set_status: 7, 0;
    u32, rsvd, _: 31, 8;
}

impl NVMeManagementResponse<[u8; 4]> {
    fn new() -> Self {
        Self([0; 4])
    }
}

bitfield! {
    struct MessageHeader([u8]);
    impl Debug;
    u8;
    csi, set_csi: 0;
    rsvd0, _: 2, 1;
    from into MessageType, nmimt, set_nmimt: 6, 3;
    ror, set_ror: 7;
    meb, set_meb: 8;
    ciap, set_ciap: 9;
    rsvd1, _: 15, 10;
}

impl MessageHeader<[u8; 3]> {
    fn new() -> Self {
        Self([0; 3])
    }

    fn extract(buf: &[u8]) -> Option<(Self, &[u8])> {
        if let Some((head, tail)) = buf.split_at_checked(3) {
            return Some((MessageHeader(head.try_into().unwrap()), tail));
        };
        None
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MessageType {
    ControlPrimitive = 0x00,
    NVMeMICommand = 0x01,
    NVMeAdminCommand = 0x02,
    PCIeCommand = 0x04,
    AsynchronousEvent = 0x05,
    Unknown = 0x100,
}

impl From<u8> for MessageType {
    fn from(num: u8) -> Self {
        match num {
            0x00 => Self::ControlPrimitive,
            0x01 => Self::NVMeMICommand,
            0x02 => Self::NVMeAdminCommand,
            0x04 => Self::PCIeCommand,
            0x05 => Self::AsynchronousEvent,
            _ => Self::Unknown,
        }
    }
}

impl From<MessageType> for u8 {
    fn from(typ: MessageType) -> Self {
        typ as Self
    }
}

bitfield! {
    struct NVMeMICommandHeader([u8]);
    impl Debug;
    u8;
    from into CommandOpcode, opcode, set_opcode: 7, 0;
    u32, rsvd, _: 31, 8;
}

impl NVMeMICommandHeader<[u8; 4]> {
    fn extract(buf: &[u8]) -> Option<(Self, &[u8])> {
        if let Some((head, tail)) = buf.split_at_checked(4) {
            return Some((NVMeMICommandHeader(head.try_into().unwrap()), tail));
        }
        None
    }
}

#[derive(Debug, PartialEq, Eq)]
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
    Unknown = 0x100,
}

impl From<u8> for CommandOpcode {
    fn from(num: u8) -> Self {
        match num {
            0x00 => Self::ReadNVMeMIDataStructure,
            0x01 => Self::NVMSubsystemHealthStatusPoll,
            0x02 => Self::ControllerHealthStatusPoll,
            0x03 => Self::ConfigurationSet,
            0x04 => Self::ConfigurationGet,
            0x05 => Self::VPDRead,
            0x06 => Self::VPDWrite,
            0x07 => Self::Reset,
            0x08 => Self::SESReceive,
            0x09 => Self::SESSend,
            0x0a => Self::ManagementEndpointBufferRead,
            0x0b => Self::ManagementEndpointBufferWrite,
            0x0c => Self::Shutdown,
            _ => Self::Unknown,
        }
    }
}

impl From<CommandOpcode> for u8 {
    fn from(opcode: CommandOpcode) -> Self {
        opcode as Self
    }
}

bitfield! {
    struct NVMeMIDataStructure([u8]);
    impl Debug;
    u8;
    u16, ctrlid, set_ctrlid: 15, 0;
    portid, set_portid: 23, 16;
    from into NVMeMIDataStructureType, dtyp, set_dtyp: 31, 24;
    iocsi, set_iocsi: 39, 32;
    u32, rsvd0, _: 63, 40;
}

impl NVMeMIDataStructure<[u8; 8]> {
    pub fn extract(buf: &[u8]) -> Option<(Self, &[u8])> {
        if let Some((head, tail)) = buf.split_at_checked(8) {
            return Some((NVMeMIDataStructure(head.try_into().unwrap()), tail));
        }
        None
    }
}

#[derive(Debug, PartialEq, Eq)]
enum NVMeMIDataStructureType {
    NVMSubsystemInformation = 0x00,
    PortInformation = 0x01,
    ControllerList = 0x02,
    ControllerInformation = 0x03,
    OptionallySupportedCommandList = 0x04,
    ManagementEndpointBufferCommandSupportList = 0x05,
    Unknown = 0x100,
}

impl From<u8> for NVMeMIDataStructureType {
    fn from(num: u8) -> Self {
        match num {
            0x00 => Self::NVMSubsystemInformation,
            0x01 => Self::PortInformation,
            0x02 => Self::ControllerList,
            0x03 => Self::ControllerInformation,
            0x04 => Self::OptionallySupportedCommandList,
            0x05 => Self::ManagementEndpointBufferCommandSupportList,
            _ => Self::Unknown,
        }
    }
}

impl From<NVMeMIDataStructureType> for u8 {
    fn from(dtyp: NVMeMIDataStructureType) -> Self {
        dtyp as Self
    }
}

bitfield! {
    struct NVMeMIDataStructureManagementResponse([u8]);
    impl Debug;
    u8;
    from into ResponseStatus, status, set_status: 7, 0;
    u16, rdl, set_rdl: 23, 8;
    rsvd, _: 31, 24;
}

impl NVMeMIDataStructureManagementResponse<[u8; 4]> {
    pub fn new() -> Self {
        Self([0; 4])
    }
}

bitfield! {
    struct NVMSubsystemInformation([u8]);
    impl Debug;
    u8;
    nump, set_nump: 7, 0;
    mjr, set_mjr: 15, 8;
    mnr, set_mnr: 23, 16;
    nnsc_sre, set_nnsc_sre: 24;
    rsvd0, _: 31, 25;
}

impl NVMSubsystemInformation<[u8; 32]> {
    fn new() -> Self {
        Self([0; 32])
    }
}

bitfield! {
    struct PortInformation([u8]);
    impl Debug;
    u8;
    prttyp, set_prttyp: 7, 0;
    prtcap_ciaps, set_prtcap_ciaps: 8;
    prtcap_aems, set_prtcap_aems: 9;
    u16, mmtus, set_mmtus: 31, 16;
    u32, mebs, set_mebs: 63, 32;
}

impl PortInformation<[u8; 8]> {
    fn new() -> Self {
        Self([0; 8])
    }
}

bitfield! {
    struct PCIePortData([u8]);
    impl Debug;
    u8;
    pciemps, set_pciemps: 7, 0;
    pcieslsv, set_pcieslsv: 15, 8;
    pciecls, set_pciecls: 23, 16;
    pciemlw, set_pciemlw: 31, 24;
    pcienlw, set_pcienlw: 39, 32;
    pciepn, set_pciepn: 47, 40;
}

impl PCIePortData<[u8; 24]> {
    fn new() -> Self {
        Self([0; 24])
    }
}

bitfield! {
    struct TwoWirePortData([u8]);
    impl Debug;
    u8;
    cvpdaddr, set_cvpdaddr: 7, 0;
    mvpdfreq, set_mvpdfreq: 15, 8;
    cmeaddr, set_cmeaddr: 23, 16;
    twprt_msmbfreq, set_twprt_msmbfreq: 25, 24;
    twprt_rsvd, _: 30, 26;
    twprt_i3csprt, set_twprt_i3csprt: 31;
    nvmebm_nvmebms, set_nvmebm_nvmebms: 32;
    nvmebm_resvd, _: 39, 33;
}

impl TwoWirePortData<[u8; 24]> {
    fn new() -> Self {
        Self([0; 24])
    }
}

bitfield! {
    struct ControllerList([u8]);
    impl Debug;
    u16;
    numids, set_numids: 15, 0;
    ids, set_ids: 31, 16, 2047;
}

impl ControllerList<[u8; 4096]> {
    fn new() -> Self {
        Self([0; 4096])
    }
}

bitfield! {
    struct ControllerInformation([u8]);
    impl Debug;
    u8;
    portid, set_portid: 7, 0;
    rsvd0, _: 39, 8;
    prii_pcieriv, set_prii_pcieriv: 40;
    prii_rsvd, _: 47, 41;
    u16, pri_pcifn, set_pri_pcifn: 50, 48;
    u16, pri_pcidn, set_pri_pcidn: 55, 51;
    u16, pri_pcibn, set_pri_pcibn: 63, 56;
    u16, pcivid, set_pcivid: 79, 64;
    u16, pcidid, set_pcidid: 95, 80;
    u16, pcisvid, set_pcisvid: 111, 96;
    u16, pcisdid, set_pcisdid: 127, 112;
    pciesn, set_pciesn: 135, 128;
}

impl ControllerInformation<[u8; 32]> {
    fn new() -> Self {
        Self([0; 32])
    }
}

bitfield! {
    struct NVMSubsystemHealthStatusPoll([u8]);
    impl Debug;
    u8;
    u32, rsvd0, _: 31, 0;
    u32, rsvd1, _: 62, 32;
    cs, set_cs: 63;
}

impl NVMSubsystemHealthStatusPoll<[u8; 8]> {
    fn extract(buf: &[u8]) -> Option<(Self, &[u8])> {
        if let Some((head, tail)) = buf.split_at_checked(8) {
            return Some((NVMSubsystemHealthStatusPoll(head.try_into().unwrap()), tail));
        }
        None
    }
}

bitfield! {
    struct NVMSubsystemHealthDataStructure([u8]);
    impl Debug;
    u8;
    nss_rsvd, _: 1, 0;
    nss_p1la, set_nss_p1la: 2;
    nss_p0la, set_nss_p0la: 3;
    nss_rnr, set_nss_rnr: 4;
    nss_df, set_nss_df: 5;
    nss_sfm, set_nss_sfm: 6;
    nss_atf, set_nss_atf: 7;
    sw_ascbt_n, set_sw_ascbt_n: 8;
    sw_ttc_n, set_sw_ttc_n: 9;
    sw_ndr_n, set_sw_ndr_n: 10;
    sw_amro_n, set_sw_amro_n: 11;
    sw_vmbf_n, set_sw_vmbf_n: 12;
    sw_pmrro_n, set_sw_pmrro_n: 13;
    sw_rsvd, _: 15, 14;
    ctemp, set_ctemp: 23, 16;
    pldu, set_pldu: 31, 24;
}

impl NVMSubsystemHealthDataStructure<[u8; 4]> {
    fn new() -> Self {
        Self([0; 4])
    }
}

bitfield! {
    struct CompositeControllerStatusDataStructure([u8]);
    impl Debug;
    u8;
    ccsf_rdy, set_ccsf_rdy: 0;
    ccsf_cfs, set_ccsf_cfs: 1;
    ccsf_shst, set_ccsf_shst: 2;
    rsvd0, _: 3;
    ccsf_nssro, set_ccsf_nssro: 4;
    ccsf_ceco, set_ccsf_ceco: 5;
    ccsf_nac, set_ccsf_nac: 6;
    ccsf_fa, set_ccsf_fa: 7;
    ccsf_csts, set_ccsf_csts: 8;
    ccsf_ctemp, set_ccsf_ctemp: 9;
    ccsf_pdlu, set_ccsf_pdlu: 10;
    ccsf_spare, set_ccsf_spare: 11;
    ccsf_cwarn, set_ccsf_cwarn: 12;
    ccsf_tcida, set_ccsf_tcida: 13;
    rsvd1, _: 15, 14;
}

impl CompositeControllerStatusDataStructure<[u8; 2]> {
    fn new() -> Self {
        Self([0; 2])
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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
    Unknown = 0x100,
}

impl From<u8> for AdminCommandOpcode {
    fn from(num: u8) -> Self {
        match num {
            0x00 => Self::DeleteIOSubmissionQueue,
            0x01 => Self::CreateIOSubmissionQueue,
            0x02 => Self::GetLogPage,
            0x04 => Self::DeleteIOCompletionQueue,
            0x05 => Self::CreateIOCompletionQueue,
            0x06 => Self::Identify,
            0x08 => Self::Abort,
            0x0a => Self::GetFeatures,
            0x0c => Self::AsynchronousEventRequest,
            0x18 => Self::KeepAlive,
            0x19 => Self::DirectiveSend,
            0x1a => Self::DirectiveReceive,
            0x1d => Self::NVMeMISend,
            0x1e => Self::NVMeMIReceive,
            0x21 => Self::DiscoveryInformationManagement,
            0x22 => Self::FabricZoningReceive,
            0x25 => Self::FabricZoningLookup,
            0x29 => Self::FabricZoningSend,
            0x39 => Self::SendDiscoveryLogPage,
            0x3d => Self::TrackSend,
            0x3e => Self::TrackReceive,
            0x41 => Self::MigrationSend,
            0x42 => Self::MigrationReceive,
            0x45 => Self::ControllerDataQueue,
            0x7c => Self::DoorbellBufferConfig,
            0x7f => Self::FabricsCommands,
            0x85 => Self::LoadProgram,
            0x88 => Self::ProgramActivationManagement,
            0x89 => Self::MemoryRangeSetManagement,
            _ => Self::Unknown,
        }
    }
}

impl From<AdminCommandOpcode> for u8 {
    fn from(opcode: AdminCommandOpcode) -> Self {
        opcode as Self
    }
}

bitfield! {
    struct AdminCommandRequestHeader([u8]);
    impl Debug;
    u8;
    from into AdminCommandOpcode, opcode, set_opcode: 7, 0;
    cflgs_dlenv, set_cflgs_dlenv: 8;
    cflgs_dofstv, set_cflgs_dofstv: 9;
    cflgs_ish, set_cflgs_ish: 10;
    u16, ctrlid, set_ctrlid: 31, 16;
}

impl AdminCommandRequestHeader<[u8; 4]> {
    fn extract(buf: &[u8]) -> Option<(Self, &[u8])> {
        if let Some((head, tail)) = buf.split_at_checked(4) {
            return Some((AdminCommandRequestHeader(head.try_into().unwrap()), tail));
        };
        None
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
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
    Unknown = 0x100,
}

impl From<u8> for ControllerOrNamespaceStructure {
    fn from(val: u8) -> Self {
        match val {
            0x00 => Self::NVMIdentifyNamespace,
            0x01 => Self::IdentifyController,
            0x02 => Self::ActiveNamespaceIDList,
            0x03 => Self::NamespaceIdentificationDescriptorList,
            0x05 => Self::IOIdentifyNamespace,
            0x06 => Self::IOIdentifyController,
            0x07 => Self::IOActiveNamespaceIDList,
            0x08 => Self::IdentifyNamespace,
            0x10 => Self::AllocatedNamespaceIDList,
            0x13 => Self::NVMSubsystemControllerList,
            0x15 => Self::SecondaryControllerList,
            _ => Self::Unknown,
        }
    }
}

impl From<ControllerOrNamespaceStructure> for u8 {
    fn from(val: ControllerOrNamespaceStructure) -> Self {
        val as Self
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StatusCodeType {
    GenericCommandStatus = 0x00,
    CommandSpecificStatus = 0x01,
    MediaAndDataIntegrityErrors = 0x02,
    PathRelatedStatus = 0x03,
    VendorSpecific = 0x07,
}

impl From<u8> for StatusCodeType {
    fn from(val: u8) -> Self {
        match val {
            0x00 => Self::GenericCommandStatus,
            0x01 => Self::CommandSpecificStatus,
            0x02 => Self::MediaAndDataIntegrityErrors,
            0x03 => Self::PathRelatedStatus,
            0x07 => Self::VendorSpecific,
            _ => panic!("Unrecognised StatusCodeType"), /* FIXME */
        }
    }
}

impl From<StatusCodeType> for u8 {
    fn from(val: StatusCodeType) -> Self {
        val as Self
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GenericCommandStatus {
    SuccessfulCompletion = 0x00,
}

impl From<u8> for GenericCommandStatus {
    fn from(val: u8) -> Self {
        match val {
            0x00 => Self::SuccessfulCompletion,
            _ => panic!("Unrecognised GenericCommandStatus"),
        }
    }
}

impl From<GenericCommandStatus> for u8 {
    fn from(val: GenericCommandStatus) -> Self {
        val as Self
    }
}

bitfield! {
    struct AdminCommandResponseHeader([u8]);
    impl Debug;
    u8;
    from into ResponseStatus, status, set_status: 7, 0;
    rsvd0, _: 31, 8;
    u32, cqedw0, _: 63, 32;
    u32, cqedw1, _: 95, 64;
    u16, cqedw3_cid, set_cqedw3_cid: 111, 96;
    cqedw3_p, set_cqedw3_p: 112;
    from into GenericCommandStatus, cqedw3_status_sc, set_cqedw3_status_sc: 120, 113;
    from into StatusCodeType, cqedw3_status, set_cqedw3_status_sct: 123, 121;
    u16, cqedw3_status_sct, set_cqedw3_status_crd: 125, 124;
    u16, cqedw3_status_m, set_cqedw3_status_m: 126;
    u16, cqedw3_status_dnr, set_cqedw3_status_dnr: 127;
}

impl AdminCommandResponseHeader<[u8; 16]> {
    fn new() -> Self {
        Self([0; 16])
    }
}

bitfield! {
    struct AdminIdentifyRequest([u8]);
    impl Debug;
    u8;
    u32, dofst, set_dofst: 191, 160;
    u32, dlen, set_dlen: 223, 192;
    from into ControllerOrNamespaceStructure, sqedw10_cns, set_sqedw10_cns: 295, 288;
    sqedw10_rsvd, _: 307, 300;
    u16, sqedw10_cntid, set_sqedw10_cntid: 323, 308;
    u16, sqedw11_cnssid, set_sqedw11_cnssid: 339, 324;
    sqedw11_rsvd, _: 347, 340;
    sqedw11_csi, set_sqedw11_csi: 355, 348;
    sqedw14_uidx, set_sqedw14_uidx: 426, 420;
}

impl AdminIdentifyRequest<[u8; 60]> {
    fn extract(buf: &[u8]) -> Option<(Self, &[u8])> {
        if let Some((head, tail)) = buf.split_at_checked(60) {
            return Some((AdminIdentifyRequest(head.try_into().unwrap()), tail));
        }
        None
    }
}

bitfield! {
    struct AdminIdentifyControllerResponse([u8]);
    u8;
    u16, vid, set_vid: 15, 0;
    u16, ssvid, set_ssvid: 31, 16;
    sn, set_sn: 39, 32, 20;
    mn, set_mn: 199, 192, 20;
    fr, set_fr: 519, 512, 8;
}

impl AdminIdentifyControllerResponse<[u8; 4096]> {
    fn new() -> Self {
        Self([0; 4096])
    }
}

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

    if let Err(e) = resp
        .send_vectored(MCTP_TYPE_NVME, true, bufs.as_slice())
        .await
    {
        debug!("Failed to send NVMe-MI response: {:?}", e);
    }
}

impl RequestHandler for MessageHeader<[u8; 3]> {
    async fn handle<A: AsyncRespChannel>(
        self,
        mep: &mut super::ManagementEndpoint,
        subsys: &mut super::Subsystem,
        rest: &[u8],
        resp: &mut A,
    ) -> Result<(), ResponseStatus> {
        debug!("{:x?}", self);
        // TODO: Command and Feature Lockdown handling
        // TODO: Handle subsystem reset, section 8.1, v2.0
        match self.nmimt() {
            MessageType::NVMeMICommand => {
                let Some((ch, rest)) = NVMeMICommandHeader::extract(rest) else {
                    debug!("Message too short to extract NVMeMICommandHeader");
                    return Err(ResponseStatus::InvalidCommandSize);
                };

                ch.handle(mep, subsys, rest, resp).await
            }
            MessageType::NVMeAdminCommand => {
                let Some((ch, rest)) = AdminCommandRequestHeader::extract(rest) else {
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

impl RequestHandler for NVMeMICommandHeader<[u8; 4]> {
    async fn handle<A: AsyncRespChannel>(
        self,
        mep: &mut super::ManagementEndpoint,
        subsys: &mut super::Subsystem,
        rest: &[u8],
        resp: &mut A,
    ) -> Result<(), ResponseStatus> {
        debug!("{:x?}", self);
        match self.opcode() {
            CommandOpcode::ReadNVMeMIDataStructure => {
                let Some((ds, rest)) = NVMeMIDataStructure::extract(rest) else {
                    debug!("Message too short to extract NVMeMIDataStructure");
                    return Err(ResponseStatus::InvalidCommandSize);
                };
                ds.handle(mep, subsys, rest, resp).await
            }
            CommandOpcode::NVMSubsystemHealthStatusPoll => {
                // 5.6, Figure 108, v2.0
                let Some((shsp, rest)) = NVMSubsystemHealthStatusPoll::extract(rest) else {
                    debug!("Message too short to extract NVMSubsystemHealthStatusPoll");
                    return Err(ResponseStatus::InvalidCommandSize);
                };

                if !rest.is_empty() {
                    debug!("Lost coherence decoding {:?}", self.opcode());
                    return Err(ResponseStatus::InvalidCommandSize);
                }

                let mut mh = MessageHeader::new();
                mh.set_ror(true);
                mh.set_nmimt(MessageType::NVMeMICommand);

                let mut mr = NVMeManagementResponse::new();
                mr.set_status(ResponseStatus::Success);

                let Some(ctlr) = subsys.ctlrs.first() else {
                    panic!("An NVMe Subsystem requires at least one controller");
                };
                let mut nvmshds = NVMSubsystemHealthDataStructure::new();

                let Some(port) = subsys.ports.iter().find(|p| p.id == ctlr.port) else {
                    panic!(
                        "Inconsistent port association for controller {:?}: {:?}",
                        ctlr.id, ctlr.port
                    );
                };

                let PortType::PCIe(pprt) = port.typ else {
                    panic!("Non-PCIe port associated with controller {:?}", ctlr.id);
                };

                nvmshds.set_nss_p0la(pprt.cls != PCIeLinkSpeed::Inactive);
                nvmshds.set_nss_p1la(false);
                nvmshds.set_nss_rnr(subsys.health.nss.rnr);
                nvmshds.set_nss_df(subsys.health.nss.df);
                nvmshds.set_nss_sfm(subsys.health.nss.sfm);
                nvmshds.set_nss_atf(subsys.health.nss.atf);

                // Derive ASCBT from spare vs capacity
                assert!(!subsys.ctlrs.is_empty());
                // Implementation-specific strategy is to pick the first controller.
                let ctlr = &subsys.ctlrs[0];
                if ctlr.spare > ctlr.capacity {
                    debug!(
                        "spare capacity {} exceeds drive capacity {}",
                        ctlr.spare, ctlr.capacity
                    );
                    return Err(ResponseStatus::InternalError);
                }
                let nominal = (100 * ctlr.spare / ctlr.capacity) < ctlr.spare_range.lower as u64;
                nvmshds.set_sw_ascbt_n(!nominal);

                // Derive TTC from operating range comparison
                assert!(ctlr.temp_range.kind == UnitKind::Kelvin);
                let nominal =
                    ctlr.temp_range.lower <= ctlr.temp && ctlr.temp <= ctlr.temp_range.upper;
                nvmshds.set_sw_ttc_n(!nominal);

                nvmshds.set_sw_ndr_n(!subsys.health.nss.rd);
                nvmshds.set_sw_amro_n(!ctlr.ro);
                nvmshds.set_sw_vmbf_n(!false);
                nvmshds.set_sw_pmrro_n(!false);

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

                // Encode the transformed temperature value
                debug_assert!(ctemp <= u8::MAX.into());
                nvmshds.set_ctemp(ctemp as u8);

                // Derive PLDU from write age and expected lifespan
                let pldu = core::cmp::min(255, 100 * ctlr.write_age / ctlr.write_lifespan);
                nvmshds.set_pldu(pldu as u8);

                let mut ccs = CompositeControllerStatusDataStructure::new();
                ccs.set_ccsf_rdy(mep.ccsf.rdy);
                ccs.set_ccsf_cfs(mep.ccsf.cfs);
                ccs.set_ccsf_shst(mep.ccsf.shst);
                ccs.set_ccsf_nssro(mep.ccsf.nssro);
                ccs.set_ccsf_ceco(mep.ccsf.ceco);
                ccs.set_ccsf_nac(mep.ccsf.nac);
                ccs.set_ccsf_fa(mep.ccsf.fa);
                ccs.set_ccsf_csts(mep.ccsf.csts);
                ccs.set_ccsf_ctemp(mep.ccsf.ctemp);
                ccs.set_ccsf_pdlu(mep.ccsf.pdlu);
                ccs.set_ccsf_spare(mep.ccsf.spare);
                ccs.set_ccsf_cwarn(mep.ccsf.cwarn);
                ccs.set_ccsf_tcida(mep.ccsf.tcida);

                // See Figure 106, NVMe MI v2.0
                if shsp.cs() {
                    mep.ccsf = super::CompositeControllerStatusFlags::default();
                }

                let pad: [u8; 2] = [0, 0];

                send_response(resp, &[&mh.0, &mr.0, &nvmshds.0, &ccs.0, &pad]).await;
                Ok(())
            }
            _ => {
                debug!("Unimplemented OPCODE: {:?}", self.opcode());
                Err(ResponseStatus::InternalError)
            }
        }
    }
}

impl RequestHandler for NVMeMIDataStructure<[u8; 8]> {
    async fn handle<A: AsyncRespChannel>(
        self,
        _mep: &mut super::ManagementEndpoint,
        subsys: &mut super::Subsystem,
        rest: &[u8],
        resp: &mut A,
    ) -> Result<(), ResponseStatus> {
        debug!("{:x?}", self);

        if !rest.is_empty() {
            debug!("Lost coherence decoding NVMe-MI message");
            return Err(ResponseStatus::InvalidCommandInputDataSize);
        }

        let mut mh = MessageHeader::new();
        mh.set_ror(true);
        mh.set_nmimt(MessageType::NVMeMICommand);

        let mut dsmr = NVMeMIDataStructureManagementResponse::new();

        match self.dtyp() {
            NVMeMIDataStructureType::NVMSubsystemInformation => {
                let mut nvmsi = NVMSubsystemInformation::new();
                assert!(!subsys.ports.is_empty(), "Need at least one port defined");
                // See 5.7.1, 5.1.1 of v2.0
                assert!(
                    subsys.ports.len() < u8::MAX as usize,
                    "Too many ports defined: {}",
                    subsys.ports.len()
                );
                // See 5.7.1 of v2.0
                nvmsi.set_nump(subsys.ports.len() as u8 - 1);
                nvmsi.set_mjr(subsys.mi.mjr);
                nvmsi.set_mnr(subsys.mi.mnr);
                nvmsi.set_nnsc_sre(subsys.caps.sre);

                debug_assert!(nvmsi.0.len() <= u16::MAX as usize);
                dsmr.set_rdl((nvmsi.0.len() as u16).to_le());
                dsmr.set_status(ResponseStatus::Success);

                send_response(resp, &[&mh.0, &dsmr.0, &nvmsi.0]).await;
                Ok(())
            }
            NVMeMIDataStructureType::PortInformation => {
                let Some(port) = subsys.ports.iter().find(|p| p.id.0 == self.portid()) else {
                    // TODO: Propagate PEL
                    return Err(ResponseStatus::InvalidParameter);
                };
                let mut pi = PortInformation::new();
                pi.set_prttyp(port.typ.id());
                pi.set_prtcap_aems(port.caps.aems);
                pi.set_prtcap_ciaps(port.caps.ciaps);
                pi.set_mmtus(port.mmtus.to_le());
                pi.set_mebs(port.mebs.to_le());

                match port.typ {
                    PortType::PCIe(pprt) => {
                        let mut ppd = PCIePortData::new();
                        ppd.set_pciemps(pprt.mps.into());
                        ppd.set_pcieslsv(0x3fu8);
                        ppd.set_pciecls(pprt.cls.into());
                        ppd.set_pciemlw(pprt.mlw.into());
                        ppd.set_pcienlw(pprt.nlw.into());
                        ppd.set_pciepn(port.id.0);

                        debug_assert!(pi.0.len() + ppd.0.len() <= u16::MAX as usize);
                        dsmr.set_rdl(((pi.0.len() + ppd.0.len()) as u16).to_le());
                        dsmr.set_status(ResponseStatus::Success);

                        send_response(resp, &[&mh.0, &dsmr.0, &pi.0, &ppd.0]).await;
                        Ok(())
                    }
                    PortType::TwoWire(twprt) => {
                        let mut twpd = TwoWirePortData::new();
                        twpd.set_cvpdaddr(twprt.cvpdaddr);
                        twpd.set_mvpdfreq(twprt.mvpdfreq.into());
                        twpd.set_cmeaddr(twprt.cmeaddr);
                        twpd.set_twprt_i3csprt(twprt.i3csprt);
                        twpd.set_twprt_msmbfreq(twprt.msmbfreq.into());
                        twpd.set_nvmebm_nvmebms(twprt.nvmebms);

                        debug_assert!((pi.0.len() + twpd.0.len()) <= u16::MAX as usize);
                        dsmr.set_rdl(((pi.0.len() + twpd.0.len()) as u16).to_le());
                        dsmr.set_status(ResponseStatus::Success);

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
                let mut cl = ControllerList::new();
                assert!(
                    subsys.ctlrs.len() <= 2047,
                    "Invalid number of controllers in drive model: {}",
                    subsys.ctlrs.len()
                );

                let mut numids: usize = 0;
                for (idx, ctlr) in subsys
                    .ctlrs
                    .iter()
                    // Section 5.7.3, NVMe MI v2.0
                    .filter(|c| c.id.0 >= self.ctrlid())
                    .enumerate()
                {
                    cl.set_ids(idx, ctlr.id.0.to_le());
                    numids += 1;
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
                debug_assert!(numids < (u16::MAX as usize / 2));
                cl.set_numids(numids as u16);
                let len = core::mem::size_of::<u16>() * (1 + numids);
                let rdl = len as u16;
                dsmr.set_rdl(rdl.to_le());
                dsmr.set_status(ResponseStatus::Success);

                send_response(resp, &[&mh.0, &dsmr.0, &cl.0[..len]]).await;
                Ok(())
            }
            NVMeMIDataStructureType::ControllerInformation => {
                let Some(ctlr) = subsys.ctlrs.iter().find(|c| c.id.0 == self.ctrlid()) else {
                    debug!("Unknown controller ID: {:?}", self.ctrlid());
                    return Err(ResponseStatus::InvalidParameter);
                };
                let mut ci = ControllerInformation::new();
                ci.set_portid(ctlr.port.0);
                ci.set_prii_pcieriv(true);

                let Some(port) = subsys.ports.iter().find(|p| p.id == ctlr.port) else {
                    panic!(
                        "Inconsistent port association for controller {:?}: {:?}",
                        ctlr.id, ctlr.port
                    );
                };

                let PortType::PCIe(pprt) = port.typ else {
                    panic!("Non-PCIe port associated with controller {:?}", ctlr.id);
                };

                ci.set_pri_pcifn(pprt.f.to_le());
                ci.set_pri_pcidn(pprt.d.to_le());
                ci.set_pri_pcibn(pprt.b.to_le());
                ci.set_pcivid(pprt.vid.to_le());
                ci.set_pcidid(pprt.did.to_le());
                ci.set_pcisvid(pprt.svid.to_le());
                ci.set_pcisdid(pprt.sdid.to_le());
                ci.set_pciesn(pprt.seg);

                debug_assert!(ci.0.len() < u16::MAX as usize);
                dsmr.set_rdl((ci.0.len() as u16).to_le());
                dsmr.set_status(ResponseStatus::Success);

                send_response(resp, &[&mh.0, &dsmr.0, &ci.0]).await;
                Ok(())
            }
            _ => {
                debug!("Unimplemented DTYP: {:?}", self.dtyp());
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

impl RequestHandler for AdminCommandRequestHeader<[u8; 4]> {
    async fn handle<A: AsyncRespChannel>(
        self,
        mep: &mut super::ManagementEndpoint,
        subsys: &mut super::Subsystem,
        rest: &[u8],
        resp: &mut A,
    ) -> Result<(), ResponseStatus> {
        debug!("{:x?}", self);

        if self.cflgs_ish() {
            todo!("Support ignore shutdown state");
        }

        let opcode = self.opcode();
        match opcode {
            AdminCommandOpcode::Identify => {
                let Some((id, rest)) = AdminIdentifyRequest::extract(rest) else {
                    debug!("Message too short to extract AdminIdentify request");
                    return Err(ResponseStatus::InvalidCommandSize);
                };
                id.handle(mep, subsys, rest, resp).await
            }
            opcode if MI_PROHIBITED_ADMIN_COMMANDS.contains(&opcode) => {
                debug!("Prohibited MI admin command opcode: {:?}", opcode);
                Err(ResponseStatus::InvalidCommandOpcode)
            }
            _ => {
                debug!("Unimplemented OPCODE: {:?}", self.opcode());
                Err(ResponseStatus::InternalError)
            }
        }
    }
}

impl AdminIdentifyRequest<[u8; 60]> {
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

        let dofst = self.dofst() as usize;
        if dofst & 3 != 0 {
            debug!("Unnatural DOFST value: {:?}", dofst);
            return Err(ResponseStatus::InvalidParameter);
        }

        if dofst >= data.len() {
            debug!(
                "DOFST value exceeds unconstrained response length: {:?}",
                dofst
            );
            return Err(ResponseStatus::InvalidParameter);
        }

        let dlen = self.dlen() as usize;

        if dlen & 3 != 0 {
            debug!("Unnatural DLEN value: {:?}", dlen);
            return Err(ResponseStatus::InvalidParameter);
        }

        if dlen > 4096 {
            debug!("DLEN too large: {:?}", dlen);
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
            debug!("DLEN cleared for command with data response: {:?}", dlen);
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

impl RequestHandler for AdminIdentifyRequest<[u8; 60]> {
    async fn handle<A: AsyncRespChannel>(
        self,
        _mep: &mut super::ManagementEndpoint,
        subsys: &mut super::Subsystem,
        rest: &[u8],
        resp: &mut A,
    ) -> Result<(), ResponseStatus> {
        debug!("{:x?}", self);

        if !rest.is_empty() {
            debug!("Invalid request size for Admin Identify");
            return Err(ResponseStatus::InvalidCommandSize);
        }

        let mut mh = MessageHeader::new();
        mh.set_ror(true);
        mh.set_nmimt(MessageType::NVMeAdminCommand);

        let mut acrh = AdminCommandResponseHeader::new();
        acrh.set_status(ResponseStatus::Success);
        acrh.set_cqedw3_p(true);
        acrh.set_cqedw3_status_sc(GenericCommandStatus::SuccessfulCompletion);
        acrh.set_cqedw3_status_sct(StatusCodeType::GenericCommandStatus);

        /* CRD and DNR must be clear if there is no error */
        acrh.set_cqedw3_status_crd(0);
        acrh.set_cqedw3_status_m(false);
        acrh.set_cqedw3_status_dnr(false);

        match self.sqedw10_cns() {
            ControllerOrNamespaceStructure::IdentifyController => {
                let Some(ctlr) = subsys.ctlrs.iter().find(|c| c.id.0 == self.sqedw10_cntid())
                else {
                    // TODO: Set PEL
                    return Err(ResponseStatus::InvalidParameter);
                };

                let mut aicr = AdminIdentifyControllerResponse::new();

                let Some(port) = subsys.ports.iter().find(|p| p.id == ctlr.port) else {
                    panic!(
                        "Inconsistent port association for controller {:?}: {:?}",
                        ctlr.id, ctlr.port
                    );
                };

                let PortType::PCIe(pprt) = port.typ else {
                    panic!("Non-PCIe port associated with controller {:?}", ctlr.id);
                };

                aicr.set_vid(pprt.vid);
                aicr.set_ssvid(pprt.svid);
                for (idx, val) in subsys.sn.bytes().enumerate().filter(|args| args.0 < 20) {
                    aicr.set_sn(idx, val);
                }
                for (idx, val) in subsys.mn.bytes().enumerate().filter(|args| args.0 < 20) {
                    aicr.set_mn(idx, val);
                }
                for (idx, val) in subsys.fr.bytes().enumerate().filter(|args| args.0 < 8) {
                    aicr.set_fr(idx, val);
                }
                // TODO: "Set CNTRLTYPE field for Base v1.4 compliance: Bytes 111, Figure 132, MI v2.0"
                // TODO: Set NVMSR fields for compliance; 1.4, MI v2.0"
                self.send_constrained_response(resp, &[&mh.0, &acrh.0], &aicr.0)
                    .await
            }
            ControllerOrNamespaceStructure::NVMSubsystemControllerList => {
                let mut cl = ControllerList::new();
                assert!(
                    subsys.ctlrs.len() <= 2047,
                    "Invalid number of controllers in drive model: {}",
                    subsys.ctlrs.len()
                );
                cl.set_numids((subsys.ctlrs.len() as u16).to_le());
                for (idx, ctlr) in subsys
                    .ctlrs
                    .iter()
                    .enumerate()
                    .filter(|args| args.1.id.0 >= self.sqedw10_cntid())
                {
                    cl.set_ids(idx, ctlr.id.0.to_le());
                }
                self.send_constrained_response(resp, &[&mh.0, &acrh.0], &cl.0)
                    .await
            }
            _ => {
                debug!("Unimplemented CNS: {:?}", self.sqedw10_cns());
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
        ic: bool,
        mut resp: A,
    ) {
        if !ic {
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

        let Some((mh, rest)) = MessageHeader::extract(msg) else {
            debug!("Message too short to extract NVMeMIMessageHeader");
            return;
        };

        if mh.csi() {
            todo!("Support second command slot");
        }

        if mh.ror() {
            debug!("NVMe-MI message was not a request: {:?}", mh.ror());
            return;
        }

        if let Err(status) = mh.handle(self, subsys, rest, &mut resp).await {
            let mut digest = ISCSI.digest();
            digest.update(&[0x80 | 0x04]);

            let mut mh = MessageHeader::new();
            mh.set_ror(true);
            mh.set_nmimt(mh.nmimt());
            digest.update(&mh.0);

            let ss: [u8; 4] = [status.into(), 0, 0, 0];
            digest.update(&ss);

            let icv = digest.finalize().to_le_bytes();
            let respv = [mh.0.as_slice(), ss.as_slice(), icv.as_slice()];
            if let Err(e) = resp.send_vectored(MCTP_TYPE_NVME, true, &respv).await {
                debug!("Failed to send NVMe-MI error response: {e:?}");
            }
        }
    }
}
