// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2025 Code Construct
 */
pub mod mi;

use hmac::Mac;
use uuid::Uuid;

const MAX_CONTROLLERS: usize = 2;
const MAX_NAMESPACES: usize = 2;
const MAX_PORTS: usize = 2;
const MAX_NIDTS: usize = 2;

#[allow(dead_code)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
enum PCIePayloadSize {
    Payload128B = 0x00,
    Payload256B = 0x01,
    Payload512B = 0x02,
    Payload1KB = 0x03,
    Payload2KB = 0x04,
    Payload4KB = 0x05,
}

impl From<PCIePayloadSize> for u8 {
    fn from(pps: PCIePayloadSize) -> Self {
        pps as Self
    }
}

#[allow(dead_code)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
enum PCIeLinkSpeed {
    Inactive = 0x00,
    GTS2P5 = 0x01,
    GTS5 = 0x02,
    GTS8 = 0x03,
    GTS16 = 0x04,
    GTS32 = 0x05,
    GTS64 = 0x06,
}

impl From<PCIeLinkSpeed> for u8 {
    fn from(pls: PCIeLinkSpeed) -> Self {
        pls as Self
    }
}

#[allow(dead_code)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
enum PCIeLinkWidth {
    X1 = 1,
    X2 = 2,
    X4 = 4,
    X8 = 8,
    X12 = 12,
    X16 = 16,
    X32 = 32,
}

impl From<PCIeLinkWidth> for u8 {
    fn from(plw: PCIeLinkWidth) -> Self {
        plw as Self
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PCIePort {
    b: u16,
    d: u16,
    f: u16,
    seg: u8,
    mps: PCIePayloadSize,
    cls: PCIeLinkSpeed,
    mlw: PCIeLinkWidth,
    nlw: PCIeLinkWidth,
}

impl PCIePort {
    pub fn new() -> Self {
        Self {
            b: 0,
            d: 0,
            f: 0,
            seg: 0,
            mps: PCIePayloadSize::Payload128B,
            cls: PCIeLinkSpeed::GTS2P5,
            mlw: PCIeLinkWidth::X2,
            nlw: PCIeLinkWidth::X1,
        }
    }
}

impl Default for PCIePort {
    fn default() -> Self {
        Self::new()
    }
}

#[allow(dead_code)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SMBusFrequency {
    FreqNotSupported,
    Freq100kHz,
    Freq400kHz,
    Freq1MHz,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TwoWirePort {
    cvpdaddr: u8,
    mvpdfreq: SMBusFrequency,
    cmeaddr: u8,
    i3csprt: bool,
    msmbfreq: SMBusFrequency,
    nvmebms: bool,
}

impl TwoWirePort {
    pub fn new() -> Self {
        Self {
            cvpdaddr: 0,
            mvpdfreq: SMBusFrequency::FreqNotSupported,
            cmeaddr: 0x1d,
            i3csprt: false,
            msmbfreq: SMBusFrequency::Freq100kHz,
            nvmebms: false,
        }
    }
}

impl Default for TwoWirePort {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum PortType {
    Inactive = 0x00,
    PCIe(PCIePort) = 0x01,
    TwoWire(TwoWirePort) = 0x02,
}

impl PortType {
    fn id(&self) -> u8 {
        // https://doc.rust-lang.org/reference/items/enumerations.html#r-items.enum.discriminant.access-memory
        unsafe { *(self as *const Self as *const u8) }
    }
}

#[derive(Clone, Copy, Debug)]
struct PortCapabilities {
    ciaps: bool,
    aems: bool,
}

impl PortCapabilities {
    fn new() -> Self {
        PortCapabilities {
            ciaps: false,
            aems: false,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Port {
    id: PortId,
    typ: PortType,
    caps: PortCapabilities,
    mmtus: u16,
    mebs: u32,
}

impl Port {
    fn new(id: PortId, typ: PortType) -> Self {
        Self {
            id,
            typ,
            caps: PortCapabilities::new(),
            mmtus: 64,
            mebs: 0,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct PortId(u8);

// XXX: Is the bunch-of-bools approach helpful in practice?
#[derive(Debug, Default)]
pub struct CompositeControllerStatusFlags {
    rdy: bool,
    cfs: bool,
    shst: bool,
    nssro: bool,
    ceco: bool,
    nac: bool,
    fa: bool,
    csts: bool,
    ctemp: bool,
    pdlu: bool,
    spare: bool,
    cwarn: bool,
    tcida: bool,
}

#[derive(Debug)]
pub struct ManagementEndpoint {
    #[expect(dead_code)]
    port: PortId,
    ccsf: CompositeControllerStatusFlags,
}

impl ManagementEndpoint {
    pub fn new(port: PortId) -> Self {
        Self {
            port,
            ccsf: CompositeControllerStatusFlags::default(),
        }
    }
}

#[derive(Debug)]
struct MICapability {
    mjr: u8,
    mnr: u8,
}

impl MICapability {
    fn new() -> Self {
        Self { mjr: 1, mnr: 2 }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum UnitKind {
    Kelvin,
    Percent,
}

#[derive(Debug)]
pub enum Temperature<T> {
    Kelvin(T),
    Celcius(T),
}

#[derive(Debug)]
struct OperatingRange {
    kind: UnitKind,
    lower: u16,
    upper: u16,
}

impl OperatingRange {
    fn new(kind: UnitKind, lower: u16, upper: u16) -> Self {
        Self { kind, lower, upper }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, PartialOrd)]
pub struct ControllerId(u16);

#[derive(Debug)]
pub struct SecondaryController {
    #[expect(dead_code)]
    id: ControllerId,
}

#[derive(Debug)]
pub struct Controller {
    id: ControllerId,
    port: PortId,
    secondaries: heapless::Vec<SecondaryController, 0>,
    active_ns: heapless::Vec<NamespaceId, MAX_NAMESPACES>,
    temp: u16,
    temp_range: OperatingRange,
    capacity: u64,
    spare: u64,
    spare_range: OperatingRange,
    write_age: u64,
    write_lifespan: u64,
    ro: bool,
}

impl Controller {
    fn new(id: ControllerId, port: PortId) -> Self {
        Self {
            id,
            port,
            secondaries: heapless::Vec::new(),
            active_ns: heapless::Vec::new(),
            temp: 293,
            temp_range: OperatingRange::new(UnitKind::Kelvin, 213, 400),
            capacity: 100,
            spare: 100,
            spare_range: OperatingRange::new(UnitKind::Percent, 5, 100),
            write_age: 38,
            write_lifespan: 100,
            ro: false,
        }
    }

    pub fn set_temperature(&mut self, temp: Temperature<u16>) {
        let Temperature::Kelvin(k) = temp else {
            todo!("Support units other than kelvin");
        };

        self.temp = k;
    }

    pub fn attach_namespace(&mut self, nsid: NamespaceId) -> Result<(), NamespaceId> {
        self.active_ns.push(nsid)
    }
}

#[derive(Debug)]
struct SubsystemCapabilities {
    sre: bool,
}

impl SubsystemCapabilities {
    fn new() -> Self {
        Self { sre: false }
    }
}

#[derive(Debug)]
struct NVMSubsystemStatus {
    atf: bool,
    sfm: bool,
    df: bool,
    rnr: bool,
    rd: bool,
}

impl NVMSubsystemStatus {
    fn new() -> Self {
        Self {
            atf: false,
            sfm: false,
            df: true,
            rnr: true,
            rd: false,
        }
    }
}

#[derive(Debug)]
struct SubsystemHealth {
    nss: NVMSubsystemStatus,
}

impl SubsystemHealth {
    fn new() -> Self {
        Self {
            nss: NVMSubsystemStatus::new(),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum CommandSetIdentifier {
    NVMCommandSet,
    KeyValueCommandSet,
    ZonedNamespaceCommandSet,
    SubsystemLocalMemoryCommandSet,
    ComputationalProgramsCommandSet,
}

#[derive(Clone, Copy, Debug)]
pub enum NamespaceIdentifierType {
    IEUID([u8; 8]),
    NGUID([u8; 16]),
    NUUID(Uuid),
    CSI(CommandSetIdentifier),
}

#[derive(Debug)]
pub struct Namespace {
    size: u64,
    capacity: u64,
    used: u64,
    block_order: u8,
    nids: [NamespaceIdentifierType; 2],
}

// NSID
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NamespaceId(u32);

impl Namespace {
    fn generate_uuid(seed: &[u8], nsid: NamespaceId) -> Uuid {
        let mut hasher = hmac::Hmac::<sha2::Sha256>::new_from_slice(seed).unwrap();
        hasher.update(&nsid.0.to_be_bytes());
        let digest = hasher.finalize().into_bytes();
        let digest: [u8; 16] = digest[..16].try_into().unwrap();
        uuid::Builder::from_random_bytes(digest).into_uuid()
    }

    pub fn new(id: Uuid, capacity: u64) -> Self {
        Self {
            size: capacity,
            capacity,
            used: 0,
            block_order: 9,
            nids: [
                NamespaceIdentifierType::NUUID(id),
                NamespaceIdentifierType::CSI(CommandSetIdentifier::NVMCommandSet),
            ],
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct SubsystemInfo {
    pub pci_vid: u16,
    pub pci_did: u16,
    pub pci_svid: u16,
    pub pci_sdid: u16,
    pub ieee_oui: [u8; 3],
    pub instance: [u8; 16],
}

impl SubsystemInfo {
    fn acquire_source_date_epoch() -> u64 {
        env!("SOURCE_DATE_EPOCH").parse::<u64>().unwrap_or(0)
    }

    fn acquire_ieee_oui() -> [u8; 3] {
        let mut oui = [0u8; 3];
        // ac-de-48 is allocated as private, used as the example value in the
        // IEEE Guidelines for use of EUI, OUI, and CID documentation
        for (idx, val) in option_env!("NVME_MI_DEV_IEEE_OUI")
            .unwrap_or("ac-de-48")
            .split('-')
            .take(oui.len())
            .map(|v| {
                u8::from_str_radix(v, 16).expect(
                    "NVME_MI_DEV_IEEE_OUI must be set in the IEEE RA hexadecimal representation",
                )
            })
            .enumerate()
        {
            oui[idx] = val;
        }
        oui
    }

    fn acquire_pci_ids() -> (u16, u16, u16, u16) {
        // ffff is the value returned by an aborted access
        let vid = u16::from_str_radix(option_env!("NVME_MI_DEV_PCI_VID").unwrap_or("ffff"), 16)
            .expect("NVME_MI_DEV_PCI_VID must be set to a 16-bit value in base-16 representation");
        let did = u16::from_str_radix(option_env!("NVME_MI_DEV_PCI_DID").unwrap_or("ffff"), 16)
            .expect("NVME_MI_DEV_PCI_DID must be set to a 16-bit value in base-16 representation");
        let svid = u16::from_str_radix(option_env!("NVME_MI_DEV_PCI_SVID").unwrap_or("ffff"), 16)
            .expect("NVME_MI_DEV_PCI_SVID must be set to a 16-bit value in base-16 representation");
        let sdid = u16::from_str_radix(option_env!("NVME_MI_DEV_PCI_SDID").unwrap_or("ffff"), 16)
            .expect("NVME_MI_DEV_PCI_SDID must be set to a 16-bit value in base-16 representation");
        (vid, did, svid, sdid)
    }

    pub fn invalid() -> Self {
        Self {
            pci_vid: 0xffff,
            pci_did: 0xffff,
            pci_svid: 0xffff,
            pci_sdid: 0xffff,
            ieee_oui: [0xac, 0xde, 0x48],
            instance: [0; 16],
        }
    }

    pub fn environment() -> Self {
        let (vid, did, svid, sdid) = SubsystemInfo::acquire_pci_ids();
        let sde = SubsystemInfo::acquire_source_date_epoch().to_le_bytes();
        let mut instance = [0u8; 16];
        instance[..sde.len()].copy_from_slice(&sde);
        Self {
            pci_vid: vid,
            pci_did: did,
            pci_svid: svid,
            pci_sdid: sdid,
            ieee_oui: SubsystemInfo::acquire_ieee_oui(),
            instance,
        }
    }
}

#[derive(Debug)]
pub struct Subsystem {
    info: SubsystemInfo,
    caps: SubsystemCapabilities,
    ports: heapless::Vec<Port, MAX_PORTS>,
    ctlrs: heapless::Vec<Controller, MAX_CONTROLLERS>,
    nss: heapless::Vec<Namespace, MAX_NAMESPACES>,
    health: SubsystemHealth,
    mi: MICapability,
    sn: &'static str,
    mn: &'static str,
    fr: &'static str,
}

impl Subsystem {
    pub fn new(info: SubsystemInfo) -> Self {
        Subsystem {
            info,
            caps: SubsystemCapabilities::new(),
            ports: heapless::Vec::new(),
            ctlrs: heapless::Vec::new(),
            nss: heapless::Vec::new(),
            health: SubsystemHealth::new(),
            mi: MICapability::new(),
            sn: "1000",
            mn: "MIDEV",
            fr: "00.00.01",
        }
    }

    pub fn add_port(&mut self, typ: PortType) -> Result<PortId, Port> {
        debug_assert!(self.ctlrs.len() <= u8::MAX.into());
        let p = Port::new(PortId(self.ports.len() as u8), typ);
        self.ports.push(p).map(|_p| self.ports.last().unwrap().id)
    }

    pub fn add_controller(&mut self, port: PortId) -> Result<ControllerId, Controller> {
        debug_assert!(self.ctlrs.len() <= u16::MAX.into());
        let c = Controller::new(ControllerId(self.ctlrs.len() as u16), port);
        self.ctlrs.push(c).map(|_c| self.ctlrs.last().unwrap().id)
    }

    pub fn controller_mut(&mut self, id: ControllerId) -> &mut Controller {
        self.ctlrs
            .get_mut(id.0 as usize)
            .expect("Invalid ControllerId provided")
    }

    pub fn add_namespace(&mut self, capacity: u64) -> Result<NamespaceId, u8> {
        debug_assert!(self.nss.len() <= u32::MAX.try_into().unwrap());
        let nsid = NamespaceId((self.nss.len() + 1).try_into().unwrap());
        let ns = Namespace::new(
            Namespace::generate_uuid(&self.info.instance, nsid),
            capacity,
        );
        match self.nss.push(ns) {
            Ok(_) => Ok(nsid),
            Err(_) => Err(0x16), // Namespace Identifier Unavailable
        }
    }
}
