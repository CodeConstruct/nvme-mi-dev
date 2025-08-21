// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2025 Code Construct
 */
#![no_std]

use deku::{DekuContainerWrite, DekuError};
use flagset::FlagSet;
use hmac::Mac;
use log::debug;
use mctp::AsyncRespChannel;
use nvme::{
    AdminGetLogPageLidRequestType, LidSupportedAndEffectsFlags, LogPageAttributes,
    mi::ResponseStatus,
};
use uuid::Uuid;

pub mod nvme;
mod wire;

extern crate deku;

const MAX_CONTROLLERS: usize = 2;
const MAX_NAMESPACES: usize = 4;
const MAX_PORTS: usize = 2;
const MAX_NIDTS: usize = 2;

#[derive(Debug)]
pub enum CommandEffect {
    SetMtu {
        port_id: PortId,
        mtus: usize,
    },
    SetSmbusFreq {
        port_id: PortId,
        freq: nvme::mi::SmbusFrequency,
    },
}

#[derive(Debug)]
pub enum CommandEffectError {
    Unsupported,
    InternalError,
}

trait RequestHandler {
    type Ctx;

    async fn handle<A, C>(
        &self,
        ctx: &Self::Ctx,
        mep: &mut crate::ManagementEndpoint,
        subsys: &mut crate::Subsystem,
        rest: &[u8],
        resp: &mut C,
        app: A,
    ) -> Result<(), ResponseStatus>
    where
        A: AsyncFnMut(CommandEffect) -> Result<(), CommandEffectError>,
        C: AsyncRespChannel;
}

trait Encode<const S: usize>: DekuContainerWrite {
    fn encode(&self) -> Result<([u8; S], usize), DekuError> {
        let mut buf = [0u8; S];
        self.to_slice(&mut buf).map(|len| (buf, len))
    }
}

/// # Safety
///
/// Must only be implemented for enums with attribute #[repr(T)]
unsafe trait Discriminant<T: Copy> {
    fn id(&self) -> T {
        // https://doc.rust-lang.org/reference/items/enumerations.html#r-items.enum.discriminant.access-memory
        unsafe { *(self as *const Self as *const T) }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PciePort {
    b: u16,
    d: u16,
    f: u16,
    seg: u8,
    mps: nvme::mi::PciePayloadSize,
    cls: nvme::mi::PcieLinkSpeed,
    mlw: nvme::mi::PcieLinkWidth,
    nlw: nvme::mi::PcieLinkWidth,
}

impl PciePort {
    pub fn new() -> Self {
        Self {
            b: 0,
            d: 0,
            f: 0,
            seg: 0,
            mps: nvme::mi::PciePayloadSize::Payload128B,
            cls: nvme::mi::PcieLinkSpeed::Gts2p5,
            mlw: nvme::mi::PcieLinkWidth::X2,
            nlw: nvme::mi::PcieLinkWidth::X1,
        }
    }
}

impl Default for PciePort {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TwoWirePort {
    // MI v2.0, 5.7.2, Figure 116
    cvpdaddr: u8,
    mvpdfreq: nvme::mi::SmbusFrequency,
    cmeaddr: u8,
    i3csprt: bool,
    msmbfreq: nvme::mi::SmbusFrequency,
    nvmebms: bool,
    // Local state
    smbfreq: nvme::mi::SmbusFrequency,
}

impl TwoWirePort {
    pub fn new() -> Self {
        Self {
            cvpdaddr: 0,
            mvpdfreq: nvme::mi::SmbusFrequency::FreqNotSupported,
            cmeaddr: 0x1d,
            i3csprt: false,
            msmbfreq: nvme::mi::SmbusFrequency::Freq400Khz,
            nvmebms: false,
            smbfreq: nvme::mi::SmbusFrequency::Freq100Khz,
        }
    }
}

impl Default for TwoWirePort {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum PortType {
    Inactive,
    Pcie(PciePort),
    TwoWire(TwoWirePort),
}

// MI v2.0, Figure 114, PRTCAP
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

#[derive(Debug)]
pub struct Port {
    id: PortId,
    // MI v2.0, 5.7.2, Figure 114
    typ: PortType,
    caps: PortCapabilities,
    mmtus: u16,
    mebs: u32,
    // Local state
    mtus: u16,
}

impl Port {
    fn new(id: PortId, typ: PortType) -> Self {
        Self {
            id,
            typ,
            caps: PortCapabilities::new(),
            mmtus: 64,
            mebs: 0,
            mtus: 64,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct PortId(u8);

#[derive(Clone, Copy, Debug, Default)]
struct ManagementEndpointControllerState {
    cc: nvme::ControllerConfiguration,
    csts: FlagSet<nvme::ControllerStatusFlags>,
    chscf: FlagSet<nvme::mi::ControllerHealthStatusChangedFlags>,
}

#[derive(Debug)]
pub struct ManagementEndpoint {
    #[expect(dead_code)]
    port: PortId,
    mecss: [ManagementEndpointControllerState; MAX_CONTROLLERS],
    ccsf: nvme::mi::CompositeControllerStatusFlagSet,
}

impl ManagementEndpoint {
    pub fn new(port: PortId) -> Self {
        Self {
            port,
            mecss: [ManagementEndpointControllerState::default(); MAX_CONTROLLERS],
            ccsf: nvme::mi::CompositeControllerStatusFlagSet::empty(),
        }
    }
}

#[derive(Debug)]
struct MiCapability {
    mjr: u8,
    mnr: u8,
}

impl MiCapability {
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
struct OperatingRange<T> {
    kind: UnitKind,
    lower: T,
    upper: T,
}

impl<T> OperatingRange<T> {
    fn new(kind: UnitKind, lower: T, upper: T) -> Self {
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

#[derive(Debug, Clone, Copy, PartialEq)]
enum ControllerType {
    Io,
    #[expect(dead_code)]
    Discovery,
    #[expect(dead_code)]
    Administrative,
}

#[derive(Debug)]
pub struct Controller {
    id: ControllerId,
    cntrltype: ControllerType,
    port: PortId,
    secondaries: heapless::Vec<SecondaryController, 0>,
    active_ns: heapless::Vec<NamespaceId, MAX_NAMESPACES>,
    temp: u16,
    temp_range: OperatingRange<u16>,
    capacity: u64,
    spare: u64,
    spare_range: OperatingRange<u64>,
    write_age: u64,
    write_lifespan: u64,
    ro: bool,
    cc: nvme::ControllerConfiguration,
    csts: FlagSet<nvme::ControllerStatusFlags>,
    lpa: FlagSet<LogPageAttributes>,
    lsaes: [FlagSet<LidSupportedAndEffectsFlags>; 19],
}

#[derive(Debug)]
pub enum ControllerError {
    NamespaceAlreadyAttached,
    NamespaceNotAttached,
    NamespaceAttachmentLimitExceeded,
}

impl Controller {
    fn new(id: ControllerId, port: PortId) -> Self {
        Self {
            id,
            cntrltype: ControllerType::Io,
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
            cc: nvme::ControllerConfiguration::default(),
            csts: FlagSet::empty(),
            lpa: FlagSet::empty(),
            lsaes: {
                let mut arr = [FlagSet::default(); 19];
                arr[AdminGetLogPageLidRequestType::SupportedLogPages.id() as usize] =
                    LidSupportedAndEffectsFlags::Lsupp.into();
                arr[AdminGetLogPageLidRequestType::SmartHealthInformation.id() as usize] =
                    LidSupportedAndEffectsFlags::Lsupp.into();
                arr[AdminGetLogPageLidRequestType::FeatureIdentifiersSupportedAndEffects.id()
                    as usize] = LidSupportedAndEffectsFlags::Lsupp.into();
                arr
            },
        }
    }

    pub fn set_property(&mut self, prop: nvme::ControllerProperties) {
        match prop {
            nvme::ControllerProperties::Cc(cc) => {
                self.cc = cc;
                if self.cc.en {
                    self.csts |= nvme::ControllerStatusFlags::Rdy;
                } else {
                    self.csts -= nvme::ControllerStatusFlags::Rdy;
                }
            }
        }
    }

    pub fn set_temperature(&mut self, temp: Temperature<u16>) {
        let Temperature::Kelvin(k) = temp else {
            todo!("Support units other than kelvin");
        };

        self.temp = k;
    }

    pub fn attach_namespace(&mut self, nsid: NamespaceId) -> Result<(), ControllerError> {
        debug!("Attaching NSID {} to CTLRID {}", nsid.0, self.id.0);
        if self.active_ns.iter().any(|ns| ns.0 == nsid.0) {
            return Err(ControllerError::NamespaceAlreadyAttached);
        }

        if self.active_ns.push(nsid).is_err() {
            return Err(ControllerError::NamespaceAttachmentLimitExceeded);
        }

        Ok(())
    }

    pub fn detach_namespace(&mut self, nsid: NamespaceId) -> Result<(), ControllerError> {
        debug!("Detaching NSID {} from CTRLID {}", nsid.0, self.id.0);
        let Some((idx, _)) = self
            .active_ns
            .iter()
            .enumerate()
            .find(|args| args.1.0 == nsid.0)
        else {
            return Err(ControllerError::NamespaceNotAttached);
        };

        let _ = self.active_ns.swap_remove(idx);

        Ok(())
    }
}

#[derive(Debug)]
struct SubsystemHealth {
    nss: nvme::mi::NvmSubsystemStatus,
}

impl SubsystemHealth {
    fn new() -> Self {
        Self {
            nss: nvme::mi::NvmSubsystemStatus::new(),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum NamespaceIdentifierType {
    Ieuid([u8; 8]),
    Nguid([u8; 16]),
    Nuuid(Uuid),
    Csi(nvme::CommandSetIdentifier),
}

#[derive(Debug)]
pub struct Namespace {
    id: NamespaceId,
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

    pub fn new(nsid: NamespaceId, uuid: Uuid, capacity: u64) -> Self {
        Self {
            id: nsid,
            size: capacity,
            capacity,
            used: 0,
            block_order: 9,
            nids: [
                NamespaceIdentifierType::Nuuid(uuid),
                NamespaceIdentifierType::Csi(nvme::CommandSetIdentifier::Nvm),
            ],
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum SubsystemError {
    ControllerLimitExceeded,
    NamespaceIdentifierUnavailable,
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
    caps: nvme::mi::SubsystemCapabilities,
    ports: heapless::Vec<Port, MAX_PORTS>,
    ctlrs: heapless::Vec<Controller, MAX_CONTROLLERS>,
    nsids: u32,
    nss: heapless::Vec<Namespace, MAX_NAMESPACES>,
    health: SubsystemHealth,
    mi: MiCapability,
    sn: &'static str,
    mn: &'static str,
    fr: &'static str,
}

impl Subsystem {
    pub fn new(info: SubsystemInfo) -> Self {
        Subsystem {
            info,
            caps: nvme::mi::SubsystemCapabilities::new(),
            ports: heapless::Vec::new(),
            ctlrs: heapless::Vec::new(),
            nsids: 0,
            nss: heapless::Vec::new(),
            health: SubsystemHealth::new(),
            mi: MiCapability::new(),
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

    pub fn add_controller(&mut self, port: PortId) -> Result<ControllerId, SubsystemError> {
        debug_assert!(self.ctlrs.len() <= u16::MAX.into());
        let cid = ControllerId(self.ctlrs.len() as u16);
        let c = Controller::new(cid, port);
        self.ctlrs
            .push(c)
            .map_err(|_| SubsystemError::ControllerLimitExceeded)?;
        Ok(cid)
    }

    pub fn controller_mut(&mut self, id: ControllerId) -> &mut Controller {
        self.ctlrs
            .get_mut(id.0 as usize)
            .expect("Invalid ControllerId provided")
    }

    pub fn add_namespace(&mut self, capacity: u64) -> Result<NamespaceId, SubsystemError> {
        let Some(allocated) = self.nsids.checked_add(1) else {
            debug!("Implement allocation tracking with reuse");
            return Err(SubsystemError::NamespaceIdentifierUnavailable);
        };
        self.nsids = allocated;
        let nsid = NamespaceId(self.nsids);
        let ns = Namespace::new(
            nsid,
            Namespace::generate_uuid(&self.info.instance, nsid),
            capacity,
        );
        match self.nss.push(ns) {
            Ok(_) => Ok(nsid),
            Err(_) => Err(SubsystemError::NamespaceIdentifierUnavailable),
        }
    }

    pub fn remove_namespace(&mut self, nsid: NamespaceId) -> Result<(), SubsystemError> {
        if nsid.0 == u32::MAX {
            self.nss.clear();
            return Ok(());
        }
        let Some(e) = self.nss.iter().enumerate().find(|args| args.1.id == nsid) else {
            return Err(SubsystemError::NamespaceIdentifierUnavailable);
        };
        let _ = self.nss.swap_remove(e.0);
        Ok(())
    }
}
