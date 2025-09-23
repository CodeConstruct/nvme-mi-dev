// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2025 Code Construct
 */
use deku::ctx::Endian;
use deku::{DekuRead, DekuWrite};

// PCIe Base 4.0r1.0, 7.5.1.2, Figure 7-10
#[derive(Debug, DekuRead, DekuWrite)]
#[deku(endian = "little")]
pub struct PciDeviceFunctionConfigurationSpace {
    vid: u16,
    did: u16,
    cmd: u16,
    sts: u16,
    rid: u8,
    #[deku(bytes = "3")]
    cc: u32,
    cls: u8,
    lt: u8,
    ht: u8,
    bist: u8,
    bars: [u32; 6],
    cis: u32,
    svid: u16,
    sdid: u16,
    rom: u32,
    cap: u8,
    #[deku(seek_from_current = "7")]
    il: u8,
    ip: u8,
    min_gnt: u8,
    max_lat: u8,
    caps: [PciCapabilityType; 2],
}
impl crate::Encode<4096> for PciDeviceFunctionConfigurationSpace {}

impl PciDeviceFunctionConfigurationSpace {
    pub fn new() -> Self {
        Self {
            vid: 0xffff,
            did: 0xffff,
            cmd: 0,
            sts: 0x0010,
            rid: 0,
            cc: 0x010803,
            cls: 0,
            lt: 0,
            ht: 0,
            bist: 0,
            bars: [0; 6],
            cis: 0,
            svid: 0xffff,
            sdid: 0xffff,
            rom: 0,
            cap: 0x40,
            il: 0,
            ip: 0,
            min_gnt: 0,
            max_lat: 0,
            caps: [
                PciCapabilityType::PciPowerManagement(PciPowerManagementCapability {
                    next: 0x48,
                    pmc: {
                        PowerManagementCapabilities {
                            version: 3,
                            pme_clock: false,
                            ready_d0: true,
                            dsi: false,
                            aux_current: 0,
                            d1: false,
                            d2: false,
                            pme: 0,
                        }
                    }
                    .into(),
                    pmcsr: 0,
                    data: 0,
                }),
                PciCapabilityType::Pcie(PcieCapability::default()),
            ],
        }
    }

    pub fn builder() -> PciDeviceFunctionConfigurationSpaceBuilder {
        Default::default()
    }
}

impl Default for PciDeviceFunctionConfigurationSpace {
    fn default() -> Self {
        PciDeviceFunctionConfigurationSpace::new()
    }
}

pub struct PciDeviceFunctionConfigurationSpaceBuilder {
    vid: u16,
    did: u16,
    svid: u16,
    sdid: u16,
}

impl Default for PciDeviceFunctionConfigurationSpaceBuilder {
    fn default() -> Self {
        Self {
            vid: 0xffff,
            did: 0xffff,
            svid: 0xffff,
            sdid: 0xffff,
        }
    }
}

impl PciDeviceFunctionConfigurationSpaceBuilder {
    pub fn vid(&mut self, vid: u16) -> &mut Self {
        self.vid = vid;
        self
    }

    pub fn did(&mut self, did: u16) -> &mut Self {
        self.did = did;
        self
    }

    pub fn svid(&mut self, svid: u16) -> &mut Self {
        self.svid = svid;
        self
    }

    pub fn sdid(&mut self, sdid: u16) -> &mut Self {
        self.sdid = sdid;
        self
    }

    pub fn build(&self) -> PciDeviceFunctionConfigurationSpace {
        PciDeviceFunctionConfigurationSpace {
            vid: self.vid,
            did: self.did,
            svid: self.svid,
            sdid: self.sdid,
            ..Default::default()
        }
    }
}

#[derive(Debug)]
pub struct PowerManagementCapabilities {
    version: u8,
    pme_clock: bool,
    ready_d0: bool,
    dsi: bool,
    aux_current: u8,
    d1: bool,
    d2: bool,
    pme: u8,
}

impl From<PowerManagementCapabilities> for u16 {
    fn from(value: PowerManagementCapabilities) -> Self {
        ((value.pme as u16 & 0xf) << 11)
            | ((value.d2 as u16) << 10)
            | ((value.d1 as u16) << 9)
            | ((value.aux_current as u16 & 0x7) << 6)
            | ((value.dsi as u16) << 5)
            | ((value.ready_d0 as u16) << 4)
            | ((value.pme_clock as u16) << 3)
            | (value.version as u16 & 0x7)
    }
}

#[derive(Debug, DekuRead, DekuWrite)]
#[deku(ctx = "endian: Endian", endian = "endian")]
pub struct PciPowerManagementCapability {
    next: u8,
    pmc: u16,
    pmcsr: u16,
    #[deku(seek_from_current = "1")]
    data: u8,
}

#[derive(Debug, Default, DekuRead, DekuWrite)]
#[deku(ctx = "endian: Endian", endian = "endian")]
pub struct PcieCapability {
    next: u8,
    pciec: u16,
    devcap: u32,
    devctl: u16,
    devsts: u16,
    linkcap: u32,
    linkctl: u16,
    linksts: u16,
    slotctl: u16,
    slotsts: u16,
    rootctl: u16,
    rootsts: u16,
    devcap2: u32,
    devctl2: u16,
    devsts2: u16,
    linkcap2: u32,
    linkctl2: u16,
    linksts2: u16,
    slotcap2: u32,
    slotctl2: u16,
    slotsts2: u16,
}

#[derive(Debug, DekuRead, DekuWrite)]
#[deku(ctx = "endian: Endian", endian = "endian", id_type = "u8")]
#[repr(u8)]
pub enum PciCapabilityType {
    #[deku(id = "0x01")]
    PciPowerManagement(PciPowerManagementCapability),
    #[deku(id = "0x10")]
    Pcie(PcieCapability),
}
unsafe impl crate::Discriminant<u8> for PciCapabilityType {}
