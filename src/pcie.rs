// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2025 Code Construct
 */
use deku::ctx::Endian;
use deku::{DekuRead, DekuWrite};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PayloadSize {
    Payload128B,
    Payload256B,
    Payload512B,
    Payload1Kb,
    Payload2Kb,
    Payload4Kb,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LinkSpeed {
    Inactive,
    Gts2p5,
    Gts5,
    Gts8,
    Gts16,
    Gts32,
    Gts64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LinkWidth {
    X1,
    X2,
    X4,
    X8,
    X12,
    X16,
    X32,
}

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
                    },
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

#[derive(Debug, DekuRead, DekuWrite)]
#[deku(bit_order = "lsb", ctx = "endian: Endian", endian = "endian")]
pub struct PowerManagementCapabilities {
    #[deku(bits = "3")]
    version: u8,
    #[deku(bits = "1")]
    pme_clock: bool,
    #[deku(bits = "1")]
    ready_d0: bool,
    #[deku(bits = "1")]
    dsi: bool,
    #[deku(bits = "3")]
    aux_current: u8,
    #[deku(bits = "1")]
    d1: bool,
    #[deku(bits = "1")]
    d2: bool,
    #[deku(bits = "5")]
    pme: u8,
}

#[derive(Debug, DekuRead, DekuWrite)]
#[deku(ctx = "endian: Endian", endian = "endian")]
pub struct PciPowerManagementCapability {
    next: u8,
    pmc: PowerManagementCapabilities,
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
