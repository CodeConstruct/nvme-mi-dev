// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2025 Code Construct
 */
use deku::prelude::*;
use flagset::FlagSet;
use heapless::Vec;
use log::debug;
use mctp::{AsyncRespChannel, MsgIC};

use crate::{
    CommandEffect, CommandEffectError, Discriminant, MAX_NAMESPACES,
    nvme::{
        AdminIdentifyActiveNamespaceIdListResponse, AdminIdentifyAllocatedNamespaceIdListResponse,
        AdminIdentifyCnsRequestType, AdminIdentifyControllerResponse,
        AdminIdentifyNamespaceIdentificationDescriptorListResponse,
        AdminIdentifyNvmIdentifyNamespaceResponse, ControllerListResponse, CqeGenericCommandStatus,
        CqeStatusCodeType, NamespaceIdentifierType,
        mi::{
            AdminCommandRequestHeader, AdminCommandResponseHeader,
            CompositeControllerStatusDataStructureResponse, ControllerInformationResponse,
            MessageType, NvmSubsystemHealthDataStructureResponse, NvmSubsystemInformationResponse,
            NvmeManagementResponse, NvmeMiCommandRequestHeader, NvmeMiCommandRequestType,
            NvmeMiDataStructureManagementResponse, NvmeMiDataStructureRequestType,
            PciePortDataResponse, PortInformationResponse, TwoWirePortDataResponse,
        },
    },
    wire::{string::WireString, vec::WireVec},
};

use crate::Encode;
use crate::RequestHandler;

use super::{
    AdminCommandRequestType, AdminIdentifyRequest, GetHealthStatusChangeResponse,
    GetMctpTransmissionUnitSizeResponse, GetSmbusI2cFrequencyResponse, MessageHeader,
    NvmeMiConfigurationGetRequest, NvmeMiConfigurationIdentifierRequestType,
    NvmeMiConfigurationSetRequest, NvmeMiDataStructureRequest, ResponseStatus,
};

const ISCSI: crc::Crc<u32> = crc::Crc::<u32>::new(&crc::CRC_32_ISCSI);
const MAX_FRAGMENTS: usize = 6;

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
    type Ctx = Self;

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
        C: AsyncRespChannel,
    {
        debug!("{self:x?}");
        // TODO: Command and Feature Lockdown handling
        // TODO: Handle subsystem reset, section 8.1, v2.0
        let Ok(nmimt) = ctx.nmimt() else {
            return Err(ResponseStatus::InvalidCommandOpcode);
        };

        match nmimt {
            MessageType::NvmeMiCommand => {
                let Ok(((rest, _), ch)) = NvmeMiCommandRequestHeader::from_bytes((rest, 0)) else {
                    debug!("Message too short to extract NVMeMICommandHeader");
                    return Err(ResponseStatus::InvalidCommandSize);
                };

                ch.handle(&ch, mep, subsys, rest, resp, app).await
            }
            MessageType::NvmeAdminCommand => {
                let Ok(((rest, _), ch)) = AdminCommandRequestHeader::from_bytes((rest, 0)) else {
                    debug!("Message too short to extract AdminCommandHeader");
                    return Err(ResponseStatus::InvalidCommandSize);
                };

                ch.handle(&ch, mep, subsys, rest, resp, app).await
            }
            _ => {
                debug!("Unimplemented NMINT: {:?}", ctx.nmimt());
                Err(ResponseStatus::InternalError)
            }
        }
    }
}

impl RequestHandler for NvmeMiCommandRequestHeader {
    type Ctx = Self;

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
        C: AsyncRespChannel,
    {
        debug!("{self:x?}");
        match &self.body {
            NvmeMiCommandRequestType::ReadNvmeMiDataStructure(ds) => {
                ds.handle(self, mep, subsys, rest, resp, app).await
            }
            NvmeMiCommandRequestType::NvmSubsystemHealthStatusPoll(shsp) => {
                // 5.6, Figure 108, v2.0
                if !rest.is_empty() {
                    debug!("Lost coherence decoding {:?}", ctx.opcode);
                    return Err(ResponseStatus::InvalidCommandSize);
                }

                let mh = MessageHeader::respond(MessageType::NvmeMiCommand).encode()?;

                let mr = NvmeManagementResponse {
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

                let crate::PortType::Pcie(pprt) = port.typ else {
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
                assert!(ctlr.temp_range.kind == crate::UnitKind::Kelvin);

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

                let nvmshds = NvmSubsystemHealthDataStructureResponse {
                    nss: (subsys.health.nss.atf as u8) << 7
                        | (subsys.health.nss.sfm as u8) << 6
                        | (subsys.health.nss.df as u8) << 5
                        | (subsys.health.nss.rnr as u8) << 4
                        | ((pprt.cls != crate::nvme::mi::PcieLinkSpeed::Inactive) as u8) << 3 // P0LA
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

                let ccs = CompositeControllerStatusDataStructureResponse {
                    ccsf: mep.ccsf.0.bits(),
                }
                .encode()?;

                // CS: See Figure 106, NVMe MI v2.0
                if (shsp.dword1 & (1u32 << 31)) != 0 {
                    mep.ccsf.0.clear();
                }

                send_response(resp, &[&mh.0, &mr.0, &nvmshds.0, &ccs.0]).await;
                Ok(())
            }
            NvmeMiCommandRequestType::ConfigurationSet(cid) => {
                cid.handle(ctx, mep, subsys, rest, resp, app).await
            }
            NvmeMiCommandRequestType::ConfigurationGet(cid) => {
                cid.handle(ctx, mep, subsys, rest, resp, app).await
            }
            _ => {
                debug!("Unimplemented OPCODE: {:?}", ctx.opcode);
                Err(ResponseStatus::InternalError)
            }
        }
    }
}

impl RequestHandler for NvmeMiConfigurationSetRequest {
    type Ctx = NvmeMiCommandRequestHeader;

    async fn handle<A, C>(
        &self,
        _ctx: &Self::Ctx,
        mep: &mut crate::ManagementEndpoint,
        subsys: &mut crate::Subsystem,
        rest: &[u8],
        resp: &mut C,
        _app: A,
    ) -> Result<(), ResponseStatus>
    where
        A: AsyncFnMut(CommandEffect) -> Result<(), CommandEffectError>,
        C: AsyncRespChannel,
    {
        match &self.body {
            NvmeMiConfigurationIdentifierRequestType::Reserved => {
                Err(ResponseStatus::InvalidParameter)
            }
            NvmeMiConfigurationIdentifierRequestType::SmbusI2cFrequency(sifr) => {
                if !rest.is_empty() {
                    debug!("Lost synchronisation when decoding ConfigurationSet SmbusI2cFrequency");
                    return Err(ResponseStatus::InvalidCommandSize);
                }

                let Some(port) = subsys.ports.get(sifr.dw0_portid as usize) else {
                    debug!("Unrecognised port ID: {}", sifr.dw0_portid);
                    return Err(ResponseStatus::InvalidParameter);
                };

                let crate::PortType::TwoWire(twprt) = port.typ else {
                    debug!("Port {} is not a TwoWire port: {:?}", sifr.dw0_portid, port);
                    return Err(ResponseStatus::InvalidParameter);
                };

                if sifr.dw0_sfreq != crate::nvme::mi::SmbusFrequency::Freq100Khz {
                    if twprt.msmbfreq != super::SmbusFrequency::Freq100Khz {
                        todo!("Maintain port state and configure the hardware");
                    }
                    return Err(ResponseStatus::InvalidParameter);
                }

                let mh = MessageHeader::respond(MessageType::NvmeMiCommand).encode()?;

                // Success
                let status = [0u8; 4];

                send_response(resp, &[&mh.0, &status]).await;
                Ok(())
            }
            NvmeMiConfigurationIdentifierRequestType::HealthStatusChange(hscr) => {
                if !rest.is_empty() {
                    debug!(
                        "Lost synchronisation when decoding ConfigurationSet HealthStatusChange"
                    );
                    return Err(ResponseStatus::InvalidCommandSize);
                }

                let Ok(clear) = FlagSet::<super::HealthStatusChangeFlags>::new(hscr.dw1) else {
                    debug!(
                        "Invalid composite controller status flags in request: {}",
                        hscr.dw1
                    );
                    return Err(ResponseStatus::InvalidParameter);
                };
                let clear: super::CompositeControllerStatusFlagSet = clear.into();
                mep.ccsf.0 -= clear.0;

                let mh = MessageHeader::respond(MessageType::NvmeMiCommand).encode()?;

                // Success
                let status = [0u8; 4];

                send_response(resp, &[&mh.0, &status]).await;
                Ok(())
            }
            NvmeMiConfigurationIdentifierRequestType::MctpTransmissionUnitSize(_) => todo!(),
            NvmeMiConfigurationIdentifierRequestType::AsynchronousEvent => todo!(),
        }
    }
}

impl RequestHandler for NvmeMiConfigurationGetRequest {
    type Ctx = NvmeMiCommandRequestHeader;

    async fn handle<A, C>(
        &self,
        _ctx: &Self::Ctx,
        _mep: &mut crate::ManagementEndpoint,
        subsys: &mut crate::Subsystem,
        rest: &[u8],
        resp: &mut C,
        _app: A,
    ) -> Result<(), ResponseStatus>
    where
        A: AsyncFnMut(CommandEffect) -> Result<(), CommandEffectError>,
        C: AsyncRespChannel,
    {
        match &self.body {
            NvmeMiConfigurationIdentifierRequestType::Reserved => {
                Err(ResponseStatus::InvalidParameter)
            }
            NvmeMiConfigurationIdentifierRequestType::SmbusI2cFrequency(sifr) => {
                if !rest.is_empty() {
                    debug!("Lost synchronisation when decoding ConfigurationGet SMBusI2CFrequency");
                    return Err(ResponseStatus::InvalidCommandSize);
                }

                let Some(port) = subsys.ports.get(sifr.dw0_portid as usize) else {
                    debug!("Unrecognised port ID: {}", sifr.dw0_portid);
                    return Err(ResponseStatus::InvalidParameter);
                };

                let crate::PortType::TwoWire(twprt) = port.typ else {
                    debug!("Port {} is not a TwoWire port: {:?}", sifr.dw0_portid, port);
                    return Err(ResponseStatus::InvalidParameter);
                };

                let mh = MessageHeader::respond(MessageType::NvmeMiCommand).encode()?;

                let fr = GetSmbusI2cFrequencyResponse {
                    status: ResponseStatus::Success,
                    mr_sfreq: twprt.msmbfreq,
                }
                .encode()?;

                send_response(resp, &[&mh.0, &fr.0]).await;
                Ok(())
            }
            NvmeMiConfigurationIdentifierRequestType::HealthStatusChange(_) => {
                // MI v2.0, 5.1.2
                if !rest.is_empty() {
                    debug!(
                        "Lost synchronisation when decoding ConfigurationGet HealthStatusChange"
                    );
                    return Err(ResponseStatus::InvalidCommandSize);
                }

                let mh = MessageHeader::respond(MessageType::NvmeMiCommand).encode()?;
                let hscr = GetHealthStatusChangeResponse {
                    status: ResponseStatus::Success,
                }
                .encode()?;

                send_response(resp, &[&mh.0, &hscr.0]).await;
                Ok(())
            }
            NvmeMiConfigurationIdentifierRequestType::MctpTransmissionUnitSize(gmtusr) => {
                if !rest.is_empty() {
                    debug!(
                        "Lost synchronisation when decoding ConfigurationGet MCTPTransmissionUnitSize"
                    );
                    return Err(ResponseStatus::InvalidCommandSize);
                }

                let Some(port) = subsys.ports.get(gmtusr.dw0_portid as usize) else {
                    debug!("Unrecognised port ID: {}", gmtusr.dw0_portid);
                    return Err(ResponseStatus::InvalidParameter);
                };

                let mh = MessageHeader::respond(MessageType::NvmeMiCommand).encode()?;

                let fr = GetMctpTransmissionUnitSizeResponse {
                    status: ResponseStatus::Success,
                    mr_mtus: port.mmtus,
                }
                .encode()?;

                send_response(resp, &[&mh.0, &fr.0]).await;
                Ok(())
            }
            NvmeMiConfigurationIdentifierRequestType::AsynchronousEvent => todo!(),
        }
    }
}

impl RequestHandler for NvmeMiDataStructureRequest {
    type Ctx = NvmeMiCommandRequestHeader;

    async fn handle<A, C>(
        &self,
        _ctx: &Self::Ctx,
        _mep: &mut crate::ManagementEndpoint,
        subsys: &mut crate::Subsystem,
        rest: &[u8],
        resp: &mut C,
        _app: A,
    ) -> Result<(), ResponseStatus>
    where
        A: AsyncFnMut(CommandEffect) -> Result<(), CommandEffectError>,
        C: AsyncRespChannel,
    {
        debug!("{self:x?}");

        if !rest.is_empty() {
            debug!("Lost coherence decoding NVMe-MI message");
            return Err(ResponseStatus::InvalidCommandInputDataSize);
        }

        let mh = MessageHeader::respond(MessageType::NvmeMiCommand).encode()?;

        match self.body {
            NvmeMiDataStructureRequestType::NvmSubsystemInformation => {
                assert!(!subsys.ports.is_empty(), "Need at least one port defined");
                // See 5.7.1, 5.1.1 of v2.0
                assert!(
                    subsys.ports.len() < u8::MAX as usize,
                    "Too many ports defined: {}",
                    subsys.ports.len()
                );
                // See 5.7.1 of v2.0
                let nvmsi = NvmSubsystemInformationResponse {
                    nump: subsys.ports.len() as u8 - 1,
                    mjr: subsys.mi.mjr,
                    mnr: subsys.mi.mnr,
                    nnsc: subsys.caps.sre.into(),
                }
                .encode()?;

                debug_assert!(nvmsi.0.len() <= u16::MAX as usize);
                let dsmr = NvmeMiDataStructureManagementResponse {
                    status: ResponseStatus::Success,
                    rdl: nvmsi.0.len() as u16,
                }
                .encode()?;

                send_response(resp, &[&mh.0, &dsmr.0, &nvmsi.0]).await;
                Ok(())
            }
            NvmeMiDataStructureRequestType::PortInformation => {
                let Some(port) = subsys.ports.iter().find(|p| p.id.0 == self.portid) else {
                    // TODO: Propagate PEL
                    return Err(ResponseStatus::InvalidParameter);
                };
                let pi = PortInformationResponse {
                    // FIXME: Change prttyp to crate::nvme::mi::PortType
                    prttyp: Into::<crate::nvme::mi::PortType>::into(&port.typ).id(),
                    prtcap: (port.caps.aems as u8) << 1 | (port.caps.ciaps as u8),
                    mmtus: port.mmtus,
                    mebs: port.mebs,
                }
                .encode()?;

                match port.typ {
                    crate::PortType::Pcie(pprt) => {
                        let ppd = PciePortDataResponse {
                            pciemps: pprt.mps.into(),
                            pcieslsv: 0x3fu8,
                            pciecls: pprt.cls.into(),
                            pciemlw: pprt.mlw.into(),
                            pcienlw: pprt.nlw.into(),
                            pciepn: port.id.0,
                        }
                        .encode()?;

                        debug_assert!(pi.0.len() + ppd.0.len() <= u16::MAX as usize);
                        let dsmr = NvmeMiDataStructureManagementResponse {
                            status: ResponseStatus::Success,
                            rdl: (pi.0.len() + ppd.0.len()) as u16,
                        }
                        .encode()?;

                        send_response(resp, &[&mh.0, &dsmr.0, &pi.0, &ppd.0]).await;
                        Ok(())
                    }
                    crate::PortType::TwoWire(twprt) => {
                        let twpd = TwoWirePortDataResponse {
                            cvpdaddr: twprt.cvpdaddr,
                            mvpdfreq: twprt.mvpdfreq.id(),
                            cmeaddr: twprt.cmeaddr,
                            twprt: (twprt.i3csprt as u8) << 7 | twprt.msmbfreq.id() & 3,
                            nvmebm: twprt.nvmebms.into(),
                        }
                        .encode()?;

                        debug_assert!((pi.0.len() + twpd.0.len()) <= u16::MAX as usize);
                        let dsmr = NvmeMiDataStructureManagementResponse {
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
            NvmeMiDataStructureRequestType::ControllerList => {
                assert!(
                    subsys.ctlrs.len() <= 2047,
                    "Invalid number of controllers in drive model: {}",
                    subsys.ctlrs.len()
                );

                let mut cl = ControllerListResponse::new();
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

                let dsmr = NvmeMiDataStructureManagementResponse {
                    status: ResponseStatus::Success,
                    rdl,
                }
                .encode()?;

                send_response(resp, &[&mh.0, &dsmr.0, &cl.0[..cl.1]]).await;
                Ok(())
            }
            NvmeMiDataStructureRequestType::ControllerInformation => {
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

                let crate::PortType::Pcie(pprt) = port.typ else {
                    panic!("Non-PCIe port associated with controller {:?}", ctlr.id);
                };

                let ci = ControllerInformationResponse {
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
                let dsmr = NvmeMiDataStructureManagementResponse {
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

const MI_PROHIBITED_ADMIN_COMMANDS: [AdminCommandRequestType; 26] = [
    AdminCommandRequestType::DeleteIoSubmissionQueue,
    AdminCommandRequestType::CreateIoSubmissionQueue,
    AdminCommandRequestType::DeleteIoCompletionQueue,
    AdminCommandRequestType::CreateIoCompletionQueue,
    AdminCommandRequestType::Abort,
    AdminCommandRequestType::AsynchronousEventRequest,
    AdminCommandRequestType::KeepAlive,
    AdminCommandRequestType::DirectiveSend,
    AdminCommandRequestType::DirectiveReceive,
    AdminCommandRequestType::NvmeMiSend,
    AdminCommandRequestType::NvmeMiReceive,
    AdminCommandRequestType::DiscoveryInformationManagement,
    AdminCommandRequestType::FabricZoningReceive,
    AdminCommandRequestType::FabricZoningLookup,
    AdminCommandRequestType::FabricZoningSend,
    AdminCommandRequestType::SendDiscoveryLogPage,
    AdminCommandRequestType::TrackSend,
    AdminCommandRequestType::TrackReceive,
    AdminCommandRequestType::MigrationSend,
    AdminCommandRequestType::MigrationReceive,
    AdminCommandRequestType::ControllerDataQueue,
    AdminCommandRequestType::DoorbellBufferConfig,
    AdminCommandRequestType::FabricsCommands,
    AdminCommandRequestType::LoadProgram,
    AdminCommandRequestType::ProgramActivationManagement,
    AdminCommandRequestType::MemoryRangeSetManagement,
];

impl RequestHandler for AdminCommandRequestHeader {
    type Ctx = Self;

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
        C: AsyncRespChannel,
    {
        debug!("{self:x?}");

        // ISH
        if ctx.cflgs & 4 != 0 {
            debug!("Support ignore shutdown state");
            return Err(ResponseStatus::InternalError);
        }

        match &self.op {
            AdminCommandRequestType::Identify(identify) => {
                identify.handle(ctx, mep, subsys, rest, resp, app).await
            }
            op if MI_PROHIBITED_ADMIN_COMMANDS.contains(&self.op) => {
                debug!("Prohibited MI admin command opcode: {:?}", op.id());
                Err(ResponseStatus::InvalidCommandOpcode)
            }
            _ => {
                debug!("Unimplemented OPCODE: {:?}", self.op.id());
                Err(ResponseStatus::InternalError)
            }
        }
    }
}

impl AdminIdentifyRequest {
    async fn send_constrained_response<A: AsyncRespChannel>(
        &self,
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
    type Ctx = AdminCommandRequestHeader;

    async fn handle<A, C>(
        &self,
        ctx: &Self::Ctx,
        _mep: &mut crate::ManagementEndpoint,
        subsys: &mut crate::Subsystem,
        rest: &[u8],
        resp: &mut C,
        _app: A,
    ) -> Result<(), ResponseStatus>
    where
        A: AsyncFnMut(CommandEffect) -> Result<(), CommandEffectError>,
        C: AsyncRespChannel,
    {
        debug!("{self:x?}");

        if !rest.is_empty() {
            debug!("Invalid request size for Admin Identify");
            return Err(ResponseStatus::InvalidCommandSize);
        }

        let mh = MessageHeader::respond(MessageType::NvmeAdminCommand).encode()?;

        let acrh = AdminCommandResponseHeader {
            status: ResponseStatus::Success,
            cqedw0: 0,
            cqedw1: 0,
            #[expect(clippy::identity_op, clippy::erasing_op)]
            cqedw3: ((false as u32) << 31) // DNR
                | ((false as u32) << 30) // M
                | (0u32 & 3) << 28 // CRD
                | (((CqeStatusCodeType::GenericCommandStatus.id() as u32) & 7) << 25) // SCT
                | (((CqeGenericCommandStatus::SuccessfulCompletion.id() as u32) & 0x1ff) << 17) // SC
                | ((true as u32) << 16) // P
                | (0u32 & 0xffff) << 0, // CID
        }
        .encode()?;

        match &self.req {
            AdminIdentifyCnsRequestType::NvmIdentifyNamespace => {
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
                    AdminIdentifyNvmIdentifyNamespaceResponse {
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
                    AdminIdentifyNvmIdentifyNamespaceResponse::default()
                }
                .encode()?;

                self.send_constrained_response(resp, &[&mh.0, &acrh.0], &ainvminr.0)
                    .await
            }
            AdminIdentifyCnsRequestType::IdentifyController => {
                let Some(ctlr) = subsys.ctlrs.get(ctx.ctlid as usize) else {
                    debug!("No such CTLID: {}", ctx.ctlid);
                    return Err(ResponseStatus::InvalidParameter);
                };

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
                    cntrltype: crate::nvme::ControllerType::AdministrativeController,
                    // TODO: Tie to data model
                    nvmsr: ((false as u8) << 1) // NVMEE
                        | (true as u8), // NVMESD
                    vwci: 0,
                    mec: ((subsys.ports.iter().any(|p| matches!(p.typ, crate::PortType::Pcie(_)))) as u8) << 1 // PCIEME
                        | (subsys.ports.iter().any(|p| matches!(p.typ, crate::PortType::TwoWire(_)))) as u8, // TWPME
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
            AdminIdentifyCnsRequestType::ActiveNamespaceIDList => {
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

                let mut aianidlr = AdminIdentifyActiveNamespaceIdListResponse::new();
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
            AdminIdentifyCnsRequestType::NamespaceIdentificationDescriptorList => {
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
            AdminIdentifyCnsRequestType::AllocatedNamespaceIdList => {
                // 5.1.13.2.9, Base v2.1
                if self.nsid >= u32::MAX - 1 {
                    debug!("Invalid NSID");
                    return Err(ResponseStatus::InvalidParameter);
                }

                assert!(subsys.nss.len() < 4096 / core::mem::size_of::<u32>());
                let aiansidl = AdminIdentifyAllocatedNamespaceIdListResponse {
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
            AdminIdentifyCnsRequestType::NvmSubsystemControllerList => {
                assert!(
                    subsys.ctlrs.len() <= 2047,
                    "Invalid number of controllers in drive model: {}",
                    subsys.ctlrs.len()
                );
                let mut cl = ControllerListResponse::new();
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
            AdminIdentifyCnsRequestType::SecondaryControllerList => {
                let Some(ctlr) = subsys.ctlrs.get(ctx.ctlid as usize) else {
                    debug!("No such CTLID: {}", ctx.ctlid);
                    return Err(ResponseStatus::InvalidParameter);
                };

                if !ctlr.secondaries.is_empty() {
                    todo!("Support listing secondary controllers");
                }

                self.send_constrained_response(resp, &[&mh.0, &acrh.0], &[0u8; 4096])
                    .await
            }
            _ => {
                debug!("Unimplemented CNS: {self:?}");
                Err(ResponseStatus::InternalError)
            }
        }
    }
}

impl crate::ManagementEndpoint {
    fn update(&mut self, subsys: &crate::Subsystem) {
        assert!(subsys.ctlrs.len() <= self.mecss.len());
        for c in &subsys.ctlrs {
            let mecs = &mut self.mecss[c.id.0 as usize];

            if mecs.cc.en != c.cc.en {
                self.ccsf.0 |= crate::nvme::mi::CompositeControllerStatusFlags::Ceco;
            }

            if mecs.csts.contains(crate::nvme::ControllerStatusFlags::Rdy)
                != c.csts.contains(crate::nvme::ControllerStatusFlags::Rdy)
            {
                self.ccsf.0 |= crate::nvme::mi::CompositeControllerStatusFlags::Rdy;
            }

            mecs.cc = c.cc;
            mecs.csts = c.csts;
        }
    }

    pub async fn handle_async<
        A: AsyncFnMut(CommandEffect) -> Result<(), CommandEffectError>,
        C: mctp::AsyncRespChannel,
    >(
        &mut self,
        subsys: &mut crate::Subsystem,
        msg: &[u8],
        ic: MsgIC,
        mut resp: C,
        app: A,
    ) {
        self.update(subsys);

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

        if let Err(status) = mh.handle(&mh, self, subsys, rest, &mut resp, app).await {
            let mut digest = ISCSI.digest();
            digest.update(&[0x80 | 0x04]);

            let Ok(mh) = MessageHeader::respond(nmimt).encode() else {
                debug!("Failed to encode MessageHeader for error response");
                return;
            };
            digest.update(&mh.0);

            let ss: [u8; 4] = [status.id(), 0, 0, 0];
            digest.update(&ss);

            let icv = digest.finalize().to_le_bytes();
            let respv = [mh.0.as_slice(), ss.as_slice(), icv.as_slice()];
            if let Err(e) = resp.send_vectored(MsgIC(true), &respv).await {
                debug!("Failed to send NVMe-MI error response: {e:?}");
            }
        }
    }
}
