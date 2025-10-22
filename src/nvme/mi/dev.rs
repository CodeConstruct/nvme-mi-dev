// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2025 Code Construct
 */
use deku::prelude::*;
use flagset::FlagSet;
use heapless::Vec;
use log::debug;
use mctp::{AsyncRespChannel, MsgIC};

use crate::nvme::mi::{NvmSubsystemStatusFlags, PortCapabilityFlags};
use crate::nvme::{
    ControllerAttributeFlags, ControllerMultipathIoNamespaceSharingCapabilityFlags,
    ManagementEndpointCapabilityFlags, NvmSubsystemReportFlags, SanitizeCapabilityFlags,
};
use crate::{
    CommandEffect, CommandEffectError, Controller, ControllerError, ControllerType, Discriminant,
    MAX_CONTROLLERS, MAX_NAMESPACES, NamespaceId, NamespaceIdDisposition, SubsystemError,
    nvme::{
        AdminGetLogPageLidRequestType, AdminGetLogPageSupportedLogPagesResponse,
        AdminIdentifyActiveNamespaceIdListResponse, AdminIdentifyAllocatedNamespaceIdListResponse,
        AdminIdentifyCnsRequestType, AdminIdentifyControllerResponse,
        AdminIdentifyNamespaceIdentificationDescriptorListResponse,
        AdminIdentifyNvmIdentifyNamespaceResponse, AdminIoCqeGenericCommandStatus,
        AdminIoCqeStatusType, ControllerListResponse, LidSupportedAndEffectsDataStructure,
        LidSupportedAndEffectsFlags, LogPageAttributes, NamespaceIdentifierType, SanitizeAction,
        SanitizeOperationStatus, SanitizeState, SanitizeStateInformation, SanitizeStatus,
        SanitizeStatusLogPageResponse, SmartHealthInformationLogPageResponse,
        mi::{
            AdminCommandRequestHeader, AdminCommandResponseHeader, AdminFormatNvmRequest,
            AdminNamespaceAttachmentRequest, AdminNamespaceManagementRequest, AdminSanitizeRequest,
            CompositeControllerStatusDataStructureResponse, CompositeControllerStatusFlagSet,
            ControllerFunctionAndReportingFlags, ControllerHealthDataStructure,
            ControllerHealthStatusPollResponse, ControllerInformationResponse,
            ControllerPropertyFlags, MessageType, NvmSubsystemHealthDataStructureResponse,
            NvmSubsystemInformationResponse, NvmeManagementResponse, NvmeMiCommandRequestHeader,
            NvmeMiCommandRequestType, NvmeMiDataStructureManagementResponse,
            NvmeMiDataStructureRequestType, PcieCommandRequestHeader, PciePortDataResponse,
            PcieSupportedLinkSpeeds, PortInformationResponse, TwoWirePortDataResponse,
        },
    },
    pcie::PciDeviceFunctionConfigurationSpace,
    wire::{WireString, WireVec},
};

use crate::Encode;
use crate::RequestHandler;

use super::{
    AdminCommandRequestType, AdminGetLogPageRequest, AdminIdentifyRequest,
    GetHealthStatusChangeResponse, GetMctpTransmissionUnitSizeResponse,
    GetSmbusI2cFrequencyResponse, MessageHeader, NvmeMiConfigurationGetRequest,
    NvmeMiConfigurationIdentifierRequestType, NvmeMiConfigurationSetRequest,
    NvmeMiDataStructureRequest, ResponseStatus,
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
        match ctx.nmimt {
            MessageType::NvmeMiCommand => {
                match &NvmeMiCommandRequestHeader::from_bytes((rest, 0)) {
                    Ok(((rest, _), ch)) => ch.handle(ch, mep, subsys, rest, resp, app).await,
                    Err(err) => {
                        debug!("Unable to parse NVMeMICommandHeader from message buffer: {err:?}");
                        // TODO: This is a bad assumption: Can see DekuError::InvalidParam too
                        Err(ResponseStatus::InvalidCommandSize)
                    }
                }
            }
            MessageType::NvmeAdminCommand => {
                match &AdminCommandRequestHeader::from_bytes((rest, 0)) {
                    Ok(((rest, _), ch)) => ch.handle(ch, mep, subsys, rest, resp, app).await,
                    Err(err) => {
                        debug!("Unable to parse AdminCommandHeader from message buffer: {err:?}");
                        // TODO: This is a bad assumption: Can see DekuError::InvalidParam too
                        Err(ResponseStatus::InvalidCommandSize)
                    }
                }
            }
            MessageType::PcieCommand => {
                match &PcieCommandRequestHeader::from_bytes((rest, 0)) {
                    Ok(((rest, _), ch)) => ch.handle(ch, mep, subsys, rest, resp, app).await,
                    Err(err) => {
                        debug!(
                            "Unable to parse PcieCommandRequestHeader from message buffer: {err:?}"
                        );
                        // TODO: This is a bad assumption: Can see DekuError::InvalidParam too
                        Err(ResponseStatus::InvalidCommandSize)
                    }
                }
            }
            _ => {
                debug!("Unimplemented NMINT: {:?}", ctx.nmimt);
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
                let pdlu = core::cmp::min(255, 100 * ctlr.write_age / ctlr.write_lifespan);

                let nvmshds = NvmSubsystemHealthDataStructureResponse {
                    nss: {
                        let mut flags = subsys.health.nss;

                        if pprt.cls != crate::pcie::LinkSpeed::Inactive {
                            flags |= NvmSubsystemStatusFlags::P0la;
                        }

                        flags
                    }
                    .into(),
                    sw: {
                        let mut flags = FlagSet::full();

                        if ctlr.ro {
                            flags -= super::SmartWarningFlags::Amro;
                            flags -= super::SmartWarningFlags::Ndr;
                        }

                        if ctlr.temp_range.lower <= ctlr.temp && ctlr.temp <= ctlr.temp_range.upper
                        {
                            flags -= super::SmartWarningFlags::Ttc;
                        }

                        if (100 * ctlr.spare / ctlr.capacity) < ctlr.spare_range.lower {
                            flags -= super::SmartWarningFlags::Ascbt;
                        }

                        flags
                    }
                    .into(),
                    ctemp: ctemp as u8,
                    pldu: pdlu as u8,
                }
                .encode()?;

                let ccs = CompositeControllerStatusDataStructureResponse {
                    ccsf: mep.ccsf.0.bits(),
                }
                .encode()?;

                // CS: See Figure 106, NVMe MI v2.0
                if shsp.cs {
                    mep.ccsf.0.clear();
                }

                send_response(resp, &[&mh.0, &mr.0, &nvmshds.0, &ccs.0]).await;
                Ok(())
            }
            NvmeMiCommandRequestType::ControllerHealthStatusPoll(req) => {
                // MI v2.0, 5.3
                if !rest.is_empty() {
                    debug!("Lost coherence decoding {:?}", ctx.opcode);
                    return Err(ResponseStatus::InvalidCommandSize);
                }

                if !req
                    .functions
                    .0
                    .contains(ControllerFunctionAndReportingFlags::All)
                {
                    debug!("TODO: Implement support for property-based selectors");
                    return Err(ResponseStatus::InternalError);
                }

                if req.functions.0.contains(
                    ControllerFunctionAndReportingFlags::Incf
                        | ControllerFunctionAndReportingFlags::Incpf
                        | ControllerFunctionAndReportingFlags::Incvf,
                ) {
                    debug!("TODO: Implement support for function-base selectors");
                    return Err(ResponseStatus::InternalError);
                }

                assert!(MAX_CONTROLLERS <= u8::MAX as usize);
                if req.maxrent < MAX_CONTROLLERS as u8 {
                    debug!("TODO: Implement response entry constraint");
                    return Err(ResponseStatus::InternalError);
                }

                if req.sctlid > 0 {
                    debug!("TODO: Implement starting controller ID constraint");
                    return Err(ResponseStatus::InternalError);
                }

                let mh = MessageHeader::respond(MessageType::NvmeMiCommand).encode()?;

                let mut chspr = ControllerHealthStatusPollResponse {
                    status: ResponseStatus::Success,
                    rent: 0,
                    body: WireVec::new(),
                };

                for ctlr in &subsys.ctlrs {
                    chspr
                        .body
                        .push(ControllerHealthDataStructure {
                            ctlid: ctlr.id.0,
                            csts: ctlr.csts.into(),
                            ctemp: ctlr.temp,
                            pdlu: core::cmp::min(255, 100 * ctlr.write_age / ctlr.write_lifespan)
                                as u8,
                            spare: <u8>::try_from(100 * ctlr.spare / ctlr.capacity)
                                .map_err(|_| ResponseStatus::InternalError)?
                                .clamp(0, 100),
                            cwarn: {
                                let mut fs = FlagSet::empty();

                                if ctlr.spare < ctlr.spare_range.lower {
                                    fs |= crate::nvme::mi::CriticalWarningFlags::St;
                                }

                                if ctlr.temp < ctlr.temp_range.lower
                                    || ctlr.temp > ctlr.temp_range.upper
                                {
                                    fs |= crate::nvme::mi::CriticalWarningFlags::Taut;
                                }

                                // TODO: RD

                                if ctlr.ro {
                                    fs |= crate::nvme::mi::CriticalWarningFlags::Ro;
                                }

                                // TODO: VMBF
                                // TODO: PMRRO

                                fs.into()
                            },
                            chsc: {
                                let mecs = &mut mep.mecss[ctlr.id.0 as usize];
                                let fs = mecs.chscf;

                                if req.properties.0.contains(ControllerPropertyFlags::Ccf) {
                                    mecs.chscf.clear();
                                    // TODO: Clear NAC, FA, TCIDA in controller health
                                }

                                fs.into()
                            },
                        })
                        .map_err(|_| {
                            debug!("Failed to push ControllerHealthDataStructure");
                            ResponseStatus::InternalError
                        })?;
                }
                chspr.update()?;
                let chspr = chspr.encode()?;

                send_response(resp, &[&mh.0, &chspr.0[..chspr.1]]).await;
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
        mut app: A,
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

                let Some(port) = subsys.ports.get_mut(sifr.portid as usize) else {
                    debug!("Unrecognised port ID: {}", sifr.portid);
                    return Err(ResponseStatus::InvalidParameter);
                };

                let crate::PortType::TwoWire(twprt) = &mut port.typ else {
                    debug!("Port {} is not a TwoWire port: {:?}", sifr.portid, port);
                    return Err(ResponseStatus::InvalidParameter);
                };

                if sifr.sfreq > twprt.msmbfreq.into() {
                    debug!("Unsupported SMBus frequency: {:?}", sifr.sfreq);
                    return Err(ResponseStatus::InvalidParameter);
                }

                app(CommandEffect::SetSmbusFreq {
                    port_id: port.id,
                    freq: sifr.sfreq.into(),
                })
                .await?;
                twprt.smbfreq = sifr.sfreq.into();

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
            NvmeMiConfigurationIdentifierRequestType::MctpTransmissionUnitSize(mtusr) => {
                if !rest.is_empty() {
                    debug!(
                        "Lost synchronisation when decoding ConfigurationSet MCTPTransmissionUnitSize"
                    );
                    return Err(ResponseStatus::InvalidCommandSize);
                }

                let Some(port) = subsys.ports.get_mut(mtusr.dw0_portid as usize) else {
                    debug!("Unrecognised port ID: {}", mtusr.dw0_portid);
                    return Err(ResponseStatus::InvalidParameter);
                };

                app(CommandEffect::SetMtu {
                    port_id: port.id,
                    mtus: mtusr.dw1_mtus as usize,
                })
                .await?;
                port.mtus = mtusr.dw1_mtus;

                let mh = MessageHeader::respond(MessageType::NvmeMiCommand).encode()?;
                let status = [0u8; 4];

                send_response(resp, &[&mh.0, &status]).await;
                Ok(())
            }
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

                let Some(port) = subsys.ports.get(sifr.portid as usize) else {
                    debug!("Unrecognised port ID: {}", sifr.portid);
                    return Err(ResponseStatus::InvalidParameter);
                };

                let crate::PortType::TwoWire(twprt) = port.typ else {
                    debug!("Port {} is not a TwoWire port: {:?}", sifr.portid, port);
                    return Err(ResponseStatus::InvalidParameter);
                };

                let mh = MessageHeader::respond(MessageType::NvmeMiCommand).encode()?;

                let fr = GetSmbusI2cFrequencyResponse {
                    status: ResponseStatus::Success,
                    sfreq: twprt.smbfreq.into(),
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
            NvmeMiConfigurationIdentifierRequestType::MctpTransmissionUnitSize(mtusr) => {
                if !rest.is_empty() {
                    debug!(
                        "Lost synchronisation when decoding ConfigurationGet MCTPTransmissionUnitSize"
                    );
                    return Err(ResponseStatus::InvalidCommandSize);
                }

                let Some(port) = subsys.ports.get(mtusr.dw0_portid as usize) else {
                    debug!("Unrecognised port ID: {}", mtusr.dw0_portid);
                    return Err(ResponseStatus::InvalidParameter);
                };

                let mh = MessageHeader::respond(MessageType::NvmeMiCommand).encode()?;

                let fr = GetMctpTransmissionUnitSizeResponse {
                    status: ResponseStatus::Success,
                    mr_mtus: port.mtus,
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
                    prttyp: Into::<crate::nvme::mi::PortType>::into(&port.typ),
                    prtcap: {
                        let mut flags = FlagSet::empty();

                        if port.caps.ciaps {
                            flags |= PortCapabilityFlags::Ciaps;
                        }

                        if port.caps.aems {
                            flags |= PortCapabilityFlags::Aems;
                        }

                        flags
                    }
                    .into(),
                    mmtus: port.mmtus,
                    mebs: port.mebs,
                }
                .encode()?;

                match port.typ {
                    crate::PortType::Pcie(pprt) => {
                        let ppd = PciePortDataResponse {
                            pciemps: pprt.mps.into(),
                            pcieslsv: {
                                PcieSupportedLinkSpeeds::Gts2p5
                                    | PcieSupportedLinkSpeeds::Gts5
                                    | PcieSupportedLinkSpeeds::Gts8
                                    | PcieSupportedLinkSpeeds::Gts16
                                    | PcieSupportedLinkSpeeds::Gts32
                                    | PcieSupportedLinkSpeeds::Gts64
                            }
                            .into(),
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
                            mvpdfreq: twprt.mvpdfreq.into(),
                            cmeaddr: twprt.cmeaddr,
                            twprt_i3csprt: twprt.i3csprt,
                            twprt_msmbfreq: twprt.msmbfreq.into(),
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
                    prii_pcieriv: true,
                    pri_pcibn: pprt.b,
                    pri_pcidn: pprt.d,
                    pri_pcifn: pprt.f,
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
            AdminCommandRequestType::GetLogPage(req) => {
                req.handle(ctx, mep, subsys, rest, resp, app).await
            }
            AdminCommandRequestType::Identify(req) => {
                req.handle(ctx, mep, subsys, rest, resp, app).await
            }
            AdminCommandRequestType::NamespaceAttachement(req) => {
                req.handle(ctx, mep, subsys, rest, resp, app).await
            }
            AdminCommandRequestType::NamespaceManagement(req) => {
                req.handle(ctx, mep, subsys, rest, resp, app).await
            }
            AdminCommandRequestType::FormatNvm(req) => {
                req.handle(ctx, mep, subsys, rest, resp, app).await
            }
            AdminCommandRequestType::Sanitize(req) => {
                req.handle(ctx, mep, subsys, rest, resp, app).await
            }
            AdminCommandRequestType::DeleteIoSubmissionQueue
            | AdminCommandRequestType::CreateIoSubmissionQueue
            | AdminCommandRequestType::DeleteIoCompletionQueue
            | AdminCommandRequestType::CreateIoCompletionQueue
            | AdminCommandRequestType::Abort
            | AdminCommandRequestType::AsynchronousEventRequest
            | AdminCommandRequestType::KeepAlive
            | AdminCommandRequestType::DirectiveSend
            | AdminCommandRequestType::DirectiveReceive
            | AdminCommandRequestType::NvmeMiSend
            | AdminCommandRequestType::NvmeMiReceive
            | AdminCommandRequestType::DiscoveryInformationManagement
            | AdminCommandRequestType::FabricZoningReceive
            | AdminCommandRequestType::FabricZoningLookup
            | AdminCommandRequestType::FabricZoningSend
            | AdminCommandRequestType::SendDiscoveryLogPage
            | AdminCommandRequestType::TrackSend
            | AdminCommandRequestType::TrackReceive
            | AdminCommandRequestType::MigrationSend
            | AdminCommandRequestType::MigrationReceive
            | AdminCommandRequestType::ControllerDataQueue
            | AdminCommandRequestType::DoorbellBufferConfig
            | AdminCommandRequestType::FabricsCommands
            | AdminCommandRequestType::LoadProgram
            | AdminCommandRequestType::ProgramActivationManagement
            | AdminCommandRequestType::MemoryRangeSetManagement => {
                debug!("Prohibited MI admin command opcode: {:?}", self.op.id());
                Err(ResponseStatus::InvalidCommandOpcode)
            }
            _ => {
                debug!("Unimplemented OPCODE: {:?}", self.op.id());
                Err(ResponseStatus::InternalError)
            }
        }
    }
}

fn admin_constrain_body(dofst: u32, dlen: u32, body: &[u8]) -> Result<&[u8], ResponseStatus> {
    // See Figure 136 in NVMe MI v2.0

    // Use send_response() instead
    assert!(!body.is_empty());

    // TODO: propagate PEL for all errors
    if dofst & 3 != 0 {
        debug!("Unnatural DOFST value: {dofst:?}");
        return Err(ResponseStatus::InvalidParameter);
    }

    // FIXME: casts
    let dofst = dofst as usize;
    let dlen = dlen as usize;

    if dofst >= body.len() {
        debug!("DOFST value exceeds unconstrained response length: {dofst:?}");
        return Err(ResponseStatus::InvalidParameter);
    }

    if dlen & 3 != 0 {
        debug!("Unnatural DLEN value: {dlen:?}");
        return Err(ResponseStatus::InvalidParameter);
    }

    if dlen > 4096 {
        debug!("DLEN too large: {dlen:?}");
        return Err(ResponseStatus::InvalidParameter);
    }

    if dlen > body.len() || body.len() - dlen < dofst {
        debug!(
            "Requested response data range beginning at {:?} for {:?} bytes exceeds bounds of unconstrained response length {:?}",
            dofst,
            dlen,
            body.len()
        );
        return Err(ResponseStatus::InvalidParameter);
    }

    if dlen == 0 {
        debug!("DLEN cleared for command with data response: {dlen:?}");
        return Err(ResponseStatus::InvalidParameter);
    }

    let end = dofst + dlen;
    Ok(&body[dofst..end])
}

async fn admin_send_response_body<C>(resp: &mut C, body: &[u8]) -> Result<(), ResponseStatus>
where
    C: AsyncRespChannel,
{
    let mh = MessageHeader::respond(MessageType::NvmeAdminCommand).encode()?;

    let acrh = AdminCommandResponseHeader {
        status: ResponseStatus::Success,
        cqedw0: 0,
        cqedw1: 0,
        cqedw3: AdminIoCqeStatusType::GenericCommandStatus(
            AdminIoCqeGenericCommandStatus::SuccessfulCompletion,
        )
        .into(),
    }
    .encode()?;

    send_response(resp, &[&mh.0, &acrh.0, body]).await;

    Ok(())
}

async fn admin_send_status<C>(
    resp: &mut C,
    status: AdminIoCqeStatusType,
) -> Result<(), ResponseStatus>
where
    C: AsyncRespChannel,
{
    let mh = MessageHeader::respond(MessageType::NvmeAdminCommand).encode()?;

    let acrh = AdminCommandResponseHeader {
        status: ResponseStatus::Success,
        cqedw0: 0,
        cqedw1: 0,
        cqedw3: status.into(),
    }
    .encode()?;

    send_response(resp, &[&mh.0, &acrh.0]).await;

    Ok(())
}

impl RequestHandler for AdminGetLogPageRequest {
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
        if !rest.is_empty() {
            debug!("Invalid request size for Admin Get Log Page");
            return Err(ResponseStatus::InvalidCommandSize);
        }

        // Base v2.1, 5.1.12, Figure 202
        match &self.req {
            AdminGetLogPageLidRequestType::SupportedLogPages
            | AdminGetLogPageLidRequestType::FeatureIdentifiersSupportedAndEffects => {
                if self.csi != 0 {
                    debug!("Support CSI");
                    return admin_send_status(
                        resp,
                        AdminIoCqeStatusType::GenericCommandStatus(
                            AdminIoCqeGenericCommandStatus::InternalError,
                        ),
                    )
                    .await;
                }
            }
            AdminGetLogPageLidRequestType::ErrorInformation
            | AdminGetLogPageLidRequestType::SmartHealthInformation
            | AdminGetLogPageLidRequestType::SanitizeStatus => (),
        };

        let Some(ctlr) = subsys.ctlrs.get(ctx.ctlid as usize) else {
            debug!("Unrecognised CTLID: {}", ctx.ctlid);
            return admin_send_status(
                resp,
                AdminIoCqeStatusType::GenericCommandStatus(
                    AdminIoCqeGenericCommandStatus::InvalidFieldInCommand,
                ),
            )
            .await;
        };

        let Some(flags) = ctlr.lsaes.get(self.req.id() as usize) else {
            debug!(
                "LSAE mismatch with known LID {:?} on controller {}",
                self.req, ctlr.id.0
            );
            return admin_send_status(
                resp,
                AdminIoCqeStatusType::GenericCommandStatus(
                    AdminIoCqeGenericCommandStatus::InvalidFieldInCommand,
                ),
            )
            .await;
        };

        // Base v2.1, 5.1.12
        if self.ot != 0 {
            // Base v2.1, 5.1.12, Figure 199, LPOL
            if flags.contains(LidSupportedAndEffectsFlags::Ios) {
                todo!("Add OT support");
            } else {
                return admin_send_status(
                    resp,
                    AdminIoCqeStatusType::GenericCommandStatus(
                        AdminIoCqeGenericCommandStatus::InvalidFieldInCommand,
                    ),
                )
                .await;
            }
        }

        // Base v2.1, 5.1.12
        let _numdw = if ctlr.lpa.contains(LogPageAttributes::Lpeds) {
            todo!("Add support for extended NUMDL / NUMDU")
        } else {
            self.numdw & ((1u32 << 13) - 1)
        };

        // TODO: RAE processing

        match &self.req {
            AdminGetLogPageLidRequestType::SupportedLogPages => {
                if (self.numdw + 1) * 4 != 1024 {
                    debug!("Implement support for NUMDL / NUMDU");
                    return admin_send_status(
                        resp,
                        AdminIoCqeStatusType::GenericCommandStatus(
                            AdminIoCqeGenericCommandStatus::InternalError,
                        ),
                    )
                    .await;
                }

                let mut lsids = WireVec::new();
                for e in ctlr.lsaes {
                    let lsaeds = LidSupportedAndEffectsDataStructure {
                        flags: e.into(),
                        lidsp: 0,
                    };
                    lsids.push(lsaeds).map_err(|_| {
                        debug!("Failed to push LidSupportedAndEffectsDataStructure");
                        ResponseStatus::InternalError
                    })?;
                }

                let slpr = AdminGetLogPageSupportedLogPagesResponse { lsids }.encode()?;

                admin_send_response_body(
                    resp,
                    admin_constrain_body(self.dofst, self.dlen, &slpr.0)?,
                )
                .await
            }
            AdminGetLogPageLidRequestType::ErrorInformation => {
                if (self.numdw + 1) * 4 != 64 {
                    debug!("Implement support for NUMDL / NUMDU");
                    return admin_send_status(
                        resp,
                        AdminIoCqeStatusType::GenericCommandStatus(
                            AdminIoCqeGenericCommandStatus::InternalError,
                        ),
                    )
                    .await;
                }
                admin_send_response_body(
                    resp,
                    admin_constrain_body(self.dofst, self.dlen, &[0u8; 64])?,
                )
                .await
            }
            AdminGetLogPageLidRequestType::SmartHealthInformation => {
                if (self.numdw + 1) * 4 != 512 {
                    debug!("Implement support for NUMDL / NUMDU");
                    return admin_send_status(
                        resp,
                        AdminIoCqeStatusType::GenericCommandStatus(
                            AdminIoCqeGenericCommandStatus::InternalError,
                        ),
                    )
                    .await;
                }

                // Base v2.1, 5.1.2, Figure 199
                let lpol = self.lpo & !3u64;
                if lpol > 512 {
                    return admin_send_status(
                        resp,
                        AdminIoCqeStatusType::GenericCommandStatus(
                            AdminIoCqeGenericCommandStatus::InvalidFieldInCommand,
                        ),
                    )
                    .await;
                }

                if self.nsid != 0 && self.nsid != u32::MAX {
                    if ctlr.lpa.contains(LogPageAttributes::Smarts) {
                        todo!();
                    } else {
                        return admin_send_status(
                            resp,
                            AdminIoCqeStatusType::GenericCommandStatus(
                                AdminIoCqeGenericCommandStatus::InvalidFieldInCommand,
                            ),
                        )
                        .await;
                    }
                }

                let shilpr = SmartHealthInformationLogPageResponse {
                    cw: {
                        let mut fs = FlagSet::empty();

                        if ctlr.spare < ctlr.spare_range.lower {
                            fs |= crate::nvme::CriticalWarningFlags::Ascbt;
                        }

                        if ctlr.temp < ctlr.temp_range.lower || ctlr.temp > ctlr.temp_range.upper {
                            fs |= crate::nvme::CriticalWarningFlags::Ttc;
                        }

                        // TODO: NDR

                        if ctlr.ro {
                            fs |= crate::nvme::CriticalWarningFlags::Amro;
                        }

                        // TODO: VMBF
                        // TODO: PMRRO

                        fs.into()
                    },
                    ctemp: ctlr.temp,
                    avsp: <u8>::try_from(100 * ctlr.spare / ctlr.capacity)
                        .map_err(|_| ResponseStatus::InternalError)?
                        .clamp(0, 100),
                    avspt: <u8>::try_from(100 * ctlr.spare_range.lower / ctlr.capacity)
                        .map_err(|_| ResponseStatus::InternalError)?
                        .clamp(0, 100),
                    pused: (100 * ctlr.write_age / ctlr.write_lifespan).clamp(0, 255) as u8,
                    egcws: FlagSet::empty().into(), // TODO: Endurance Groups
                    dur: 0,
                    duw: 0,
                    hrc: 0,
                    hwc: 0,
                    cbt: 0,
                    pwrc: 0, // TOOD: track power cycles
                    poh: 0,  // TODO: Track power on hours
                    upl: 0,  // TODO: Track unexpected power loss
                    mdie: 0,
                    neile: 0, // TODO: Track error log entries
                    wctt: 0,  // TODO: Track temperature excursions
                    cctt: 0,  // TODO: track temperature excursions
                    tsen: [ctlr.temp; 8],
                    tmttc: [0; 2],
                    tttmt: [0; 2],
                }
                .encode()?;

                admin_send_response_body(
                    resp,
                    admin_constrain_body(self.dofst, self.dlen, &shilpr.0)?,
                )
                .await
            }
            AdminGetLogPageLidRequestType::FeatureIdentifiersSupportedAndEffects => {
                if (self.numdw + 1) * 4 != 1024 {
                    debug!("Implement support for NUMDL / NUMDU");
                    return admin_send_status(
                        resp,
                        AdminIoCqeStatusType::GenericCommandStatus(
                            AdminIoCqeGenericCommandStatus::InternalError,
                        ),
                    )
                    .await;
                }

                admin_send_response_body(
                    resp,
                    admin_constrain_body(
                        self.dofst,
                        self.dlen,
                        // TODO: Support feature reporting
                        &[0u8; 1024],
                    )?,
                )
                .await
            }
            AdminGetLogPageLidRequestType::SanitizeStatus => {
                if (self.numdw + 1) * 4 != 512 {
                    debug!("Implement support for NUMDL / NUMDU");
                    return admin_send_status(
                        resp,
                        AdminIoCqeStatusType::GenericCommandStatus(
                            AdminIoCqeGenericCommandStatus::InternalError,
                        ),
                    )
                    .await;
                }

                let sslpr = SanitizeStatusLogPageResponse {
                    sprog: u16::MAX,
                    sstat: subsys.sstat,
                    scdw10: subsys.sconf.unwrap_or_default(),
                    eto: u32::MAX,
                    etbe: u32::MAX,
                    etce: u32::MAX,
                    etodmm: u32::MAX,
                    etbenmm: u32::MAX,
                    etcenmm: u32::MAX,
                    etpvds: u32::MAX,
                    ssi: subsys.ssi,
                }
                .encode()?;

                admin_send_response_body(
                    resp,
                    admin_constrain_body(self.dofst, self.dlen, &sslpr.0)?,
                )
                .await
            }
        }
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
        if !rest.is_empty() {
            debug!("Invalid request size for Admin Identify");
            return Err(ResponseStatus::InvalidCommandSize);
        }

        let res = match &self.req {
            AdminIdentifyCnsRequestType::NvmIdentifyNamespace => {
                match NamespaceId(self.nsid).disposition(subsys) {
                    NamespaceIdDisposition::Invalid => {
                        debug!("Invalid NSID: {}", self.nsid);
                        Err(AdminIoCqeGenericCommandStatus::InvalidNamespaceOrFormat)
                    }
                    NamespaceIdDisposition::Broadcast => {
                        AdminIdentifyNvmIdentifyNamespaceResponse {
                            lbaf0_lbads: 9, // TODO: Tie to controller model
                            ..Default::default()
                        }
                        .encode()
                        .map_err(AdminIoCqeGenericCommandStatus::from)
                    }
                    NamespaceIdDisposition::Unallocated => {
                        debug!("Unallocated NSID: {}", self.nsid);
                        Err(AdminIoCqeGenericCommandStatus::InvalidNamespaceOrFormat)
                    }
                    NamespaceIdDisposition::Inactive(_) => {
                        AdminIdentifyNvmIdentifyNamespaceResponse::default()
                            .encode()
                            .map_err(AdminIoCqeGenericCommandStatus::from)
                    }
                    // 4.1.5.1 NVM Command Set Spec, v1.0c
                    NamespaceIdDisposition::Active(ns) => {
                        Into::<AdminIdentifyNvmIdentifyNamespaceResponse>::into(ns)
                            .encode()
                            .map_err(AdminIoCqeGenericCommandStatus::from)
                    }
                }
            }
            AdminIdentifyCnsRequestType::IdentifyController => {
                if let Some(ctlr) = subsys.ctlrs.get(ctx.ctlid as usize) {
                    AdminIdentifyControllerResponse {
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
                        cmic: {
                            let mut flags = FlagSet::empty();

                            if subsys.ctlrs.len() > 1 {
                                flags |=
                                    ControllerMultipathIoNamespaceSharingCapabilityFlags::Mctrs;
                            }

                            if subsys.ports.len() > 1 {
                                flags |=
                                    ControllerMultipathIoNamespaceSharingCapabilityFlags::Mports;
                            }

                            flags
                        }
                        .into(),
                        mdts: 0,
                        cntlid: ctlr.id.0,
                        ver: 0,
                        rtd3r: 0,
                        rtd3e: 0,
                        oaes: 0,
                        // TODO: Tie to data model
                        ctratt: {
                            let mut flags = FlagSet::empty();

                            flags -= ControllerAttributeFlags::Nsets;
                            flags -= ControllerAttributeFlags::Egs;
                            flags -= ControllerAttributeFlags::Deg;
                            flags -= ControllerAttributeFlags::Dnvms;

                            flags
                        }
                        .into(),
                        cntrltype: ctlr.cntrltype.into(),
                        // TODO: Tie to data model
                        nvmsr: { FlagSet::empty() | NvmSubsystemReportFlags::Nvmesd }.into(),
                        vwci: 0,
                        mec: {
                            let mut flags = FlagSet::empty();

                            if subsys
                                .ports
                                .iter()
                                .any(|p| matches!(p.typ, crate::PortType::Pcie(_)))
                            {
                                flags |= ManagementEndpointCapabilityFlags::Pcieme;
                            }

                            if subsys
                                .ports
                                .iter()
                                .any(|p| matches!(p.typ, crate::PortType::TwoWire(_)))
                            {
                                flags |= ManagementEndpointCapabilityFlags::Twpme;
                            }

                            flags
                        }
                        .into(),
                        ocas: 0,
                        acl: 0,
                        aerl: 0,
                        frmw: 0,
                        lpa: ctlr.lpa.into(),
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
                        nn: NamespaceId::max(subsys),
                        oncs: 0,
                        fuses: 0,
                        fna: ctlr.fna.into(),
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
                        apsta: 0,
                        sanicap: crate::nvme::SanitizeCapabilities {
                            caps: subsys.sanicap.into(),
                            nodmmas: subsys.nodmmas,
                        },
                    }
                    .encode()
                    .map_err(AdminIoCqeGenericCommandStatus::from)
                } else {
                    debug!("No such CTLID: {}", ctx.ctlid);
                    Err(AdminIoCqeGenericCommandStatus::InvalidFieldInCommand)
                }
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
                aianidlr
                    .encode()
                    .map_err(AdminIoCqeGenericCommandStatus::from)
            }
            AdminIdentifyCnsRequestType::NamespaceIdentificationDescriptorList => {
                // 5.1.13.2.3, Base v2.1
                match NamespaceId(self.nsid).disposition(subsys) {
                    NamespaceIdDisposition::Invalid => {
                        if self.nsid == u32::MAX - 1 {
                            debug!(
                                "Unacceptable NSID for Namespace Identification Descriptor List"
                            );
                        } else {
                            debug!("Invalid NSID: {}", self.nsid);
                        }
                        Err(AdminIoCqeGenericCommandStatus::InvalidNamespaceOrFormat)
                    }
                    NamespaceIdDisposition::Broadcast => {
                        debug!("Invalid NSID: {}", self.nsid);
                        Err(AdminIoCqeGenericCommandStatus::InvalidNamespaceOrFormat)
                    }
                    NamespaceIdDisposition::Unallocated => {
                        debug!("Unallocated NSID: {}", self.nsid);
                        Err(AdminIoCqeGenericCommandStatus::InvalidNamespaceOrFormat)
                    }
                    NamespaceIdDisposition::Inactive(ns) | NamespaceIdDisposition::Active(ns) => {
                        AdminIdentifyNamespaceIdentificationDescriptorListResponse {
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
                        .encode()
                        .map_err(AdminIoCqeGenericCommandStatus::from)
                    }
                }
            }
            AdminIdentifyCnsRequestType::AllocatedNamespaceIdList => {
                // 5.1.13.2.9, Base v2.1
                if self.nsid >= u32::MAX - 1 {
                    debug!("Invalid NSID");
                    return Err(ResponseStatus::InvalidParameter);
                }

                assert!(NamespaceId::max(subsys) < (4096 / core::mem::size_of::<u32>()) as u32);
                AdminIdentifyAllocatedNamespaceIdListResponse {
                    nsid: {
                        let mut allocated: heapless::Vec<u32, MAX_NAMESPACES> = subsys
                            .nss
                            .iter()
                            .map(|ns| ns.id.0)
                            .filter(|nsid| *nsid > self.nsid)
                            .collect();
                        allocated.sort_unstable();
                        let mut vec = WireVec::new();
                        for nsid in allocated {
                            if vec.push(nsid).is_err() {
                                debug!("Failed to insert NSID {nsid}");
                                return Err(ResponseStatus::InternalError);
                            };
                        }
                        vec
                    },
                }
                .encode()
                .map_err(AdminIoCqeGenericCommandStatus::from)
            }
            AdminIdentifyCnsRequestType::IdentifyNamespaceForAllocatedNamespaceId => {
                // Base v2.1, 5.1.13.2.10
                match NamespaceId(self.nsid).disposition(subsys) {
                    NamespaceIdDisposition::Invalid | NamespaceIdDisposition::Broadcast => {
                        Err(AdminIoCqeGenericCommandStatus::InvalidNamespaceOrFormat)
                    }
                    NamespaceIdDisposition::Unallocated => {
                        AdminIdentifyNvmIdentifyNamespaceResponse::default()
                            .encode()
                            .map_err(AdminIoCqeGenericCommandStatus::from)
                    }
                    NamespaceIdDisposition::Inactive(ns) | NamespaceIdDisposition::Active(ns) => {
                        let ainvminr: AdminIdentifyNvmIdentifyNamespaceResponse = ns.into();
                        ainvminr
                            .encode()
                            .map_err(AdminIoCqeGenericCommandStatus::from)
                    }
                }
            }
            AdminIdentifyCnsRequestType::NamespaceAttachedControllerList => {
                match NamespaceId(self.nsid).disposition(subsys) {
                    NamespaceIdDisposition::Invalid => ControllerListResponse::new()
                        .encode()
                        .map_err(AdminIoCqeGenericCommandStatus::from),
                    NamespaceIdDisposition::Broadcast => {
                        Err(AdminIoCqeGenericCommandStatus::InvalidFieldInCommand)
                    }
                    NamespaceIdDisposition::Unallocated | NamespaceIdDisposition::Inactive(_) => {
                        ControllerListResponse::new()
                            .encode()
                            .map_err(AdminIoCqeGenericCommandStatus::from)
                    }
                    NamespaceIdDisposition::Active(ns) => {
                        let mut clr = ControllerListResponse::new();
                        for cid in subsys.ctlrs.iter().filter_map(|c| {
                            if c.id.0 >= self.cntid && c.active_ns.contains(&ns.id) {
                                Some(c.id)
                            } else {
                                None
                            }
                        }) {
                            if let Err(id) = clr.ids.push(cid.0) {
                                debug!("Failed to push controller ID {id}");
                                return Err(ResponseStatus::InternalError);
                            }
                        }
                        clr.update()?;
                        clr.encode().map_err(AdminIoCqeGenericCommandStatus::from)
                    }
                }
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
                cl.encode().map_err(AdminIoCqeGenericCommandStatus::from)
            }
            AdminIdentifyCnsRequestType::SecondaryControllerList => {
                let Some(ctlr) = subsys.ctlrs.get(ctx.ctlid as usize) else {
                    debug!("No such CTLID: {}", ctx.ctlid);
                    return Err(ResponseStatus::InvalidParameter);
                };

                if !ctlr.secondaries.is_empty() {
                    todo!("Support listing secondary controllers");
                }

                Ok(([0u8; 4096], 4096usize))
            }
            _ => {
                debug!("Unimplemented CNS: {self:?}");
                return Err(ResponseStatus::InternalError);
            }
        };

        match res {
            Ok(response) => {
                admin_send_response_body(
                    resp,
                    admin_constrain_body(self.dofst, self.dlen, &response.0)?,
                )
                .await
            }
            Err(err) => {
                admin_send_status(resp, AdminIoCqeStatusType::GenericCommandStatus(err)).await
            }
        }
    }
}

impl RequestHandler for AdminNamespaceManagementRequest {
    type Ctx = AdminCommandRequestHeader;

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
        #[repr(u8)]
        enum CommandSpecificStatus {
            NamespaceIdentifierUnavailable = 0x16,
        }
        unsafe impl Discriminant<u8> for CommandSpecificStatus {}

        if !rest.is_empty() {
            debug!("Invalid request size for Admin Identify");
            return Err(ResponseStatus::InvalidCommandSize);
        }

        match &self.req {
            crate::nvme::mi::AdminNamespaceManagementSelect::Create(req) => {
                if self.csi != 0 {
                    debug!("Support CSI {}", self.csi);
                    return admin_send_status(
                        resp,
                        AdminIoCqeStatusType::GenericCommandStatus(
                            AdminIoCqeGenericCommandStatus::InternalError,
                        ),
                    )
                    .await;
                }

                let Ok(nsid) = subsys.add_namespace(req.ncap) else {
                    debug!("Failed to create namespace");
                    // TODO: Implement Base v2.1, 5.1.21.1, Figure 370
                    return admin_send_status(
                        resp,
                        AdminIoCqeStatusType::GenericCommandStatus(
                            AdminIoCqeGenericCommandStatus::InternalError,
                        ),
                    )
                    .await;
                };
                let mh = MessageHeader::respond(MessageType::NvmeAdminCommand).encode()?;

                let acrh = AdminCommandResponseHeader {
                    status: ResponseStatus::Success,
                    cqedw0: nsid.0,
                    cqedw1: 0,
                    cqedw3: AdminIoCqeStatusType::GenericCommandStatus(
                        AdminIoCqeGenericCommandStatus::SuccessfulCompletion,
                    )
                    .into(),
                }
                .encode()?;

                send_response(resp, &[&mh.0, &acrh.0]).await;

                Ok(())
            }
            crate::nvme::mi::AdminNamespaceManagementSelect::Delete => {
                let res = subsys.remove_namespace(NamespaceId(self.nsid));
                let status = match &res {
                    Ok(_) => AdminIoCqeStatusType::GenericCommandStatus(
                        AdminIoCqeGenericCommandStatus::SuccessfulCompletion,
                    ),
                    Err(err) => {
                        assert_eq!(err, &SubsystemError::NamespaceIdentifierUnavailable);
                        AdminIoCqeStatusType::CommandSpecificStatus(
                            CommandSpecificStatus::NamespaceIdentifierUnavailable.id(),
                        )
                    }
                };
                let mh = MessageHeader::respond(MessageType::NvmeAdminCommand).encode()?;

                let acrh = AdminCommandResponseHeader {
                    status: ResponseStatus::Success,
                    cqedw0: self.nsid, // TODO: Base v2.1, 5.1.21 unclear, test against hardware
                    cqedw1: 0,
                    cqedw3: status.into(),
                }
                .encode()?;

                send_response(resp, &[&mh.0, &acrh.0]).await;

                Ok(())
            }
        }
    }
}

impl RequestHandler for AdminNamespaceAttachmentRequest {
    type Ctx = AdminCommandRequestHeader;

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
        // Base v2.1, 5.1.20.1, Figure 365
        #[repr(u8)]
        enum CommandSpecificStatus {
            NamespaceAlreadyAttached = 0x18,
            NamespaceNotAttached = 0x1a,
            ControllerListInvalid = 0x1c,
            NamespaceAttachmentLimitExceeded = 0x27,
        }
        unsafe impl Discriminant<u8> for CommandSpecificStatus {}

        impl From<ControllerError> for CommandSpecificStatus {
            fn from(value: ControllerError) -> Self {
                match value {
                    ControllerError::NamespaceAlreadyAttached => Self::NamespaceAlreadyAttached,
                    ControllerError::NamespaceAttachmentLimitExceeded => {
                        Self::NamespaceAttachmentLimitExceeded
                    }
                    ControllerError::NamespaceNotAttached => Self::NamespaceNotAttached,
                }
            }
        }

        // SAFETY: Protected in parsing by DekuError::InvalidParam
        debug_assert!(self.body.numids <= 2047);

        let expected = (2047 - (self.body.numids as usize)) * core::mem::size_of::<u16>();
        if rest.len() != expected {
            debug!(
                "Invalid request size for Admin Namespace Attachment: Found {}, expected {expected}",
                rest.len()
            );
            return Err(ResponseStatus::InvalidCommandSize);
        }

        if self.nsid == u32::MAX {
            debug!("Refusing to perform {:?} for broadcast NSID", self.sel);
            return admin_send_status(
                resp,
                AdminIoCqeStatusType::GenericCommandStatus(
                    AdminIoCqeGenericCommandStatus::InvalidFieldInCommand,
                ),
            )
            .await;
        }

        // TODO: Handle MAXCNA

        let mut status = AdminIoCqeStatusType::GenericCommandStatus(
            AdminIoCqeGenericCommandStatus::SuccessfulCompletion,
        );

        let action = match &self.sel {
            crate::nvme::AdminNamespaceAttachmentSelect::ControllerAttach => {
                |ctlr: &mut Controller, ns: NamespaceId| ctlr.attach_namespace(ns)
            }
            crate::nvme::AdminNamespaceAttachmentSelect::ControllerDetach => {
                |ctlr: &mut Controller, ns: NamespaceId| ctlr.detach_namespace(ns)
            }
        };

        for cid in &self.body.ids.0 {
            let Some(ctlr) = subsys.ctlrs.get_mut(*cid as usize) else {
                debug!("Unrecognised controller ID: {cid}");
                status = AdminIoCqeStatusType::CommandSpecificStatus(
                    CommandSpecificStatus::ControllerListInvalid.id(),
                );
                break;
            };

            // TODO: Allow addition of non-IO controllers
            if ctlr.cntrltype != ControllerType::Io {
                debug!(
                    "Require {:?} controller type, have {:?}",
                    ControllerType::Io,
                    ctlr.cntrltype
                );
                status = AdminIoCqeStatusType::CommandSpecificStatus(
                    CommandSpecificStatus::ControllerListInvalid.id(),
                );
                break;
            }

            // TODO: Handle Namespace Is Private
            // TODO: Handle I/O Command Set Not Supported
            // TODO: Handle I/O Command Set Not Enabled

            // XXX: Should this be transactional? Two loops?
            if let Err(err) = action(ctlr, NamespaceId(self.nsid)) {
                let err: CommandSpecificStatus = err.into();
                status = AdminIoCqeStatusType::CommandSpecificStatus(err.id());
                break;
            }
        }

        let mh = MessageHeader::respond(MessageType::NvmeAdminCommand).encode()?;

        let acrh = AdminCommandResponseHeader {
            status: ResponseStatus::Success,
            cqedw0: self.nsid,
            cqedw1: 0,
            cqedw3: status.into(),
        }
        .encode()?;

        send_response(resp, &[&mh.0, &acrh.0]).await;

        Ok(())
    }
}

impl RequestHandler for AdminSanitizeRequest {
    type Ctx = AdminCommandRequestHeader;

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
        if !rest.is_empty() {
            debug!("Invalid request size for Admin Sanitize");
            return Err(ResponseStatus::InvalidCommandSize);
        }

        if subsys.sanicap.contains(SanitizeCapabilityFlags::Ndi) && self.config.ndas {
            debug!("Request for No-Deallocate After Sanitize when No-Deallocate is inhibited");
            return admin_send_status(
                resp,
                AdminIoCqeStatusType::GenericCommandStatus(
                    AdminIoCqeGenericCommandStatus::InvalidFieldInCommand,
                ),
            )
            .await;
        }

        // TODO: Implement action latency, progress state machine, error states
        match self.config.sanact {
            SanitizeAction::Reserved => Err(ResponseStatus::InvalidParameter),
            SanitizeAction::ExitFailureMode | SanitizeAction::ExitMediaVerificationState => {
                if subsys.ssi.sans != SanitizeState::Idle {
                    todo!("Implement sanitize state machine!");
                }
                admin_send_response_body(resp, &[]).await
            }
            SanitizeAction::StartBlockErase | SanitizeAction::StartCryptoErase => {
                subsys.ssi = SanitizeStateInformation {
                    sans: SanitizeState::Idle,
                    fails: 0,
                };
                subsys.sstat = SanitizeStatus {
                    opc: 0,
                    sos: SanitizeOperationStatus::Sanitized,
                    mvcncled: false,
                    gde: true,
                };
                subsys.sconf = Some(self.config);

                admin_send_response_body(resp, &[]).await
            }
            SanitizeAction::StartOverwrite => {
                subsys.ssi = SanitizeStateInformation {
                    sans: SanitizeState::Idle,
                    fails: 0,
                };
                subsys.sstat = SanitizeStatus {
                    opc: self.config.owpass,
                    sos: SanitizeOperationStatus::Sanitized,
                    mvcncled: false,
                    gde: true,
                };
                subsys.sconf = Some(self.config);

                admin_send_response_body(resp, &[]).await
            }
        }
    }
}

impl RequestHandler for AdminFormatNvmRequest {
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
        if !rest.is_empty() {
            debug!("Invalid request size for Admin Format NVM");
            return Err(ResponseStatus::InvalidCommandSize);
        }

        let Some(ctlr) = subsys.ctlrs.iter().find(|c| c.id.0 == ctx.ctlid) else {
            debug!("Unrecognised CTLID: {}", ctx.ctlid);
            return admin_send_status(
                resp,
                AdminIoCqeStatusType::GenericCommandStatus(
                    AdminIoCqeGenericCommandStatus::InvalidFieldInCommand,
                ),
            )
            .await;
        };

        if self.config.lbafi() != 0 {
            debug!("Unsupported LBA format index: {}", self.config.lbafi());
            return admin_send_status(
                resp,
                AdminIoCqeStatusType::GenericCommandStatus(
                    AdminIoCqeGenericCommandStatus::InvalidFieldInCommand,
                ),
            )
            .await;
        }

        if !ctlr.active_ns.iter().any(|ns| ns.0 == self.nsid) && self.nsid != u32::MAX {
            debug!("Unrecognised NSID: {}", self.nsid);
            return admin_send_status(
                resp,
                AdminIoCqeStatusType::GenericCommandStatus(
                    AdminIoCqeGenericCommandStatus::InvalidFieldInCommand,
                ),
            )
            .await;
        }

        // TODO: handle config.ses

        admin_send_response_body(resp, &[]).await
    }
}

impl RequestHandler for PcieCommandRequestHeader {
    type Ctx = PcieCommandRequestHeader;

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
        A: AsyncFnMut(crate::CommandEffect) -> Result<(), CommandEffectError>,
        C: mctp::AsyncRespChannel,
    {
        match &ctx.op {
            super::PcieCommandRequestType::ConfigurationRead(req) => {
                if !rest.is_empty() {
                    debug!("Invalid request size for PcieCommand");
                    return Err(ResponseStatus::InvalidCommandSize);
                }

                if req.length != 4096 {
                    debug!("Implement length support");
                    return Err(ResponseStatus::InternalError);
                }

                if req.offset != 0 {
                    debug!("Implement offset support");
                    return Err(ResponseStatus::InternalError);
                }

                let mh = MessageHeader::respond(MessageType::PcieCommand).encode()?;

                let status = [0u8; 4]; /* Success */

                let cr = PciDeviceFunctionConfigurationSpace::builder()
                    .vid(subsys.info.pci_vid)
                    .did(subsys.info.pci_did)
                    .svid(subsys.info.pci_svid)
                    .sdid(subsys.info.pci_sdid)
                    .build()
                    .encode()?;

                send_response(resp, &[&mh.0, &status, &cr.0]).await;
                Ok(())
            }
            super::PcieCommandRequestType::ConfigurationWrite(req) => {
                let response = if rest.len() == req.length as usize {
                    debug!("Unsupported write at {} for {}", req.offset, req.length);
                    ResponseStatus::AccessDenied
                } else {
                    debug!(
                        "Request data size {} does not match requested write size {}",
                        rest.len(),
                        req.length
                    );
                    ResponseStatus::InvalidCommandInputDataSize
                };

                let mh = MessageHeader::respond(MessageType::PcieCommand).encode()?;

                let status = [response.id(), 0, 0, 0];

                send_response(resp, &[&mh.0, &status]).await;
                Ok(())
            }
            _ => {
                debug!("Unimplemented OPCODE: {:?}", ctx._opcode);
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

            // It might seem tempting to compose self.ccsf with an
            // assignment-union over each controller's mecs.chscf. However, this
            // doesn't work in practice due to the requirements of NVMe MI /
            // Configuration Set / Health Status Change on the behaviour of
            // clearing the composite controller flags, against the requirements
            // of NVMe MI / Controller Health Status Poll on the behaviour of
            // clearing the controller health status flags.
            //
            // Instead, update each independently by first gathering the change
            // flags for the current update cycle, then using union-assignment
            // into both mecs.chscf and self.ccsf (in the case of the latter,
            // via the conversion to the composite controller flag set).
            let mut update = FlagSet::empty();

            if mecs.cc.en != c.cc.en {
                update |= crate::nvme::mi::ControllerHealthStatusChangedFlags::Ceco;
            }

            if mecs.csts.contains(crate::nvme::ControllerStatusFlags::Rdy)
                != c.csts.contains(crate::nvme::ControllerStatusFlags::Rdy)
            {
                update |= crate::nvme::mi::ControllerHealthStatusChangedFlags::Rdy;
            }

            mecs.chscf |= update;

            let update: CompositeControllerStatusFlagSet = update.into();
            self.ccsf.0 |= update.0;

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

        let res = MessageHeader::from_bytes((msg, 0));
        let Ok(((rest, _), mh)) = &res else {
            debug!(
                "Message too short to extract NVMeMIMessageHeader: {:?}",
                res
            );
            return;
        };

        if mh.csi != 0 {
            debug!("Support second command slot");
            return;
        }

        if mh.ror {
            debug!("NVMe-MI message was not a request: {:?}", mh.ror);
            return;
        }

        if let Err(status) = mh.handle(mh, self, subsys, rest, &mut resp, app).await {
            let mut digest = ISCSI.digest();
            digest.update(&[0x80 | 0x04]);

            let Ok(mh) = MessageHeader::respond(mh.nmimt).encode() else {
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
