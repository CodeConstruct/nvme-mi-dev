// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2025 Code Construct
 */
use deku::{DekuError, DekuReader, DekuWriter, no_std_io, reader::Reader, writer::Writer};
use uuid::Uuid;

#[derive(Clone, Copy, Debug)]
pub struct WireUuid(Uuid);

impl WireUuid {
    pub fn new(uuid: Uuid) -> Self {
        Self(uuid)
    }
}

impl<'a, Ctx> DekuReader<'a, Ctx> for WireUuid
where
    Ctx: Copy,
    u8: deku::DekuReader<'a, Ctx>,
{
    fn from_reader_with_ctx<R: no_std_io::Read + no_std_io::Seek>(
        reader: &mut Reader<R>,
        inner_ctx: Ctx,
    ) -> Result<Self, DekuError>
    where
        Self: Sized,
    {
        let val = <[u8; 16]>::from_reader_with_ctx(reader, inner_ctx)?;
        Ok(Self(Uuid::from_bytes(val)))
    }
}

impl<Ctx: Copy> DekuWriter<Ctx> for WireUuid
where
    u8: DekuWriter<Ctx>,
{
    fn to_writer<W: no_std_io::Write + no_std_io::Seek>(
        &self,
        writer: &mut Writer<W>,
        inner_ctx: Ctx,
    ) -> Result<(), DekuError> {
        self.0.into_bytes().to_writer(writer, inner_ctx)
    }
}
