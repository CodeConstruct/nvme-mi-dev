// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2025 Code Construct
 */
use deku::{
    DekuError, DekuReader, DekuWriter, deku_error,
    no_std_io::{self},
    reader::Reader,
    writer::Writer,
};
use log::debug;

#[derive(Debug)]
pub struct WireString<const S: usize>(heapless::String<S>);

impl<const S: usize> WireString<S> {
    pub fn new() -> Self {
        Self(heapless::String::new())
    }

    pub fn from(string: &str) -> Result<Self, ()> {
        let mut s = heapless::String::new();
        if s.push_str(string).is_err() {
            debug!("Failed to insert '{string}'");
            return Err(());
        }
        Ok(Self(s))
    }

    pub fn push(&mut self, c: char) -> Result<(), ()> {
        self.0.push(c)
    }
}

impl<'a, Ctx, const S: usize> DekuReader<'a, Ctx> for WireString<S>
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
        let mut res: WireString<S> = WireString::new();
        let mut i = S;

        while i != 0 {
            let val = <u8>::from_reader_with_ctx(reader, inner_ctx)?;
            if res.push(val as char).is_err() {
                return Err(deku_error!(
                    DekuError::InvalidParam,
                    "Failed to insert item into WireString"
                ));
            };
            i -= 1;
        }

        Ok(res)
    }
}

impl<Ctx: Copy, const S: usize> DekuWriter<Ctx> for WireString<S>
where
    u8: DekuWriter<Ctx>,
{
    fn to_writer<W: no_std_io::Write + no_std_io::Seek>(
        &self,
        writer: &mut Writer<W>,
        inner_ctx: Ctx,
    ) -> Result<(), DekuError> {
        for v in self.0.bytes().chain([0u8; S].into_iter()).take(S) {
            v.to_writer(writer, inner_ctx)?;
        }
        Ok(())
    }
}
