use core::mem;

use deku::{
    DekuError, DekuReader, DekuWriter,
    ctx::{Endian, Limit},
    deku_error,
    no_std_io::{self, Read, Seek},
    reader::Reader,
    writer::Writer,
};

#[derive(Debug)]
pub struct WireVec<T, const S: usize>(heapless::Vec<T, S>);

impl<T, const S: usize> WireVec<T, S> {
    pub fn new() -> Self {
        Self(heapless::Vec::new())
    }

    pub fn last(&self) -> Option<&T> {
        self.0.last()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn push(&mut self, item: T) -> Result<(), T> {
        self.0.push(item)
    }
}

fn reader_vec_with_predicate<'a, T, Ctx, Predicate, R: Read + Seek, const S: usize>(
    reader: &mut Reader<R>,
    capacity: Option<usize>,
    ctx: Ctx,
    mut predicate: Predicate,
) -> Result<WireVec<T, S>, DekuError>
where
    T: DekuReader<'a, Ctx>,
    Ctx: Copy,
    Predicate: FnMut(usize, &T) -> bool,
{
    if let Some(cap) = capacity
        && cap > S
    {
        return Err(deku_error!(
            DekuError::InvalidParam,
            "Provided capacity is larger than vector capacity",
            "{} exceeds {}",
            cap,
            S
        ));
    }
    if mem::size_of::<T>() == 0 {
        return Ok(WireVec::new());
    }

    let mut res = WireVec::new();

    let start_read = reader.bits_read;

    loop {
        let val = <T>::from_reader_with_ctx(reader, ctx)?;
        if res.push(val).is_err() {
            return Err(deku_error!(
                DekuError::InvalidParam,
                "Failed to insert item into WireVec"
            ));
        };

        // This unwrap is safe as we are pushing to the vec immediately before it,
        // so there will always be a last element
        if predicate(reader.bits_read - start_read, res.last().unwrap()) {
            break;
        }
    }

    Ok(res)
}

impl<'a, T, Ctx, Predicate, const S: usize> DekuReader<'a, (Limit<T, Predicate>, Ctx)>
    for WireVec<T, S>
where
    T: DekuReader<'a, Ctx>,
    Ctx: Copy,
    Predicate: FnMut(&T) -> bool,
{
    fn from_reader_with_ctx<R: no_std_io::Read + no_std_io::Seek>(
        reader: &mut Reader<R>,
        (limit, inner_ctx): (Limit<T, Predicate>, Ctx),
    ) -> Result<Self, DekuError>
    where
        Self: Sized,
    {
        match limit {
            Limit::Count(mut count) => {
                // Handle the trivial case of reading an empty vector
                if count == 0 {
                    return Ok(WireVec::new());
                }

                // Otherwise, read until we have read `count` elements
                reader_vec_with_predicate(reader, Some(count), inner_ctx, move |_, _| {
                    count -= 1;
                    count == 0
                })
            }
            Limit::Until(_, _phantom_data) => todo!(),
            Limit::ByteSize(size) => {
                let bit_size = size.0 * 8;

                // Handle the trivial case of reading an empty vector
                if bit_size == 0 {
                    return Ok(WireVec::new());
                }

                reader_vec_with_predicate(reader, None, inner_ctx, move |read_bits, _| {
                    read_bits == bit_size
                })
            }
            Limit::BitSize(_size) => todo!(),
            Limit::End => todo!(),
        }
    }
}

impl<'a, T, const S: usize> DekuReader<'a, Endian> for WireVec<T, S>
where
    T: DekuReader<'a, Endian>,
{
    fn from_reader_with_ctx<R: no_std_io::Read + no_std_io::Seek>(
        reader: &mut Reader<R>,
        endian: Endian,
    ) -> Result<Self, DekuError>
    where
        Self: Sized,
    {
        let mut res: WireVec<T, S> = WireVec::new();
        let mut i = S;

        while i != 0 {
            let val = <T>::from_reader_with_ctx(reader, endian)?;
            if res.push(val).is_err() {
                return Err(deku_error!(
                    DekuError::InvalidParam,
                    "Failed to insert item into WireVec"
                ));
            };
            i -= 1;
        }

        Ok(res)
    }
}

impl<T: DekuWriter<Ctx>, Ctx: Copy, const S: usize> DekuWriter<Ctx> for WireVec<T, S> {
    fn to_writer<W: no_std_io::Write + no_std_io::Seek>(
        &self,
        writer: &mut Writer<W>,
        inner_ctx: Ctx,
    ) -> Result<(), DekuError> {
        for v in &self.0 {
            v.to_writer(writer, inner_ctx)?;
        }
        Ok(())
    }
}
