// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2025 Code Construct
 */

use deku::{DekuError, DekuReader, DekuWriter, deku_error, reader::Reader, writer::Writer};
use flagset::{FlagSet, Flags};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WireFlagSet<T: Flags>(pub FlagSet<T>);

impl<T: Flags> From<FlagSet<T>> for WireFlagSet<T> {
    fn from(value: FlagSet<T>) -> Self {
        Self(value)
    }
}

impl<T: Flags> Default for WireFlagSet<T> {
    fn default() -> Self {
        Self(FlagSet::empty())
    }
}

impl<'a, Ctx, T> DekuReader<'a, Ctx> for WireFlagSet<T>
where
    T: Flags,
    <T as Flags>::Type: DekuReader<'a, Ctx>,
{
    fn from_reader_with_ctx<R: deku::no_std_io::Read + deku::no_std_io::Seek>(
        reader: &mut Reader<R>,
        ctx: Ctx,
    ) -> Result<Self, DekuError>
    where
        Self: Sized,
    {
        let val = <<T as Flags>::Type>::from_reader_with_ctx(reader, ctx)?;
        let fs = FlagSet::new(val)
            .map_err(|_| deku_error!(DekuError::Parse, "Found invalid flag set", "{}", val))?;
        Ok(WireFlagSet(fs))
    }
}

impl<Ctx, T> DekuWriter<Ctx> for WireFlagSet<T>
where
    T: Flags,
    <T as Flags>::Type: DekuWriter<Ctx>,
{
    fn to_writer<W: deku::no_std_io::Write + deku::no_std_io::Seek>(
        &self,
        writer: &mut Writer<W>,
        ctx: Ctx,
    ) -> Result<(), DekuError> {
        self.0.bits().to_writer(writer, ctx)
    }
}

#[cfg(test)]
mod test {
    use deku::{DekuReader, DekuWriter, no_std_io::Cursor, reader::Reader, writer::Writer};
    use flagset::{FlagSet, flags};

    use crate::wire::flags::WireFlagSet;

    flags! {
        enum TestFlags: u8 {
            One = 1,
            Two = 2,
            Both = (TestFlags::One | TestFlags::Two).bits(),
        }
    }

    #[test]
    fn empty() {
        let test_data = [0u8; 1];

        let mut cursor = Cursor::new(&test_data);
        let mut reader = Reader::new(&mut cursor);
        let deku_test = WireFlagSet::<TestFlags>::from_reader_with_ctx(&mut reader, ()).unwrap();
        assert_eq!(deku_test, FlagSet::empty().into());

        let mut ret_data = [0xffu8; 1];
        let mut cursor = Cursor::new(ret_data.as_mut_slice());
        let mut writer = Writer::new(&mut cursor);
        deku_test.to_writer(&mut writer, ()).unwrap();

        assert_eq!(test_data, ret_data);
    }

    #[test]
    fn one() {
        let test_data = [1u8; 1];

        let mut cursor = Cursor::new(&test_data);
        let mut reader = Reader::new(&mut cursor);
        let deku_test = WireFlagSet::<TestFlags>::from_reader_with_ctx(&mut reader, ()).unwrap();

        let set: FlagSet<TestFlags> = TestFlags::One.into();
        assert_eq!(deku_test, set.into());

        let mut ret_data = [0xffu8; 1];
        let mut cursor = Cursor::new(ret_data.as_mut_slice());
        let mut writer = Writer::new(&mut cursor);
        deku_test.to_writer(&mut writer, ()).unwrap();

        assert_eq!(test_data, ret_data);
    }

    #[test]
    fn two() {
        let test_data = [2u8; 1];

        let mut cursor = Cursor::new(&test_data);
        let mut reader = Reader::new(&mut cursor);
        let deku_test = WireFlagSet::<TestFlags>::from_reader_with_ctx(&mut reader, ()).unwrap();

        let set: FlagSet<TestFlags> = TestFlags::Two.into();
        assert_eq!(deku_test, set.into());

        let mut ret_data = [0xffu8; 1];
        let mut cursor = Cursor::new(ret_data.as_mut_slice());
        let mut writer = Writer::new(&mut cursor);
        deku_test.to_writer(&mut writer, ()).unwrap();

        assert_eq!(test_data, ret_data);
    }

    #[test]
    fn one_two() {
        let test_data = [3u8; 1];

        let mut cursor = Cursor::new(&test_data);
        let mut reader = Reader::new(&mut cursor);
        let deku_test = WireFlagSet::<TestFlags>::from_reader_with_ctx(&mut reader, ()).unwrap();

        let set = TestFlags::One | TestFlags::Two;
        assert_eq!(deku_test, set.into());

        let set: FlagSet<TestFlags> = TestFlags::Both.into();
        assert_eq!(deku_test, set.into());

        let mut ret_data = [0xffu8; 1];
        let mut cursor = Cursor::new(ret_data.as_mut_slice());
        let mut writer = Writer::new(&mut cursor);
        deku_test.to_writer(&mut writer, ()).unwrap();

        assert_eq!(test_data, ret_data);
    }
}
