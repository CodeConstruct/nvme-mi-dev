#![no_std]
// bitfield needs this to cope with large structure sizes?
#![recursion_limit = "512"]

pub mod nvme;

#[macro_use]
extern crate bitfield;
