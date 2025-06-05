// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2025 Code Construct
 */
#![no_std]
// bitfield needs this to cope with large structure sizes?
#![recursion_limit = "512"]

pub mod nvme;

#[macro_use]
extern crate bitfield;
