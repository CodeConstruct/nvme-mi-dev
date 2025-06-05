// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2025 Code Construct
 */
use std::time::SystemTime;

fn main() {
    let sde = option_env!("SOURCE_DATE_EPOCH");
    if sde.is_none() {
        let sde = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        println!("cargo::rustc-env=SOURCE_DATE_EPOCH={}", sde);
    }
}
