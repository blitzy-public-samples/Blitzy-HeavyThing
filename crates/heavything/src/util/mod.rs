// Rust translation © 2026, licensed under GPL-3.0-or-later.
//
// Derived from the HeavyThing assembly library:
//   Copyright © 2015–2018 2 Ton Digital, Jeff Marrison <info@2ton.com.au>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

//! `util` subsystem — general-purpose helpers backing `crypto`, `net`, `tui`,
//! and `ds`. Per AAP §0.5.1.7, this module aggregates the Rust translations of
//! the `.inc` utility files.
//!
//! This file currently declares only the subset of `util` child modules whose
//! Rust translations have been authored. Sibling agents are expected to extend
//! this list with additional `pub mod` declarations (`string`, `crc`, `base64`,
//! `json`, `zlib`, `png`, `formatter`, `date`, `file`, `dir`, `sysinfo`,
//! `syslog`, `mapped`, `privmapped`, `mappedheap`) as those files are created.

pub mod math;
pub mod profiler;
pub mod sleeps;
pub mod string_math;
pub mod unicodecase;
pub mod vdso;
