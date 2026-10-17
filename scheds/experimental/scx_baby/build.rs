// SPDX-License-Identifier: GPL-2.0
//
// Copyright (C) 2026 bunkbail <nabildanial.93@gmail.com>
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

fn main() {
    scx_cargo::BpfBuilder::new()
        .unwrap()
        .enable_intf("src/bpf/intf.h", "bpf_intf.rs")
        .enable_skel("src/bpf/main.bpf.c", "bpf")
        .add_source("src/bpf/util.bpf.c")
        .add_source("src/bpf/stats.bpf.c")
        .add_source("src/bpf/class.bpf.c")
        .add_source("src/bpf/idle.bpf.c")
        .add_source("src/bpf/power.bpf.c")
        .add_source("src/bpf/balance.bpf.c")
        .compile_link_gen()
        .unwrap();
}
