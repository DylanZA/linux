// SPDX-License-Identifier: GPL-2.0
fn main() {
    std::process::exit(datafs_tools::loader::run("datafs_smb.bpf.o", "datafs_smb"));
}
