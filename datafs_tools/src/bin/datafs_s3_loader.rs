// SPDX-License-Identifier: GPL-2.0
fn main() {
    std::process::exit(datafs_tools::loader::run_s3("datafs_s3.bpf.o", "datafs_s3"));
}
