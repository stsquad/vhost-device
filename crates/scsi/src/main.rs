// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

mod backend;
mod scsi;
mod vhu_scsi;
mod virtio;

fn main() -> backend::Result<()> {
    backend::scsi_init()
}
