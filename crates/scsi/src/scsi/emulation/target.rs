// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

use std::convert::TryFrom;
use std::io::{Read, Write};

use log::error;

use crate::scsi::{sense, CmdError, CmdOutput, Request, Target, TaskAttr};

use super::{
    command::{
        Cdb, Command, LunIndependentCommand, LunSpecificCommand, ParseError, ReportLunsSelectReport,
    },
    missing_lun::MissingLun,
    response_data::{respond_report_luns, SilentlyTruncate},
};

pub(crate) struct LunRequest<'a, W: Write, R: Read> {
    pub _id: u64,
    pub task_attr: TaskAttr,
    pub data_in: SilentlyTruncate<&'a mut W>,
    pub _data_out: &'a mut R,
    pub crn: u8,
    pub prio: u8,
    pub _allocation_length: Option<u32>,
    pub naca: bool,
}

/// A single logical unit of an emulated SCSI device.
pub(crate) trait LogicalUnit<W: Write, R: Read>: Send + Sync {
    /// Process a SCSI command sent to this logical unit.
    ///
    /// # Return value
    /// This function returns a Result, but it should return Err only in limited
    /// circumstances: when something goes wrong at the transport level, such
    /// as writes to `req.data_in` failing or `req.cdb` being too short.
    /// Any other errors, such as invalid SCSI commands or I/O errors
    /// accessing an underlying file, should result in an Ok return value
    /// with a `CmdOutput` representing a SCSI-level error (i.e. CHECK
    /// CONDITION status, and appropriate sense data).
    fn execute_command(
        &mut self,
        parameters: LunRequest<'_, W, R>,
        command: LunSpecificCommand,
    ) -> Result<CmdOutput, CmdError>;
}

/// A SCSI target implemented by emulating a device within vhost-user-scsi.
pub(crate) struct EmulatedTarget<W: Write, R: Read> {
    luns: Vec<Box<dyn LogicalUnit<W, R>>>,
}

impl<W: Write, R: Read> EmulatedTarget<W, R> {
    pub(crate) fn new() -> Self {
        Self { luns: Vec::new() }
    }

    pub(crate) fn add_lun(&mut self, logical_unit: Box<dyn LogicalUnit<W, R>>) {
        self.luns.push(logical_unit);
    }

    pub(crate) fn luns(&self) -> impl Iterator<Item = u16> + ExactSizeIterator + '_ {
        // unwrap is safe: we limit LUNs at 256
        self.luns
            .iter()
            .enumerate()
            .map(|(idx, _logical_unit)| u16::try_from(idx).unwrap())
    }
}

impl<W: Write, R: Read> Default for EmulatedTarget<W, R> {
    fn default() -> Self {
        Self::new()
    }
}

impl<W: Write, R: Read> Target<W, R> for EmulatedTarget<W, R> {
    fn execute_command(&mut self, lun: u16, req: Request<'_, W, R>) -> Result<CmdOutput, CmdError> {
        match Cdb::parse(req.cdb) {
            Ok(cdb) => {
                let mut data_in = SilentlyTruncate::new(
                    req.data_in,
                    cdb.allocation_length.map_or(usize::MAX, |x| x as usize),
                );
                match cdb.command {
                    Command::LunIndependentCommand(cmd) => match cmd {
                        LunIndependentCommand::ReportLuns(select_report) => {
                            match select_report {
                                ReportLunsSelectReport::NoWellKnown
                                | ReportLunsSelectReport::All => {
                                    respond_report_luns(&mut data_in, self.luns())
                                        .map_err(CmdError::DataIn)?;
                                }
                                ReportLunsSelectReport::WellKnownOnly
                                | ReportLunsSelectReport::Administrative
                                | ReportLunsSelectReport::TopLevel
                                | ReportLunsSelectReport::SameConglomerate => {
                                    respond_report_luns(&mut data_in, vec![].into_iter())
                                        .map_err(CmdError::DataIn)?;
                                }
                            }
                            Ok(CmdOutput::ok())
                        }
                    },
                    Command::LunSpecificCommand(cmd) => {
                        //                         pub id: u64,
                        // pub task_attr: TaskAttr,
                        // pub data_in: &'a mut W,
                        // pub data_out: &'a mut R,
                        // pub crn: u8,
                        // pub prio: u8,
                        // pub allocation_length: Option<u32>,
                        // pub naca: bool,

                        let req = LunRequest {
                            _id: req.id,
                            task_attr: req.task_attr,
                            data_in,
                            _data_out: req.data_out,
                            crn: req.crn,
                            prio: req.prio,
                            _allocation_length: cdb.allocation_length,
                            naca: cdb.naca,
                        };
                        match self.luns.get_mut(lun as usize) {
                            Some(lun) => lun.execute_command(req, cmd),
                            None => MissingLun.execute_command(req, cmd),
                        }
                    }
                }
            }
            Err(ParseError::InvalidCommand) => {
                error!("Rejecting CDB for unknown command: {:?}", req.cdb);
                Ok(CmdOutput::check_condition(
                    sense::INVALID_COMMAND_OPERATION_CODE,
                ))
            }
            // TODO: SCSI has a provision for INVALID FIELD IN CDB to include the
            // index of the invalid field, but it's not clear if that's mandatory.
            // In any case, QEMU omits it.
            Err(ParseError::InvalidField) => {
                error!("Rejecting CDB with invalid field: {:?}", req.cdb);
                Ok(CmdOutput::check_condition(sense::INVALID_FIELD_IN_CDB))
            }
            Err(ParseError::TooSmall) => Err(CmdError::CdbTooShort),
        }
    }
}
