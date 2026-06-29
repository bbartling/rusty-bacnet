use bacnet_types::enums::{ErrorClass, ErrorCode};
use bacnet_types::error::Error;

use crate::sc_frame::{ScBvlcResult, ScFunction};

use super::{generate_random48_vmac, ScConnection, ScConnectionState};

impl ScConnection {
    /// Handle a BVLC-Result received while waiting for Connect-Accept.
    ///
    /// AB.6.2.2 requires an initiating peer that receives a
    /// NODE_DUPLICATE_VMAC NAK for its Connect-Request to select a new
    /// Random-48 VMAC before any subsequent connection attempt.
    pub fn handle_connect_result(&mut self, result: &ScBvlcResult) -> Result<bool, Error> {
        self.state = ScConnectionState::Disconnected;
        self.pending_connect_message_id = None;

        let ScBvlcResult::Nak {
            result_for,
            error_class,
            error_code,
            ..
        } = result
        else {
            return Ok(false);
        };

        if *result_for == ScFunction::ConnectRequest
            && *error_class == ErrorClass::COMMUNICATION.to_raw()
            && *error_code == ErrorCode::NODE_DUPLICATE_VMAC.to_raw()
        {
            self.local_vmac = generate_random48_vmac()?;
            Ok(true)
        } else {
            Ok(false)
        }
    }
}
