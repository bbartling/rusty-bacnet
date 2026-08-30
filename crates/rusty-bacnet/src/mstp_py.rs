//! Helpers for constructing MS/TP transports from Python kwargs.

use pyo3::exceptions::PyRuntimeError;
use pyo3::PyResult;

use bacnet_transport::any::AnyTransport;
use bacnet_transport::mstp::{MstpConfig, MstpTransport};
use bacnet_transport::mstp_serial::{SerialConfig, TokioSerialPort};

/// Serial port type used by the Python bindings' [`AnyTransport`] parameter.
pub type PySerial = TokioSerialPort;

/// Open an MS/TP transport from Python kwargs.
pub fn build_mstp_transport(
    serial_port: Option<&str>,
    mstp_baud: u32,
    mstp_mac: u8,
    mstp_max_master: u8,
    mstp_max_info_frames: u8,
) -> PyResult<AnyTransport<PySerial>> {
    let path = serial_port
        .ok_or_else(|| PyRuntimeError::new_err("serial_port is required for transport='mstp'"))?;
    if mstp_mac > 127 {
        return Err(PyRuntimeError::new_err(
            "mstp_mac must be in 0..=127 (Clause 9 Max_Master range)",
        ));
    }
    if mstp_max_master > 127 {
        return Err(PyRuntimeError::new_err(
            "mstp_max_master must be in 0..=127",
        ));
    }
    if mstp_mac > mstp_max_master {
        return Err(PyRuntimeError::new_err(
            "mstp_mac must be <= mstp_max_master",
        ));
    }
    let serial = TokioSerialPort::open(&SerialConfig {
        port_name: path.to_string(),
        baud_rate: mstp_baud,
    })
    .map_err(|e| PyRuntimeError::new_err(format!("serial open failed: {e}")))?;
    let config = MstpConfig {
        this_station: mstp_mac,
        max_master: mstp_max_master,
        max_info_frames: mstp_max_info_frames.max(1),
        baud_rate: mstp_baud,
    };
    Ok(AnyTransport::Mstp(MstpTransport::new(serial, config)))
}
