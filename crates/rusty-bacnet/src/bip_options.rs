//! Constructor checks for B/IP-only options.

use pyo3::exceptions::PyValueError;
use pyo3::PyResult;

/// `share_port_by_address` (#1538) binds a B/IP interface address, so it
/// means nothing on another transport: refuse it there rather than ignore it.
pub(crate) fn only_on_bip(share_port_by_address: bool, transport: &str) -> PyResult<()> {
    if share_port_by_address && transport != "bip" {
        return Err(PyValueError::new_err(
            "share_port_by_address applies only to transport='bip'",
        ));
    }
    Ok(())
}
