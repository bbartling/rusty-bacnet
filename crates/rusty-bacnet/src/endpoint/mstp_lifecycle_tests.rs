//! Private injection: exercises the actual MS/TP Python wrapper and session.
//! Darwin PTYs reject the serial backend's ioctl; this is no hardware claim.
use super::*;
use bacnet_transport::mstp::{LoopbackSerial, SerialPort};
use bacnet_types::error::Error;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

pub(super) type SerialOpener = Arc<dyn Fn(&SerialConfig) -> PyResult<TestSerial> + Send + Sync>;

pub(super) enum TestSerial {
    Real(TokioSerialPort),
    Injected(Box<TrackedSerial>),
}
pub(super) struct TrackedSerial {
    serial: LoopbackSerial,
    _peer: LoopbackSerial,
    live: Arc<AtomicUsize>,
}
impl Drop for TrackedSerial {
    fn drop(&mut self) {
        self.live.fetch_sub(1, Ordering::SeqCst);
    }
}
impl SerialPort for TestSerial {
    async fn write(&self, data: &[u8]) -> Result<(), Error> {
        match self {
            Self::Real(port) => port.write(data).await,
            Self::Injected(port) => port.serial.write(data).await,
        }
    }
    async fn drain(&self) -> Result<(), Error> {
        match self {
            Self::Real(port) => port.drain().await,
            Self::Injected(port) => port.serial.drain().await,
        }
    }
    async fn read(&self, buf: &mut [u8]) -> Result<usize, Error> {
        match self {
            Self::Real(port) => port.read(buf).await,
            Self::Injected(port) => port.serial.read(buf).await,
        }
    }
}

#[test]
fn mstp_python_wrapper_owns_one_serial_and_returns_none() {
    Python::initialize();
    let opens = Arc::new(AtomicUsize::new(0));
    let live = Arc::new(AtomicUsize::new(0));
    let mut endpoint = PyMstpEndpoint::new(
        8002,
        "injected-serial",
        "Lifecycle",
        555,
        38400,
        3,
        127,
        1,
        480,
        None,
        None,
        None,
        16,
        6000,
        0,
    )
    .unwrap();
    endpoint.config.serial_opener = Some(Arc::new({
        let opens = opens.clone();
        let live = live.clone();
        move |_| {
            opens.fetch_add(1, Ordering::SeqCst);
            live.fetch_add(1, Ordering::SeqCst);
            let (serial, peer) = LoopbackSerial::pair();
            Ok(TestSerial::Injected(Box::new(TrackedSerial {
                serial,
                _peer: peer,
                live: live.clone(),
            })))
        }
    }));
    Python::attach(|py| {
        let globals = PyDict::new(py);
        globals
            .set_item("endpoint", Py::new(py, endpoint).unwrap())
            .unwrap();
        py.run(pyo3::ffi::c_str!(r#"
import asyncio
async def exercise():
    results = await asyncio.gather(endpoint.start(), endpoint.start(), return_exceptions=True)
    assert sum(result is None for result in results) == 1, results
    assert sum(isinstance(result, Exception) for result in results) == 1, results
    assert 'endpoint already started' in str(next(result for result in results if result is not None))
    assert await endpoint.__aenter__() is endpoint
    assert (await endpoint.status())['is_running']
    assert await endpoint.broadcast_i_am() is None
    assert await endpoint.__aexit__(None, None, None) is None
    assert await endpoint.close() is None
    endpoint.add_analog_input(instance=1, name='Restart')
    assert await endpoint.start() is None
    assert await endpoint.__aenter__() is endpoint
    assert await endpoint.close() is None
    assert await endpoint.__aexit__(None, None, None) is None
asyncio.run(exercise())
"#),Some(&globals),None).unwrap();
    });
    assert_eq!(
        opens.load(Ordering::SeqCst),
        2,
        "one open per admitted session, including restart"
    );
    assert_eq!(
        live.load(Ordering::SeqCst),
        0,
        "awaited close releases serial owner"
    );
}
