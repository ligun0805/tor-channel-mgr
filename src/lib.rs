mod tor_connector;

use std::str::FromStr;
use pyo3::prelude::*;
use pyo3::exceptions::PyValueError;
use futures::AsyncWriteExt;
use tor_rtcompat::{BlockOn, PreferredRuntime};
use crate::tor_connector::TorConnector;

#[pyclass]
#[pyo3(text_signature = "()")]
pub struct TorClient {
    runtime: PreferredRuntime,
    manager: TorConnector<PreferredRuntime>,
}

#[pymethods]
impl TorClient {
    #[new]
    fn new() -> PyResult<Self> {
        let runtime = PreferredRuntime::create()?;
        let manager = TorConnector::new(runtime.clone())
            .map_err(|e| PyValueError::new_err(format!("Failed to create manager: {}", e)))?;
        
        Ok(Self { runtime, manager })
    }

    #[pyo3(text_signature = "()")]
    fn init(&self) -> PyResult<()> {
        self.runtime.block_on(async {
            self.manager.init().await
                .map_err(|e| PyValueError::new_err(format!("Connection failed: {}", e)))
        })
    }

    #[pyo3(text_signature = "(relay_ip, relay_port, rsa_id, target_ip, target_port)")]
    fn connect(
        &self,
        relay_ip: &str,
        relay_port: u16,
        rsa_id: &str,
        url: &str,
        port: u16
    ) -> PyResult<String> {
        let (_, rest) = url.split_once("://")
            .ok_or_else(|| PyValueError::new_err("Invalid URL: Missing scheme (http or https)"))?;

        let (host, path) = match rest.split_once('/') {
            Some((host, path)) => (host, format!("/{}", path)),
            None => (rest, "/".to_string()),
        };

        self.runtime.block_on(async {
            match self.manager.connect(
                relay_ip,
                relay_port,
                rsa_id,
                host,
                port,
            ).await {
                Ok(mut stream) => {
                    let request = format!(
                        "GET {} HTTP/1.1\r\n\
                         Host: {}\r\n\
                         Connection: close\r\n\
                         \r\n",
                        path, host
                    );
                    
                    match stream.write_all(request.as_bytes()).await {
                        Ok(_) => {
                            let response = String::from_str("Hi! I'm a Tor client.").unwrap();
                            Ok(response)
                        },
                        Err(e) => Err(PyValueError::new_err(format!("Connection failed: {}", e)))
                    }
                },
                Err(e) => Err(PyValueError::new_err(format!("Connection failed: {}", e)))
            }
        })
    }
}

#[pymodule]
fn tor_py_client(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<TorClient>()?;
    m.add("__all__", vec!["TorClient"])?;
    Ok(())
}