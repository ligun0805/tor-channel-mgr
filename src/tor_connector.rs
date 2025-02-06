use anyhow::{anyhow, Result as AnyResult};
use tor_memquota::{MemoryQuotaTracker, Config};
use std::sync::{Arc, Mutex};
use std::net::SocketAddr;
use tor_chanmgr::{ChanMgr, ChannelConfig, ChannelUsage, Dormancy};
use tor_linkspec::{HasRelayIds, OwnedChanTarget, OwnedCircTarget};
use tor_proto::stream::DataStream;
use tor_proto::{
    circuit::CircParameters,
    ccparams::{Algorithm, CongestionControlParamsBuilder, FixedWindowParamsBuilder, RoundTripEstimatorParamsBuilder, CongestionWindowParamsBuilder}
};
use tor_units::Percentage;
use tor_rtcompat::Runtime;
use tor_netdir::{NetDir, NetDirProvider, DirEvent, Timeliness, Error, params::NetParameters};
use tor_llcrypto::pk::rsa::RsaIdentity;
// use tor_llcrypto::pk::curve25519::PublicKey as NtorOnionKey;
use futures::stream::BoxStream;
use postage::broadcast::{self, Receiver, Sender};

pub struct TorConnector<R: Runtime> {
    chan_mgr: Arc<ChanMgr<R>>,
    runtime: R,
}

impl<R: Runtime> TorConnector<R> {
    pub fn new(runtime: R) -> AnyResult<Self> {
        let netparams = NetParameters::default();
        let chanmgr_config = ChannelConfig::default();
        let memquota_config = Config::builder()
            .build()?;
        let memquota_tracker = MemoryQuotaTracker::new(&runtime.clone(), memquota_config)?;

        let chan_mgr = Arc::new(ChanMgr::new(
            runtime.clone(),
            &chanmgr_config,
            Dormancy::Active,
            &netparams,
            memquota_tracker.clone(),
        ));

        Ok(Self {
            chan_mgr,
            runtime,
        })
    }

    pub async fn init(&self) -> AnyResult<()> {
        let provider = Arc::new(SingleRelayNetDirProvider::new());

        // Launch background tasks
        self.chan_mgr
            .launch_background_tasks(&self.runtime, provider)
            .map_err(|e| anyhow!("Failed to launch background tasks: {}", e))?;

        Ok(())
    }

    pub async fn connect(
        &self, relay_ip: &str,
        relay_port: u16,
        relay_fingerprint: &str,
        target_host: &str,
        target_port: u16
    ) -> AnyResult<DataStream> {
        println!("\n-------------- Connecting to {}:{} ---------------\n", relay_ip, relay_port);
        
        let addr = format!("{}:{}", relay_ip, relay_port)
            .parse::<SocketAddr>()
            .map_err(|e| anyhow!("Invalid address: {}", e))?;

        println!("Establishing TCP connection to {}...", addr);
        tokio::time::timeout(
            std::time::Duration::from_secs(10),
            self.runtime.connect(&addr)
        )
            .await
            .map_err(|_| anyhow!("Timeout connecting to relay"))?
            .map_err(|e| anyhow!("Failed to connect to relay: {}", e))?;
        println!("TCP connection established successfully");

        // Convert RSA fingerprint from hex string to bytes
        let rsa_id_bytes = hex::decode(relay_fingerprint.replace(" ", ""))
            .map_err(|e| anyhow!("Invalid RSA fingerprint: {}", e))?;
        if rsa_id_bytes.len() != 20 {
            return Err(anyhow!("RSA fingerprint must be 20 bytes (40 hex characters)"));
        }
        let rsa_identity = RsaIdentity::from_bytes(&rsa_id_bytes)
            .expect("Failed to create RsaIdentity from bytes");

        // Convert ntor_onion_key from hex string to bytes
        // let ntor_onion_key_bytes = base64::decode("qXyNGi1ZYSDOz+Yd8+/UeHxi+Zm115l0Y6RUXp6cLU0")
        //     .map_err(|e| anyhow!("Invalid ntor_onion_key: {}", e))?;
        // if ntor_onion_key_bytes.len() != 32 {
        //     return Err(anyhow!("RSA fingerprint must be 32 bytes (64 hex characters)"));
        // }
        // let mut ntor_key_slice = [0u8; 32];
        // ntor_key_slice.copy_from_slice(&ntor_onion_key_bytes[..32]);
        // let ntor_onion_key = NtorOnionKey::from(ntor_key_slice);

        println!("\nConnecting to relay {} at {}:{}", relay_fingerprint, relay_ip, relay_port);

        // Create channel target using the builder pattern
        let target = OwnedChanTarget::builder()
            .addrs(vec![addr])
            .rsa_identity(rsa_identity.clone())
            // .ed_identity(ed_identity)
            .build()
            .map_err(|e| anyhow!("Failed to build channel target: {}", e))?;

        // Get or launch a channel to the target
        let (channel, provenance) = self
            .chan_mgr
            .get_or_launch(&target, ChannelUsage::UserTraffic)
            .await
            .map_err(|e| anyhow!("Failed to establish channel: {}", e))?;

        println!("Provenance: {:?}\n", provenance);

        println!("Channel established successfully pk_relayid_ed: {:?} unique_id: {:?}", channel.ed_identity(), channel.unique_id());

        println!("\nCreating circuit...");
        let cc_params = self.build_circuit_params()?;
        let circ_params = CircParameters::new(true, cc_params);
        let mut circ_builder = OwnedCircTarget::builder();
        circ_builder
            .chan_target()
            .addrs(vec![addr])
            .ed_identity(channel.ed_identity().unwrap().clone())
            .rsa_identity(rsa_identity);
        // let ct = circ_builder
        //     .ntor_onion_key(ntor_onion_key)
        //     .protocols("FlowCtrl=2".parse().unwrap())
        //     .build()
        //     .unwrap();

        let (pending_client_circuit, _) = match channel.new_circ().await {
            Ok(circ) => {
                println!("Pending circuit created successfully");
                circ
            },
            Err(e) => return Err(anyhow!("Pending circuit creation failed: {}", e)),
        };

        println!("Attempting handshake to create a circuit...");
        let circuit = match tokio::time::timeout(
            std::time::Duration::from_secs(30),
            // pending_client_circuit.create_firsthop_ntor(&ct, circ_params)
            pending_client_circuit.create_firsthop_fast(&circ_params)
        ).await {
            Ok(result) => match result {
                Ok(circ) => {
                    println!("Handshake successful");
                    circ
                },
                Err(e) => return Err(anyhow!("Handshake failed: {} (This might mean the relay rejected the cell)", e)),
            },
            Err(_) => return Err(anyhow!("Handshake timed out after 30 seconds")),
        };

        println!("\nCreating stream to {}:{}...", target_host, target_port);
        let stream = match circuit.begin_stream(target_host, target_port, None).await {
            Ok(s) => {
                println!("Stream created successfully");
                s
            },
            Err(e) => return Err(anyhow!("Stream creation failed: {}", e)),
        };
    
        println!("\nConnection established successfully!");

        Ok(stream)
    }

    fn build_circuit_params(&self) -> AnyResult<tor_proto::ccparams::CongestionControlParams> {
        let params = FixedWindowParamsBuilder::default()
            .circ_window_start(1000)
            .circ_window_min(100)
            .circ_window_max(1000)
            .build()
            .map_err(|e| anyhow!("Failed to build fixed window params: {}", e))?;

        let rtt_params = RoundTripEstimatorParamsBuilder::default()
            .ewma_cwnd_pct(Percentage::new(50))
            .ewma_max(10)
            .ewma_ss_max(2)
            .rtt_reset_pct(Percentage::new(100))
            .build()
            .map_err(|e| anyhow!("Failed to build RTT parameters: {}", e))?;

        let cwnd_params = CongestionWindowParamsBuilder::default()
            .cwnd_init(124)
            .cwnd_inc_pct_ss(Percentage::new(100))
            .cwnd_inc(1)
            .cwnd_inc_rate(31)
            .cwnd_min(124)
            .cwnd_max(u32::MAX)
            .sendme_inc(31)
            .build()
            .map_err(|e| anyhow!("Failed to build congestion window parameters: {}", e))?;

        CongestionControlParamsBuilder::default()
            .rtt_params(rtt_params)
            .cwnd_params(cwnd_params)
            .alg(Algorithm::FixedWindow(params))
            .build()
            .map_err(|e| anyhow!("Failed to build CC params: {}", e))
    }
}


pub struct SingleRelayNetDirProvider {
    inner: Mutex<Inner>,
}

/// Inner state for the provider
struct Inner {
    /// Current network directory
    current: Option<Arc<NetDir>>,
    /// Event sender for network directory updates
    event_tx: Sender<DirEvent>,
    /// Event receiver (kept to prevent channel closure)
    _event_rx: Receiver<DirEvent>,
}

impl SingleRelayNetDirProvider {
    pub fn new() -> Self {
        let (event_tx, _event_rx) = broadcast::channel(128);
        let inner = Inner {
            current: None,
            event_tx,
            _event_rx,
        };

        Self {
            inner: Mutex::new(inner),
        }
    }

    // /// Set the network directory
    // pub fn set_netdir(&self, dir: impl Into<Arc<NetDir>>) {
    //     let mut inner = self.inner.lock().expect("lock poisoned");
    //     inner.current = Some(dir.into());
    // }

    // /// Set the network directory and notify listeners
    // pub async fn set_netdir_and_notify(&self, dir: impl Into<Arc<NetDir>>) {
    //     let mut event_tx = {
    //         let mut inner = self.inner.lock().expect("lock poisoned");
    //         inner.current = Some(dir.into());
    //         inner.event_tx.clone()
    //     };
    //     let _ = event_tx.send(DirEvent::NewConsensus).await;
    // }
}

impl Default for SingleRelayNetDirProvider {
    fn default() -> Self {
        Self::new()
    }
}


pub type TResult<T> = std::result::Result<T, Error>;

impl NetDirProvider for SingleRelayNetDirProvider {
    fn netdir(&self, _timeliness: Timeliness) -> TResult<Arc<NetDir>> {
        match self.inner.lock().expect("lock poisoned").current.as_ref() {
            Some(netdir) => Ok(Arc::clone(netdir)),
            None => Err(tor_netdir::Error::NoInfo),
        }
    }

    fn events(&self) -> BoxStream<'static, DirEvent> {
        let inner = self.inner.lock().expect("lock poisoned");
        let events = inner.event_tx.subscribe();
        Box::pin(events)
    }

    fn params(&self) -> Arc<dyn AsRef<NetParameters>> {
        if let Ok(nd) = self.netdir(Timeliness::Unchecked) {
            nd
        } else {
            Arc::new(NetParameters::default())
        }
    }
}