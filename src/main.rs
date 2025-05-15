use error::CaptureError;
use pcap::{Capture, Device};
use std::{thread, time::Duration};
use log::{info, warn, error};

mod error;

fn main() -> Result<(), CaptureError> {
    env_logger::init();
    start_capture("lo")?;
    Ok(())
}

pub fn start_capture(interface_name: &str) -> Result<(), CaptureError> {
    info!("Starting packet capture on '{}'", interface_name);

    let iface = Device::list()
        .map_err(CaptureError::PcapError)?
        .into_iter()
        .find(|d| d.name == interface_name)
        .ok_or_else(|| CaptureError::InterfaceNotFound(interface_name.to_string()))?;

    info!("Interface found: {}", iface.name);

    let mut cap = Capture::from_device(iface).map_err(CaptureError::PcapError)?
        .promisc(true)
        .immediate_mode(true)
        .open().map_err(CaptureError::PcapError)?
        .setnonblock().map_err(CaptureError::PcapError)?;

    let mut count = 0;
    let mut last_stats = None;

    loop {
        match cap.stats() {
            Ok(stats) => {
                let current = (stats.received, stats.dropped, stats.if_dropped);
                if last_stats != Some(current) {
                    last_stats = Some(current);
                    let (received, dropped, if_dropped) = current;
                    info!("Stats => received: {}, dropped: {}, kernel drop: {}", received, dropped, if_dropped);
                    info!("Delta recv - processed: {}", received.saturating_sub(count));
                }
            }
            Err(e) => warn!("Unable to retrieve stats: {:?}", e),
        }

        match cap.next_packet() {
            Ok(packet) => {
                info!(
                    "PACKET len = {}, ts = {}.{}",
                    packet.data.len(),
                    packet.header.ts.tv_sec,
                    packet.header.ts.tv_usec
                );
                count += 1;
            }
            Err(pcap::Error::PcapError(e)) if e.contains("Packets are not available") => {
                thread::sleep(Duration::from_micros(500));
            }
            Err(pcap::Error::TimeoutExpired) => {
                thread::sleep(Duration::from_micros(500));
            }
            Err(pcap::Error::PcapError(e)) if e.contains("Interrupted") => {
                warn!("Capture interrupted cleanly");
                break;
            }
            Err(pcap::Error::PcapError(e)) if e.contains("Operation not permitted") => {
                error!("Missing privileges. Try:\nsudo setcap cap_net_raw,cap_net_admin=eip ./your_binary");
                break;
            }
            Err(e) => {
                error!("Unknown error: {:?}", e);
                break;
            }
        }
    }

    info!("Capture completed. Total packets: {}", count);
    Ok(())
}
