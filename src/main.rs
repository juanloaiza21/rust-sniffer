use error::CaptureError;
use pcap::{Capture, Device};
use std::{thread, time::Duration};
use log::{info, warn, error, debug};
use std::io::{self, Write};
use std::env;

mod error;
mod protocols;  // New module for protocol parsing
mod ai_analyzer;  // New module for AI analysis



use protocols::ethernet::EthernetFrame;
use protocols::frame_control::FrameControlInfo;
use ai_analyzer::AIAnalyzer;




//TODO fix the interface name to automatic
#[tokio::main]
async fn main() -> Result<(), CaptureError> {
    let interface_name = "enp4s0"; // Replace with your network interface name
    env_logger::init();
    print!("Select the capture mode (1: Basic, 2: AI): ");
    let mut input = String::new();
    match io::stdin().read_line(&mut input) {
        Ok(_) => {
            let choice: u8 = input.trim().parse().unwrap_or(1);
            match choice {
                1 => {
                    start_capture(interface_name)?;
                }
                2 => {
                    let api_key = env::var("DEEPSEEK_API_KEY").expect("DEEPSEEK_API_KEY enviroment variable not set"); //
                    let analyzer = AIAnalyzer::new(&api_key);
                    start_capture_with_ai(interface_name, analyzer).await?;
                }
                _ => {
                    println!("Invalid choice. Defaulting to basic capture.");
                    start_capture(interface_name)?;
                }
            }
        }
        Err(e) => {
            eprintln!("Error reading input: {}", e);
            return Err(CaptureError::InputError(e.to_string()));
        }
    }
    Ok(())
}



pub fn start_capture(interface_name: &str) -> Result<(), CaptureError> {
    info!("Starting packet capture on '{}'", interface_name);

    let iface = Device::list()
        .map_err(|e| CaptureError::PcapError(e.to_string()))?
        .into_iter()
        .find(|d| d.name == interface_name)
        .ok_or_else(|| CaptureError::InterfaceNotFound(interface_name.to_string()))?;
    info!("Interface found: {}", iface.name);

    let mut cap = Capture::from_device(iface).map_err(|e| CaptureError::PcapError(e.to_string()))?
        .promisc(true)
        .immediate_mode(true)
        .open().map_err(|e| CaptureError::PcapError(e.to_string()))?
        .setnonblock().map_err(|e| CaptureError::PcapError(e.to_string()))?;

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
                
                // Parse frame control information from the packet
                if let Some(frame_control) = analyze_frame_control(&packet.data) {
                    info!("Frame Control: {}", frame_control);
                }
                
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

async fn start_capture_with_ai(interface_name: &str, analyzer: AIAnalyzer) -> Result<(), Box<dyn std::error::Error>> {
    info!("Starting packet capture on '{}'", interface_name);

    let iface = Device::list()
        .map_err(|e| CaptureError::PcapError(e.to_string()))?
        .into_iter()
        .find(|d| d.name == interface_name)
        .ok_or_else(|| CaptureError::InterfaceNotFound(interface_name.to_string()))?;

    info!("Interface found: {}", iface.name);

    let mut cap = Capture::from_device(iface)
        .map_err(|e| CaptureError::PcapError(e.to_string()))?
        .promisc(true)
        .immediate_mode(true)
        .open()
        .map_err(|e| CaptureError::PcapError(e.to_string()))?
        .setnonblock()
        .map_err(|e| CaptureError::PcapError(e.to_string()))?;

    let mut count = 0;
    let mut last_stats = None;
    let mut first_packet_analyzed = false;

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

        if first_packet_analyzed {
            // If we've already analyzed the first packet, wait for user input
            println!("Press Enter to continue capturing packets...");
            let mut input = String::new();
            io::stdin().read_line(&mut input)?;
            first_packet_analyzed = false; // Reset so we can continue capturing
            println!("Continuing packet capture...");
        }

        match cap.next_packet() {
            Ok(packet) => {
                info!(
                    "PACKET len = {}, ts = {}.{}",
                    packet.data.len(),
                    packet.header.ts.tv_sec,
                    packet.header.ts.tv_usec
                );
                
                // Parse frame control information from the packet
                if let Some(frame_control) = analyze_frame_control(&packet.data) {
                    info!("Frame Control: {}", frame_control);
                }
                
                count += 1;
                
                // Analyze first packet with AI
                if count == 1 {
                    println!("Analyzing security of first packet...");
                    
                    match analyzer.analyze_packet_security(&packet).await {
                        Ok(analysis) => {
                            println!("\n==== AI SECURITY ANALYSIS ====");
                            println!("Security Score: {:.2}", analysis.security_score);
                            println!("\nPotential Threats:");
                            for threat in &analysis.potential_threats {
                                println!("  - {}", threat);
                            }
                            println!("\nRecommendations:");
                            for recommendation in &analysis.recommendations {
                                println!("  - {}", recommendation);
                            }
                            println!("==============================\n");
                            
                            first_packet_analyzed = true;
                        },
                        Err(e) => {
                            eprintln!("Error analyzing packet: {}", e);
                            // Continue capturing even if AI analysis fails
                        }
                    }
                }
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

/// Analyzes a packet's raw data and extracts frame control information
fn analyze_frame_control(data: &[u8]) -> Option<FrameControlInfo> {
    if data.len() < 14 {  // Minimum Ethernet frame size
        debug!("Packet too small to contain valid frame control data");
        return None;
    }
    
    // Try to parse as Ethernet frame
    match EthernetFrame::parse(data) {
        Ok(eth_frame) => Some(eth_frame.get_frame_control()),
        Err(e) => {
            debug!("Failed to parse frame control: {}", e);
            None
        }
    }
}
