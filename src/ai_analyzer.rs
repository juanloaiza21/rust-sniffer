use std::error::Error;
use pcap::Packet;
use serde::{Deserialize, Serialize};
use reqwest;

pub struct AIAnalyzer {
    api_key: String,
    client: reqwest::Client,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SecurityAnalysis {
    pub security_score: f32,
    pub potential_threats: Vec<String>,
    pub recommendations: Vec<String>,
}

// Request structure for the deepseek API
#[derive(Serialize)]
struct DeepseekRequest {
    model: String,
    prompt: String,
    max_tokens: u32,
}

// Response structure for the deepseek API
#[derive(Deserialize)]
struct DeepseekResponse {
    choices: Vec<DeepseekChoice>,
}

#[derive(Deserialize)]
struct DeepseekChoice {
    text: String,
}

impl AIAnalyzer {
    pub fn new(api_key: &str) -> Self {
        Self {
            api_key: api_key.to_string(),
            client: reqwest::Client::new(),
        }
    }

    pub async fn analyze_packet_security(&self, packet: &Packet<'_>) -> Result<SecurityAnalysis, Box<dyn Error>> {
        // Extract relevant packet data for analysis
        let packet_info = format!(
            "Packet length: {}, Timestamp: {}.{}, Data (first 50 bytes, hex): {:?}",
            packet.data.len(),
            packet.header.ts.tv_sec,
            packet.header.ts.tv_usec,
            &packet.data.iter().take(50).map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" ")
        );
        
        // Create a prompt for the AI model
        let prompt = format!(
            "You are a network security expert. Analyze the security of this network packet:\n\n{}\n\n\
            Provide your analysis in the following JSON format:\n\
            {{\n\
              \"security_score\": <float between 0.0 (insecure) to 1.0 (secure)>,\n\
              \"potential_threats\": [<list of potential threat strings>],\n\
              \"recommendations\": [<list of recommendation strings>]\n\
            }}\n\n\
            Return only valid JSON without any additional text.", 
            packet_info
        );
        
        // Create request payload
        let request_payload = DeepseekRequest {
            model: "deepseek-coder".to_string(),
            prompt,
            max_tokens: 1000,
        };

        // Make the API request
        let response = self.client.post("https://api.deepseek.com/v1/completions")
            .header("Authorization", format!("Bearer {}", self.api_key))
            .json(&request_payload)
            .send()
            .await?
            .json::<DeepseekResponse>()
            .await?;
        
        // Parse the AI response
        let response_text = &response.choices[0].text;
        let security_analysis: SecurityAnalysis = serde_json::from_str(response_text)?;
        
        Ok(security_analysis)
    }
}
