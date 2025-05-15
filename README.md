# rust-sniffer
A sniffer made with rust and using some AI calls to evaluate security, quality of service and speed

Use the next commands to run it:

1. sudo apt-get install libpcap-dev
2. ip link show
    * If ip link show is lo go to next step, otherwise change line 14 "lo" to your desired configuration. In further actualization whis will be automatic
3. cargo build
4. sudo setcap cap_net_raw,cap_net_admin=eip ./target/debug/rust-sniffer
5. RUST_LOG=info cargo run

This way you'll run this sniffer.
Rn this is only tested on Ubuntu, but it might works in any debian Distro, im not sure if this works on windows devices.
