TUN interfaces [![Crates.io](https://img.shields.io/crates/v/tun.svg)](https://crates.io/crates/tun) ![tun](https://docs.rs/tun/badge.svg) ![WTFPL](http://img.shields.io/badge/license-WTFPL-blue.svg)
==============
This crate allows the creation and usage of TUN interfaces, the aim is to make this cross-platform.

Usage
-----
First, add the following to your `Cargo.toml`:

```toml
[dependencies]
tun = "0.5"
```

Next, add this to your crate root:

```rust
extern crate tun;
```

If you want to use the TUN interface with mio/tokio, you need to enable the `async` feature:

```toml
[dependencies]
tun = { version = "0.5", features = ["async"] }
```

Example
-------
The following example creates and configures a TUN interface and starts reading
packets from it.

```rust
use std::io::Read;

extern crate tun;

fn main() {
	let mut config = tun::Configuration::default();
	config.address((10, 0, 0, 1))
	       .netmask((255, 255, 255, 0))
	       .up();

	#[cfg(target_os = "linux")]
	config.platform(|config| {
		config.packet_information(true);
	});

	let mut dev = tun::create(&config).unwrap();
	let mut buf = [0; 4096];

	loop {
		let amount = dev.read(&mut buf).unwrap();
		println!("{:?}", &buf[0 .. amount]);
	}
}
```

Platforms
=========
Not every platform is supported.

Linux
-----
You will need the `tun` module to be loaded and root is required to create
interfaces.

macOS
-----
It just werks, but you have to set up routing manually.

iOS
----
You can pass the file descriptor of the TUN device to `rust-tun` to create the interface.

Here is an example to create the TUN device on iOS and pass the `fd` to `rust-tun`:
```swift
// Swift
class PacketTunnelProvider: NEPacketTunnelProvider {
    override func startTunnel(options: [String : NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        let tunnelNetworkSettings = createTunnelSettings() // Configure TUN address, DNS, mtu, routing...
        setTunnelNetworkSettings(tunnelNetworkSettings) { [weak self] error in
            let tunFd = self?.packetFlow.value(forKeyPath: "socket.fileDescriptor") as! Int32
            DispatchQueue.global(qos: .default).async {
                start_tun(tunFd)
            }
            completionHandler(nil)
        }
    }
}
```

```rust
#[no_mangle]
pub extern "C" fn start_tun(fd: std::os::raw::c_int) {
    let mut rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let mut cfg = tun::Configuration::default();
        cfg.raw_fd(fd);
        let mut tun = tun::create_as_async(&cfg).unwrap();
        let mut framed = tun.into_framed();
        while let Some(packet) = framed.next().await {
            ...
        }
    });
}
```
