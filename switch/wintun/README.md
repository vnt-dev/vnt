# wintun

Safe rust idiomatic bindings for the Wintun C library: <https://wintun.net>

All features of the Wintun library are wrapped using pure rust types and functions to make
usage feel ergonomic.

## Usage

Inside your code load the wintun.dll signed driver file, downloaded from <https://wintun.net>,
using [`load`], [`load_from_path`] or [`load_from_library`].

Then either call [`Adapter::create`] or [`Adapter::open`] to obtain a wintun
adapter. Start a session with [`Adapter::start_session`].

## Example
```rust
use std::sync::Arc;

//Must be run as Administrator because we create network adapters
//Load the wintun dll file so that we can call the underlying C functions
//Unsafe because we are loading an arbitrary dll file
let wintun = unsafe { wintun::load_from_path("path/to/wintun.dll") }
    .expect("Failed to load wintun dll");

//Try to open an adapter with the name "Demo"
let adapter = match wintun::Adapter::open(&wintun, "Demo") {
    Ok(a) => a,
    Err(_) => {
        //If loading failed (most likely it didn't exist), create a new one
        wintun::Adapter::create(&wintun, "Example", "Demo", None)
            .expect("Failed to create wintun adapter!")
    }
};
//Specify the size of the ring buffer the wintun driver should use.
let session = Arc::new(adapter.start_session(wintun::MAX_RING_CAPACITY).unwrap());

//Get a 20 byte packet from the ring buffer
let mut packet = session.allocate_send_packet(20).unwrap();
let bytes: &mut [u8] = packet.bytes_mut();
//Write IPV4 version and header length
bytes[0] = 0x40;

//Finish writing IP header
bytes[9] = 0x69;
bytes[10] = 0x04;
bytes[11] = 0x20;
//...

//Send the packet to wintun virtual adapter for processing by the system
session.send_packet(packet);

//Stop any readers blocking for data on other threads
//Only needed when a blocking reader is preventing shutdown Ie. it holds an Arc to the
//session, blocking it from being dropped
session.shutdown();

//the session is stopped on drop
//drop(session);

//drop(adapter)
//And the adapter closes its resources when dropped
```

See `examples/wireshark.rs` for a more complete example that writes received packets to a pcap
file.

## Features

- `panic_on_unsent_packets`: Panics if a send packet is dropped without being sent. Useful for
debugging packet issues because unsent packets that are dropped without being sent hold up
wintun's internal ring buffer.

## TODO:
- Add async support
Requires hooking into a windows specific reactor and registering read interest on wintun's read
handle. Asyncify other slow operations via tokio::spawn_blocking. As always, PR's are welcome!


License: MIT
