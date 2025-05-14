# rust-bpf

A Rust library for attaching Berkeley Packet Filter (BPF) programs to sockets on Linux systems.

## Features

- Create and attach BPF filters to sockets
- Lock BPF filters to prevent further modifications
- Detach BPF filters when no longer needed
- Provides a convenient macro for creating BPF programs
- Trait-based API for easy integration with socket types
- Cross-platform compatibility (dummy implementation on non-Linux systems)

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
bpf = "0.1"
```

### Basic Example

```rust
use bpf::{bpfprog, BpfFilterAttachable};
use std::net::UdpSocket;

fn main() -> std::io::Result<()> {
    let socket = UdpSocket::bind("127.0.0.1:0")?;

    // Create a BPF program that only accepts UDP packets on port 53 (DNS)
    // Each tuple is (code, jt, jf, k) for a BPF instruction
    let filter = bpfprog!(4,
        0x28 0 0 0x0000000c,  // (000) ldh      [12]
        0x15 0 2 0x00000800,  // (001) jeq      #0x800           jt 2    jf 4
        0x30 0 0 0x00000017,  // (002) ldb      [23]
        0x15 0 1 0x00000011,  // (003) jeq      #0x11            jt 4    jf 5
        0x06 0 0 0x00000001   // (004) ret      #1
    );

    // Attach filter to socket
    socket.attach_filter(filter)?;

    // Lock the filter if needed
    socket.lock_filter()?;

    // Use the socket...

    // Later, detach the filter if needed
    socket.detach_filter()?;

    Ok(())
}
```

## License

ISC License

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
