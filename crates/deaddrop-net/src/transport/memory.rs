use tokio::io::DuplexStream;

pub fn pair(max: usize) -> (DuplexStream, DuplexStream) {
    tokio::io::duplex(max)
}
