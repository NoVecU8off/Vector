// pub fn get_available_port<A: ToSocketAddrs>(addr: A) -> Result<String> {
//     for address in addr.to_socket_addrs()? {
//         if let Ok(listener) = TcpListener::bind(address) {
//             return Ok(format!("{}", listener.local_addr()?));
//         }
//     }
//     Err(anyhow!("No available port found"))
// }