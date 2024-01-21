use std::error::Error;
mod bvlc;
mod network;

use network::NPDUServer;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let server = NPDUServer::new("[::]:47808").await?;
    println!("Server running on [::]:47808");

    server.run().await?;

    Ok(())
}
