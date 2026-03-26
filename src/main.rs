#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
    balnceDNS::cli::run().await
}
