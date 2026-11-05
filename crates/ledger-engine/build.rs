//! xrpld gRPC client code from the protocol definitions (proto/, rippled 3.4.1).
//! protox compiles the definitions without an external protoc.

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let fds = protox::compile(["org/xrpl/rpc/v1/xrp_ledger.proto"], ["proto"])?;
    tonic_prost_build::configure()
        .build_server(false)
        .compile_fds(fds)?;
    println!("cargo:rerun-if-changed=proto");
    Ok(())
}
