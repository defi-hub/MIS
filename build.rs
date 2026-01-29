// Build script to compile protobuf files with tonic-build

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .compile(&["proto/policy.proto"], &["proto"])?;
    
    Ok(())
}
