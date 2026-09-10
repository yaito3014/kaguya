fn main() -> Result<(), Box<dyn std::error::Error>> {
    // gRPC clients for loreserver's read services + the kaguya-auth exchange API.
    // Imported model protos (lore/model/v1, lore/thin_client/v1/model) are pulled
    // in via the include path; servers are not generated (we are a client only).
    tonic_prost_build::configure()
        .build_client(true)
        .build_server(false)
        .compile_protos(
            &[
                "proto/lore/repository/v1/repository.proto",
                "proto/lore/revision/v1/revision.proto",
                "proto/lore/thin_client/v1/thin_client.proto",
                "proto/lore/storage/v1/storage.proto",
                "proto/auth_api.proto",
            ],
            &["proto"],
        )?;
    Ok(())
}
