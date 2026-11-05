# hawkbit-ddi

Blocking client for the [Eclipse hawkBit](https://eclipse.dev/hawkbit/) Direct Device Integration
(DDI) API, built on [`ureq`](https://crates.io/crates/ureq). It polls a controller for its pending
deployment (accepting cancel requests on the way), reports feedback and progress, and sends target
attributes.

```rust,no_run
use hawkbit_ddi::{DdiClient, Execution, Finished, Token};

let client = DdiClient::new(
    "https://hawkbit.example.com",
    "DEFAULT",
    Token::TargetToken("secret".into()),
);
if let Some(deployment) = client.pending("my-device")? {
    println!("update to {:?} from {:?}", deployment.version(), deployment.bundle_url());
    client.feedback("my-device", &deployment.id, Execution::Closed, Finished::Success, &[])?;
}
# Ok::<(), ureq::Error>(())
```

Server certificates are verified by default. To trust a private CA, pass your own agent with
`DdiClient::with_agent`.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT)
at your option.
