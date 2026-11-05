# hawkbit-ddi

Blocking client for the [Eclipse hawkBit](https://eclipse.dev/hawkbit/) Direct Device Integration
(DDI) API, built on [`ureq`](https://crates.io/crates/ureq). It polls a controller for its open
action (a deployment or a cancel request) and polling interval, reports feedback and progress, answers
cancel requests, and sends target attributes.

```rust,no_run
use hawkbit_ddi::{Action, DdiClient, Execution, Finished, Token};

let client = DdiClient::new(
    "https://hawkbit.example.com",
    "DEFAULT",
    Token::TargetToken("secret".into()),
);
let poll = client.poll("my-device")?;
match poll.action {
    Some(Action::Deploy(deployment)) => {
        println!("update to {:?} from {:?}", deployment.version(), deployment.bundle_url(".raucb"));
        client.feedback("my-device", &deployment.id, Execution::Closed, Finished::Success, &[])?;
    }
    Some(Action::Cancel(id)) => {
        client.cancel_feedback("my-device", &id, Execution::Closed, Finished::Success, &[])?;
    }
    None => {}
}
std::thread::sleep(poll.sleep.unwrap_or(std::time::Duration::from_secs(300)));
# Ok::<(), ureq::Error>(())
```

Server certificates are verified by default. To trust a private CA, pass your own agent with
`DdiClient::with_agent`.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT)
at your option.
