use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

use quicp::flow::relay_bidirectional;

#[tokio::test]
async fn relay_preserves_bounded_bidirectional_flow() {
    let (mut left_app, mut left_flow) = duplex(32);
    let (mut right_flow, mut right_app) = duplex(32);

    let relay =
        tokio::spawn(async move { relay_bidirectional(&mut left_flow, &mut right_flow).await });
    let left = tokio::spawn(async move {
        left_app.write_all(b"left").await.unwrap();
        left_app.shutdown().await.unwrap();
        let mut received = Vec::new();
        left_app.read_to_end(&mut received).await.unwrap();
        received
    });
    let right = tokio::spawn(async move {
        right_app.write_all(b"right").await.unwrap();
        right_app.shutdown().await.unwrap();
        let mut received = Vec::new();
        right_app.read_to_end(&mut received).await.unwrap();
        received
    });

    assert_eq!(left.await.unwrap(), b"right");
    assert_eq!(right.await.unwrap(), b"left");
    assert_eq!(relay.await.unwrap().unwrap(), (4, 5));
}
