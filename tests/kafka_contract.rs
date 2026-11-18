//! Native librdkafka protocol exercise against its mock broker. This is not
//! Redpanda/Docker acceptance evidence for runtime activation.
use futures_util::future::BoxFuture;
use octopus::{
    config::KafkaCfg,
    kafka::{
        consumer_settings, producer, BatchHandler, BoundaryError, LockedConsumer, LockedRecord,
        Poison,
    },
};
use rdkafka::{
    consumer::{BaseConsumer, Consumer},
    mocking::MockCluster,
    producer::FutureRecord,
    TopicPartitionList,
};
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio_util::sync::CancellationToken;

#[derive(Clone)]
struct Handler(Arc<Mutex<Vec<(i32, i64)>>>);
impl BatchHandler<String> for Handler {
    fn process(
        &self,
        records: Vec<LockedRecord<String>>,
    ) -> BoxFuture<'_, Result<(), BoundaryError>> {
        Box::pin(async move {
            // Deliberately slow one partition; all three workers must remain
            // live even though global active batch concurrency is only two.
            if records.first().is_some_and(|r| r.record.partition == 0) {
                tokio::time::sleep(Duration::from_millis(40)).await;
            }
            for record in records {
                self.0
                    .lock()
                    .unwrap()
                    .push((record.record.partition, record.record.offset));
            }
            Ok(())
        })
    }
}
fn decode(raw: &str) -> Result<String, Poison> {
    Ok(raw.into())
}

async fn wait_committed(
    consumer: &BaseConsumer,
    topic: &str,
    expected: &[(i32, i64)],
    handled: &Handler,
    task: &mut tokio::task::JoinHandle<Result<(), BoundaryError>>,
) {
    let mut last = String::new();
    // The mock's classic group coordinator can delay a restarted group's
    // election by session.timeout.ms - 1000 (29s with our 30s setting).
    // Wait beyond that protocol deadline while still bounding convergence.
    let result = tokio::time::timeout(Duration::from_secs(40), async {
        loop {
            let mut request = TopicPartitionList::new();
            for (partition, _) in expected {
                request.add_partition(topic, *partition);
            }
            let offsets = consumer.committed_offsets(request, Duration::from_millis(200));
            last = format!("{offsets:?}");
            if offsets.is_ok_and(|offsets| {
                expected.iter().all(|(partition, expected)| {
                    offsets
                        .find_partition(topic, *partition)
                        .is_some_and(|found| found.offset().to_raw() == Some(*expected))
                })
            }) {
                break;
            }
            tokio::select! {
                result = &mut *task => panic!("consumer terminated before committing expected offsets: {result:?}"),
                _ = tokio::time::sleep(Duration::from_millis(40)) => {},
            }
        }
    })
    .await;
    assert!(
        result.is_ok(),
        "durable offsets {expected:?} did not converge: last={last}; handled={:?}",
        handled.0.lock().unwrap()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_mock_broker_processes_every_partition_and_restarts_from_committed_offsets() {
    // librdkafka's mock constructor aborts the process when sandbox policy
    // prevents socket creation; probe in Rust so required integration fails
    // with a useful diagnostic instead of a native assertion.
    if std::net::TcpListener::bind("127.0.0.1:0").is_err() {
        assert_ne!(
            std::env::var("OCTOPUS_REQUIRE_DOCKER").as_deref(),
            Ok("true"),
            "required native Kafka protocol test cannot bind a loopback socket"
        );
        eprintln!("native Kafka protocol test unavailable; no integration result claimed");
        return;
    }
    let cluster = MockCluster::new(1).unwrap();
    let topic = "sync.scan.request";
    cluster.create_topic(topic, 3, 1).unwrap();
    cluster.create_topic("sync.scan.request.dlq", 3, 1).unwrap();
    let cfg = KafkaCfg {
        bootstrap_servers: cluster.bootstrap_servers(),
        locked_batch_size: 2,
        locked_batch_window_ms: 20,
        topic_replication_factor: 1,
        ..KafkaCfg::default()
    };
    let producer = producer(&cfg).unwrap();
    for partition in 0..3 {
        for _ in 0..2 {
            producer
                .send(
                    FutureRecord::to(topic)
                        .partition(partition)
                        .key("key")
                        .payload("valid"),
                    Duration::from_secs(3),
                )
                .await
                .unwrap();
        }
    }
    let group = "octopus-native-contract-v1";
    let observer: BaseConsumer = consumer_settings(&cfg, group).unwrap().create().unwrap();
    let first = Handler(Arc::new(Mutex::new(Vec::new())));
    let stop = CancellationToken::new();
    let runner = LockedConsumer::new(cfg.clone(), group.into(), topic.into()).unwrap();
    let mut task = tokio::spawn(runner.run(2, decode, first.clone(), stop.clone()));
    wait_committed(
        &observer,
        topic,
        &[(0, 2), (1, 2), (2, 2)],
        &first,
        &mut task,
    )
    .await;
    stop.cancel();
    task.await.unwrap().unwrap();
    let mut observed = first.0.lock().unwrap().clone();
    observed.sort();
    assert_eq!(
        observed,
        vec![(0, 0), (0, 1), (1, 0), (1, 1), (2, 0), (2, 1)]
    );

    let restarted = Handler(Arc::new(Mutex::new(Vec::new())));
    let stop = CancellationToken::new();
    let runner = LockedConsumer::new(cfg, group.into(), topic.into()).unwrap();
    let mut task = tokio::spawn(runner.run(2, decode, restarted.clone(), stop.clone()));
    producer
        .send(
            FutureRecord::to(topic)
                .partition(2)
                .key("key")
                .payload("next"),
            Duration::from_secs(3),
        )
        .await
        .unwrap();
    wait_committed(&observer, topic, &[(2, 3)], &restarted, &mut task).await;
    stop.cancel();
    task.await.unwrap().unwrap();
    assert_eq!(*restarted.0.lock().unwrap(), vec![(2, 2)]);
}
