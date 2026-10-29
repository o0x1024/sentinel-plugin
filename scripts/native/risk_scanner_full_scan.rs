//! Temporary owned acceptance probe; copied beside existing lifecycle fixtures.
#[allow(dead_code)]
#[path = "manager_lifecycle_support/mod.rs"]
mod support;
use sentinel_plugins::{
    init_dictionary_pool,
    monitor_results::{MonitorCommitAck, MonitorResultSink},
    terminate_plugin_executions_by_run, PluginManager,
};
use serde_json::{json, Value};
use std::{
    sync::{atomic::{AtomicUsize, Ordering}, Arc},
    time::{Duration, Instant},
};

fn context(target: &str) -> Value {
    json!({
        "task_id":"owned-risk-full", "task_name":"Owned full rule scan",
        "program_id":"owned", "execution_mode":"test",
        "started_at":"2026-10-29T00:00:00Z", "current_plugin":"risk_scanner",
        "current_plugin_index":1, "completed_steps":0, "total_steps":1,
        "result_stream":{"protocol":"monitor-results-v2","targets":[target],
            "max_work_items":32,"max_pending_commits":2,"max_bytes":2097152}
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dictionary_full_coverage_global_limit_and_cancel() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let started = Instant::now();
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1).connect("sqlite::memory:").await.unwrap();
    for statement in [
        "CREATE TABLE dictionaries(id TEXT PRIMARY KEY, name TEXT)",
        "CREATE TABLE dictionary_words(dictionary_id TEXT, word TEXT, weight REAL, category TEXT, metadata TEXT)",
        "CREATE INDEX owned_dictionary_order ON dictionary_words(dictionary_id, weight DESC, word ASC)",
        "INSERT INTO dictionaries VALUES('owned-rules','Owned rules')",
    ] {
        sqlx::query(statement).execute(&pool).await.unwrap();
    }
    let mut transaction = pool.begin().await.unwrap();
    for index in 0..10005 {
        let mut metadata = json!({
            "requests":[{"method":"GET","path":"/probe/{{rule_id}}"}],
            "matchers":[{"part":"status","type":"equals","value":404}]
        });
        if index >= 100 {
            metadata["preconditions"] = json!([{
                "field":"variables.execute_extra", "op":"equals", "value":true
            }]);
        }
        sqlx::query("INSERT INTO dictionary_words VALUES(?,?,?,?,?)")
            .bind("owned-rules").bind(format!("rule-{index:05}"))
            .bind(1.0f64).bind("owned").bind(metadata.to_string())
            .execute(&mut *transaction).await.unwrap();
    }
    transaction.commit().await.unwrap();
    init_dictionary_pool(pool);
    let mut settings = sentinel_plugins::get_plugin_runtime_settings();
    settings.direct_fetch_max_concurrent = 4;
    sentinel_plugins::set_plugin_runtime_settings(settings).unwrap();
    let manager = Arc::new(PluginManager::new());
    let bundle = std::env::var_os("SENTINEL_RISK_SCANNER_BUNDLE")
        .expect("native acceptance runner supplies the exact plugin bundle");
    let code = std::fs::read_to_string(bundle).unwrap();
    support::register(&manager, "risk_scanner", code, true, true).await;

    let rule_records = Arc::new(AtomicUsize::new(0));
    let target_records = Arc::new(AtomicUsize::new(0));
    let sink: MonitorResultSink = {
        let (rules, targets) = (rule_records.clone(), target_records.clone());
        Arc::new(move |request| {
            let (rules, targets) = (rules.clone(), targets.clone());
            Box::pin(async move {
                for item in request["work"].as_array().unwrap() {
                    let key = item["key"].as_str().unwrap();
                    if key.starts_with("rule:") && !key.contains(":step:") {
                        rules.fetch_add(1, Ordering::SeqCst);
                    }
                    if item["complete"] == true {
                        targets.fetch_add(1, Ordering::SeqCst);
                    }
                }
                Ok(MonitorCommitAck { newly_committed: true,
                    response: json!({"ok":true,"sequence":request["sequence"]}) })
            })
        })
    };
    let server = support::Server::start(false).await;
    let input = json!({"targets":[server.base],"dictionaryId":"owned-rules","concurrency":32,
        "__monitorExecution":context(&server.base)});
    let (_, output) = manager.execute_execution_plugin_with_result_sink(
        "risk_scanner", &input, "monitor_test", Some("owned-risk-full".into()),
        Duration::from_secs(30), Some(sink.clone())
    ).await.unwrap();
    let output = output.unwrap();
    assert_eq!(output["success"], true, "owned plugin output: {output}");
    assert_eq!(output["data"]["stream_complete"], true);
    let diagnostics = &output["data"]["summary"]["diagnostics"];
    for key in ["loaded_rules","applicable_rules","planned_rule_tasks","completed_rule_tasks"] {
        assert_eq!(diagnostics[key], 10005, "{key}");
    }
    assert_eq!(rule_records.load(Ordering::SeqCst), 10005);
    assert_eq!(target_records.load(Ordering::SeqCst), 1);
    let full_http_requests = server.requests.load(Ordering::SeqCst);
    assert_eq!(full_http_requests, 100);
    server.shutdown().await;

    let cancelled = support::Server::start(true).await;
    let cancel_input = json!({"targets":[cancelled.base],"concurrency":32,
        "dictionaryEntries":(0..10000).map(|index|json!({
            "word":format!("cancel-{index}"),"metadata":{
                "requests":[{"path":"/hold","method":"GET"}]
            }
        })).collect::<Vec<_>>(),
        "__monitorExecution":context(&cancelled.base)});
    let worker = manager.clone();
    let cancel_sink = sink.clone();
    let running = tokio::spawn(async move {
        worker.execute_execution_plugin_with_result_sink(
            "risk_scanner", &cancel_input, "monitor_test", Some("owned-risk-cancel".into()),
            Duration::from_secs(30), Some(cancel_sink)
        ).await
    });
    tokio::time::timeout(Duration::from_secs(5), async {
        while cancelled.requests.load(Ordering::SeqCst) < 4 {
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    }).await.expect("first four owned requests started");
    tokio::time::sleep(Duration::from_millis(30)).await;
    let held_requests = cancelled.requests.load(Ordering::SeqCst);
    assert_eq!(held_requests, 4, "plugin concurrency 32 still shares host limit 4");
    assert_eq!(terminate_plugin_executions_by_run("owned-risk-cancel"), 1);
    let error = tokio::time::timeout(Duration::from_secs(5), running)
        .await.unwrap().unwrap().unwrap_err();
    assert!(error.to_string().to_lowercase().contains("cancel"), "{error}");
    tokio::time::timeout(Duration::from_secs(5), async {
        while cancelled.active.load(Ordering::SeqCst) != 0 {
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    }).await.expect("cancelled owned connections drained");
    assert_eq!(terminate_plugin_executions_by_run("owned-risk-cancel"), 0);
    assert_eq!(target_records.load(Ordering::SeqCst), 1, "cancelled run cannot claim target completion");
    cancelled.shutdown().await;
    support::healthy(&manager).await;
    let report = json!({
        "runtime":"real PluginManager / QuickJS / in-memory SQLite / owned loopback HTTP",
        "loaded_rules":10005, "completed_rule_tasks":10005,
        "real_http_requests":full_http_requests,
        "plugin_concurrency":32, "host_global_concurrency":4, "held_requests_before_cancel":held_requests,
        "cancelled_connections_remaining":0, "cancelled_run_completed_targets":0,
        "next_runtime_healthy":true, "elapsed_ms":started.elapsed().as_millis()
    });
    if let Ok(path) = std::env::var("SENTINEL_RISK_FULL_SCAN_EVIDENCE") {
        std::fs::write(path, serde_json::to_string_pretty(&report).unwrap() + "\n").unwrap();
    }
    println!("{report}");
}
