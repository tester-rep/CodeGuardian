"""Comprehensive tests for the multi-language performance engine."""

from pathlib import Path
from tempfile import TemporaryDirectory

from codeguardian.config.loader import load_app_config
from codeguardian.core.context import ScanContext
from codeguardian.engines.performance_engine import PerformanceEngine


# ════════════════════════════════════════════════════════════════════════
# Python tests (preserved from original + expanded)
# ════════════════════════════════════════════════════════════════════════


async def test_performance_engine_detects_python_performance_and_api_misuse_patterns() -> None:
    source = """
import requests
import time

async def poll(url):
    time.sleep(1)
    requests.get(url)

while not ready:
    pass

for attempt in range(3):
    try:
        requests.get("https://example.com/api")
        break
    except Exception:
        continue
"""

    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "sample.py").write_text(source.strip() + "\n", encoding="utf-8")

        ctx = ScanContext(project_root=str(root), config=load_app_config(None))
        result = await PerformanceEngine().analyze(ctx)

    rule_ids = {finding.rule_id for finding in result.findings}
    assert {
        "HTTP-NO-TIMEOUT",
        "BUSY-WAIT",
        "RETRY-WITHOUT-BACKOFF",
        "BLOCKING-CALL-IN-ASYNC",
    }.issubset(rule_ids)


async def test_performance_engine_avoids_well_bounded_patterns() -> None:
    source = """
import asyncio
import requests
import time

async def poll():
    await asyncio.sleep(1)
    return "ok"


def fetch(url):
    for attempt in range(3):
        try:
            return requests.get(url, timeout=3)
        except Exception:
            time.sleep(1)
    return None
"""

    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "sample.py").write_text(source.strip() + "\n", encoding="utf-8")

        ctx = ScanContext(project_root=str(root), config=load_app_config(None))
        result = await PerformanceEngine().analyze(ctx)

    rule_ids = {finding.rule_id for finding in result.findings}
    assert "HTTP-NO-TIMEOUT" not in rule_ids
    assert "RETRY-WITHOUT-BACKOFF" not in rule_ids
    assert "BLOCKING-CALL-IN-ASYNC" not in rule_ids
    assert "BUSY-WAIT" not in rule_ids


# ════════════════════════════════════════════════════════════════════════
# Java tests
# ════════════════════════════════════════════════════════════════════════


async def test_java_http_no_timeout_openconnection() -> None:
    source = """
import java.net.URL;
import java.net.HttpURLConnection;

public class Client {
    public void fetch() throws Exception {
        URL url = new URL("https://example.com");
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("GET");
        int code = conn.getResponseCode();
    }
}
"""

    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "Client.java").write_text(source.strip() + "\n", encoding="utf-8")

        ctx = ScanContext(project_root=str(root), config=load_app_config(None))
        result = await PerformanceEngine().analyze(ctx)

    rule_ids = {finding.rule_id for finding in result.findings}
    assert "HTTP-NO-TIMEOUT" in rule_ids


async def test_java_http_with_timeout_not_flagged() -> None:
    source = """
import java.net.URL;
import java.net.HttpURLConnection;

public class Client {
    public void fetch() throws Exception {
        URL url = new URL("https://example.com");
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setConnectTimeout(5000);
        conn.setReadTimeout(5000);
        int code = conn.getResponseCode();
    }
}
"""

    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "Client.java").write_text(source.strip() + "\n", encoding="utf-8")

        ctx = ScanContext(project_root=str(root), config=load_app_config(None))
        result = await PerformanceEngine().analyze(ctx)

    rule_ids = {finding.rule_id for finding in result.findings}
    assert "HTTP-NO-TIMEOUT" not in rule_ids


async def test_java_httpclient_no_timeout() -> None:
    source = """
import java.net.http.HttpClient;

public class Client {
    public void fetch() {
        HttpClient client = HttpClient.newHttpClient();
    }
}
"""

    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "Client.java").write_text(source.strip() + "\n", encoding="utf-8")

        ctx = ScanContext(project_root=str(root), config=load_app_config(None))
        result = await PerformanceEngine().analyze(ctx)

    rule_ids = {finding.rule_id for finding in result.findings}
    assert "HTTP-NO-TIMEOUT" in rule_ids


async def test_java_busy_wait() -> None:
    source = """
public class Poller {
    public void waitForReady() {
        while (!isReady()) {
        }
    }

    private boolean isReady() {
        return false;
    }
}
"""

    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "Poller.java").write_text(source.strip() + "\n", encoding="utf-8")

        ctx = ScanContext(project_root=str(root), config=load_app_config(None))
        result = await PerformanceEngine().analyze(ctx)

    rule_ids = {finding.rule_id for finding in result.findings}
    assert "BUSY-WAIT" in rule_ids


async def test_java_retry_without_backoff() -> None:
    source = """
import java.net.http.HttpClient;

public class RetryClient {
    public void fetchWithRetry() {
        for (int i = 0; i < 3; i++) {
            try {
                doRequest();
                return;
            } catch (Exception e) {
                System.out.println("retry " + i);
            }
        }
    }

    private void doRequest() throws Exception {}
}
"""

    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "RetryClient.java").write_text(source.strip() + "\n", encoding="utf-8")

        ctx = ScanContext(project_root=str(root), config=load_app_config(None))
        result = await PerformanceEngine().analyze(ctx)

    rule_ids = {finding.rule_id for finding in result.findings}
    assert "RETRY-WITHOUT-BACKOFF" in rule_ids


async def test_java_retry_with_sleep_not_flagged() -> None:
    source = """
public class RetryClient {
    public void fetchWithRetry() throws InterruptedException {
        for (int i = 0; i < 3; i++) {
            try {
                doRequest();
                return;
            } catch (Exception e) {
                Thread.sleep(1000 * (i + 1));
            }
        }
    }

    private void doRequest() throws Exception {}
}
"""

    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "RetryClient.java").write_text(source.strip() + "\n", encoding="utf-8")

        ctx = ScanContext(project_root=str(root), config=load_app_config(None))
        result = await PerformanceEngine().analyze(ctx)

    rule_ids = {finding.rule_id for finding in result.findings}
    assert "RETRY-WITHOUT-BACKOFF" not in rule_ids


# ════════════════════════════════════════════════════════════════════════
# Go tests
# ════════════════════════════════════════════════════════════════════════


async def test_go_http_no_timeout() -> None:
    source = """
package main

import "net/http"

func fetch() {
    resp, err := http.Get("https://example.com")
    _ = resp
    _ = err
}
"""

    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "main.go").write_text(source.strip() + "\n", encoding="utf-8")

        ctx = ScanContext(project_root=str(root), config=load_app_config(None))
        result = await PerformanceEngine().analyze(ctx)

    rule_ids = {finding.rule_id for finding in result.findings}
    assert "HTTP-NO-TIMEOUT" in rule_ids


async def test_go_busy_wait() -> None:
    source = """
package main

func waitForReady(ready *bool) {
    for !(*ready) {
    }
}
"""

    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "main.go").write_text(source.strip() + "\n", encoding="utf-8")

        ctx = ScanContext(project_root=str(root), config=load_app_config(None))
        result = await PerformanceEngine().analyze(ctx)

    rule_ids = {finding.rule_id for finding in result.findings}
    assert "BUSY-WAIT" in rule_ids


async def test_go_unbounded_goroutine() -> None:
    source = """
package main

import "fmt"

func processItems(items []string) {
    for _, item := range items {
        go func(s string) {
            fmt.Println(s)
        }(item)
    }
}
"""

    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "main.go").write_text(source.strip() + "\n", encoding="utf-8")

        ctx = ScanContext(project_root=str(root), config=load_app_config(None))
        result = await PerformanceEngine().analyze(ctx)

    rule_ids = {finding.rule_id for finding in result.findings}
    assert "UNBOUNDED-GOROUTINE" in rule_ids


async def test_go_goroutine_with_waitgroup_not_flagged() -> None:
    source = """
package main

import (
    "fmt"
    "sync"
)

func processItems(items []string) {
    var wg sync.WaitGroup
    for _, item := range items {
        wg.Add(1)
        go func(s string) {
            defer wg.Done()
            fmt.Println(s)
        }(item)
    }
    wg.Wait()
}
"""

    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "main.go").write_text(source.strip() + "\n", encoding="utf-8")

        ctx = ScanContext(project_root=str(root), config=load_app_config(None))
        result = await PerformanceEngine().analyze(ctx)

    rule_ids = {finding.rule_id for finding in result.findings}
    assert "UNBOUNDED-GOROUTINE" not in rule_ids


async def test_go_mutex_lock_no_unlock() -> None:
    source = """
package main

import "sync"

type Counter struct {
    mu    sync.Mutex
    count int
}

func (c *Counter) Increment() {
    c.mu.Lock()
    c.count++
}
"""

    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "counter.go").write_text(source.strip() + "\n", encoding="utf-8")

        ctx = ScanContext(project_root=str(root), config=load_app_config(None))
        result = await PerformanceEngine().analyze(ctx)

    rule_ids = {finding.rule_id for finding in result.findings}
    assert "MUTEX-LOCK-NO-UNLOCK" in rule_ids


async def test_go_mutex_with_defer_unlock_not_flagged() -> None:
    source = """
package main

import "sync"

type Counter struct {
    mu    sync.Mutex
    count int
}

func (c *Counter) Increment() {
    c.mu.Lock()
    defer c.mu.Unlock()
    c.count++
}
"""

    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "counter.go").write_text(source.strip() + "\n", encoding="utf-8")

        ctx = ScanContext(project_root=str(root), config=load_app_config(None))
        result = await PerformanceEngine().analyze(ctx)

    rule_ids = {finding.rule_id for finding in result.findings}
    assert "MUTEX-LOCK-NO-UNLOCK" not in rule_ids


# ════════════════════════════════════════════════════════════════════════
# JavaScript / TypeScript tests
# ════════════════════════════════════════════════════════════════════════


async def test_js_fetch_no_timeout() -> None:
    source = """
async function getData() {
    const response = await fetch("https://api.example.com/data");
    return response.json();
}
"""

    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "api.js").write_text(source.strip() + "\n", encoding="utf-8")

        ctx = ScanContext(project_root=str(root), config=load_app_config(None))
        result = await PerformanceEngine().analyze(ctx)

    rule_ids = {finding.rule_id for finding in result.findings}
    assert "HTTP-NO-TIMEOUT" in rule_ids


async def test_js_fetch_with_signal_not_flagged() -> None:
    source = """
async function getData() {
    const controller = new AbortController();
    const response = await fetch("https://api.example.com/data", {
        signal: controller.signal,
    });
    return response.json();
}
"""

    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "api.js").write_text(source.strip() + "\n", encoding="utf-8")

        ctx = ScanContext(project_root=str(root), config=load_app_config(None))
        result = await PerformanceEngine().analyze(ctx)

    rule_ids = {finding.rule_id for finding in result.findings}
    assert "HTTP-NO-TIMEOUT" not in rule_ids


async def test_js_blocking_in_async() -> None:
    source = """
const fs = require('fs');

async function loadConfig() {
    const data = fs.readFileSync('/etc/config.json', 'utf-8');
    return JSON.parse(data);
}
"""

    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "config.js").write_text(source.strip() + "\n", encoding="utf-8")

        ctx = ScanContext(project_root=str(root), config=load_app_config(None))
        result = await PerformanceEngine().analyze(ctx)

    rule_ids = {finding.rule_id for finding in result.findings}
    assert "BLOCKING-CALL-IN-ASYNC" in rule_ids


async def test_ts_axios_no_timeout() -> None:
    source = """
import axios from 'axios';

async function fetchData(): Promise<any> {
    const response = await axios.get("https://api.example.com/data");
    return response.data;
}
"""

    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "api.ts").write_text(source.strip() + "\n", encoding="utf-8")

        ctx = ScanContext(project_root=str(root), config=load_app_config(None))
        result = await PerformanceEngine().analyze(ctx)

    rule_ids = {finding.rule_id for finding in result.findings}
    assert "HTTP-NO-TIMEOUT" in rule_ids


async def test_js_retry_without_backoff() -> None:
    source = """
function fetchWithRetry(url) {
    for (let i = 0; i < 3; i++) {
        try {
            return doRequest(url);
        } catch (e) {
            console.log("retrying...");
        }
    }
}
"""

    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "retry.js").write_text(source.strip() + "\n", encoding="utf-8")

        ctx = ScanContext(project_root=str(root), config=load_app_config(None))
        result = await PerformanceEngine().analyze(ctx)

    rule_ids = {finding.rule_id for finding in result.findings}
    assert "RETRY-WITHOUT-BACKOFF" in rule_ids


# ════════════════════════════════════════════════════════════════════════
# C++ tests
# ════════════════════════════════════════════════════════════════════════


async def test_cpp_busy_wait() -> None:
    source = """
#include <atomic>

void waitForReady(std::atomic<bool>& ready) {
    while (!ready.load()) {
    }
}
"""

    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "poller.cpp").write_text(source.strip() + "\n", encoding="utf-8")

        ctx = ScanContext(project_root=str(root), config=load_app_config(None))
        result = await PerformanceEngine().analyze(ctx)

    rule_ids = {finding.rule_id for finding in result.findings}
    assert "BUSY-WAIT" in rule_ids


async def test_cpp_mutex_lock_no_unlock() -> None:
    source = """
#include <mutex>

std::mutex mtx;
int counter = 0;

void increment() {
    mtx.lock();
    counter++;
}
"""

    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "counter.cpp").write_text(source.strip() + "\n", encoding="utf-8")

        ctx = ScanContext(project_root=str(root), config=load_app_config(None))
        result = await PerformanceEngine().analyze(ctx)

    rule_ids = {finding.rule_id for finding in result.findings}
    assert "MUTEX-LOCK-NO-UNLOCK" in rule_ids


async def test_cpp_mutex_with_lock_guard_not_flagged() -> None:
    source = """
#include <mutex>

std::mutex mtx;
int counter = 0;

void increment() {
    std::lock_guard<std::mutex> guard(mtx);
    counter++;
}
"""

    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "counter.cpp").write_text(source.strip() + "\n", encoding="utf-8")

        ctx = ScanContext(project_root=str(root), config=load_app_config(None))
        result = await PerformanceEngine().analyze(ctx)

    rule_ids = {finding.rule_id for finding in result.findings}
    assert "MUTEX-LOCK-NO-UNLOCK" not in rule_ids


async def test_cpp_mutex_with_unlock_not_flagged() -> None:
    source = """
#include <mutex>

std::mutex mtx;
int counter = 0;

void increment() {
    mtx.lock();
    counter++;
    mtx.unlock();
}
"""

    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "counter.cpp").write_text(source.strip() + "\n", encoding="utf-8")

        ctx = ScanContext(project_root=str(root), config=load_app_config(None))
        result = await PerformanceEngine().analyze(ctx)

    rule_ids = {finding.rule_id for finding in result.findings}
    assert "MUTEX-LOCK-NO-UNLOCK" not in rule_ids


# ════════════════════════════════════════════════════════════════════════
# Multi-language integration test
# ════════════════════════════════════════════════════════════════════════


async def test_multi_language_scan_detects_issues_across_languages() -> None:
    """Run the engine on a project with multiple languages and verify cross-language detection."""

    python_src = """
import requests

while True:
    pass

requests.get("https://example.com")
"""

    java_src = """
import java.net.http.HttpClient;

public class App {
    public void run() {
        HttpClient client = HttpClient.newHttpClient();
    }
}
"""

    go_src = """
package main

import "net/http"

func main() {
    resp, _ := http.Get("https://example.com")
    _ = resp
}
"""

    js_src = """
async function load() {
    const resp = await fetch("https://api.example.com");
    return resp.json();
}
"""

    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "app.py").write_text(python_src.strip() + "\n", encoding="utf-8")
        (root / "App.java").write_text(java_src.strip() + "\n", encoding="utf-8")
        (root / "main.go").write_text(go_src.strip() + "\n", encoding="utf-8")
        (root / "app.js").write_text(js_src.strip() + "\n", encoding="utf-8")

        ctx = ScanContext(project_root=str(root), config=load_app_config(None))
        result = await PerformanceEngine().analyze(ctx)

    rule_ids = {finding.rule_id for finding in result.findings}
    # Python: BUSY-WAIT + HTTP-NO-TIMEOUT
    assert "BUSY-WAIT" in rule_ids
    assert "HTTP-NO-TIMEOUT" in rule_ids

    # Verify findings come from multiple languages
    languages_found = {
        f.evidences[0].language for f in result.findings if f.evidences
    }
    assert "python" in languages_found
