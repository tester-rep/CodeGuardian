"""Behavior-locking tests for Top 5 newly added meaningful rules.

Covers:
- INSECURE-TLS-VERIFICATION (security, regex)  — Java/Go/Node/Python TLS bypass
- UNSAFE-DESERIALIZATION expansion (security)  — Java fastjson/Jackson/ObjectInputStream + .NET
- WEAK-CIPHER (security, regex)                — DES/3DES/RC4 + ECB mode
- MONEY-FLOAT-PRECISION (defect, regex)        — money fields stored as float/double/number
- BIGDECIMAL-DOUBLE-CTOR (defect, regex)       — `new BigDecimal(0.1)` literal-double constructor
- EXECUTOR-NOT-SHUTDOWN (defect, file-level)   — Java thread pool created without shutdown
"""

from pathlib import Path
from tempfile import TemporaryDirectory

from codeguardian.config.loader import load_app_config
from codeguardian.core.context import ScanContext
from codeguardian.engines.defect_engine import DefectEngine
from codeguardian.engines.security_engine import SecurityEngine


async def _security_findings(filename: str, source: str) -> list:
    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / filename).write_text(source, encoding="utf-8")
        ctx = ScanContext(project_root=str(root), config=load_app_config(None))
        return (await SecurityEngine().analyze(ctx)).findings


async def _defect_findings(filename: str, source: str) -> list:
    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / filename).write_text(source, encoding="utf-8")
        ctx = ScanContext(project_root=str(root), config=load_app_config(None))
        return (await DefectEngine().analyze(ctx)).findings


# ── INSECURE-TLS-VERIFICATION ───────────────────────────────────────────


async def test_tls_go_insecure_skip_verify_flagged() -> None:
    source = """
package main

import "crypto/tls"

func client() *tls.Config {
    return &tls.Config{InsecureSkipVerify: true}
}
"""
    findings = await _security_findings("c.go", source)
    hits = [f for f in findings if f.rule_id == "INSECURE-TLS-VERIFICATION"]
    assert len(hits) >= 1


async def test_tls_node_reject_unauthorized_false_flagged() -> None:
    source = """
const https = require('https');
const opts = { hostname: 'x', rejectUnauthorized: false };
https.request(opts);
"""
    findings = await _security_findings("c.js", source)
    hits = [f for f in findings if f.rule_id == "INSECURE-TLS-VERIFICATION"]
    assert len(hits) >= 1


async def test_tls_python_requests_verify_false_flagged() -> None:
    source = """
import requests
def fetch(url):
    return requests.get(url, verify=False)
"""
    findings = await _security_findings("c.py", source)
    hits = [f for f in findings if f.rule_id == "INSECURE-TLS-VERIFICATION"]
    assert len(hits) >= 1


async def test_tls_java_allow_all_hostname_flagged() -> None:
    source = """
import javax.net.ssl.*;
public class C {
    static void cfg(HttpsURLConnection c) {
        c.setHostnameVerifier(SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER);
    }
}
"""
    findings = await _security_findings("C.java", source)
    hits = [f for f in findings if f.rule_id == "INSECURE-TLS-VERIFICATION"]
    assert len(hits) >= 1


async def test_tls_normal_https_call_not_flagged() -> None:
    source = """
import requests
def fetch(url):
    return requests.get(url, timeout=5)
"""
    findings = await _security_findings("c.py", source)
    hits = [f for f in findings if f.rule_id == "INSECURE-TLS-VERIFICATION"]
    assert hits == []


# ── UNSAFE-DESERIALIZATION (Java/C# expansion) ──────────────────────────


async def test_unsafe_deser_java_fastjson_object_class_flagged() -> None:
    source = """
import com.alibaba.fastjson.JSON;
public class C {
    static Object parse(String s) {
        return JSON.parseObject(s, Object.class);
    }
}
"""
    findings = await _security_findings("C.java", source)
    hits = [f for f in findings if f.rule_id == "UNSAFE-DESERIALIZATION"]
    assert len(hits) >= 1


async def test_unsafe_deser_java_jackson_default_typing_flagged() -> None:
    source = """
import com.fasterxml.jackson.databind.ObjectMapper;
public class C {
    static ObjectMapper m() {
        ObjectMapper m = new ObjectMapper();
        m.enableDefaultTyping();
        return m;
    }
}
"""
    findings = await _security_findings("C.java", source)
    hits = [f for f in findings if f.rule_id == "UNSAFE-DESERIALIZATION"]
    assert len(hits) >= 1


async def test_unsafe_deser_java_object_input_stream_flagged() -> None:
    source = """
import java.io.*;
public class C {
    static Object load(InputStream in) throws Exception {
        return new ObjectInputStream(in).readObject();
    }
}
"""
    findings = await _security_findings("C.java", source)
    hits = [f for f in findings if f.rule_id == "UNSAFE-DESERIALIZATION"]
    assert len(hits) >= 1


async def test_unsafe_deser_csharp_binary_formatter_flagged() -> None:
    source = """
using System.Runtime.Serialization.Formatters.Binary;
public class C {
    public static object Load(System.IO.Stream s) {
        var f = new BinaryFormatter();
        return f.Deserialize(s);
    }
}
"""
    findings = await _security_findings("C.cs", source)
    hits = [f for f in findings if f.rule_id == "UNSAFE-DESERIALIZATION"]
    assert len(hits) >= 1


# ── WEAK-CIPHER ─────────────────────────────────────────────────────────


async def test_weak_cipher_java_des_flagged() -> None:
    source = """
import javax.crypto.Cipher;
public class C {
    static Cipher c() throws Exception {
        return Cipher.getInstance("DES");
    }
}
"""
    findings = await _security_findings("C.java", source)
    hits = [f for f in findings if f.rule_id == "WEAK-CIPHER"]
    assert len(hits) >= 1


async def test_weak_cipher_java_aes_ecb_flagged() -> None:
    source = """
import javax.crypto.Cipher;
public class C {
    static Cipher c() throws Exception {
        return Cipher.getInstance("AES/ECB/PKCS5Padding");
    }
}
"""
    findings = await _security_findings("C.java", source)
    hits = [f for f in findings if f.rule_id == "WEAK-CIPHER"]
    assert len(hits) >= 1


async def test_weak_cipher_python_des_new_flagged() -> None:
    source = """
from Crypto.Cipher import DES
def enc(key, data):
    c = DES.new(key, DES.MODE_ECB)
    return c.encrypt(data)
"""
    findings = await _security_findings("c.py", source)
    hits = [f for f in findings if f.rule_id == "WEAK-CIPHER"]
    # 应同时命中 DES.new 和 MODE_ECB
    assert len(hits) >= 1


async def test_weak_cipher_go_des_new_cipher_flagged() -> None:
    source = """
package main
import "crypto/des"
func enc(k []byte) {
    _, _ = des.NewCipher(k)
}
"""
    findings = await _security_findings("c.go", source)
    hits = [f for f in findings if f.rule_id == "WEAK-CIPHER"]
    assert len(hits) >= 1


async def test_weak_cipher_aes_gcm_not_flagged() -> None:
    source = """
import javax.crypto.Cipher;
public class C {
    static Cipher c() throws Exception {
        return Cipher.getInstance("AES/GCM/NoPadding");
    }
}
"""
    findings = await _security_findings("C.java", source)
    hits = [f for f in findings if f.rule_id == "WEAK-CIPHER"]
    assert hits == []


# ── MONEY-FLOAT-PRECISION ───────────────────────────────────────────────


async def test_money_double_field_java_flagged() -> None:
    source = """
public class Order {
    private double amount;
    private Double totalPrice;
}
"""
    findings = await _defect_findings("Order.java", source)
    hits = [f for f in findings if f.rule_id == "MONEY-FLOAT-PRECISION"]
    assert len(hits) >= 2


async def test_money_float_field_python_flagged() -> None:
    source = """
class Order:
    amount: float = 0.0
    balance: float = 100.0
"""
    findings = await _defect_findings("o.py", source)
    hits = [f for f in findings if f.rule_id == "MONEY-FLOAT-PRECISION"]
    assert len(hits) >= 2


async def test_money_number_field_typescript_flagged() -> None:
    source = """
interface Order {
    price: number;
    fee: number;
}
"""
    findings = await _defect_findings("o.ts", source)
    hits = [f for f in findings if f.rule_id == "MONEY-FLOAT-PRECISION"]
    assert len(hits) >= 2


async def test_money_int_field_not_flagged() -> None:
    """金额用 long/int（最小货币单位）不应告警。"""
    source = """
public class Order {
    private long amountInCents;
    private int totalCents;
}
"""
    findings = await _defect_findings("Order.java", source)
    hits = [f for f in findings if f.rule_id == "MONEY-FLOAT-PRECISION"]
    assert hits == []


async def test_money_unrelated_double_not_flagged() -> None:
    """非金额语义的 double 字段不应告警。"""
    source = """
public class Sensor {
    private double temperature;
    private double humidity;
}
"""
    findings = await _defect_findings("Sensor.java", source)
    hits = [f for f in findings if f.rule_id == "MONEY-FLOAT-PRECISION"]
    assert hits == []


# ── BIGDECIMAL-DOUBLE-CTOR ──────────────────────────────────────────────


async def test_bigdecimal_double_literal_flagged() -> None:
    source = """
import java.math.BigDecimal;
public class C {
    static BigDecimal a() {
        return new BigDecimal(0.1);
    }
}
"""
    findings = await _defect_findings("C.java", source)
    hits = [f for f in findings if f.rule_id == "BIGDECIMAL-DOUBLE-CTOR"]
    assert len(hits) == 1


async def test_bigdecimal_double_suffix_flagged() -> None:
    source = """
import java.math.BigDecimal;
public class C {
    static BigDecimal a() {
        return new BigDecimal(1d);
    }
}
"""
    findings = await _defect_findings("C.java", source)
    hits = [f for f in findings if f.rule_id == "BIGDECIMAL-DOUBLE-CTOR"]
    assert len(hits) == 1


async def test_bigdecimal_string_ctor_not_flagged() -> None:
    source = """
import java.math.BigDecimal;
public class C {
    static BigDecimal a() {
        return new BigDecimal("0.1");
    }
}
"""
    findings = await _defect_findings("C.java", source)
    hits = [f for f in findings if f.rule_id == "BIGDECIMAL-DOUBLE-CTOR"]
    assert hits == []


async def test_bigdecimal_int_ctor_not_flagged() -> None:
    """`new BigDecimal(100)` 整数构造无精度问题。"""
    source = """
import java.math.BigDecimal;
public class C {
    static BigDecimal a() {
        return new BigDecimal(100);
    }
}
"""
    findings = await _defect_findings("C.java", source)
    hits = [f for f in findings if f.rule_id == "BIGDECIMAL-DOUBLE-CTOR"]
    assert hits == []


# ── EXECUTOR-NOT-SHUTDOWN ───────────────────────────────────────────────


async def test_executor_fixed_pool_no_shutdown_flagged() -> None:
    source = """
import java.util.concurrent.*;
public class Worker {
    public void run() {
        ExecutorService pool = Executors.newFixedThreadPool(4);
        pool.submit(() -> System.out.println("hi"));
    }
}
"""
    findings = await _defect_findings("Worker.java", source)
    hits = [f for f in findings if f.rule_id == "EXECUTOR-NOT-SHUTDOWN"]
    assert len(hits) == 1


async def test_executor_thread_pool_executor_no_shutdown_flagged() -> None:
    source = """
import java.util.concurrent.*;
public class Worker {
    public void run() {
        ThreadPoolExecutor pool = new ThreadPoolExecutor(2, 4, 60L,
            TimeUnit.SECONDS, new LinkedBlockingQueue<>());
        pool.submit(() -> {});
    }
}
"""
    findings = await _defect_findings("Worker.java", source)
    hits = [f for f in findings if f.rule_id == "EXECUTOR-NOT-SHUTDOWN"]
    assert len(hits) == 1


async def test_executor_with_shutdown_not_flagged() -> None:
    source = """
import java.util.concurrent.*;
public class Worker {
    public void run() {
        ExecutorService pool = Executors.newFixedThreadPool(4);
        try {
            pool.submit(() -> {});
        } finally {
            pool.shutdown();
        }
    }
}
"""
    findings = await _defect_findings("Worker.java", source)
    hits = [f for f in findings if f.rule_id == "EXECUTOR-NOT-SHUTDOWN"]
    assert hits == []


async def test_executor_with_shutdown_now_not_flagged() -> None:
    source = """
import java.util.concurrent.*;
public class Worker {
    public void run() {
        ExecutorService pool = Executors.newCachedThreadPool();
        pool.submit(() -> {});
        pool.shutdownNow();
    }
}
"""
    findings = await _defect_findings("Worker.java", source)
    hits = [f for f in findings if f.rule_id == "EXECUTOR-NOT-SHUTDOWN"]
    assert hits == []


async def test_executor_non_java_not_flagged() -> None:
    """规则只对 Java 启用，Python concurrent.futures 不应误报。"""
    source = """
from concurrent.futures import ThreadPoolExecutor
def run():
    pool = ThreadPoolExecutor(max_workers=4)
    pool.submit(print, "hi")
"""
    findings = await _defect_findings("c.py", source)
    hits = [f for f in findings if f.rule_id == "EXECUTOR-NOT-SHUTDOWN"]
    assert hits == []
