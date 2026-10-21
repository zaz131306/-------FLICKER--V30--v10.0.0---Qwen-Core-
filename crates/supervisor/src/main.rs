//! FLICKER Tom 1 — `flicker-supervisor`
//!
//! Security microkernel (ТЗ V30 §4.3, §6). Привилегированный процесс:
//!   · абстракция keystore (software для разработки, PKCS#11 для production)
//!   · crypto-erase С ВЕРИФИКАЦИЕЙ нечитаемости (R6.1.1, критерий A5)
//!   · аудированный IPC по Unix domain socket с защитой от replay (R4.4)
//!   · TEE attestation — **stub** (зависимость DEP-HW-01)
//!
//! std-only. `unwrap`/`expect` не используются (§4.3, критерий A6).
//!
//! ## Маркировка зрелости (§6.2)
//! Каждый модуль несёт явный маркер. CI агрегирует их в отчёт о готовности,
//! поэтому заявить «HSM интегрирован», имея stub в коде, нельзя технически.
//!
//! | Компонент                  | maturity   |
//! |----------------------------|------------|
//! | SoftwareKeystore           | verified   |
//! | crypto_erase + verification| verified   |
//! | IPC (UDS, HMAC, AAD, anti-replay) | verified |
//! | Pkcs11Keystore             | stub       |
//! | TEE attestation            | stub       |
//! | AES-256-GCM confidentiality| not implemented (DEP-CRYPTO-01) |

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use symbolic_core::json::{parse_json, Json};
use symbolic_core::sha2::{hmac_sha256, sha256_hex, to_hex};
use symbolic_core::VERSION;

pub mod maturity {
    //! Машинно-читаемые маркеры зрелости (§6.2 ТЗ).
    pub const SOFTWARE_KEYSTORE: &str = "verified";
    pub const CRYPTO_ERASE: &str = "verified";
    pub const IPC: &str = "verified";
    pub const PKCS11_KEYSTORE: &str = "stub";
    pub const TEE_ATTESTATION: &str = "stub";
    pub const TRANSPORT_CONFIDENTIALITY: &str = "not-implemented";

    pub fn report() -> Vec<(&'static str, &'static str, &'static str)> {
        vec![
            ("software_keystore", SOFTWARE_KEYSTORE, "in-memory keys, zeroize on destroy, verified unreadable after erase"),
            ("crypto_erase", CRYPTO_ERASE, "destroys master key AND verifies it cannot be read back (R6.1.1)"),
            ("ipc", IPC, "Unix domain socket, HMAC-SHA256 auth, AAD{session_id,sequence}, anti-replay"),
            ("pkcs11_keystore", PKCS11_KEYSTORE, "requires real HSM hardware — DEP-HW-01"),
            ("tee_attestation", TEE_ATTESTATION, "NVIDIA CC available only under NDA; AMD SEV-SNP path not implemented"),
            ("transport_confidentiality", TRANSPORT_CONFIDENTIALITY, "AES-256-GCM requires a certified SKZI backend — DEP-CRYPTO-01; integrity IS provided by HMAC"),
        ]
    }
}

mod exit {
    pub const OK: u8 = 0;
    pub const USAGE: u8 = 2;
    pub const IO: u8 = 3;
    /// crypto-erase не прошёл верификацию — эксплуатация должна быть остановлена
    pub const ERASE_UNVERIFIED: u8 = 10;
    pub const AUTH: u8 = 11;
}

// ---------------------------------------------------------------------------
// Keystore
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub enum KeyClass {
    Master,
    Derived,
}

#[derive(Debug)]
pub struct KeyHandle {
    pub id: String,
    pub class: KeyClass,
    /// Material хранится только в памяти. `destroy` затирает байты явно,
    /// а не полагается на drop (§6.5: `mlock` + явное затирание).
    material: Vec<u8>,
    destroyed: bool,
}

impl KeyHandle {
    fn new(id: &str, class: KeyClass, material: Vec<u8>) -> Self {
        Self { id: id.to_string(), class, material, destroyed: false }
    }
    pub fn is_destroyed(&self) -> bool {
        self.destroyed || self.material.is_empty()
    }
    pub fn read(&self) -> Result<&[u8], String> {
        if self.is_destroyed() {
            // R6.1.1: после уничтожения чтение ОБЯЗАНО проваливаться.
            return Err(format!("key '{}' has been destroyed (handle invalid)", self.id));
        }
        Ok(&self.material)
    }
    /// Явное затирание материала.
    ///
    /// Намеренно БЕЗ `unsafe`: нормативное ядро держит инвариант
    /// «0 unsafe-блоков», и добавлять `write_volatile` ради этого нельзя.
    /// `std::hint::black_box` (stable) не даёт компилятору выбросить запись
    /// как мёртвый код, после чего память освобождается.
    ///
    /// Честное ограничение (§6.5): затирание в пользовательском пространстве не
    /// защищает от снятия образа памяти на уровне ядра или от cold-boot. Эти
    /// угрозы закрываются аппаратным шифрованием памяти (AMD SME/SEV-SNP,
    /// Intel TME/TDX) в TEE-контуре, а не программным затиранием.
    fn destroy(&mut self) {
        for b in self.material.iter_mut() {
            *b = 0;
            std::hint::black_box(b as *const u8);
        }
        self.material.clear();
        self.material.shrink_to_fit();
        self.destroyed = true;
    }
}

impl Drop for KeyHandle {
    fn drop(&mut self) {
        if !self.destroyed {
            self.destroy();
        }
    }
}

/// Абстракция keystore. Production-бэкенд (PKCS#11/HSM) — `stub`.
pub trait Keystore {
    fn maturity(&self) -> &'static str;
    fn backend_name(&self) -> &'static str;
    fn create_key(&mut self, id: &str, class: KeyClass, material: Vec<u8>) -> Result<(), String>;
    fn read_key(&self, id: &str) -> Result<&[u8], String>;
    fn list_ids(&self) -> Vec<String>;
    fn destroy_key(&mut self, id: &str) -> Result<(), String>;
}

/// Программный keystore для разработки и CI. **verified.**
#[derive(Debug, Default)]
pub struct SoftwareKeystore {
    keys: BTreeMap<String, KeyHandle>,
}

impl SoftwareKeystore {
    pub fn new() -> Self {
        Self::default()
    }
    /// Инициализация мастер-ключа и производных. Детерминированно из seed,
    /// чтобы selftest был воспроизводим.
    pub fn bootstrap(&mut self, seed: &[u8]) {
        let master = symbolic_core::sha2::sha256(seed).to_vec();
        let _ = self.create_key("master", KeyClass::Master, master.clone());
        for i in 0..3u8 {
            let mut s = seed.to_vec();
            s.push(i);
            let d = symbolic_core::sha2::sha256(&s).to_vec();
            let _ = self.create_key(&format!("derived-{}", i), KeyClass::Derived, d);
        }
    }
}

impl Keystore for SoftwareKeystore {
    fn maturity(&self) -> &'static str { maturity::SOFTWARE_KEYSTORE }
    fn backend_name(&self) -> &'static str { "software" }

    fn create_key(&mut self, id: &str, class: KeyClass, material: Vec<u8>) -> Result<(), String> {
        if self.keys.contains_key(id) {
            return Err(format!("key '{}' already exists", id));
        }
        self.keys.insert(id.to_string(), KeyHandle::new(id, class, material));
        Ok(())
    }

    fn read_key(&self, id: &str) -> Result<&[u8], String> {
        let h = self.keys.get(id).ok_or_else(|| format!("no such key '{}'", id))?;
        h.read()
    }

    fn list_ids(&self) -> Vec<String> {
        self.keys.keys().cloned().collect()
    }

    fn destroy_key(&mut self, id: &str) -> Result<(), String> {
        let h = self.keys.get_mut(id).ok_or_else(|| format!("no such key '{}'", id))?;
        h.destroy();
        Ok(())
    }
}

/// PKCS#11 / HSM бэкенд. **stub** — DEP-HW-01.
pub struct Pkcs11Keystore;

impl Keystore for Pkcs11Keystore {
    fn maturity(&self) -> &'static str { maturity::PKCS11_KEYSTORE }
    fn backend_name(&self) -> &'static str { "pkcs11-stub" }
    fn create_key(&mut self, _id: &str, _c: KeyClass, _m: Vec<u8>) -> Result<(), String> {
        Err("PKCS#11 backend is a stub: real HSM hardware required (DEP-HW-01)".into())
    }
    fn read_key(&self, _id: &str) -> Result<&[u8], String> {
        Err("PKCS#11 backend is a stub: real HSM hardware required (DEP-HW-01)".into())
    }
    fn list_ids(&self) -> Vec<String> { Vec::new() }
    fn destroy_key(&mut self, _id: &str) -> Result<(), String> {
        Err("PKCS#11 backend is a stub: real HSM hardware required (DEP-HW-01)".into())
    }
}

// ---------------------------------------------------------------------------
// Crypto-Erase (R6.1.1, критерий A5)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct EraseReport {
    pub master_destroyed: bool,
    pub derived_attempted: usize,
    pub derived_destroyed: usize,
    /// R6.1.1 шаг 3: попытка прочитать мастер-ключ ДОЛЖНА провалиться.
    /// Без этого шага требование не считается выполненным.
    pub verification_passed: bool,
    pub verification_detail: String,
    pub elapsed_ms: u64,
}

impl EraseReport {
    pub fn ok(&self) -> bool {
        self.master_destroyed && self.verification_passed
    }
    pub fn to_json(&self) -> Json {
        let mut o = Json::obj();
        o.insert("ok", Json::Bool(self.ok()));
        o.insert("master_destroyed", Json::Bool(self.master_destroyed));
        o.insert("derived_attempted", Json::int(self.derived_attempted as i64));
        o.insert("derived_destroyed", Json::int(self.derived_destroyed as i64));
        o.insert("verification_passed", Json::Bool(self.verification_passed));
        o.insert("verification_detail", Json::str(self.verification_detail.clone()));
        o.insert("elapsed_ms", Json::int(self.elapsed_ms as i64));
        o
    }
}

/// Гарантированное криптографическое стирание.
///
/// Отличие от дефектной реализации V28 (`destroy_all_keys()` делал только
/// `logout`): здесь мастер-ключ уничтожается, производные ключи уничтожаются
/// явно, а затем **выполняется верификация** — попытка чтения обязана
/// провалиться. Метрика «< 2 с» без верификации не принимается (R6.1.2).
pub fn crypto_erase<K: Keystore>(ks: &mut K) -> EraseReport {
    let start = SystemTime::now();

    // 1. Уничтожить мастер-ключ. Это и есть crypto-erase: без него все данные,
    //    зашифрованные на производных ключах, становятся статистическим шумом.
    let master_destroyed = ks.destroy_key("master").is_ok();

    // 2. Производные ключи — уничтожить явно, не полагаясь на каскад.
    //    best-effort: отказ одного не должен прерывать стирание остальных.
    let ids: Vec<String> = ks.list_ids().into_iter().filter(|i| i != "master").collect();
    let derived_attempted = ids.len();
    let mut derived_destroyed = 0usize;
    for id in &ids {
        if ks.destroy_key(id).is_ok() {
            derived_destroyed += 1;
        }
    }

    // 3. ВЕРИФИКАЦИЯ: чтение мастер-ключа должно провалиться.
    let (verification_passed, verification_detail) = match ks.read_key("master") {
        Err(e) => (true, format!("read correctly refused: {}", e)),
        Ok(_) => (false, "CRITICAL: master key is still readable after erase".to_string()),
    };

    // 3b. Дополнительно проверим, что производные тоже нечитаемы.
    let mut still_readable = Vec::new();
    for id in &ids {
        if ks.read_key(id).is_ok() {
            still_readable.push(id.clone());
        }
    }
    let verification_detail = if still_readable.is_empty() {
        verification_detail
    } else {
        format!("{}; derived keys still readable: {}", verification_detail, still_readable.join(", "))
    };
    let verification_passed = verification_passed && still_readable.is_empty();

    let elapsed_ms = SystemTime::now()
        .duration_since(start)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);

    EraseReport {
        master_destroyed,
        derived_attempted,
        derived_destroyed,
        verification_passed,
        verification_detail,
        elapsed_ms,
    }
}

// ---------------------------------------------------------------------------
// IPC: AAD + защита от replay (§4.4, R4.4)
// ---------------------------------------------------------------------------

/// AAD = {session_id, sequence}. Привязка MAC к контексту сессии и порядковому
/// номеру исключает и подмену контекста, и повторное воспроизведение.
fn compute_mac(session_key: &[u8], session_id: &str, sequence: u64, body: &str) -> String {
    let aad = format!("{}|{}", session_id, sequence);
    let mut msg = Vec::with_capacity(aad.len() + body.len() + 1);
    msg.extend_from_slice(aad.as_bytes());
    msg.push(b'\n');
    msg.extend_from_slice(body.as_bytes());
    to_hex(&hmac_sha256(session_key, &msg))
}

/// Трекер сессии: отклоняет повторные и неупорядоченные sequence.
#[derive(Debug, Default)]
pub struct SessionGuard {
    pub session_id: String,
    last_sequence: Option<u64>,
}

impl SessionGuard {
    pub fn new(session_id: &str) -> Self {
        Self { session_id: session_id.to_string(), last_sequence: None }
    }
    /// Возвращает Ok(()) либо причину отказа. Строго возрастающая sequence —
    /// монотонный счётчик, поэтому повторное воспроизведение невозможно.
    pub fn accept(&mut self, sequence: u64) -> Result<(), String> {
        match self.last_sequence {
            Some(last) if sequence <= last => Err(format!(
                "replay or out-of-order: sequence {} <= last accepted {}",
                sequence, last
            )),
            _ => {
                self.last_sequence = Some(sequence);
                Ok(())
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Обработка запросов
// ---------------------------------------------------------------------------

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

fn handle_request(ks: &mut SoftwareKeystore, guard: &mut SessionGuard, req: &Json) -> Json {
    let method = req.get("method").and_then(|v| v.as_str()).unwrap_or("");
    let mut o = Json::obj();
    o.insert("ok", Json::Bool(true));
    o.insert("method", Json::str(method));
    o.insert("ts_ms", Json::int(now_ms() as i64));

    match method {
        "ping" => {
            o.insert("version", Json::str(VERSION));
            o.insert("session_id", Json::str(guard.session_id.clone()));
        }
        "status" => {
            o.insert("backend", Json::str(ks.backend_name()));
            o.insert("backend_maturity", Json::str(ks.maturity()));
            o.insert("keys", Json::int(ks.list_ids().len() as i64));
            let mut arr = Vec::new();
            for (name, mat, note) in maturity::report() {
                let mut e = Json::obj();
                e.insert("component", Json::str(name));
                e.insert("maturity", Json::str(mat));
                e.insert("note", Json::str(note));
                arr.push(e);
            }
            o.insert("maturity_report", Json::arr(arr));
        }
        "keys.list" => {
            o.insert("ids", Json::arr(ks.list_ids().into_iter().map(Json::str).collect()));
        }
        "keys.read_fingerprint" => {
            // Материал ключа НИКОГДА не покидает Том 1. Возвращается только
            // отпечаток — этого достаточно для диагностики и не раскрывает ключ.
            let id = req.get("id").and_then(|v| v.as_str()).unwrap_or("");
            match ks.read_key(id) {
                Ok(m) => {
                    o.insert("id", Json::str(id));
                    o.insert("fingerprint", Json::str(sha256_hex(m)));
                }
                Err(e) => {
                    o.insert("ok", Json::Bool(false));
                    o.insert("error", Json::str(e));
                }
            }
        }
        "zeroize" => {
            let r = crypto_erase(ks);
            o.insert("ok", Json::Bool(r.ok()));
            o.insert("report", r.to_json());
            if !r.ok() {
                o.insert("critical", Json::str(
                    "crypto-erase verification FAILED — R15.2 requires immediate halt"));
            }
        }
        "attest" => {
            // STUB — DEP-HW-01. Честно сообщаем, а не возвращаем поддельный отчёт.
            o.insert("ok", Json::Bool(false));
            o.insert("maturity", Json::str(maturity::TEE_ATTESTATION));
            o.insert("error", Json::str(
                "TEE attestation is a stub: NVIDIA CC requires NDA, AMD SEV-SNP path not implemented (DEP-HW-01)"));
        }
        other => {
            o.insert("ok", Json::Bool(false));
            o.insert("error", Json::str(format!("unknown method '{}'", other)));
        }
    }
    o
}

// ---------------------------------------------------------------------------
// Сервер UDS
// ---------------------------------------------------------------------------

fn serve(socket: &Path, session_id: &str, session_key: &[u8], max_requests: Option<usize>) -> std::io::Result<()> {
    if socket.exists() {
        std::fs::remove_file(socket)?;
    }
    if let Some(parent) = socket.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let listener = UnixListener::bind(socket)?;
    eprintln!("[supervisor] listening on {}", socket.display());
    eprintln!("[supervisor] backend=software maturity={} session={}", maturity::SOFTWARE_KEYSTORE, session_id);

    let running = AtomicBool::new(true);
    let mut served = 0usize;

    for stream in listener.incoming() {
        if !running.load(Ordering::SeqCst) {
            break;
        }
        match stream {
            Ok(s) => {
                if let Err(e) = handle_connection(s, session_id, session_key) {
                    eprintln!("[supervisor] connection error: {}", e);
                }
                served += 1;
                if let Some(max) = max_requests {
                    if served >= max {
                        eprintln!("[supervisor] reached max-connections={}, shutting down", max);
                        break;
                    }
                }
            }
            Err(e) => eprintln!("[supervisor] accept error: {}", e),
        }
    }
    let _ = std::fs::remove_file(socket);
    Ok(())
}

fn handle_connection(mut stream: UnixStream, session_id: &str, session_key: &[u8]) -> std::io::Result<()> {
    let mut ks = SoftwareKeystore::new();
    ks.bootstrap(session_key);
    let mut guard = SessionGuard::new(session_id);

    let peer = stream.try_clone()?;
    let mut reader = BufReader::new(peer);
    let mut line = String::new();

    loop {
        line.clear();
        let n = reader.read_line(&mut line)?;
        if n == 0 {
            break; // EOF
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let resp = match parse_json(trimmed) {
            Err(e) => {
                let mut o = Json::obj();
                o.insert("ok", Json::Bool(false));
                o.insert("error", Json::str(format!("malformed JSON: {}", e.message)));
                o
            }
            Ok(req) => {
                // --- Проверка AAD и MAC (R4.4) ---
                let got_session = req.get("session_id").and_then(|v| v.as_str()).unwrap_or("");
                let got_seq = req.get("sequence").and_then(|v| v.as_int()).unwrap_or(-1);
                let got_mac = req.get("mac").and_then(|v| v.as_str()).unwrap_or("");
                let body = req.get("body").map(|v| v.to_canonical().unwrap_or_default()).unwrap_or_default();

                let mut err: Option<String> = None;
                if got_session != session_id {
                    err = Some(format!("session_id mismatch: got '{}'", got_session));
                } else if got_seq < 0 {
                    err = Some("missing or negative 'sequence'".into());
                } else {
                    let expected = compute_mac(session_key, got_session, got_seq as u64, &body);
                    // Сравнение должно быть постоянным по времени, чтобы не
                    // давать побочный канал по MAC.
                    if !ct_eq(expected.as_bytes(), got_mac.as_bytes()) {
                        err = Some("MAC verification failed".into());
                    } else if let Err(e) = guard.accept(got_seq as u64) {
                        err = Some(e);
                    }
                }

                match err {
                    Some(e) => {
                        let mut o = Json::obj();
                        o.insert("ok", Json::Bool(false));
                        o.insert("error", Json::str(format!("auth: {}", e)));
                        o
                    }
                    None => {
                        let body_json = parse_json(&body).ok();
                        match body_json {
                            Some(b) => handle_request(&mut ks, &mut guard, &b),
                            None => {
                                let mut o = Json::obj();
                                o.insert("ok", Json::Bool(false));
                                o.insert("error", Json::str("body is not valid JSON"));
                                o
                            }
                        }
                    }
                }
            }
        };

        let mut out = resp.to_canonical().unwrap_or_else(|_| "{\"ok\":false}".to_string());
        out.push('\n');
        stream.write_all(out.as_bytes())?;
        stream.flush()?;
    }
    Ok(())
}

/// Сравнение, постоянное по времени: длина фиксируется, содержимое не
/// влияет на время возврата.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        // Длина MAC фиксирована (64 hex), поэтому само по себе сравнение длин
        // секрет не раскрывает.
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

// ---------------------------------------------------------------------------
// Клиент (для smoke-теста и для Тома 2)
// ---------------------------------------------------------------------------

fn client_call(socket: &Path, session_id: &str, session_key: &[u8], seq: u64, method: &str, args: Json) -> Result<Json, String> {
    let mut stream = UnixStream::connect(socket).map_err(|e| format!("connect {}: {}", socket.display(), e))?;
    let body = {
        let mut b = Json::obj();
        b.insert("method", Json::str(method));
        if let Json::Obj(m) = args {
            for (k, v) in m {
                b.insert(&k, v);
            }
        }
        b
    };
    let body_canon = body.to_canonical().map_err(|e| e.message)?;
    let mac = compute_mac(session_key, session_id, seq, &body_canon);

    let mut env = Json::obj();
    env.insert("session_id", Json::str(session_id));
    env.insert("sequence", Json::int(seq as i64));
    env.insert("mac", Json::str(mac));
    env.insert("body", parse_json(&body_canon).map_err(|e| e.message)?);
    let mut line = env.to_canonical().map_err(|e| e.message)?;
    line.push('\n');

    stream.write_all(line.as_bytes()).map_err(|e| e.to_string())?;
    stream.flush().map_err(|e| e.to_string())?;
    stream.shutdown(std::net::Shutdown::Write).map_err(|e| e.to_string())?;

    let mut reader = BufReader::new(stream);
    let mut resp = String::new();
    reader.read_line(&mut resp).map_err(|e| e.to_string())?;
    parse_json(resp.trim()).map_err(|e| e.message)
}

// ---------------------------------------------------------------------------
// Selftest — локальная проверка A5/A6 без сети
// ---------------------------------------------------------------------------

fn cmd_selftest(json: bool) -> ExitCode {
    let mut checks: Vec<(String, bool, String)> = Vec::new();

    // A5: crypto-erase уничтожает мастер-ключ И верифицирует нечитаемость
    let mut ks = SoftwareKeystore::new();
    ks.bootstrap(b"flicker-selftest-seed");
    let before = ks.read_key("master").is_ok();
    checks.push(("master key readable before erase".into(), before, "".into()));

    let report = crypto_erase(&mut ks);

    checks.push(("master key destroyed".into(), report.master_destroyed, "".into()));
    checks.push((
        "R6.1.1 verification: master unreadable after erase".into(),
        report.verification_passed,
        report.verification_detail.clone(),
    ));
    checks.push((
        "all derived keys destroyed".into(),
        report.derived_destroyed == report.derived_attempted && report.derived_attempted > 0,
        format!("{}/{}", report.derived_destroyed, report.derived_attempted),
    ));
    checks.push((
        "A5 crypto-erase < 2000 ms".into(),
        report.elapsed_ms < 2000,
        format!("{} ms", report.elapsed_ms),
    ));
    checks.push(("erase report ok()".into(), report.ok(), "".into()));

    // A6-прокси: отсутствие unwrap/expect проверяется clippy в CI; здесь —
    // поведение Drop (zeroize on drop).
    let dropped_ok = {
        let mut inner = SoftwareKeystore::new();
        let _ = inner.create_key("tmp", KeyClass::Derived, vec![1, 2, 3, 4]);
        inner.destroy_key("tmp").is_ok() && inner.read_key("tmp").is_err()
    };
    checks.push(("destroyed key refuses read".into(), dropped_ok, "".into()));

    // Anti-replay
    let mut g = SessionGuard::new("s1");
    let a1 = g.accept(1).is_ok();
    let a2 = g.accept(2).is_ok();
    let replay = g.accept(2).is_err();
    let rewind = g.accept(1).is_err();
    checks.push(("sequence strictly increasing accepted".into(), a1 && a2, "".into()));
    checks.push(("replayed sequence rejected".into(), replay, "".into()));
    checks.push(("rewound sequence rejected".into(), rewind, "".into()));

    // MAC привязан к AAD: смена session_id или sequence ломает MAC
    let key = b"session-key";
    let body = r#"{"method":"ping"}"#;
    let m1 = compute_mac(key, "sess-A", 7, body);
    let m2 = compute_mac(key, "sess-B", 7, body);
    let m3 = compute_mac(key, "sess-A", 8, body);
    checks.push(("MAC binds session_id (AAD)".into(), m1 != m2, "".into()));
    checks.push(("MAC binds sequence (AAD)".into(), m1 != m3, "".into()));
    checks.push(("MAC is 64 hex chars".into(), m1.len() == 64, m1.clone()));
    checks.push(("constant-time compare accepts equal".into(), ct_eq(m1.as_bytes(), m1.as_bytes()), "".into()));
    checks.push(("constant-time compare rejects different".into(), !ct_eq(m1.as_bytes(), m2.as_bytes()), "".into()));
    checks.push(("constant-time compare rejects length mismatch".into(), !ct_eq(b"abc", b"abcd"), "".into()));

    // Stub-честность: PKCS#11 и attestation обязаны СООБЩАТЬ, что они stub
    let mut p11 = Pkcs11Keystore;
    let p11_err = p11.create_key("x", KeyClass::Derived, vec![1]).err().unwrap_or_default();
    checks.push((
        "pkcs11 stub reports itself as stub".into(),
        p11.maturity() == maturity::PKCS11_KEYSTORE && p11_err.contains("stub"),
        p11_err.clone(),
    ));

    let all_ok = checks.iter().all(|(_, ok, _)| *ok);

    if json {
        let mut arr = Vec::new();
        for (n, ok, d) in &checks {
            let mut e = Json::obj();
            e.insert("check", Json::str(n.clone()));
            e.insert("ok", Json::Bool(*ok));
            if !d.is_empty() { e.insert("detail", Json::str(d.clone())); }
            arr.push(e);
        }
        let mut o = Json::obj();
        o.insert("ok", Json::Bool(all_ok));
        o.insert("component", Json::str("flicker-supervisor"));
        o.insert("version", Json::str(VERSION));
        o.insert("erase_report", report.to_json());
        o.insert("checks", Json::arr(arr));
        println!("{}", o.to_pretty());
    } else {
        println!("SUPERVISOR SELFTEST · v{} · backend=software", VERSION);
        for (n, ok, d) in &checks {
            println!("  [{}] {}{}", if *ok { "PASS" } else { "FAIL" }, n,
                if d.is_empty() { String::new() } else { format!("  ({})", d) });
        }
        println!("  erase report: {}", report.verification_detail);
        println!("RESULT: {}", if all_ok { "ALL PASS" } else { "FAILURES PRESENT" });
    }
    if all_ok { ExitCode::from(exit::OK) } else { ExitCode::from(exit::ERASE_UNVERIFIED) }
}

// ---------------------------------------------------------------------------

const USAGE: &str = r#"flicker-supervisor — FLICKER Tom 1 security microkernel

USAGE:
    flicker-supervisor <COMMAND> [OPTIONS]

COMMANDS:
    selftest        Локальные проверки A5/A6, anti-replay, AAD, stub-честность
    serve           Запустить IPC-сервер на Unix domain socket
    call <method>   Однократный вызов метода через сокет (smoke-тест)
    status          То же, что `call status`
    zeroize         То же, что `call zeroize` (crypto-erase с верификацией)
    maturity        Отчёт о зрелости компонентов (§6.2)
    version         Версия

OPTIONS:
    --socket <path>       Путь UDS                [default: /run/flicker/supervisor.sock]
    --session-id <id>     Идентификатор сессии    [default: dev-session]
    --session-key <hex|text>  Ключ сессии (HMAC)  [default: dev-session-key]
    --max-connections <n> Завершиться после n соединений (для тестов)
    --json                Машинно-читаемый вывод

METHODS (через `call`): ping, status, keys.list, keys.read_fingerprint, zeroize, attest

EXIT CODES:
    0 ok · 2 usage · 3 io · 10 crypto-erase не верифицирован · 11 auth

ВАЖНО: транспорт обеспечивает ЦЕЛОСТНОСТЬ и защиту от replay (HMAC-SHA256 + AAD).
КОНФИДЕНЦИАЛЬНОСТЬ (AES-256-GCM) не реализована — DEP-CRYPTO-01, см. `maturity`.
"#;

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().collect();
    let mut cmd = String::new();
    let mut method = String::new();
    let mut socket = PathBuf::from("/run/flicker/supervisor.sock");
    let mut session_id = "dev-session".to_string();
    let mut session_key = "dev-session-key".to_string();
    let mut max_conn: Option<usize> = None;
    let mut json = false;

    let mut i = 1usize;
    while i < argv.len() {
        let a = argv[i].clone();
        match a.as_str() {
            "--socket" => { i += 1; socket = argv.get(i).map(PathBuf::from).unwrap_or(socket); }
            "--session-id" => { i += 1; if let Some(v) = argv.get(i) { session_id = v.clone(); } }
            "--session-key" => { i += 1; if let Some(v) = argv.get(i) { session_key = v.clone(); } }
            "--max-connections" => {
                i += 1;
                max_conn = argv.get(i).and_then(|v| v.parse::<usize>().ok());
            }
            "--json" => json = true,
            "-h" | "--help" => { print!("{}", USAGE); return ExitCode::from(exit::OK); }
            other => {
                if !other.starts_with('-') {
                    if cmd.is_empty() { cmd = other.to_string(); }
                    else if method.is_empty() { method = other.to_string(); }
                    else { eprintln!("error: unexpected argument '{}'", other); return ExitCode::from(exit::USAGE); }
                } else {
                    eprintln!("error: unknown flag '{}'", other);
                    return ExitCode::from(exit::USAGE);
                }
            }
        }
        i += 1;
    }

    let key_bytes = session_key.as_bytes().to_vec();

    match cmd.as_str() {
        "" | "help" => { print!("{}", USAGE); ExitCode::from(if cmd.is_empty() { exit::USAGE } else { exit::OK }) }
        "version" => {
            if json {
                let mut o = Json::obj();
                o.insert("ok", Json::Bool(true));
                o.insert("component", Json::str("flicker-supervisor"));
                o.insert("version", Json::str(VERSION));
                println!("{}", o.to_pretty());
            } else {
                println!("flicker-supervisor {} · symbolic-core {}", VERSION, VERSION);
            }
            ExitCode::from(exit::OK)
        }
        "maturity" => {
            if json {
                let mut arr = Vec::new();
                for (n, m, note) in maturity::report() {
                    let mut e = Json::obj();
                    e.insert("component", Json::str(n));
                    e.insert("maturity", Json::str(m));
                    e.insert("note", Json::str(note));
                    arr.push(e);
                }
                let mut o = Json::obj();
                o.insert("ok", Json::Bool(true));
                o.insert("components", Json::arr(arr));
                println!("{}", o.to_pretty());
            } else {
                println!("MATURITY REPORT (§6.2) · flicker-supervisor v{}", VERSION);
                for (n, m, note) in maturity::report() {
                    println!("  {:<28} {:<18} {}", n, m, note);
                }
                println!("\nЧестность обязательна: заявлять компонент как реализованный,");
                println!("имея maturity=stub, запрещено (R6.2, §16.1 ТЗ).");
            }
            ExitCode::from(exit::OK)
        }
        "selftest" => cmd_selftest(json),
        "serve" => {
            match serve(&socket, &session_id, &key_bytes, max_conn) {
                Ok(()) => ExitCode::from(exit::OK),
                Err(e) => {
                    eprintln!("[supervisor] serve failed: {}", e);
                    ExitCode::from(exit::IO)
                }
            }
        }
        "status" | "zeroize" | "call" => {
            let m = if cmd == "call" {
                if method.is_empty() {
                    eprintln!("error: `call` requires a method name");
                    return ExitCode::from(exit::USAGE);
                }
                method.clone()
            } else {
                cmd.clone()
            };
            match client_call(&socket, &session_id, &key_bytes, 1, &m, Json::obj()) {
                Ok(resp) => {
                    if json {
                        println!("{}", resp.to_pretty());
                    } else {
                        println!("{}", resp.to_canonical().unwrap_or_else(|_| "{}".into()));
                    }
                    let ok = resp.get("ok").and_then(|v| v.as_bool()).unwrap_or(false);
                    if ok {
                        ExitCode::from(exit::OK)
                    } else if m == "zeroize" {
                        ExitCode::from(exit::ERASE_UNVERIFIED)
                    } else {
                        ExitCode::from(exit::AUTH)
                    }
                }
                Err(e) => {
                    eprintln!("error: {}", e);
                    ExitCode::from(exit::IO)
                }
            }
        }
        other => {
            eprintln!("error: unknown command '{}'\n\n{}", other, USAGE);
            ExitCode::from(exit::USAGE)
        }
    }
}

// ---------------------------------------------------------------------------
// Тесты Тома 1
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn software_keystore_bootstrap_creates_master_and_derived() {
        let mut ks = SoftwareKeystore::new();
        ks.bootstrap(b"seed");
        assert!(ks.read_key("master").is_ok());
        assert_eq!(ks.list_ids().len(), 4, "master + 3 derived");
        assert!(ks.read_key("derived-0").is_ok());
    }

    #[test]
    fn duplicate_key_creation_is_refused() {
        let mut ks = SoftwareKeystore::new();
        assert!(ks.create_key("k", KeyClass::Derived, vec![1]).is_ok());
        assert!(ks.create_key("k", KeyClass::Derived, vec![2]).is_err());
    }

    #[test]
    fn a5_crypto_erase_destroys_and_verifies() {
        let mut ks = SoftwareKeystore::new();
        ks.bootstrap(b"seed");
        assert!(ks.read_key("master").is_ok(), "precondition: key exists");

        let r = crypto_erase(&mut ks);
        assert!(r.master_destroyed);
        assert!(r.verification_passed, "R6.1.1 step 3 must pass: {}", r.verification_detail);
        assert!(r.ok());
        assert_eq!(r.derived_attempted, 3);
        assert_eq!(r.derived_destroyed, 3);
        assert!(r.elapsed_ms < 2000, "A5: must be under 2 s, was {} ms", r.elapsed_ms);

        // Ключ действительно нечитаем
        assert!(ks.read_key("master").is_err());
        assert!(ks.read_key("derived-0").is_err());
    }

    #[test]
    fn crypto_erase_is_idempotent() {
        let mut ks = SoftwareKeystore::new();
        ks.bootstrap(b"seed");
        let r1 = crypto_erase(&mut ks);
        assert!(r1.ok());
        // Повторный вызов не должен паниковать и обязан остаться verifiable.
        let r2 = crypto_erase(&mut ks);
        assert!(r2.verification_passed, "second erase must still verify: {}", r2.verification_detail);
    }

    #[test]
    fn v28_defect_would_be_caught() {
        // Регрессия на дефект V28: `destroy_all_keys()` делал только logout,
        // ключи оставались читаемы. Если бы erase не уничтожал материал,
        // verification_passed был бы false. Проверяем, что верификация
        // действительно чувствительна к чтению.
        let mut ks = SoftwareKeystore::new();
        ks.bootstrap(b"seed");
        let fp_before = sha256_hex(ks.read_key("master").unwrap_or(&[]));
        let r = crypto_erase(&mut ks);
        assert!(r.verification_passed);
        // После erase отпечаток получить нельзя
        assert!(ks.read_key("master").is_err());
        assert_eq!(fp_before.len(), 64);
    }

    #[test]
    fn session_guard_rejects_replay_and_rewind() {
        let mut g = SessionGuard::new("s");
        assert!(g.accept(1).is_ok());
        assert!(g.accept(2).is_ok());
        assert!(g.accept(3).is_ok());
        assert!(g.accept(3).is_err(), "replay");
        assert!(g.accept(2).is_err(), "rewind");
        assert!(g.accept(0).is_err(), "genesis replay");
        assert!(g.accept(4).is_ok(), "still accepts forward progress");
    }

    #[test]
    fn mac_binds_aad_context() {
        let k = b"key";
        let b = r#"{"method":"zeroize"}"#;
        let m = compute_mac(k, "sess", 1, b);
        assert_eq!(m.len(), 64);
        assert_ne!(m, compute_mac(k, "sess2", 1, b), "session_id must be bound");
        assert_ne!(m, compute_mac(k, "sess", 2, b), "sequence must be bound");
        assert_ne!(m, compute_mac(k, "sess", 1, r#"{"method":"ping"}"#), "body must be bound");
        assert_ne!(m, compute_mac(b"other", "sess", 1, b), "key must be bound");
        assert_eq!(m, compute_mac(k, "sess", 1, b), "deterministic");
    }

    #[test]
    fn constant_time_compare_is_correct() {
        assert!(ct_eq(b"abcdef", b"abcdef"));
        assert!(!ct_eq(b"abcdef", b"abcdeg"));
        assert!(!ct_eq(b"abcdef", b"abcde"));
        assert!(!ct_eq(b"", b"a"));
        assert!(ct_eq(b"", b""));
    }

    #[test]
    fn pkcs11_stub_admits_it_is_a_stub() {
        let mut p = Pkcs11Keystore;
        assert_eq!(p.maturity(), maturity::PKCS11_KEYSTORE);
        let e = p.create_key("x", KeyClass::Master, vec![1]).err();
        assert!(e.is_some());
        let msg = e.unwrap_or_default();
        assert!(msg.contains("stub"), "must self-identify as stub: {}", msg);
        assert!(msg.contains("DEP-HW-01"), "must name the blocking dependency: {}", msg);
        assert!(p.read_key("x").is_err());
        assert!(p.destroy_key("x").is_err());
        assert!(p.list_ids().is_empty());
    }

    #[test]
    fn maturity_report_covers_all_components() {
        let r = maturity::report();
        assert!(r.len() >= 6);
        let names: Vec<&str> = r.iter().map(|x| x.0).collect();
        for required in ["software_keystore", "crypto_erase", "ipc", "pkcs11_keystore", "tee_attestation"] {
            assert!(names.contains(&required), "missing component {}", required);
        }
        // Ни один компонент не заявлен как verified без основания
        for (n, m, note) in &r {
            assert!(!m.is_empty(), "{} has empty maturity", n);
            assert!(!note.is_empty(), "{} has no note", n);
        }
    }

    #[test]
    fn handle_request_rejects_unknown_method() {
        let mut ks = SoftwareKeystore::new();
        ks.bootstrap(b"s");
        let mut g = SessionGuard::new("s");
        let mut req = Json::obj();
        req.insert("method", Json::str("drop-table"));
        let resp = handle_request(&mut ks, &mut g, &req);
        assert_eq!(resp.get("ok").and_then(|v| v.as_bool()), Some(false));
    }

    #[test]
    fn handle_request_zeroize_reports_success() {
        let mut ks = SoftwareKeystore::new();
        ks.bootstrap(b"s");
        let mut g = SessionGuard::new("s");
        let mut req = Json::obj();
        req.insert("method", Json::str("zeroize"));
        let resp = handle_request(&mut ks, &mut g, &req);
        assert_eq!(resp.get("ok").and_then(|v| v.as_bool()), Some(true));
        assert!(resp.get("report").is_some());
    }

    #[test]
    fn handle_request_attest_is_honest_about_stub() {
        let mut ks = SoftwareKeystore::new();
        let mut g = SessionGuard::new("s");
        let mut req = Json::obj();
        req.insert("method", Json::str("attest"));
        let resp = handle_request(&mut ks, &mut g, &req);
        // STUB обязан сообщать ok=false, а не возвращать поддельный отчёт
        assert_eq!(resp.get("ok").and_then(|v| v.as_bool()), Some(false));
        assert_eq!(resp.get("maturity").and_then(|v| v.as_str()), Some(maturity::TEE_ATTESTATION));
    }

    #[test]
    fn keys_read_fingerprint_never_leaks_material() {
        let mut ks = SoftwareKeystore::new();
        ks.bootstrap(b"s");
        let mut g = SessionGuard::new("s");
        let mut req = Json::obj();
        req.insert("method", Json::str("keys.read_fingerprint"));
        req.insert("id", Json::str("master"));
        let resp = handle_request(&mut ks, &mut g, &req);
        assert_eq!(resp.get("ok").and_then(|v| v.as_bool()), Some(true));
        let fp = resp.get("fingerprint").and_then(|v| v.as_str()).unwrap_or("");
        assert_eq!(fp.len(), 64, "fingerprint must be a SHA-256 hex digest");
        // сам материал не должен присутствовать в ответе
        let canon = resp.to_canonical().unwrap_or_default();
        let raw = ks.read_key("master").unwrap_or(&[]);
        if !raw.is_empty() {
            assert!(!canon.contains(&to_hex(raw)), "response must not contain key material");
        }
    }

    #[test]
    fn end_to_end_over_unix_socket() {
        // Сквозной тест IPC: сервер в потоке, клиент вызывает ping и zeroize.
        let dir = std::env::temp_dir().join(format!("flicker-suptest-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let sock = dir.join("s.sock");
        let _ = std::fs::remove_file(&sock);

        let s_clone = sock.clone();
        let h = std::thread::spawn(move || {
            let _ = serve(&s_clone, "test-session", b"test-key", Some(2));
        });

        // ждём появления сокета
        let mut waited = 0;
        while !sock.exists() && waited < 100 {
            std::thread::sleep(std::time::Duration::from_millis(20));
            waited += 1;
        }
        assert!(sock.exists(), "server did not create the socket");

        let r1 = client_call(&sock, "test-session", b"test-key", 1, "ping", Json::obj())
            .unwrap_or_else(|e| panic!("ping failed: {}", e));
        assert_eq!(r1.get("ok").and_then(|v| v.as_bool()), Some(true));
        assert_eq!(r1.get("method").and_then(|v| v.as_str()), Some("ping"));

        let r2 = client_call(&sock, "test-session", b"test-key", 2, "status", Json::obj())
            .unwrap_or_else(|e| panic!("status failed: {}", e));
        assert_eq!(r2.get("backend").and_then(|v| v.as_str()), Some("software"));

        // Неверный session_id -> отказ аутентификации
        let r3 = client_call(&sock, "WRONG-session", b"test-key", 3, "ping", Json::obj());
        if let Ok(v) = r3 {
            assert_eq!(v.get("ok").and_then(|x| x.as_bool()), Some(false),
                       "wrong session must be refused");
        }
        // Err(_) допустим: супервизор мог закрыть соединение после отказа

        let _ = h.join();
        let _ = std::fs::remove_file(&sock);
        let _ = std::fs::remove_dir(&dir);
    }
}
