'use strict';
/**
 * chrome_hooks.js — Chrome (BoringSSL) TLS 密钥提取 Frida Hook
 *
 * T5.2:
 *   Python 侧将配置 JSON 注入到 %HOOK_CONFIG% 占位符。
 *
 * T6.2 Phase 2:
 *   为 ssl_log_secret 单独走 client_random 路径，正式产出 keylog 行，
 *   用于补齐复用场景下现有主链路未覆盖的密钥。
 */

const CFG = %HOOK_CONFIG%;

// ── 去重集合 ─────────────────────────────────────────────────────
const _emitted = new Set();
const _sslLogSeen = new Set();
const SSL_LOG_DEBUG_MAX = 24;

// ── TLS 1.2 master_secret 校准 ──────────────────────────────────
let _msCalibrated = false, _msPathType = null, _msOff1 = 0, _msOff2 = 0;
const _prfCache = new Map();

// ── 配置展开 ─────────────────────────────────────────────────────
const NSS_LABEL = CFG.tls13_label_map || {};
const KEY_LEN_OFFSET = {};
for (const [label, value] of Object.entries(CFG.tls13_key_len_offsets || {})) {
    if (typeof value === 'string') {
        KEY_LEN_OFFSET[label] = ptr(value).toInt32();
    }
}

const PRF_RVA = CFG.hook_points.prf.rva;
const KEY_EXP_RVA = CFG.hook_points.key_expansion.rva;
const HKDF_RVA = CFG.hook_points.hkdf.rva;
const SSL_LOG_SECRET_RVA = CFG.hook_points.ssl_log_secret && CFG.hook_points.ssl_log_secret.rva;
const RBIO_OFFSET = ptr(CFG.struct_offsets.ssl_st_rbio).toInt32();
const BIO_NUM_OFFSET = ptr(CFG.struct_offsets.bio_st_num).toInt32();

// ── 工具函数 ─────────────────────────────────────────────────────

function hex(buf) {
    if (!buf) return null;
    return Array.from(new Uint8Array(buf))
        .map(b => b.toString(16).padStart(2, '0')).join('');
}

function ptrHex(v) {
    return ptr(v).toString();
}

function safeUtf8(p, len = -1) {
    try {
        if (!p || ptr(p).isNull()) return null;
        return len > 0 ? ptr(p).readUtf8String(len) : ptr(p).readUtf8String();
    } catch (_) {
        return null;
    }
}

function readSecretPreview(secretPtr, secretLen) {
    try {
        if (!secretPtr || ptr(secretPtr).isNull()) return null;
        if (!(secretLen > 0 && secretLen <= 128)) return null;
        const n = Math.min(secretLen, 8);
        const buf = ptr(secretPtr).readByteArray(n);
        return hex(buf);
    } catch (_) {
        return null;
    }
}

function isLikelyCR(buf) {
    if (!buf) return false;
    const u8 = new Uint8Array(buf);
    if (u8.length !== 32) return false;
    if (u8[0] === 0 && u8[1] === 0 && u8[2] === 0 && u8[3] === 0) return false;
    if (new Set(u8).size < 16) return false;
    return true;
}

/**
 * 读取 client_random（已验证路径）:
 *   s3 = *ssl_ptr → sub = *(s3 + 0x30) → cr = sub + 0x30 → 32字节
 */
function readCR(ssl) {
    try {
        const s3 = ssl.readPointer();
        const sub = s3.add(0x30).readPointer();
        const buf = sub.add(0x30).readByteArray(32);
        return isLikelyCR(buf) ? buf : null;
    } catch (_) {
        return null;
    }
}

/**
 * ssl_log_secret 专用 client_random 路径（Phase 2 探针确认）:
 *   p = *(ssl + 0x30) → cr = p + 0x30 → 32字节
 */
function readCRSslLog(ssl) {
    try {
        const p = ssl.add(0x30).readPointer();
        if (p.isNull()) return null;
        const buf = p.add(0x30).readByteArray(32);
        return isLikelyCR(buf) ? buf : null;
    } catch (_) {
        return null;
    }
}

/**
 * 尝试读取 fd（ssl_ptr → rbio → fd）
 * 注意：HKDF 的 args[0] 不是 ssl_st*，此函数在 HKDF 上下文中通常返回 -1
 */
function readFd(ssl) {
    try {
        const rbio = ssl.add(RBIO_OFFSET).readPointer();
        if (rbio.isNull()) return -1;
        const fd = rbio.add(BIO_NUM_OFFSET).readS32();
        return (fd >= 3 && fd <= 65535) ? fd : -1;
    } catch (_) {
        return -1;
    }
}

function emitKey(line, src, fd) {
    const p = line.split(' ');
    if (p.length < 3) return;
    const dk = p[0] + '|' + p[1];
    if (_emitted.has(dk)) return;
    _emitted.add(dk);
    send({ t: 'key', v: line, src: src, pid: Process.id, fd: fd });
}

function dbg(msg) {
    send({ t: 'dbg', v: '[pid=' + Process.id + '] ' + msg });
}

function sslLogDbg(label, secretLen, fd, secretPreview, ssl) {
    const key = [label || '?', secretLen, fd, secretPreview || '?'].join('|');
    if (_sslLogSeen.has(key)) return;
    if (_sslLogSeen.size >= SSL_LOG_DEBUG_MAX) return;
    _sslLogSeen.add(key);

    dbg('[ssl_log_secret] label=' + JSON.stringify(label) +
        ' len=' + secretLen +
        ' fd=' + fd +
        ' secret8=' + (secretPreview || '?') +
        ' ssl=' + ptrHex(ssl));
}

function calibrateMs(ssl, knownMsHex) {
    const msBytes = [];
    for (let i = 0; i < 96; i += 2)
        msBytes.push(parseInt(knownMsHex.substr(i, 2), 16));

    try {
        const dump = new Uint8Array(ssl.readByteArray(0x1000));
        for (let off = 0; off <= dump.length - 48; off += 8) {
            if (dump[off] !== msBytes[0] || dump[off + 1] !== msBytes[1]) continue;
            let ok = true;
            for (let j = 2; j < 48; j++) {
                if (dump[off + j] !== msBytes[j]) { ok = false; break; }
            }
            if (ok) {
                _msPathType = 'direct';
                _msOff1 = off;
                _msCalibrated = true;
                dbg('MS cal: ssl+0x' + off.toString(16));
                return true;
            }
        }
    } catch (_) {}

    try {
        for (let pOff = 0; pOff < 0x400; pOff += 8) {
            let p;
            try { p = ssl.add(pOff).readPointer(); } catch (_) { continue; }
            if (p.isNull()) continue;
            let sub;
            try { sub = new Uint8Array(p.readByteArray(0x200)); } catch (_) { continue; }
            for (let off = 0; off <= sub.length - 48; off += 8) {
                if (sub[off] !== msBytes[0] || sub[off + 1] !== msBytes[1]) continue;
                let ok = true;
                for (let j = 2; j < 48; j++) {
                    if (sub[off + j] !== msBytes[j]) { ok = false; break; }
                }
                if (ok) {
                    _msPathType = 'indirect';
                    _msOff1 = pOff;
                    _msOff2 = off;
                    _msCalibrated = true;
                    dbg('MS cal: *(ssl+0x' + pOff.toString(16) + ')+0x' + off.toString(16));
                    return true;
                }
            }
        }
    } catch (_) {}
    return false;
}

function readMsCalibrated(ssl) {
    try {
        if (_msPathType === 'direct')
            return ssl.add(_msOff1).readByteArray(48);
        if (_msPathType === 'indirect')
            return ssl.add(_msOff1).readPointer().add(_msOff2).readByteArray(48);
    } catch (_) {}
    return null;
}

function emitSslLogSecret(label, secretPtr, secretLen, ssl, fd) {
    try {
        if (!label || !secretPtr || ptr(secretPtr).isNull()) return false;
        if (!(secretLen > 0 && secretLen <= 128)) return false;

        const cr = readCRSslLog(ssl);
        if (!cr) return false;

        const secret = ptr(secretPtr).readByteArray(secretLen);
        if (!secret) return false;

        if (label === 'CLIENT_RANDOM') {
            if (secretLen !== 48) return false;
            emitKey('CLIENT_RANDOM ' + hex(cr) + ' ' + hex(secret), 'ssl_log', fd);
            return true;
        }

        const tls13Labels = new Set([
            'CLIENT_HANDSHAKE_TRAFFIC_SECRET',
            'SERVER_HANDSHAKE_TRAFFIC_SECRET',
            'CLIENT_TRAFFIC_SECRET_0',
            'SERVER_TRAFFIC_SECRET_0',
            'EXPORTER_SECRET',
            'CLIENT_EARLY_TRAFFIC_SECRET'
        ]);

        if (!tls13Labels.has(label)) return false;
        emitKey(label + ' ' + hex(cr) + ' ' + hex(secret), 'ssl_log', fd);
        return true;
    } catch (_) {
        return false;
    }
}

function installHooks(mod) {
    dbg('模块: ' + mod.name + ' base=' + mod.base +
        ' size=' + (mod.size / 1024 / 1024 | 0) + 'MB' +
        ' cfg_version=' + (CFG.meta.version || '?') +
        ' match=' + (CFG.meta.match_type || '?'));

    let prf_ok = false, keyexp_ok = false, hkdf_ok = false, ssl_log_ok = false;

    try {
        Interceptor.attach(mod.base.add(ptr(PRF_RVA)), {
            onEnter(args) {
                this.ssl = args[0];
                this.out = args[1];
            },
            onLeave(_) {
                try {
                    const cr = readCR(this.ssl);
                    const ms = this.out.readByteArray(48);
                    if (!cr || !ms) return;
                    const msHex = hex(ms);
                    const fd = readFd(this.ssl);
                    emitKey('CLIENT_RANDOM ' + hex(cr) + ' ' + msHex, 'prf', fd);
                    _prfCache.set(this.ssl.toString(), msHex);
                } catch (_) {}
            }
        });
        prf_ok = true;
        dbg('PRF hook OK @ ' + mod.base.add(ptr(PRF_RVA)));
    } catch (e) {
        dbg('PRF fail: ' + e);
    }

    try {
        Interceptor.attach(mod.base.add(ptr(KEY_EXP_RVA)), {
            onEnter(args) {
                this.ssl = args[0];
            },
            onLeave(_) {
                try {
                    const cr = readCR(this.ssl);
                    if (!cr) return;
                    let ms = null;
                    if (_msCalibrated) {
                        ms = readMsCalibrated(this.ssl);
                    } else {
                        const cached = _prfCache.get(this.ssl.toString());
                        if (cached && calibrateMs(this.ssl, cached))
                            ms = readMsCalibrated(this.ssl);
                    }
                    if (!cr || !ms) return;
                    const fd = readFd(this.ssl);
                    emitKey('CLIENT_RANDOM ' + hex(cr) + ' ' + hex(ms), 'key_exp', fd);
                } catch (_) {}
            }
        });
        keyexp_ok = true;
        dbg('key_expansion hook OK @ ' + mod.base.add(ptr(KEY_EXP_RVA)));
    } catch (e) {
        dbg('key_exp fail: ' + e);
    }

    try {
        Interceptor.attach(mod.base.add(ptr(HKDF_RVA)), {
            onEnter(args) {
                this.ssl = args[0];
                this.out = args[1];
                try {
                    const ll = args[4].toInt32();
                    this.lbl = (ll > 0 && ll <= 20)
                        ? args[3].readUtf8String(ll) : null;
                } catch (_) {
                    this.lbl = null;
                }
            },
            onLeave(_) {
                try {
                    if (!this.lbl) return;
                    const nss = NSS_LABEL[this.lbl];
                    if (!nss) return;

                    let kl;
                    if (this.lbl === 'exp master') {
                        try {
                            const s3 = this.ssl.readPointer();
                            const sub = s3.add(0x30).readPointer();
                            kl = sub.add(0x1b2).readU8();
                            if (!kl || kl > 64) kl = 48;
                        } catch (_) {
                            kl = 48;
                        }
                    } else {
                        const lo = KEY_LEN_OFFSET[this.lbl];
                        kl = lo ? this.ssl.add(lo).readU8() : 32;
                        if (!kl || kl > 64) kl = 32;
                    }

                    const secret = this.out.readByteArray(kl);
                    const cr = readCR(this.ssl);
                    if (!secret || !cr) return;
                    const fd = readFd(this.ssl);
                    emitKey(nss + ' ' + hex(cr) + ' ' + hex(secret), 'hkdf', fd);
                } catch (_) {}
            }
        });
        hkdf_ok = true;
        dbg('HKDF hook OK @ ' + mod.base.add(ptr(HKDF_RVA)));
    } catch (e) {
        dbg('HKDF fail: ' + e);
    }

    if (SSL_LOG_SECRET_RVA) {
        try {
            Interceptor.attach(mod.base.add(ptr(SSL_LOG_SECRET_RVA)), {
                onEnter(args) {
                    try {
                        const ssl = args[0];
                        const label = safeUtf8(args[1]);
                        const secretPtr = args[2];
                        const secretLen = args[3].toInt32();
                        const secretPreview = readSecretPreview(secretPtr, secretLen);
                        const fd = readFd(ssl);
                        const emitted = emitSslLogSecret(label, secretPtr, secretLen, ssl, fd);
                        if (!emitted) {
                            sslLogDbg(label, secretLen, fd, secretPreview, ssl);
                        }
                    } catch (_) {}
                }
            });
            ssl_log_ok = true;
            dbg('ssl_log_secret phase2 hook OK @ ' + mod.base.add(ptr(SSL_LOG_SECRET_RVA)));
        } catch (e) {
            dbg('ssl_log_secret phase2 fail: ' + e);
        }
    } else {
        dbg('ssl_log_secret phase2 skipped: no RVA in config');
    }

    send({ t: 'ready', prf: prf_ok, keyexp: keyexp_ok, hkdf: hkdf_ok, ssl_log: ssl_log_ok });
}

(function () {
    try {
        installHooks(Process.getModuleByName('chrome'));
    } catch (_) {
        let retries = 0;
        const poll = () => {
            try {
                installHooks(Process.getModuleByName('chrome'));
            } catch (_) {
                if (++retries < 100) setTimeout(poll, 100);
                else dbg('模块等待超时');
            }
        };
        setTimeout(poll, 100);
    }
})();
