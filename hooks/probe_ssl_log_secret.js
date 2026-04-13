'use strict';
/**
 * probe_ssl_log_secret.js
 *
 * 目标：
 *   在 ssl_log_secret 触发时，对 args[0] 做分层内存探测，
 *   交叉比对 SSLKEYLOGFILE 中的 client_random，确认 ssl_st* 下的真实路径。
 *
 * 用法：
 *   1. 先用 SSLKEYLOGFILE 启动 Chrome
 *   2. 将本脚本 attach 到对应 NetworkService 进程
 *   3. 访问少量 HTTPS 站点
 *   4. 用 SSLKEYLOGFILE 中的 client_random 去匹配本脚本输出
 */

const CHROME_MODULE = 'chrome';
const SSL_LOG_SECRET_RVA = ptr('0x04883520');
const MAX_HITS = 10;
const L1_SIZE = 0x300;
const L2_SIZE = 0x100;
const L3_SIZE = 0x40;
const PTR_OFFSETS_L2 = [0x00, 0x08, 0x10, 0x18, 0x20, 0x28, 0x30, 0x38, 0x40, 0x48];
const PTR_OFFSETS_L3 = [0x00, 0x08, 0x10, 0x30];
const SUB_OFFSETS_L3 = [0x00, 0x10, 0x20, 0x28, 0x30, 0x38, 0x40, 0x50, 0x60];

let hitCount = 0;

function toHex(bytes) {
    return Array.from(bytes)
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
}

function safeUtf8(p) {
    try {
        if (!p || ptr(p).isNull()) return '?';
        return ptr(p).readUtf8String() || '?';
    } catch (_) {
        return '?';
    }
}

function isReadable(addr, size) {
    try {
        const range = Process.findRangeByAddress(ptr(addr));
        if (!range) return false;
        if (range.protection.indexOf('r') === -1) return false;
        const end = ptr(addr).add(size);
        return end.compare(range.base.add(range.size)) <= 0;
    } catch (_) {
        return false;
    }
}

function safeReadPointer(addr) {
    try {
        const p = ptr(addr);
        if (!isReadable(p, Process.pointerSize)) return null;
        const v = p.readPointer();
        if (v.isNull()) return null;
        if (v.compare(ptr('0x1000')) < 0) return null;
        if (!isReadable(v, 1)) return null;
        return v;
    } catch (_) {
        return null;
    }
}

function safeReadBytes(addr, size) {
    try {
        const p = ptr(addr);
        if (!isReadable(p, size)) return null;
        const data = p.readByteArray(size);
        return data ? new Uint8Array(data) : null;
    } catch (_) {
        return null;
    }
}

function uniqueCount(arr) {
    return new Set(arr).size;
}

function logL1(ssl) {
    console.log('[L1] ssl_st 直接偏移:');
    const u8 = safeReadBytes(ssl, L1_SIZE);
    if (!u8) {
        console.log('  L1 读取失败');
        return;
    }

    for (let off = 0; off < L1_SIZE; off += 0x10) {
        const slice = u8.slice(off, off + 0x10);
        const hex16 = toHex(slice);
        if (hex16 !== '00000000000000000000000000000000') {
            console.log(`  +0x${off.toString(16).padStart(3, '0')}: ${hex16}`);
        }
    }
}

function logL2(ssl) {
    console.log('[L2] *(ssl+offset) 一级解引用:');
    for (const pOff of PTR_OFFSETS_L2) {
        const p = safeReadPointer(ssl.add(pOff));
        if (!p) continue;

        const u8 = safeReadBytes(p, L2_SIZE);
        if (!u8) continue;

        for (let off = 0; off < L2_SIZE; off += 0x20) {
            const slice = u8.slice(off, off + 0x20);
            if (uniqueCount(slice) <= 12) continue;
            console.log(`  [L2] *(ssl+0x${pOff.toString(16)})+0x${off.toString(16).padStart(3, '0')}: ${toHex(slice)}`);
        }
    }
}

function logL3(ssl) {
    console.log('[L3] *(*(ssl+offset)+offset) 二级解引用:');
    for (const pOff of PTR_OFFSETS_L3) {
        const p1 = safeReadPointer(ssl.add(pOff));
        if (!p1) continue;

        for (const subOff of SUB_OFFSETS_L3) {
            const p2 = safeReadPointer(p1.add(subOff));
            if (!p2) continue;

            const u8 = safeReadBytes(p2, L3_SIZE);
            if (!u8) continue;

            const head32 = u8.slice(0, 32);
            if (uniqueCount(head32) <= 16) continue;
            console.log(`  [L3] *(*(ssl+0x${pOff.toString(16)})+0x${subOff.toString(16)})+0x000: ${toHex(head32)}`);
        }
    }
}

const mod = Process.getModuleByName(CHROME_MODULE);
const hookAddr = mod.base.add(SSL_LOG_SECRET_RVA);

Interceptor.attach(hookAddr, {
    onEnter(args) {
        if (hitCount >= MAX_HITS) return;
        hitCount += 1;

        const ssl = args[0];
        const label = safeUtf8(args[1]);
        let secretLen = -1;
        try {
            secretLen = args[3].toInt32();
        } catch (_) {}

        console.log(`\n=== ssl_log_secret #${hitCount} label="${label}" len=${secretLen} ssl=${ssl} ===`);
        logL1(ssl);
        logL2(ssl);
        logL3(ssl);
    }
});

console.log(`[*] probe ready: ${CHROME_MODULE}!${SSL_LOG_SECRET_RVA} => ${hookAddr}`);
console.log('[*] 访问少量 HTTPS 页面后，拿 SSLKEYLOGFILE 的 client_random 来比对输出');

