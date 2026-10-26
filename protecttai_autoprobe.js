/* ============================================================
 *  Protecttai-Bypass -> Frida port  [AUTO-PROBE EDITION]
 *  Original Xposed module: github.com/reveny/Protecttai-Bypass
 *
 *  Discovers the target by signature, then -- when candidates tie --
 *  PROBES each one's runtime behaviour to identify the startup check
 *  and auto-promotes the winner to an enforcing (skip) hook.
 *
 *  MODES (CONFIG.mode):
 *    "report" - static candidate list only, nothing hooked
 *    "probe"  - hook all candidates pass-through, print behaviour, no bypass
 *    "hook"   - bypass (fast-path if unambiguous, probe if tied)
 *
 *  Run:
 *    frida -U -f com.kotak.neo -l protecttai_autoprobe.js --no-pause
 * ============================================================ */

'use strict';

var CONFIG = {
    signature: ["java.lang.String", "int", "int", "int", "java.lang.String", "int"],

    mode:        "hook",    // "report" | "probe" | "hook"
    forceClass:  null,      // e.g. "f.g" -> skip discovery
    logArgs:     false,

    // discovery
    minScore:       40,
    initialDelayMs: 300,
    scanIntervalMs: 500,
    maxScans:       120,
    postScans:      4,

    // probing
    probeWindowMs:  4000,   // how long to observe before deciding
    earlyPromote:   true,   // promote as soon as behaviour is conclusive
    captureStack:   true,
    maxStackFrames: 6,

    verbose: true
};

var SIG = CONFIG.signature;
var startMs = Date.now();

function log(m) { if (CONFIG.verbose) console.log("[protecttai] " + m); }

function defaultFor(t) {
    switch (t) {
        case "void":    return undefined;
        case "boolean": return false;
        case "byte": case "short": case "char":
        case "int":  case "long":  case "float": case "double": return 0;
        default:        return null;   // == Xposed param.setResult(null)
    }
}

function keyOf(c) { return c.className + "#" + c.methodName; }

/* ---------------- discovery ---------------- */

var SKIP = /^(java|javax|sun|com\.sun|jdk|android|androidx|dalvik|kotlin|kotlinx|org\.apache|org\.json|org\.xml|org\.w3c|org\.bouncycastle|junit|com\.google|com\.facebook|okhttp3|okio|retrofit2|com\.squareup|io\.reactivex|com\.crashlytics|com\.fasterxml|com\.newrelic|com\.appsflyer|com\.adjust|com\.clevertap|com\.moengage|com\.mixpanel|com\.bugsnag|com\.sentry|bolts|net\.sqlcipher|com\.github|de\.robv)\./;

function shouldInspect(name) {
    if (!name || name[0] === "[") return false;
    if (/protect/i.test(name)) return true;
    return !SKIP.test(name);
}

function resolve(name) {
    try { return Java.use(name); } catch (e) {}
    try {
        var loaders = Java.enumerateClassLoadersSync();
        for (var i = 0; i < loaders.length; i++) {
            try { var c = loaders[i].loadClass(name); if (c) return c; } catch (e) {}
        }
    } catch (e) {}
    return null;
}

function staticScore(className, methodName, returnType) {
    var s = 0, segs = className.split(".");
    var allShort    = segs.every(function (x) { return x.length <= 2; });
    var mostlyShort = segs.every(function (x) { return x.length <= 3; });
    if (allShort) s += 45; else if (mostlyShort) s += 25;
    if (/^[a-z]{1,2}[0-9]?$/.test(methodName)) s += 25;
    else if (methodName.length <= 3) s += 12;
    if (segs.length === 2 && segs[0].length <= 2) s += 15;
    if (returnType === "void" || returnType === "boolean") s += 6;
    if (/protect/i.test(className)) s += 60;
    return s;
}

function doScan() {
    var names;
    try { names = Java.enumerateLoadedClassesSync(); } catch (e) { return []; }

    var out = [], seen = {};
    for (var i = 0; i < names.length; i++) {
        var name = names[i];
        if (seen[name]) continue; seen[name] = 1;
        if (CONFIG.forceClass) { if (name !== CONFIG.forceClass) continue; }
        else if (!shouldInspect(name)) continue;

        var klass = resolve(name);
        if (!klass) continue;

        var methods;
        try { methods = klass.class.getDeclaredMethods(); } catch (e) { continue; }

        for (var j = 0; j < methods.length; j++) {
            var m = methods[j], ptypes;
            try { ptypes = m.getParameterTypes(); } catch (e) { continue; }
            if (ptypes.length !== SIG.length) continue;

            var ok = true;
            for (var k = 0; k < ptypes.length; k++) {
                if (ptypes[k].getName() !== SIG[k]) { ok = false; break; }
            }
            if (!ok) continue;

            var mName = m.getName();
            var rType = m.getReturnType().getName();
            out.push({
                className: name, methodName: mName, returnType: rType,
                klass: klass, score: staticScore(name, mName, rType),
                mode: "probe", count: 0, firstMs: null, lastMs: null, thread: null, stack: null
            });
        }
    }
    return out;
}

/* ---------------- behaviour recording ---------------- */

var ThreadCls = null;
function threadName() {
    try {
        if (!ThreadCls) ThreadCls = Java.use("java.lang.Thread");
        return ThreadCls.currentThread().getName();
    } catch (e) { return "?"; }
}

function captureStack() {
    try {
        var E = Java.use("java.lang.Exception");
        var L = Java.use("android.util.Log");
        var s = L.getStackTraceString(E.$new());
        return s.split("\n").slice(0, CONFIG.maxStackFrames).join("\n");
    } catch (e) { return null; }
}

function recordHit(c) {
    var now = Date.now() - startMs;
    c.count++;
    if (c.firstMs === null) {
        c.firstMs = now;
        c.thread  = threadName();
        c.stack   = CONFIG.captureStack ? captureStack() : null;
    }
    c.lastMs = now;
}

function behaviouralScore(c) {
    if (!c.count) return -30;                       // never called -> suspicious
    var s = 0;
    if (c.count === 1)      s += 55;                 // one-shot
    else if (c.count === 2) s += 30;
    else if (c.count <= 5)  s += 8;
    else                    s -= 20;                 // repeated -> probably not the check
    if (c.firstMs !== null) {
        if (c.firstMs < 1500)      s += 25;          // called very early
        else if (c.firstMs < 4000) s += 12;
        else if (c.firstMs < 8000) s += 4;
    }
    if (c.thread && c.thread !== "main") s += 15;    // background thread
    if (c.count === 1 && c.firstMs !== null && c.firstMs < 2000) s += 15;
    return s;
}

function totalScore(c) { return c.score + behaviouralScore(c); }

/* ---------------- hooking ---------------- */

var installed = {};   // key -> candidate (already hooked in some mode)

function installHook(c) {
    if (installed[keyOf(c)]) return true;
    try {
        var method = c.klass[c.methodName];
        var ov = method.overload.apply(method, SIG);
        var ret = c.returnType;

        ov.implementation = function () {
            recordHit(c);                                    // always observe
            if (CONFIG.logArgs) log("ARGS " + c.className + "." + c.methodName + "(" + Array.prototype.join.call(arguments, ", ") + ")");
            if (c.mode === "enforce") return defaultFor(ret); // skip original
            return this[c.methodName].apply(this, arguments); // probe/pass -> original
        };
        installed[keyOf(c)] = c;
        return true;
    } catch (e) {
        log("hook failed " + c.className + "." + c.methodName + ": " + e);
        return false;
    }
}

function promote(winner, all) {
    all.forEach(function (c) {
        if (c === winner) c.mode = "enforce";
        else if (c.mode !== "enforce") c.mode = "pass";
    });
    log(">> ENFORCING " + winner.className + "." + winner.methodName +
        " (static " + winner.score + " + behaviour " + behaviouralScore(winner) + " = " + totalScore(winner) + ")");
    reportBehaviour(all);
}

/* ---------------- reporting ---------------- */

function reportBehaviour(list) {
    log("--- behaviour report ---");
    list.slice().sort(function (a, b) { return totalScore(b) - totalScore(a); }).forEach(function (c, i) {
        log("  [" + (i + 1) + "] " + c.className + "." + c.methodName +
            "  mode=" + c.mode + "  calls=" + c.count +
            "  first=" + (c.firstMs === null ? "-" : c.firstMs + "ms") +
            "  thread=" + (c.thread || "-") +
            "  total=" + totalScore(c));
        if (c.stack) c.stack.split("\n").slice(0, 4).forEach(function (l) { log("        " + l.trim()); });
    });
}

/* ---------------- orchestration ---------------- */

var all = [];          // every candidate discovered
var probing = false;
var decided = false;
var finished = false;
var scanCount = 0, postRounds = 0;

function finish() { finished = true; log("stopped."); }

function enterProbe(cands) {
    probing = true;
    cands.forEach(function (c) { if (c.mode !== "enforce") c.mode = "probe"; installHook(c); });
    log("tie -> probing " + cands.length + " candidates for " + CONFIG.probeWindowMs + "ms");
    if (CONFIG.mode === "probe") { setTimeout(function () { reportBehaviour(all); finish(); }, CONFIG.probeWindowMs); return; }
    setTimeout(decide, CONFIG.probeWindowMs);
}

function decide() {
    if (decided || finished) return;
    decided = true;
    var called = all.filter(function (c) { return c.count > 0; });
    if (!called.length) {
        var best = all.slice().sort(function (a, b) { return b.score - a.score; })[0];
        log("nothing was called during probe -> falling back to static best");
        promote(best, all);
    } else {
        called.sort(function (a, b) { return totalScore(b) - totalScore(a); });
        promote(called[0], all);
    }
}

function maybeEarlyPromote() {
    if (decided || !CONFIG.earlyPromote) return;
    var called = all.filter(function (c) { return c.count > 0; });
    if (!called.length) return;
    called.sort(function (a, b) { return totalScore(b) - totalScore(a); });
    var top = called[0], second = called[1];
    var now = Date.now() - startMs;
    var oneShot = top.count === 1 && top.firstMs !== null && top.firstMs < 2500 && (now - top.firstMs) > 1200;
    var ahead = !second || (totalScore(top) - totalScore(second)) >= 25;
    if (oneShot && ahead) { decided = true; promote(top, all); }
}

function tick() { if (!finished) Java.perform(tickInner); }

function tickInner() {
    scanCount++;

    var cands = doScan();

    // register new, un-hooked candidates
    cands.forEach(function (c) {
        var k = keyOf(c);
        if (!installed[k]) {
            var exists = all.filter(function (x) { return keyOf(x) === k; })[0];
            if (!exists) { all.push(c); }
        }
    });

    if (all.length === 0) {
        if (scanCount >= CONFIG.maxScans) { log("no candidates after " + scanCount + " scans."); finish(); }
        else setTimeout(tick, CONFIG.scanIntervalMs);
        return;
    }

    if (CONFIG.mode === "report") {
        log("--- " + all.length + " candidate(s) ---");
        all.slice().sort(function (a, b) { return b.score - a.score; }).slice(0, 12).forEach(function (c, i) {
            log("  [" + (i + 1) + "] score=" + c.score + "  " + c.className + "." + c.methodName + " : " + c.returnType);
        });
        finish(); return;
    }

    if (!probing && !decided) {
        if (all.length === 1) {
            // fast path: unambiguous
            installHook(all[0]);
            all[0].mode = "enforce";
            log("single candidate -> enforcing " + all[0].className + "." + all[0].methodName + " (no probe needed)");
            decided = true;
        } else {
            enterProbe(all);
        }
    } else if (probing && !decided) {
        all.forEach(function (c) { if (!installed[keyOf(c)]) installHook(c); });
        maybeEarlyPromote();
    }

    if (decided) {
        if (++postRounds >= CONFIG.postScans) finish();
        else setTimeout(tick, CONFIG.scanIntervalMs);
    } else {
        setTimeout(tick, CONFIG.scanIntervalMs);
    }
}

/* ---------------- go ---------------- */

log("started; mode=" + CONFIG.mode + "; signature=(" + SIG.join(", ") + ")");
try {
    Process.enumerateModules().forEach(function (m) {
        if (/protect/i.test(m.name)) log("native module present: " + m.name);
    });
} catch (e) {}

setTimeout(tick, CONFIG.initialDelayMs);
