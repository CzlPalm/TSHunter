import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class BoringSslAnalyzer extends StackAnalyzer {
    private static final List<String> HKDF_TLS13_LABELS = List.of(
        "c hs traffic",
        "s hs traffic",
        "c ap traffic",
        "s ap traffic"
    );

    private final StringXrefUtil xrefs;
    private final FingerprintExtractor fingerprintExtractor;
    private final Map<String, ResultRecord> results = new LinkedHashMap<>();

    public BoringSslAnalyzer(GhidraScript script) {
        super(script);
        this.xrefs = new StringXrefUtil(script);
        this.fingerprintExtractor = new FingerprintExtractor(script);
    }

    @Override
    public double detectConfidence() {
        int hits = 0;
        if (xrefs.findStringInReadonlyData("BoringSSL") != null || xrefs.findStringInReadonlyData("boringssl") != null) {
            hits++;
        }
        if (xrefs.findStringInReadonlyData("EXPORTER_SECRET") != null) {
            hits++;
        }
        if (xrefs.findStringInReadonlyData("CLIENT_RANDOM") != null) {
            hits++;
        }
        if (hits >= 3) {
            hits = 3;
        }

        double confidence = 0.0;
        if (hits >= 3) {
            confidence = 0.95;
        } else if (hits == 2) {
            confidence = 0.70;
        } else if (hits == 1) {
            confidence = 0.30;
        }

        if (confidence > 0.0) {
            if (xrefs.findStringInReadonlyData("c hs traffic") != null) {
                confidence = Math.max(confidence, 0.99);
            }
            if (xrefs.findStringInReadonlyData("key expansion") != null) {
                confidence = Math.max(confidence, 0.99);
            }
        }
        return confidence;
    }

    @Override
    public List<ResultRecord> analyze() {
        identifyHKDF();
        analyzeSslLogSecret();
        identifyPRF();
        identifyKeyExpansion();
        return new ArrayList<>(results.values());
    }

    @Override
    public String getName() {
        return "boringssl";
    }

    private void identifyHKDF() {
        script.println("[*] HKDF: 开始识别（next-CALL 投票策略）...");

        Map<String, List<Address>> labelAddrs = new LinkedHashMap<>();
        for (String label : HKDF_TLS13_LABELS) {
            List<Address> addrs = xrefs.findAllStringsInReadonlyData(label);
            labelAddrs.put(label, addrs);
            script.println("[*] HKDF: label \"" + label + "\" rodata hits = " + addrs.size());
        }

        Map<Function, Integer> votes = new LinkedHashMap<>();
        ReferenceManager refMgr = program.getReferenceManager();

        for (Map.Entry<String, List<Address>> entry : labelAddrs.entrySet()) {
            String label = entry.getKey();
            for (Address strAddr : entry.getValue()) {
                ReferenceIterator refs = refMgr.getReferencesTo(strAddr);
                while (refs.hasNext()) {
                    Reference ref = refs.next();
                    Address fromAddr = ref.getFromAddress();
                    Function container = script.getFunctionContaining(fromAddr);
                    if (container == null) {
                        continue;
                    }
                    Function callee = xrefs.findFirstCalledFunctionAfterReference(container, fromAddr);
                    if (callee == null) {
                        continue;
                    }
                    votes.merge(callee, 1, Integer::sum);
                    script.println("[*] HKDF:   label=\"" + label + "\" LEA@" + fromAddr
                        + " inside " + container.getName()
                        + " → CALL target " + callee.getName());
                }
            }
        }

        Function winner = null;
        int winnerVotes = 0;
        int totalVotes = 0;
        for (Map.Entry<Function, Integer> e : votes.entrySet()) {
            totalVotes += e.getValue();
            if (e.getValue() > winnerVotes) {
                winner = e.getKey();
                winnerVotes = e.getValue();
            }
        }
        if (winner != null) {
            script.println("[*] HKDF: next-CALL 投票命中 → " + winner.getName()
                + " (votes=" + winnerVotes + "/" + totalVotes + ")");
            addResult("HKDF", winner, "TLS 1.3 Derive-Secret (post-label CALL voting)");
            return;
        }

        Set<Function> hsOnly = new LinkedHashSet<>();
        for (Address addr : labelAddrs.getOrDefault("c hs traffic", List.of())) {
            hsOnly.addAll(xrefs.getReferencingFunctions(addr));
        }
        Set<Function> shsFuncs = new LinkedHashSet<>();
        for (Address addr : labelAddrs.getOrDefault("s hs traffic", List.of())) {
            shsFuncs.addAll(xrefs.getReferencingFunctions(addr));
        }
        hsOnly.retainAll(shsFuncs);
        Function fallback = xrefs.pickBestFunctionByXrefs(hsOnly);
        if (fallback != null) {
            script.println("[*] HKDF: 回退到握手标签二重交集 → " + fallback.getName());
            addResult("HKDF", fallback, "TLS 1.3 Derive-Secret (fallback wrapper intersection)");
            return;
        }

        script.println("[-] HKDF: 所有策略均未命中");
    }

    private void analyzeSslLogSecret() {
        FunctionRef selected = findSslLogSecretCandidate();
        if (selected == null || selected.function == null) {
            script.println("[WARN] type=SSL_LOG_SECRET status=not_found");
            return;
        }

        addResult("SSL_LOG_SECRET", selected.function, null);
    }

    private void identifyPRF() {
        script.println("[*] PRF: 开始识别...");

        List<Address> masterSecretAddrs = xrefs.findAllStringsInReadonlyData("master secret");
        List<Address> extMasterSecretAddrs = xrefs.findAllStringsInReadonlyData("extended master secret");

        Set<Function> msFuncs = new LinkedHashSet<>();
        Set<Function> emsFuncs = new LinkedHashSet<>();

        for (Address addr : masterSecretAddrs) {
            msFuncs.addAll(xrefs.getReferencingFunctions(addr));
        }
        for (Address addr : extMasterSecretAddrs) {
            emsFuncs.addAll(xrefs.getReferencingFunctions(addr));
        }

        Set<Function> intersection = new LinkedHashSet<>(msFuncs);
        intersection.retainAll(emsFuncs);
        Function prfFunc = xrefs.pickBestFunctionByXrefs(intersection);
        if (prfFunc != null) {
            script.println("[*] PRF: 双标签交叉验证命中 → " + prfFunc.getName());
            addResult("PRF", prfFunc, "TLS 1.2 Unified PRF (cross-validated)");
            return;
        }

        for (Address addr : masterSecretAddrs) {
            if (!xrefs.isStandaloneString(addr)) {
                continue;
            }
            Set<Function> funcs = xrefs.getReferencingFunctions(addr);
            Function standalone = xrefs.pickBestFunctionByXrefs(funcs);
            if (standalone != null) {
                script.println("[*] PRF: 独立字符串 XREF 命中 → " + standalone.getName());
                addResult("PRF", standalone, "TLS 1.2 PRF (standalone string XREF)");
                return;
            }
        }

        Function best = xrefs.pickBestFunctionByXrefs(msFuncs);
        if (best != null) {
            script.println("[*] PRF: fallback XREF 命中 → " + best.getName());
            addResult("PRF", best, "TLS 1.2 PRF (fallback, may need verification)");
            return;
        }

        script.println("[-] PRF: 所有策略均未命中");
    }

    private void identifyKeyExpansion() {
        script.println("[*] KEY_EXPANSION: 开始识别...");

        List<Address> addrs = xrefs.findAllStringsInReadonlyData("key expansion");
        for (Address addr : addrs) {
            Set<Function> funcs = xrefs.getReferencingFunctions(addr);
            Function best = xrefs.pickBestFunctionByXrefs(funcs);
            if (best != null) {
                String note = "TLS 1.2 key block derivation";
                if (isSameAsPrf(best)) {
                    note = "shared with PRF";
                }
                addResult("KEY_EXPANSION", best, note);
                return;
            }
        }

        script.println("[-] KEY_EXPANSION: 未找到");
    }

    private FunctionRef findSslLogSecretCandidate() {
        String[] strings = {"EXPORTER_SECRET", "CLIENT_RANDOM"};

        for (String needle : strings) {
            List<FunctionRef> refs = xrefs.findFunctionsUsingString(needle);
            if (refs.isEmpty()) {
                Address rodataAddress = xrefs.findStringInReadonlyData(needle);
                if (rodataAddress != null) {
                    refs = xrefs.collectReferencingFunctions(rodataAddress);
                }
            }

            for (FunctionRef ref : refs) {
                if (ref.function == null || ref.referenceAddress == null) {
                    continue;
                }
                Function called = xrefs.findFirstCalledFunctionAfterReference(ref.function, ref.referenceAddress);
                if (called != null) {
                    return new FunctionRef(called, ref.referenceAddress);
                }
                return ref;
            }
        }

        return null;
    }

    private void addResult(String type, Function function, String note) {
        String fingerprint = fingerprintExtractor.extractFingerprint(function);
        String rva = fingerprintExtractor.getRva(function.getEntryPoint());
        results.put(type, new ResultRecord(type, function.getName(), rva, fingerprint, note));
    }

    private boolean isSameAsPrf(Function function) {
        ResultRecord prf = results.get("PRF");
        if (prf == null) {
            return false;
        }
        return prf.rva.equals(fingerprintExtractor.getRva(function.getEntryPoint()));
    }
}


