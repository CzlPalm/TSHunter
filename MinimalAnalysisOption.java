/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
// Turns off heavyweight analyzers before headless Ghidra import/analysis.
//@category FunctionID
import java.util.Map;

import ghidra.app.script.GhidraScript;

public class MinimalAnalysisOption extends GhidraScript {
    private static final String FUNCTION_ID_ANALYZER = "Function ID";
    private static final String LIBRARY_IDENTIFICATION = "Library Identification";
    private static final String DEMANGLER_MS_ANALYZER = "Demangler Microsoft";
    private static final String DEMANGLER_GNU_ANALYZER = "Demangler GNU";
    private static final String SCALAR_OPERAND_ANALYZER = "Scalar Operand References";
    private static final String DECOMPILER_SWITCH_ANALYSIS = "Decompiler Switch Analysis";
    private static final String STACK_ANALYSIS = "Stack";
    private static final String CONSTANT_PROPAGATION_ANALYSIS = "Basic Constant Reference Analyzer";
    private static final String DWARF_ANALYZER = "DWARF";

    @Override
    protected void run() throws Exception {
        Map<String, String> options = getCurrentAnalysisOptionsAndValues(currentProgram);
        disableIfPresent(options, FUNCTION_ID_ANALYZER);
        disableIfPresent(options, LIBRARY_IDENTIFICATION);
        disableIfPresent(options, DEMANGLER_MS_ANALYZER);
        disableIfPresent(options, DEMANGLER_GNU_ANALYZER);
        disableIfPresent(options, SCALAR_OPERAND_ANALYZER);
        disableIfPresent(options, DECOMPILER_SWITCH_ANALYSIS);
        disableIfPresent(options, STACK_ANALYSIS);
        disableIfPresent(options, CONSTANT_PROPAGATION_ANALYSIS);
        disableIfPresent(options, DWARF_ANALYZER);
    }

    private void disableIfPresent(Map<String, String> options, String key) throws Exception {
        if (options.containsKey(key)) {
            setAnalysisOption(currentProgram, key, "false");
        }
    }
}

