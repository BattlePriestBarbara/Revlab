// Export a compact JSON summary of the current program.
//
// Used as an analyzeHeadless post-script, so it has to survive stripped
// binaries: functions come from the analysis database, strings from the
// defined-data listing, decompilation only for the functions that matter.
//
// Args: <output.json> [name-filter] [max-functions-to-decompile]
//@category RevLab

import java.io.File;
import java.io.FileWriter;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;

public class ExportProgramSummary extends GhidraScript {

    private static String esc(String value) {
        if (value == null) {
            return "";
        }
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '"': out.append("\\\""); break;
                case '\\': out.append("\\\\"); break;
                case '\n': out.append("\\n"); break;
                case '\r': out.append("\\r"); break;
                case '\t': out.append("\\t"); break;
                default:
                    if (c < 0x20) {
                        out.append(String.format("\\u%04x", (int) c));
                    } else {
                        out.append(c);
                    }
            }
        }
        return out.toString();
    }

    private static String quoted(String value) {
        return "\"" + esc(value) + "\"";
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        String outPath = args.length > 0 ? args[0] : "program_summary.json";
        String nameFilter = args.length > 1 ? args[1] : "";
        int maxDecompile = args.length > 2 ? Integer.parseInt(args[2]) : 40;

        List<Function> functions = new ArrayList<>();
        FunctionIterator iterator = currentProgram.getFunctionManager().getFunctions(true);
        while (iterator.hasNext() && !monitor.isCancelled()) {
            functions.add(iterator.next());
        }

        // Rank by incoming references: the licence check or the crypto routine is
        // usually called from several places, a leaf helper is usually not.
        List<Function> ranked = new ArrayList<>(functions);
        ranked.sort(new Comparator<Function>() {
            @Override
            public int compare(Function a, Function b) {
                return Integer.compare(refCount(b), refCount(a));
            }
        });

        List<String> interesting = new ArrayList<>();
        for (Function function : ranked) {
            if (interesting.size() >= maxDecompile) {
                break;
            }
            String name = function.getName();
            if (nameFilter.isEmpty() || name.toLowerCase().contains(nameFilter.toLowerCase())) {
                interesting.add(name);
            }
        }

        StringBuilder json = new StringBuilder();
        json.append("{\n");
        json.append("  \"program\": ").append(quoted(currentProgram.getName())).append(",\n");
        json.append("  \"language\": ").append(quoted(currentProgram.getLanguageID().toString())).append(",\n");
        json.append("  \"compiler\": ").append(quoted(currentProgram.getCompilerSpec().getCompilerSpecID().toString())).append(",\n");
        json.append("  \"image_base\": ").append(quoted(currentProgram.getImageBase().toString())).append(",\n");
        json.append("  \"sha256\": ").append(quoted(currentProgram.getExecutableSHA256())).append(",\n");
        json.append("  \"function_count\": ").append(functions.size()).append(",\n");

        json.append("  \"functions\": [\n");
        List<String> functionEntries = new ArrayList<>();
        for (Function function : ranked) {
            if (functionEntries.size() >= 400) {
                break;
            }
            functionEntries.add("    {\"name\": " + quoted(function.getName())
                + ", \"entry\": " + quoted(function.getEntryPoint().toString())
                + ", \"size\": " + function.getBody().getNumAddresses()
                + ", \"callers\": " + refCount(function)
                + ", \"thunk\": " + function.isThunk()
                + ", \"external\": " + function.isExternal() + "}");
        }
        json.append(String.join(",\n", functionEntries));
        json.append("\n  ],\n");

        List<String> imports = new ArrayList<>();
        FunctionIterator external = currentProgram.getFunctionManager().getExternalFunctions();
        while (external.hasNext()) {
            Function function = external.next();
            imports.add(quoted(function.getName() + " @ " + function.getEntryPoint()));
        }

        List<String> definedStrings = new ArrayList<>();
        DataIterator data = currentProgram.getListing().getDefinedData(true);
        while (data.hasNext() && definedStrings.size() < 1500 && !monitor.isCancelled()) {
            Data item = data.next();
            Object value = item.getValue();
            if (value instanceof String) {
                String text = ((String) value).trim();
                if (text.length() >= 6 && text.length() <= 400) {
                    definedStrings.add("{\"address\": " + quoted(item.getAddress().toString())
                        + ", \"value\": " + quoted(text) + "}");
                }
            }
        }

        List<String> symbols = new ArrayList<>();
        SymbolIterator symbolIterator = currentProgram.getSymbolTable().getAllSymbols(true);
        while (symbolIterator.hasNext() && symbols.size() < 3000) {
            Symbol symbol = symbolIterator.next();
            symbols.add("{\"name\": " + quoted(symbol.getName())
                + ", \"address\": " + quoted(symbol.getAddress().toString())
                + ", \"type\": " + quoted(symbol.getSymbolType().toString()) + "}");
        }

        json.append("  \"imports\": [").append(String.join(", ", imports)).append("],\n");
        json.append("  \"strings\": [\n");
        json.append(String.join(",\n", definedStrings));
        json.append("\n  ],\n");
        json.append("  \"symbols\": [\n");
        json.append(String.join(",\n", symbols));
        json.append("\n  ],\n");

        // Decompilation is the expensive part: only the ranked shortlist.
        List<String> decompiled = new ArrayList<>();
        DecompInterface decompiler = new DecompInterface();
        decompiler.toggleCCode(true);
        decompiler.setSimplificationStyle("decompile");
        int produced = 0;
        if (decompiler.openProgram(currentProgram)) {
            for (String name : interesting) {
                if (produced >= maxDecompile || monitor.isCancelled()) {
                    break;
                }
                Function function = null;
                for (Function candidate : functions) {
                    if (candidate.getName().equals(name)) {
                        function = candidate;
                        break;
                    }
                }
                if (function == null) {
                    continue;
                }
                DecompileResults results = decompiler.decompileFunction(function, 60, monitor);
                if (results == null || !results.decompileCompleted()
                    || results.getDecompiledFunction() == null) {
                    continue;
                }
                decompiled.add("{\"name\": " + quoted(name)
                    + ", \"entry\": " + quoted(function.getEntryPoint().toString())
                    + ", \"c\": " + quoted(results.getDecompiledFunction().getC()) + "}");
                produced++;
            }
        }
        decompiler.dispose();

        json.append("  \"decompiled\": [\n");
        json.append(String.join(",\n", decompiled));
        json.append("\n  ],\n");
        json.append("  \"decompiled_count\": ").append(decompiled.size()).append("\n");
        json.append("}\n");

        File out = new File(outPath);
        if (out.getParentFile() != null) {
            out.getParentFile().mkdirs();
        }
        try (FileWriter writer = new FileWriter(out)) {
            writer.write(json.toString());
        }
        println("ExportProgramSummary: wrote " + outPath + " ("
            + functions.size() + " functions, " + decompiled.size() + " decompiled, "
            + definedStrings.size() + " strings)");
    }

    private static int refCount(Function function) {
        int count = 0;
        ReferenceIterator iterator =
            function.getProgram().getReferenceManager().getReferencesTo(function.getEntryPoint());
        while (iterator.hasNext() && count < 1000) {
            Reference reference = iterator.next();
            count++;
        }
        return count;
    }
}
