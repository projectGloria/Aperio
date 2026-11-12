// Aperio post-script: decompile every function of the current program to a C file.
// Usage (headless):
//   analyzeHeadless <projDir> <projName> -import <bin> -scriptPath <dir>
//                   -postScript ExportDecompiled.java <output.c> -deleteProject
// @category Aperio
// @runtime Java

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;

public class ExportDecompiled extends GhidraScript {

    private static final int PER_FUNCTION_TIMEOUT_SECS = 60;

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        File out = args.length > 0
                ? new File(args[0])
                : new File(currentProgram.getExecutablePath() + ".c");
        if (out.getParentFile() != null) {
            out.getParentFile().mkdirs();
        }

        DecompInterface ifc = new DecompInterface();
        DecompileOptions options = new DecompileOptions();
        ifc.setOptions(options);
        ifc.toggleCCode(true);
        ifc.toggleSyntaxTree(false);
        ifc.setSimplificationStyle("decompile");
        if (!ifc.openProgram(currentProgram)) {
            printerr("Decompiler failed to open program: " + ifc.getLastMessage());
            return;
        }

        int total = currentProgram.getFunctionManager().getFunctionCount();
        int done = 0, failed = 0;
        monitor.initialize(total);
        monitor.setMessage("Aperio: decompiling " + total + " functions");

        try (BufferedWriter w = new BufferedWriter(new OutputStreamWriter(
                new FileOutputStream(out), StandardCharsets.UTF_8))) {
            w.write("/*\n * Decompiled by Ghidra via Aperio ExportDecompiled.java\n");
            w.write(" * Program : " + currentProgram.getName() + "\n");
            w.write(" * Language: " + currentProgram.getLanguageID() + "\n");
            w.write(" * Compiler: " + currentProgram.getCompilerSpec().getCompilerSpecID() + "\n");
            w.write(" * Functions: " + total + "\n */\n\n");

            FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
            while (it.hasNext()) {
                if (monitor.isCancelled()) {
                    w.write("\n/* export cancelled */\n");
                    break;
                }
                Function f = it.next();
                monitor.incrementProgress(1);
                if (f.isExternal() || f.isThunk()) {
                    continue;
                }
                DecompileResults res = ifc.decompileFunction(f, PER_FUNCTION_TIMEOUT_SECS, monitor);
                w.write("// ---- " + f.getName() + " @ " + f.getEntryPoint() + "\n");
                if (res != null && res.decompileCompleted() && res.getDecompiledFunction() != null) {
                    w.write(res.getDecompiledFunction().getC());
                    done++;
                } else {
                    String msg = res == null ? "null result" : String.valueOf(res.getErrorMessage());
                    w.write("/* decompilation failed: " + msg.replace("*/", "* /") + " */\n");
                    failed++;
                }
                w.write("\n");
            }
        } finally {
            ifc.dispose();
        }
        println("Aperio: wrote " + out.getAbsolutePath() + " (" + done + " ok, " + failed + " failed)");
    }
}
