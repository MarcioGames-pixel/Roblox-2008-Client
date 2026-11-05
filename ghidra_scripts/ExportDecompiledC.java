import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;

public class ExportDecompiledC extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            printerr("Uso: ExportDecompiledC.java <diretorio-de-saida>");
            return;
        }

        File outputDir = new File(args[0]);
        if (!outputDir.exists() && !outputDir.mkdirs()) {
            printerr("Não foi possível criar: " + outputDir.getAbsolutePath());
            return;
        }

        String module = currentProgram.getName().replaceAll("[^A-Za-z0-9._-]", "_");
        File cFile = new File(outputDir, module + "_decompiled.c");
        File csvFile = new File(outputDir, module + "_functions.csv");

        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);

        int total = 0;
        int exported = 0;
        int failed = 0;

        try (BufferedWriter cOut = new BufferedWriter(new FileWriter(cFile));
             BufferedWriter csvOut = new BufferedWriter(new FileWriter(csvFile))) {
            csvOut.write("name,address,signature,status");
            csvOut.newLine();

            FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);
            while (functions.hasNext() && !monitor.isCancelled()) {
                Function function = functions.next();
                total++;

                String name = function.getName();
                String address = function.getEntryPoint().toString();
                String signature = function.getSignature().getPrototypeString();
                String safeName = name.replace("\\", "\\\\").replace("\"", "\\\"");

                DecompileResults result = decompiler.decompileFunction(function, 90, monitor);
                if (result != null && result.decompileCompleted()
                        && result.getDecompiledFunction() != null) {
                    cOut.write("\n/* Function: " + safeName + " @ " + address + " */\n");
                    cOut.write(result.getDecompiledFunction().getC());
                    cOut.write("\n");
                    exported++;
                    writeCsv(csvOut, name, address, signature, "decompiled");
                } else {
                    failed++;
                    writeCsv(csvOut, name, address, signature, "failed");
                }

                if (total % 100 == 0) {
                    println("Funções processadas: " + total + " | exportadas: " + exported
                            + " | falhas: " + failed);
                }
            }
        } finally {
            decompiler.dispose();
        }

        println("Módulo: " + currentProgram.getName());
        println("Total: " + total + " | exportadas: " + exported + " | falhas: " + failed);
        println("C: " + cFile.getAbsolutePath());
        println("CSV: " + csvFile.getAbsolutePath());
    }

    private void writeCsv(BufferedWriter out, String name, String address,
                          String signature, String status) throws IOException {
        out.write(csv(name));
        out.write(",");
        out.write(csv(address));
        out.write(",");
        out.write(csv(signature));
        out.write(",");
        out.write(csv(status));
        out.newLine();
    }

    private String csv(String value) {
        return "\"" + value.replace("\"", "\"\"") + "\"";
    }
}
