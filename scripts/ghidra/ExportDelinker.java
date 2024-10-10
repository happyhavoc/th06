/*
 * LICENSE
 */
// Description
//@author renzo904
//@category exports
//@keybinding
//@menupath Skeleton
//@toolbar Skeleton
import static java.util.Map.entry;

import ghidra.app.analyzers.RelocationTableSynthesizerAnalyzer;
import ghidra.app.script.GhidraScript;
import ghidra.app.services.Analyzer;
import ghidra.app.util.DomainObjectService;
import ghidra.app.util.Option;
import ghidra.app.util.exporter.CoffRelocatableObjectExporter;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.GhidraClass;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Symbol;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

public class ExportDelinker extends GhidraScript
{
    @Override protected void run() throws Exception
    {
        // First run the Relocation Table Synthesizer, to pickup any potentially
        // new globals in the reloc table.
        Analyzer analyzer = new RelocationTableSynthesizerAnalyzer();
        analyzer.added(currentProgram, currentProgram.getMemory(), monitor, new MessageLog());

        // Then, export the COFFs.
        CoffRelocatableObjectExporter exporter = new CoffRelocatableObjectExporter();

        List<Option> exporterOptions = exporter.getOptions(new DomainObjectService() {
            @Override public DomainObject getDomainObject()
            {
                return currentProgram;
            }
        });

        // We change the default option from "Prepend" to "Do Nothing"

        Object doNothing = exporterOptions.get(1).getValueClass().getEnumConstants()[0];
        Option newOptions = new Option("Leading underscore", doNothing);
        exporterOptions.set(1, newOptions);
        exporter.setOptions(exporterOptions);

        File inFile = askFile("Config File", "Select");
        File outDir = askDirectory("Output Folder", "Select");

        String configFile = Files.readString(inFile.toPath(), StandardCharsets.UTF_8);

        Iterator<String> iterator = configFile.lines().iterator();
        for (String objDataStr = iterator.next(); iterator.hasNext(); objDataStr = iterator.next())
        {
            String objDataStr = iterator.next();
            List<String> objData = new ArrayList<>(Arrays.asList(objDataStr.split(",")));

            String objClass = objData.remove(0);

            File outFile = new File(outDir, objClass + ".obj");

            AddressSet set = new AddressSet();
            for (String ghidraClassName : objData)
            {
                printf("Handling %s.obj - class %s\n", objClass, ghidraClassName);

                List<String> ghidraClassNameParts = new ArrayList<>(Arrays.asList(ghidraClassName.split("::")));
                String finalPart = ghidraClassNameParts.removeLast();

                Namespace curNs = null;
                for (String nsPart : ghidraClassNameParts)
                {
                    curNs = this.getNamespace(curNs, nsPart);
                }

                Symbol sym;
                if ((sym = this.getSymbol(finalPart, curNs)) == null)
                {
                    printf("Cannot find namespace or function %s, skipping.\n", ghidraClassName);
                    continue;
                }
                if (!(sym.getObject() instanceof Namespace))
                {
                    printf("Namespace %s is not a namespace or a function, skipping.\n", ghidraClassName);
                    continue;
                }

                Namespace ns = (Namespace)sym.getObject();
                set = set.union(ns.getBody());
            }

            if (set.isEmpty())
            {
                printf("No namespaces found for %s.obj, skipping.\n", objClass);
                continue;
            }
            exporter.export(outFile, currentProgram, set, monitor);
        }
    }
}
