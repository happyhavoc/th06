/*
 * LICENSE
 */
// Description
//@author renzo904
//@category exports
//@keybinding
//@menupath Skeleton
//@toolbar Skeleton
import ghidra.app.analyzers.RelocationTableSynthesizerAnalyzer;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.DomainObjectService;
import ghidra.app.util.Option;
import ghidra.app.util.exporter.CoffRelocatableObjectExporter;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.listing.GhidraClass;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.Namespace;
import java.io.File;
import java.util.List;

public class ExportDelinker extends GhidraScript
{

    static final String[] classesNames = {
        "AnmManager",    "AnmVm",       "AsciiManager", "BulletManager",   "Chain",       "EclManager",
        "EffectManager", "Enemy",       "EnemyManager", "FileAbstraction", "FileSystem",  "GameErrorContext",
        "GameManager",   "GameWindow",  "Gui",          "IPbg3Parser",     "ItemManager", "MainMenu",
        "MidiOutput",    "Pbg3Archive", "Pbg3Parser",   "Player",          "Rng",         "ScreenEffect",
        "SoundPlayer",   "Stage",       "Supervisor",   "TextHelper",      "ZunTimer"};

    @Override protected void run() throws Exception
    {
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

        File outDir = askDirectory("Output Folder", "Select");
        int outVer = askInt("File Version to Export", "");

        // We get the DomainFile this way to ensure we get a GhidraFile and not
        // a DomainProxyFile. This is because DomainProxyFile does not handle
        // getting anything but the latest version of a file.

        DomainFile f = parseDomainFile(currentProgram.getDomainFile().getPathname());

        DomainObject obj = f.getReadOnlyDomainObject(this, outVer, monitor);

        for (String objClass : classesNames)
        {
            Namespace ghidraClass = currentProgram.getSymbolTable().getNamespace(objClass, null);

            File outFile = new File(outDir, ghidraClass.getName() + ".obj");

            exporter.export(outFile, obj, ghidraClass.getBody(), monitor);
        }

        obj.release(this);
    }
}
