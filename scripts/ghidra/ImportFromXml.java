/*
 * LICENSE
 */
// Description
//@author roblabla
//@category exports
//@keybinding
//@menupath Skeleton
//@toolbar Skeleton
import ghidra.app.script.GhidraScript;
import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.app.util.opinion.XmlLoader;
import ghidra.formats.gfilesystem.FSRL;
import ghidra.formats.gfilesystem.FileSystemService;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.mem.Memory;
import java.io.File;
import java.util.ArrayList;
import java.util.Collection;

public class ImportFromXml extends GhidraScript
{
    @Override protected void run() throws Exception
    {
        File inFile = askFile("Input XML", "");

        XmlLoader loader = new XmlLoader();

        FSRL fsrl = FileSystemService.getInstance().getLocalFSRL(inFile);
        ByteProvider bp = FileSystemService.getInstance().getByteProvider(fsrl, false, monitor);

        Collection<LoadSpec> specs = loader.findSupportedLoadSpecs(bp);
        if (specs.isEmpty())
        {
            throw new Exception("No specs found");
        }
        if (specs.size() > 1)
        {
            throw new Exception("More than 1 spec found");
        }

        LoadSpec loadSpec = specs.iterator().next();
        MessageLog messageLog = new MessageLog();

        ArrayList<Option> opts = new ArrayList();
        opts.add(new Option("Memory Blocks", false));
        loader.loadInto(bp, loadSpec, opts, messageLog, currentProgram, monitor);

        this.println(messageLog.toString());
    }
}
