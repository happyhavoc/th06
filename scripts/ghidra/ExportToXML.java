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
import ghidra.app.util.exporter.XmlExporter;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.mem.Memory;
import java.io.File;

public class ExportToXML extends GhidraScript
{
    @Override protected void run() throws Exception
    {
        XmlExporter exporter = new XmlExporter();

        File outFile = askFile("Output XML", "");
        int outVer = askInt("File Version to Export", "");

        // We get the DomainFile this way to ensure we get a GhidraFile and not
        // a DomainProxyFile. This is because DomainProxyFile does not handle
        // getting anything but the latest version of a file.
        DomainFile f = parseDomainFile(currentProgram.getDomainFile().getPathname());

        DomainObject obj = f.getReadOnlyDomainObject(this, outVer, monitor);
        Memory mem = getCurrentProgram().getMemory();

        exporter.export(outFile, obj, mem, monitor);
        obj.release(this);
    }
}
