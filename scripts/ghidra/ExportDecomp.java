/*
 * LICENSE
 */
// Description
//@author roblabla
//@category exports
//@keybinding
//@menupath Skeleton
//@toolbar Skeleton
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.data.DataTypeWriter;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolType;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;

public class ExportDecomp extends GhidraScript
{
    @Override protected void run() throws Exception
    {
        File outDir = askDirectory("Output Folder", "");
        int outVer = askInt("File Version to Export", "");

        // We get the DomainFile this way to ensure we get a GhidraFile and not
        // a DomainProxyFile. This is because DomainProxyFile does not handle
        // getting anything but the latest version of a file.
        DomainFile f = parseDomainFile(currentProgram.getDomainFile().getPathname());

        DomainObject obj = f.getReadOnlyDomainObject(this, outVer, monitor);

        Program p = (Program)obj;

        DecompInterface decomp = new DecompInterface();
        DecompileOptions options = new DecompileOptions();
        decomp.setOptions(options);
        decomp.toggleCCode(true);
        decomp.toggleSyntaxTree(true);
        decomp.setSimplificationStyle("decompile");

        decomp.openProgram(p);

        SymbolTable st = p.getSymbolTable();
        SymbolIterator si = st.getSymbolIterator();

        while (si.hasNext())
        {
            Symbol s = si.next();
            if (s.getSymbolType() == SymbolType.FUNCTION && !s.isExternal() && s.getAddress().getOffset() < 0x0043d160)
            {
                Function fun = p.getFunctionManager().getFunctionAt(s.getAddress());
                if (!fun.isThunk())
                {
                    extractFunction(decomp, fun, outDir);
                }
            }
        }

        File datatypesFile = new File(outDir, "types.h");
        FileWriter fw = new FileWriter(datatypesFile);

        DataTypeWriter dtw = new DataTypeWriter(p.getDataTypeManager(), fw);
        dtw.write(p.getDataTypeManager(), monitor);
        fw.close();

        obj.release(this);
    }

    String getFullName(Namespace n)
    {
        String s = n.getName();
        while (!n.getParentNamespace().isGlobal())
        {
            n = n.getParentNamespace();
            s = n.getName() + "::" + s;
        }
        return s;
    }

    void extractFunction(DecompInterface decomp, Function f, File outputDir) throws IOException
    {
        DecompileResults res = decomp.decompileFunction(f, 120, monitor);
        if (res.getDecompiledFunction() != null)
        {
            outputDir = new File(outputDir, f.getParentNamespace().getName());
            outputDir.mkdirs();
            File outputFile = new File(outputDir, f.getName() + ".c");
            FileWriter fw = new FileWriter(outputFile);
            PrintWriter pw = new PrintWriter(fw);
            pw.write(res.getDecompiledFunction().getC());
            pw.close();
        }
        else
        {
            printf("Can't decompile %s\n", getFullName(f));
        }
    }
}
