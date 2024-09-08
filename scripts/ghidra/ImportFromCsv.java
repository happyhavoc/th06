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
import ghidra.app.util.NamespaceUtils;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.exception.DuplicateNameException;
import java.io.File;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Scanner;

public class ImportFromCsv extends GhidraScript
{
    @Override protected void run() throws Exception
    {
        File inFile = askFile("Input CSV", "");

        Scanner sc = new Scanner(inFile);

        // Give name to everything
        while (sc.hasNextLine())
        {
            String v = sc.nextLine();
            String[] values = v.split(",");
            String name = values[0];
            Address addr = this.toAddr(values[1]);
            Long size = Long.decode(values[2]);
            AddressSet range = new AddressSet(addr, size > 0 ? addr.add(size - 1) : addr);

            // Get the parent namespace.
            List<String> namespaceElems = new ArrayList<>(Arrays.asList(name.split("::")));
            String funName = namespaceElems.removeLast();

            Namespace curNamespace = this.getCurrentProgram().getGlobalNamespace();
            for (String curElem : namespaceElems)
            {
                Namespace ns;
                if ((ns = this.getNamespace(curNamespace, curElem)) != null)
                {
                    curNamespace = ns;
                }
                else
                {
                    // Create the namespace
                    curNamespace = this.getCurrentProgram().getSymbolTable().createNameSpace(curNamespace, curElem,
                                                                                             SourceType.USER_DEFINED);
                }
            }

            // Check if a function already exists.
            Function fun;
            if ((fun = this.getFunctionContaining(addr)) == null)
            {
                printf("No function exist for %s at %x - creating\n", name, addr.getOffset());
                fun = this.getCurrentProgram().getFunctionManager().createFunction(funName, curNamespace, addr, range,
                                                                                   SourceType.USER_DEFINED);
            }
            fun.setParentNamespace(curNamespace);
            try
            {
                fun.setName(funName, SourceType.USER_DEFINED);
            }
            catch (DuplicateNameException ex)
            {
            }
        }

        // Go over the switchD, and fix them. Sometimes they have duplicate
        // symbols, which leads to problem in the delinker extension.
        HashSet set = new HashSet<>();
        for (Symbol sym : this.getCurrentProgram().getSymbolTable().getSymbolIterator())
        {
            if (sym.getName().startsWith("caseD"))
            {
                String fullyQualifiedName =
                    NamespaceUtils.getNamespaceQualifiedName(sym.getParentNamespace(), sym.getName(), false);
                if (!set.add(fullyQualifiedName))
                {
                    sym.setName(sym.getName() + "__default", SourceType.USER_DEFINED);
                }
            }
        }
    }
}
