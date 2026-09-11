import ghidra.app.script.GhidraScript;
import ghidra.pcode.floatformat.BigFloat;
import ghidra.pcode.floatformat.FloatFormat;
import ghidra.program.database.symbol.FunctionSymbol;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DoubleDataType;
import ghidra.program.model.data.FloatDataType;
import ghidra.program.model.data.StringDataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolType;
import java.io.File;
import java.nio.file.Files;

public class ExportGhidraToReccmp extends GhidraScript
{
    private String makeReccmpFunctionsCSV()
    {
        StringBuilder builder = new StringBuilder();

        builder.append("name,address,type\n");
        SymbolTable symbolTable = currentProgram.getSymbolTable();

        SymbolIterator symbolIter = symbolTable.getAllSymbols(true);

        while (symbolIter.hasNext())
        {
            long size = 0;

            Symbol symbol = symbolIter.next();

            SymbolType type = symbol.getSymbolType();
            String strType = "";
            String symbolName = symbol.getName(true);

            if (type == SymbolType.FUNCTION)
            {
                /* This is a nice ole hack to get rid of library functions in the reccmp report. */
                if (symbol.getAddress().getOffset() >= 0x43eba0)
                {
                    strType = "library";
                }
                else
                {
                    strType = "function";
                }
                if (symbol instanceof FunctionSymbol)
                {
                    Function function = (Function)((FunctionSymbol)symbol).getObject();

                    /* we don't care about external functions */
                    if (function.isExternal())
                    {
                        continue;
                    }

                    /* or thunks */
                    if (function.isThunk())
                    {
                        continue;
                    }

                    size = function.getBody().getNumAddresses();

                    /* some symbol names need to "demangled" in order to match with reccmp. */

                    if (symbolName.startsWith("_"))
                    {
                        /* remove the leading _ */
                        symbolName = symbolName.substring(1);
                    }
                    /* operator_new and operator_delete */
                    if (symbolName.startsWith("operator"))
                    {
                        symbolName = symbolName.replace('_', ' ');
                    }

                    /* e.g. `eh_vector_constructor_iterator' or `scalar_deleting_destructor' */
                    if (symbolName.indexOf('`') != -1 && symbolName.indexOf('\'') != -1)
                    {
                        symbolName = symbolName.replace('_', ' ');
                    }
                }
            }
            else
            {
                continue;
            }

            builder.append(symbolName);
            builder.append(",0x");
            builder.append(Long.toHexString(symbol.getAddress().getOffset()));
            builder.append(",");
            builder.append(strType);
            builder.append("\n");
        }

        return builder.toString();
    }

    private String makeReccmpGlobalsCSV()
    {
        StringBuilder builder = new StringBuilder();

        builder.append("name,address,type,size\n");
        SymbolTable symbolTable = currentProgram.getSymbolTable();

        SymbolIterator symbolIter = symbolTable.getAllSymbols(true);

        while (symbolIter.hasNext())
        {
            Symbol symbol = symbolIter.next();

            SymbolType type = symbol.getSymbolType();
            String strType = "";
            String symbolName = symbol.getName(true);

            Data data = currentProgram.getListing().getDefinedDataAt(symbol.getAddress());

            if (data == null)
            {
                continue;
            }

            if (type == SymbolType.LABEL)
            {
                /* filters out switch labels */
                if (symbol.getSource() != SourceType.USER_DEFINED)
                {
                    continue;
                }

                if (symbolName.contains("`vftable"))
                {
                    strType = "vtable";
                }
                else
                {
                    strType = "global";
                }
            }
            else
            {
                continue;
            }

            builder.append(symbolName);
            builder.append(",0x");
            builder.append(Long.toHexString(symbol.getAddress().getOffset()));
            builder.append(",");
            builder.append(strType);
            builder.append(",");
            builder.append(data.getLength());
            builder.append("\n");
        }

        return builder.toString();
    }

    public static String convertStringtoCString(String input)
    {
        StringBuilder builder = new StringBuilder();

        for (char c : input.toCharArray())
        {
            switch (c)
            {
            case '\n':
                builder.append("\\n");
                break;
            case '\r':
                builder.append("\\r");
                break;
            case '\t':
                builder.append("\\t");
                break;
            case '\\':
                builder.append("\\\\");
                break;
            case '\"':
                builder.append("\\\"");
                break;
            case '\'':
                builder.append("\\\'");
                break;
            default:
                builder.append(c);
                break;
            }
        }

        return builder.toString();
    }

    private String makeReccmpStringsCSV()
    {
        StringBuilder builder = new StringBuilder();

        builder.append("address,type,x-text\n");

        String strType = "";

        DataIterator dataIter = currentProgram.getListing().getDefinedData(true);

        while (dataIter.hasNext())
        {
            Data data = dataIter.next();
            DataType type = data.getDataType();

            if (type instanceof StringDataType)
            {
                strType = "string";
            }
            else
            {
                continue;
            }

            builder.append("0x");
            builder.append(Long.toHexString(data.getAddress().getOffset()));
            builder.append(",");
            builder.append("string,");
            builder.append("\"");
            builder.append(convertStringtoCString((String)data.getValue()));
            builder.append("\"");
            builder.append("\n");
        }

        return builder.toString();
    }

    private String makeReccmpFloatsCSV()
    {
        StringBuilder builder = new StringBuilder();

        builder.append("address,type,size\n");

        String strType = "";

        DataIterator dataIter = currentProgram.getListing().getDefinedData(true);

        while (dataIter.hasNext())
        {
            Data data = dataIter.next();
            DataType type = data.getDataType();
            int size = 0;

            strType = "float";

            if (type instanceof FloatDataType)
            {
                size = 4;
            }
            else if (type instanceof DoubleDataType)
            {
                size = 8;
            }
            else
            {
                continue;
            }

            builder.append("0x");
            builder.append(Long.toHexString(data.getAddress().getOffset()));
            builder.append(",");
            builder.append(strType);
            builder.append(",");
            builder.append(Integer.toString(size));
            builder.append("\n");
        }

        return builder.toString();
    }

    @Override public void run() throws Exception
    {
        String fileContents;
        File outputFile;

        fileContents = makeReccmpFunctionsCSV();
        outputFile = askFile("reccmp-functions.csv", "Save");
        Files.write(outputFile.toPath(), fileContents.getBytes());

        fileContents = makeReccmpGlobalsCSV();
        outputFile = askFile("reccmp-globals.csv", "Save");
        Files.write(outputFile.toPath(), fileContents.getBytes());

        fileContents = makeReccmpStringsCSV();
        outputFile = askFile("reccmp-strings.csv", "Save");
        Files.write(outputFile.toPath(), fileContents.getBytes());

        fileContents = makeReccmpFloatsCSV();
        outputFile = askFile("reccmp-floats.csv", "Save");
        Files.write(outputFile.toPath(), fileContents.getBytes());
    }
}
