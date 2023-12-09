// Generate mapping.toml
//@category TH06

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import java.io.File;
import java.nio.file.Files;

public class GenerateMapping extends GhidraScript
{
    public String generateCsv()
    {
        StringBuilder builder = new StringBuilder();

        FunctionIterator funcIter = currentProgram.getListing().getFunctions(true);
        while (funcIter.hasNext())
        {
            Function func = funcIter.next();

            if (func.isThunk())
            {
                continue;
            }

            builder.append(func.getName(true));
            builder.append(",0x");
            builder.append(Long.toHexString(func.getEntryPoint().getOffset()));
            builder.append(",0x");
            builder.append(Long.toHexString(func.getBody().getNumAddresses()));
            builder.append("\n");
        }

        return builder.toString();
    }

    // TODO: handle duplicated
    public String generateToml()
    {
        StringBuilder builder = new StringBuilder();

        FunctionIterator funcIter = currentProgram.getListing().getFunctions(true);
        while (funcIter.hasNext())
        {
            Function func = funcIter.next();

            if (func.isThunk())
            {
                continue;
            }

            builder.append("[[function]]\n");

            builder.append("name = \"");
            builder.append(func.getName(true));
            builder.append("\"\n");

            builder.append("address = 0x");
            builder.append(Long.toHexString(func.getEntryPoint().getOffset()));
            builder.append("\n");

            builder.append("size = 0x");
            builder.append(Long.toHexString(func.getBody().getNumAddresses()));
            builder.append("\n");
            builder.append("\n");
        }

        return builder.toString();
    }

    @Override public void run() throws Exception
    {
        String mappingData = generateCsv();
        File outputMapping = askFile("mapping.csv", "Save");
        Files.write(outputMapping.toPath(), mappingData.getBytes());
    }
}
