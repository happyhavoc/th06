// Generate mapping.toml
//@category TH06

import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Parameter;
import java.io.File;
import java.nio.file.Files;

public class GenerateMapping extends GhidraScript
{

    private String transformType(DataType ty)
    {
        switch (ty.toString())
        {
        case "u8":
        case "i8":
        case "u16":
        case "i16":
        case "u32":
        case "i32":
        case "f32":
            return ty.toString();

        // Unsigned primitives
        case "undefined":
        case "undefined1":
        case "byte":
        case "bool":
            return "u8";
        case "undefined2":
        case "ushort":
            return "u16";
        case "undefined4":
        case "uint":
            return "u32";
        case "ulong":
            return "unsigned long";

        // Signed primitives
        case "short":
            return "i16";
        case "int":
            return "i32";
        case "long":
            return "long";

        // Floats
        case "float":
            return "f32";
        }
        if (ty instanceof Pointer)
        {
            Pointer ptr = (Pointer)ty;
            DataType pointee = ptr.getDataType();
            return transformType(pointee) + "*";
        }
        if (ty instanceof TypeDef)
        {
            TypeDef typedef = (TypeDef)ty;
            return transformType(typedef.getBaseDataType());
        }
        return ty.getName();
    }

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
            builder.append(",");
            builder.append(func.getCallingConventionName());
            builder.append(",");
            builder.append(func.hasVarArgs() ? "varargs" : "");
            builder.append(",");
            builder.append(transformType(func.getReturnType()));
            for (Parameter p : func.getParameters())
            {
                builder.append(",");
                builder.append(transformType(p.getDataType()));
            }
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
