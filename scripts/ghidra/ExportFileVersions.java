/*
 * LICENSE
 */
// Description
//@author roblabla
//@category exports
//@keybinding
//@menupath Skeleton
//@toolbar Skeleton
import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.stream.JsonWriter;
import ghidra.app.script.GhidraScript;
import ghidra.framework.model.DomainFile;
import ghidra.framework.store.Version;
import java.io.File;
import java.io.FileWriter;

public class ExportFileVersions extends GhidraScript
{
    @Override protected void run() throws Exception
    {
        // We get the DomainFile this way to ensure we get a GhidraFile and not
        // a DomainProxyFile. This is because DomainProxyFile does not contain
        // the VersionHistory that we need.
        DomainFile f = parseDomainFile(currentProgram.getDomainFile().getPathname());
        File outFile = askFile("Output JSON", "");
        Version versions[] = f.getVersionHistory();
        JsonArray arr = new JsonArray(versions.length);
        for (Version ver : versions)
        {
            JsonObject obj = new JsonObject();
            obj.addProperty("version", ver.getVersion());
            obj.addProperty("user", ver.getUser());
            obj.addProperty("comment", ver.getComment());
            obj.addProperty("createTime", ver.getCreateTime());
            arr.add(obj);
        }
        FileWriter outFileWriter = new FileWriter(outFile);
        new Gson().toJson(arr, outFileWriter);
        outFileWriter.flush();
        outFileWriter.close();
    }
}
