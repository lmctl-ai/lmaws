package ai.lmctl.lmaws;

import io.lmctl.lmcode.*;
import java.nio.file.*;
import java.io.IOException;
import java.util.*;

/** Safe projected metadata. Retained rows are charged against the VM budget. */
public final class Rows {
    final List<Map<String,String>> rows;
    public Rows(List<Map<String,String>> source, Context context) {
        long size=128;
        for (var row:source) for(var field:row.entrySet()) size=Math.addExact(size,128L+2L*(field.getKey().length()+field.getValue().length()));
        context.charge(size);
        rows=source.stream().map(r->Collections.unmodifiableMap(new LinkedHashMap<>(r))).toList();
    }
    static String get(Map<String,String> row,String key) {return Jsons.mask(row.getOrDefault(key,""));}
    public String csv() {
        Set<String> columns=new LinkedHashSet<>();rows.forEach(r->columns.addAll(r.keySet()));
        StringBuilder out=new StringBuilder();out.append(String.join(",",columns.stream().map(Rows::cell).toList())).append('\n');
        for(var row:rows) out.append(String.join(",",columns.stream().map(k->cell(get(row,k))).toList())).append('\n');
        return out.toString();
    }
    private static String cell(String value) {
        String safe=Jsons.mask(value);
        if(!safe.isEmpty() && "=+-@\t\r".indexOf(safe.charAt(0))>=0) safe="'"+safe;
        return "\""+safe.replace("\"","\"\"")+"\"";
    }
    public void write(String name) {
        try {Files.writeString(Path.of(name),csv());}catch(IOException e){throw VmException.host("CSV export failed");}
    }
}
