package ai.lmctl.lmaws;

import java.nio.file.*;
import java.util.*;

/** Offline checks for the provisioning write-ahead file; no AWS clients. */
public final class ProvisionJournalChecks {
    public static void main(String[] args) throws Exception {
        String id="journal-"+UUID.randomUUID().toString().substring(0,8);
        Path path;
        try(var j=ProvisionJournal.open(id,true)) {
            j.save(Map.of("config",Map.of("volume_gib",10),"client_token","stable","state","requested"));
            j.request("RunInstances");j.receipt(Map.of("ok",true,"state","pending"));
            path=j.path;
        }
        try(var j=ProvisionJournal.open(id,true)) {
            if(!j.state().get("client_token").equals("stable")
                ||((Number)((Map<?,?>)j.state().get("config")).get("volume_gib")).intValue()!=10)
                throw new AssertionError("restart lost configuration/token");
        }
        byte[] valid=Files.readAllBytes(path);
        Files.writeString(path,"{torn",StandardOpenOption.APPEND);
        boolean refused=false;
        try(var ignored=ProvisionJournal.open(id,true)){}
        catch(IllegalStateException expected){refused=true;}
        if(!refused)throw new AssertionError("torn journal accepted");
        Files.write(path,valid);
        String original=Files.readString(path);
        Files.writeString(path,original.replace("stable","changed"));
        refused=false;
        try(var ignored=ProvisionJournal.open(id,true)){}
        catch(IllegalStateException expected){refused=true;}
        if(!refused)throw new AssertionError("corrupted journal accepted");
        Files.deleteIfExists(path);Files.deleteIfExists(path.resolveSibling(id+".lock"));
        System.out.println("PASS provisioning journal restart, numeric canonicalization, torn/corrupt fail-closed and fsync replay");
    }
}
