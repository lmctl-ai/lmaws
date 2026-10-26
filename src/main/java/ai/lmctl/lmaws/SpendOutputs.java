package ai.lmctl.lmaws;

import java.nio.file.*;
import java.io.IOException;

/** Live spend output is private by construction, even when a script supplies a path. */
final class SpendOutputs {
    private SpendOutputs() {}
    static void requirePrivate(Path directory) {
        Path root=Path.of(".lmaws-local","spend").toAbsolutePath().normalize();
        Path target=directory.toAbsolutePath().normalize();
        if(!target.startsWith(root))throw new IllegalArgumentException("live spend output must be under .lmaws-local/spend");
        // Refuse pre-existing symlinks anywhere in the directory chain.
        Path current=Path.of("").toAbsolutePath().normalize();
        for(Path part:current.relativize(target)) {
            current=current.resolve(part);
            if(Files.isSymbolicLink(current))throw new IllegalArgumentException("live spend output cannot traverse a symbolic link");
        }
    }
    static void createPrivate(Path directory) {
        requirePrivate(directory);
        try {
            Files.createDirectories(directory);
            try {Files.setPosixFilePermissions(Path.of(".lmaws-local","spend").toAbsolutePath(),java.nio.file.attribute.PosixFilePermissions.fromString("rwx------"));Files.setPosixFilePermissions(directory,java.nio.file.attribute.PosixFilePermissions.fromString("rwx------"));}
            catch(UnsupportedOperationException ignored){}
        }catch(IOException e){throw new IllegalStateException("cannot create private spend directory");}
    }
}
