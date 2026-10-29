package ai.lmctl.lmaws;

import java.io.IOException;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.nio.file.attribute.UserPrincipal;
import java.util.*;

/** Offline checks for provisioning journal recovery and path/permission safety. */
public final class ProvisionJournalChecks {
    private static Path forbiddenPath;
    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }

    private static boolean symlinksSupported() {
        Path probe = null;
        try {
            probe = Files.createTempDirectory("lmprov-symlink-probe-");
            Path target = probe.resolve("target");
            Path link = probe.resolve("link");
            Files.createDirectory(target);
            Files.createSymbolicLink(link, target);
            return Files.isSymbolicLink(link);
        } catch (UnsupportedOperationException | IOException | SecurityException unavailable) {
            return false;
        } finally { if (probe != null) deleteTree(probe); }
    }

    private static boolean posixSupported() {
        return FileSystems.getDefault().supportedFileAttributeViews().contains("posix");
    }

    private static void deleteTree(Path root) {
        if (root == null || !Files.exists(root, LinkOption.NOFOLLOW_LINKS)) return;
        try (var paths = Files.walk(root)) {
            paths.sorted(Comparator.reverseOrder()).forEach(path -> {
                try { Files.deleteIfExists(path); } catch (IOException ignored) { }
            });
        } catch (IOException ignored) { }
    }

    private static IllegalStateException refused(String expectedCheck, String expectedClass, String forbidden, Runnable action) {
        try { action.run(); }
        catch (IllegalStateException failure) {
            String message = String.valueOf(failure.getMessage()).toLowerCase(Locale.ROOT);
            check(message.contains("check=" + expectedCheck.toLowerCase(Locale.ROOT)),
                "journal refusal must identify check=" + expectedCheck + ": " + failure.getMessage());
            check(message.contains("path_class=" + expectedClass.toLowerCase(Locale.ROOT)),
                "journal refusal must identify path_class=" + expectedClass + ": " + failure.getMessage());
            check(!message.contains(forbidden.toLowerCase(Locale.ROOT)),
                "journal refusal must not disclose IDs or raw temporary paths: " + failure.getMessage());
            if (forbiddenPath != null) check(!message.contains(forbiddenPath.toString().toLowerCase(Locale.ROOT)),
                "journal refusal must not disclose the raw temporary path: " + failure.getMessage());
            return failure;
        }
        throw new AssertionError("unsafe journal path was accepted: check=" + expectedCheck + " path_class=" + expectedClass);
    }

    private static void basicReplay(Path base) throws Exception {
        String id = "journal-" + UUID.randomUUID().toString().substring(0, 8);
        Path path;
        try (var journal = ProvisionJournal.open(id, true, base)) {
            journal.save(Map.of("config", Map.of("volume_gib", 10), "client_token", "stable", "state", "requested"));
            journal.request("RunInstances"); journal.receipt(Map.of("ok", true, "state", "pending")); path = journal.path;
            check(path.toRealPath().startsWith(base.toRealPath()), "journal escaped canonical base");
        }
        try (var journal = ProvisionJournal.open(id, true, base)) {
            check("stable".equals(journal.state().get("client_token")), "restart lost token");
            check(((Number) ((Map<?, ?>) journal.state().get("config")).get("volume_gib")).intValue() == 10, "restart lost numeric config");
        }
        byte[] valid = Files.readAllBytes(path);
        Files.writeString(path, "{torn", StandardOpenOption.APPEND);
        boolean rejected = false; try (var ignored = ProvisionJournal.open(id, true, base)) { } catch (IllegalStateException expected) {
            rejected = true; String message = String.valueOf(expected.getMessage()).toLowerCase(Locale.ROOT);
            check(message.contains("check=journal_replay") && message.contains("path_class=canonical-journal-file"), "torn replay diagnostic: " + expected.getMessage());
        }
        check(rejected, "torn journal accepted"); Files.write(path, valid);
        Files.writeString(path, Files.readString(path).replace("stable", "changed")); rejected = false;
        try (var ignored = ProvisionJournal.open(id, true, base)) { } catch (IllegalStateException expected) {
            rejected = true; String message = String.valueOf(expected.getMessage()).toLowerCase(Locale.ROOT);
            check(message.contains("check=journal_replay") && message.contains("path_class=canonical-journal-file"), "corrupt replay diagnostic: " + expected.getMessage());
        }
        check(rejected, "corrupted journal accepted"); Files.write(path, valid);
        Files.deleteIfExists(path); Files.deleteIfExists(path.resolveSibling(id + ".lock"));
    }

    private static void pathChecks() throws Exception {
        Path temp = Files.createTempDirectory("lmprov-journal-check-");
        forbiddenPath = temp;
        try {
            Path real = temp.resolve("real"); Files.createDirectories(real);
            if (posixSupported()) Files.setPosixFilePermissions(real, PosixFilePermissions.fromString("rwx------"));
            try {
                UserPrincipal rootOwner = Files.getOwner(Path.of("/"));
                UserPrincipal currentOwner = Path.of("/").getFileSystem().getUserPrincipalLookupService()
                    .lookupPrincipalByName(System.getProperty("user.name", ""));
                if (!rootOwner.equals(currentOwner)) {
                    refused("directory_owner", "configured-directory", "owner-check",
                        () -> ProvisionJournal.open("owner-check", true, Path.of("/")));
                } else {
                    System.out.println("SKIP owner-negative regression: current user owns filesystem root");
                }
            } catch (IOException | UnsupportedOperationException | SecurityException unavailable) {
                System.out.println("SKIP owner-negative regression: filesystem owner lookup unavailable");
            }
            if (symlinksSupported()) {
                Path parentLink = temp.resolve("parent-link"); Files.createSymbolicLink(parentLink, real);
                Path configuredThroughLink = parentLink.resolve("journals");
                try (var journal = ProvisionJournal.open("canonical-parent", true, configuredThroughLink)) {
                    check(journal.path.toRealPath().startsWith(real.toRealPath()), "symlinked parent was not canonicalized");
                    journal.save(Map.of("client_token", "canonical-parent-token", "state", "requested"));
                }
                try (var journal = ProvisionJournal.open("canonical-parent", true, real.resolve("journals"))) {
                    check("canonical-parent-token".equals(journal.state().get("client_token")), "canonical parent state did not reopen through real path");
                }
                Path target = temp.resolve("final-target"), finalLink = temp.resolve("final-link"); Files.createDirectory(target); Files.createSymbolicLink(finalLink, target);
                refused("final_component_symlink", "configured-directory", "final-link", () -> ProvisionJournal.open("final-link", true, finalLink));
                Path modeTarget = temp.resolve("mode-target"), modeLink = real.resolve("demo"); Files.createDirectory(modeTarget); Files.createSymbolicLink(modeLink, modeTarget);
                refused("final_component_symlink", "canonical-mode-directory", "mode-leaf", () -> ProvisionJournal.open("mode-leaf", true, real));
                Path privateBase = temp.resolve("files"); Files.createDirectory(privateBase); if (posixSupported()) Files.setPosixFilePermissions(privateBase, PosixFilePermissions.fromString("rwx------"));
                String fileId = "file-check";
                Path fileJournal, fileLock;
                try (var journal = ProvisionJournal.open(fileId, true, privateBase)) { fileJournal = journal.path; fileLock = journal.path.resolveSibling(fileId + ".lock"); }
                Path journalBackup = privateBase.resolve("journal-backup"); Files.move(fileJournal, journalBackup); Files.createSymbolicLink(fileJournal, journalBackup);
                refused("final_component_symlink", "canonical-journal-file", fileId, () -> ProvisionJournal.open(fileId, true, privateBase));
                Files.delete(fileJournal); Files.move(journalBackup, fileJournal);
                Path lockBackup = privateBase.resolve("lock-backup"); Files.move(fileLock, lockBackup); Files.createSymbolicLink(fileLock, lockBackup);
                refused("final_component_symlink", "canonical-lock-file", fileId, () -> ProvisionJournal.open(fileId, true, privateBase));
                Files.delete(fileLock); Files.move(lockBackup, fileLock);
            } else System.out.println("SKIP symlink-parent regression: symbolic links unavailable");
            if (posixSupported()) {
                Path open = temp.resolve("open"); Files.createDirectory(open); Files.setPosixFilePermissions(open, PosixFilePermissions.fromString("rwxr-xr-x"));
                refused("directory_permissions", "configured-directory", "world-readable", () -> ProvisionJournal.open("world-readable", true, open));
                Path mode = temp.resolve("mode"); Files.createDirectory(mode); Files.setPosixFilePermissions(mode, PosixFilePermissions.fromString("rwx------"));
                Path modeDir = mode.resolve("demo"); Files.createDirectory(modeDir); Files.setPosixFilePermissions(modeDir, PosixFilePermissions.fromString("rwxr-xr-x"));
                refused("directory_permissions", "canonical-mode-directory", "unsafe-mode-id", () -> ProvisionJournal.open("unsafe-mode-id", true, mode));
                check(Files.getPosixFilePermissions(open).equals(PosixFilePermissions.fromString("rwxr-xr-x")), "permission test unexpectedly changed configured root");
                check(Files.getPosixFilePermissions(modeDir).equals(PosixFilePermissions.fromString("rwxr-xr-x")), "permission test unexpectedly changed mode root");
            } else System.out.println("SKIP POSIX permission regression: POSIX attributes unavailable");
            Path privateBase = temp.resolve("private"); Files.createDirectory(privateBase); if (posixSupported()) Files.setPosixFilePermissions(privateBase, PosixFilePermissions.fromString("rwx------"));
            basicReplay(privateBase);
        } finally { forbiddenPath = null; deleteTree(temp); }
    }

    public static void main(String[] args) throws Exception {
        pathChecks();
        System.out.println("PASS provisioning journal canonical symlink-parent, final-symlink and permissions guards; torn/corrupt replay remains fail-closed");
    }
}
