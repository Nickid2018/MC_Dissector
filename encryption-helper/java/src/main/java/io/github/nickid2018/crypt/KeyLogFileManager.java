package io.github.nickid2018.crypt;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.SecretKey;
import java.io.File;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.charset.StandardCharsets;
import java.nio.file.StandardOpenOption;
import java.util.*;

// We should avoid <clinit> in this class, so we use static methods instead of static fields.
@SuppressWarnings("unused")
public class KeyLogFileManager {

    private static FileChannel keyFile;
    private static Logger logger;
    private static boolean disabled;

    private static Logger getLogger() {
        if (logger != null)
            return logger;
        logger = LoggerFactory.getLogger("KeyLogFileManager");
        return logger;
    }

    private static FileChannel getFileChannel() {
        if (keyFile != null)
            return keyFile;

        String keyLogFile = System.getenv("MINECRAFT_KEY_LOG_FILE");
        if (keyLogFile == null || keyLogFile.isEmpty()) {
            getLogger().warn("Environment variable MINECRAFT_KEY_LOG_FILE is not set, key logging is disabled.");
            disabled = true;
            return null;
        }

        try {
            Set<StandardOpenOption> options = new HashSet<>();
            options.add(StandardOpenOption.WRITE);
            options.add(StandardOpenOption.APPEND);
            options.add(StandardOpenOption.CREATE);
            keyFile = FileChannel.open(new File(keyLogFile).toPath(), options);
        } catch (IOException e) {
            getLogger().error("Failed to open key log file: {}", keyLogFile, e);
            keyFile = null;
        } catch (Exception e) {
            getLogger().error("Unexpected error while opening key log file: {}", keyLogFile, e);
            keyFile = null;
        }
        return keyFile;
    }

    private static String byteArrayToHexString(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    private static void pushKeyInfo(SecretKey key, byte[] challenge) {
        if (disabled)
            return;

        FileChannel channel = getFileChannel();
        if (channel == null && !disabled) {
            getLogger().warn("Key file channel is not initialized, cannot flush keys.");
            return;
        }

        try (FileLock ignored = channel.lock()) {
            String writeContent = String.format(
                "%s %s\n",
                byteArrayToHexString(challenge),
                byteArrayToHexString(key.getEncoded())
            );
            ByteBuffer buffer = ByteBuffer.wrap(writeContent.getBytes(StandardCharsets.UTF_8));
            channel.write(buffer);
            channel.force(true);
            getLogger().info(
                "Successfully wrote key log file for challenge: {}",
                byteArrayToHexString(challenge)
            );
        } catch (IOException e) {
            getLogger().error("Failed to operate key file", e);
        }
    }
}
