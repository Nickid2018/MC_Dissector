package io.github.nickid2018.crypt;

import lombok.SneakyThrows;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.IOException;
import java.lang.reflect.Method;
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

    private static void writeIntoFile(String content, String index) {
        FileChannel channel = getFileChannel();
        if (channel == null && !disabled) {
            getLogger().warn("Key file channel is not initialized, cannot flush keys.");
            return;
        }

        try (FileLock ignored = channel.lock()) {
            String writeContent = String.format("%s %s\n", index, content);
            ByteBuffer buffer = ByteBuffer.wrap(writeContent.getBytes(StandardCharsets.UTF_8));
            channel.write(buffer);
            channel.force(true);
            getLogger().info("Successfully wrote key log file for challenge: {}", index);
        } catch (IOException e) {
            getLogger().error("Failed to operate key file", e);
        }
    }

    // We compile this file in Java 8, but we need Record in higher Java version, so reflect reflection
    @SneakyThrows
    private static Object getRecordComponent(Object obj, int index) {
        Class<?> clazz = obj.getClass(); // should be a record, we will not check it
        Method getRecordComponents = Class.class.getDeclaredMethod("getRecordComponents");
        getRecordComponents.setAccessible(true);
        Object[] recordComponents = (Object[]) getRecordComponents.invoke(clazz);
        Object component = recordComponents[index];
        Method getAccessor = component.getClass().getDeclaredMethod("getAccessor");
        getAccessor.setAccessible(true);
        Method accessor = (Method) getAccessor.invoke(component);
        accessor.setAccessible(true);
        return accessor.invoke(obj);
    }

    // V1
    private static void pushKeyInfo(SecretKey key, byte[] challenge) {
        if (disabled)
            return;
        writeIntoFile(byteArrayToHexString(key.getEncoded()), byteArrayToHexString(challenge));
    }

    // V2
    private static SecretKey savedKey;

    private static void push(byte[] data) {
        if (disabled)
            return;
        if (savedKey == null) {
            savedKey = new SecretKeySpec(data, "AES");
        } else {
            writeIntoFile(byteArrayToHexString(savedKey.getEncoded()), byteArrayToHexString(data));
            savedKey = null;
        }
    }

    // V3
    private static void pushSalt(
        Object savedSalt,
        SecretKey serverToClientKey,
        SecretKey clientToServerKey,
        IvParameterSpec serverToClient,
        IvParameterSpec clientToServer
    ) {
        if (disabled)
            return;
        writeIntoFile(String.format("%s %s %s %s",
            byteArrayToHexString(serverToClientKey.getEncoded()),
            byteArrayToHexString(clientToServerKey.getEncoded()),
            byteArrayToHexString(serverToClient.getIV()),
            byteArrayToHexString(clientToServer.getIV())
        ), String.format("S%x", (Long) (savedSalt)));
    }
}
