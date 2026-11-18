package io.github.nickid2018.crypt;

import lombok.extern.slf4j.Slf4j;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.commons.ClassRemapper;
import org.objectweb.asm.commons.Remapper;
import org.objectweb.asm.tree.*;

import java.io.IOException;
import java.util.stream.Stream;

@Slf4j
public class TransformProviders {

    public static final String KEY_LOG_FILE_MANAGER_CLASS = "io/github/nickid2018/crypt/KeyLogFileManager";
    public static final String KEY_LOG_INJECTION_DESC = "(Ljavax/crypto/SecretKey;Ljava/security/PublicKey;[B)V";
    public static final String KEY_LOG_INJECTION2_DESC = "(Ljava/security/Key;[B)[B";
    public static final String RANDOM_SUFFIX = "$$KeyLog$$" + Long.toHexString(System.nanoTime());

    private static void injectKeyLogFileManager(String className, ClassWriter cw) throws IOException {
        ClassReader injectClassReader = new ClassReader(KEY_LOG_FILE_MANAGER_CLASS);
        ClassNode injectNode = new ClassNode();
        ClassRemapper classMapper = new ClassRemapper(
            injectNode,
            new Remapper(Opcodes.ASM9) {
                @Override
                public String map(String typeName) {
                    return typeName.equals(KEY_LOG_FILE_MANAGER_CLASS) ? className : typeName;
                }

                @Override
                public String mapMethodName(String owner, String name, String desc) {
                    return owner.equals(KEY_LOG_FILE_MANAGER_CLASS) ? name + RANDOM_SUFFIX : name;
                }

                @Override
                public String mapFieldName(String owner, String name, String desc) {
                    return owner.equals(KEY_LOG_FILE_MANAGER_CLASS) ? name + RANDOM_SUFFIX : name;
                }
            }
        );
        injectClassReader.accept(classMapper, 0);
        injectNode.methods.removeIf(m -> m.name.startsWith("<"));
        injectNode.accept(cw);
    }

    public static final TransformProvider KEY_LOG_TRANSFORM_V1 = (classNode, className, _pool) -> {
        for (MethodNode methodNode : classNode.methods) {
            if (!methodNode.name.equals("<init>"))
                return null;
            if (methodNode.desc.equals(KEY_LOG_INJECTION_DESC)) {
                InsnList list = new InsnList();
                list.add(new VarInsnNode(Opcodes.ALOAD, 1)); // SecretKey
                list.add(new VarInsnNode(Opcodes.ALOAD, 3)); // byte[]
                list.add(new MethodInsnNode(
                    Opcodes.INVOKESTATIC,
                    className,
                    "pushKeyInfo" + RANDOM_SUFFIX,
                    "(Ljavax/crypto/SecretKey;[B)V",
                    false
                ));
                methodNode.instructions.insert(list);
                ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_FRAMES);
                injectKeyLogFileManager(className, cw);
                classNode.accept(cw);
                return cw.toByteArray();
            }
        }
        return null;
    };

    public static final TransformProvider KEY_LOG_TRANSFORM_V2 = (classNode, className, constantPool) -> {
        if (!constantPool.contains("AES/CFB8/NoPadding")) return null; // Crypt
        log.info("Crypt => {}", className);

        MethodNode encryptUsingKeyNode = null;
        for (MethodNode methodNode : classNode.methods) {
            if (!methodNode.desc.equals(KEY_LOG_INJECTION2_DESC)) continue;
            if (Stream.of(methodNode.instructions.toArray())
                .filter(m -> m instanceof InsnNode)
                .map(InsnNode.class::cast)
                .anyMatch(m -> m.getOpcode() == Opcodes.ICONST_1)) {
                encryptUsingKeyNode = methodNode;
                break;
            }
        }
        if (encryptUsingKeyNode == null) return null;
        log.info("encryptUsingKey => {}", encryptUsingKeyNode.name);

        InsnList list = new InsnList();
        list.add(new VarInsnNode(Opcodes.ALOAD, 1)); // [B
        list.add(new MethodInsnNode(Opcodes.INVOKESTATIC, className, "push" + RANDOM_SUFFIX, "([B)V", false));
        encryptUsingKeyNode.instructions.insert(list);
        ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_FRAMES);
        injectKeyLogFileManager(className, cw);
        classNode.accept(cw);
        return cw.toByteArray();
    };

    public static final TransformProvider KEY_LOG_TRANSFORM_V3 = (classNode, className, constantPool) -> {
        if (!constantPool.contains("Authentication failed: {}")) return null; // ClientHandshakePacketListenerImpl
        log.info("ClientHandshakePacketListenerImpl => {}", className);

        MethodNode handleKeyNode = null;
        for (MethodNode methodNode : classNode.methods) {
            if (Stream.of(methodNode.instructions.toArray())
                .filter(m -> m instanceof LdcInsnNode)
                .map(LdcInsnNode.class::cast)
                .anyMatch(node -> node.cst.equals("Protocol error"))
            ) {
                handleKeyNode = methodNode; // handleKey
                break;
            }
        }
        if (handleKeyNode == null) return null;
        log.info("handleKey => {}", handleKeyNode.name);

        FieldInsnNode putPendingIvSeedsFNode = Stream.of(handleKeyNode.instructions.toArray())
            .filter(m -> m instanceof FieldInsnNode)
            .map(FieldInsnNode.class::cast)
            .filter(m -> m.getOpcode() == Opcodes.PUTFIELD)
            .findFirst().orElse(null);
        if (putPendingIvSeedsFNode == null) return null;
        String fPendingIvSeeds = putPendingIvSeedsFNode.name;
        String cPendingIvSeeds = putPendingIvSeedsFNode.desc;
        log.info("pendingIvSeeds => {} [{}]", fPendingIvSeeds, cPendingIvSeeds);

        MethodInsnNode sendKeysMNode = Stream.of(handleKeyNode.instructions.toArray())
            .filter(m -> m instanceof MethodInsnNode)
            .map(MethodInsnNode.class::cast)
            .filter(m -> m.desc.endsWith(";[B)V") && m.owner.equals(className))
            .findFirst().orElse(null); // sendKeys
        if (sendKeysMNode == null) return null;
        String sendKeyMethodName = sendKeysMNode.name;
        log.info("sendKeys => {}", sendKeyMethodName);
        MethodNode sendKeysNode = classNode.methods.stream().filter(m -> m.name.equals(sendKeyMethodName)).findFirst().orElse(null);
        if (sendKeysNode == null) return null;

        String recordReflect = "getRecordComponent" + RANDOM_SUFFIX;
        String recordDesc = "(Ljava/lang/Object;I)Ljava/lang/Object;";
        String putSalt = "pushSalt" + RANDOM_SUFFIX;
        String putSaltDesc = "(Ljava/lang/Object;Ljavax/crypto/SecretKey;Ljavax/crypto/SecretKey;Ljavax/crypto/spec/IvParameterSpec;Ljavax/crypto/spec/IvParameterSpec;)V";
        InsnList sendKey = new InsnList();
        sendKey.add(new VarInsnNode(Opcodes.ALOAD, 1)); // SessionKeys
        sendKey.add(new InsnNode(Opcodes.ICONST_0)); // sessionCommonInfo
        sendKey.add(new MethodInsnNode(Opcodes.INVOKESTATIC, className, recordReflect, recordDesc));
        sendKey.add(new InsnNode(Opcodes.ICONST_1)); // salt
        sendKey.add(new MethodInsnNode(Opcodes.INVOKESTATIC, className, recordReflect, recordDesc));
        // stack: [salt: Object/long]
        sendKey.add(new VarInsnNode(Opcodes.ALOAD, 1)); // SessionKeys
        sendKey.add(new InsnNode(Opcodes.ICONST_3)); // streamAToB
        sendKey.add(new MethodInsnNode(Opcodes.INVOKESTATIC, className, recordReflect, recordDesc));
        sendKey.add(new TypeInsnNode(Opcodes.CHECKCAST, "javax/crypto/SecretKey"));
        // stack: [salt: Object/long, streamAToB: SecretKey]
        sendKey.add(new VarInsnNode(Opcodes.ALOAD, 1)); // SessionKeys
        sendKey.add(new InsnNode(Opcodes.ICONST_4)); // streamBToA
        sendKey.add(new MethodInsnNode(Opcodes.INVOKESTATIC, className, recordReflect, recordDesc));
        sendKey.add(new TypeInsnNode(Opcodes.CHECKCAST, "javax/crypto/SecretKey"));
        // stack: [salt: Object/long, streamAToB: SecretKey, streamBToA: SecretKey]
        sendKey.add(new VarInsnNode(Opcodes.ALOAD, 0)); // this
        sendKey.add(new FieldInsnNode(Opcodes.GETFIELD, className, fPendingIvSeeds, cPendingIvSeeds)); // pendingIvSeeds
        sendKey.add(new InsnNode(Opcodes.ICONST_0));  // serverToClient
        sendKey.add(new MethodInsnNode(Opcodes.INVOKESTATIC, className, recordReflect, recordDesc));
        sendKey.add(new TypeInsnNode(Opcodes.CHECKCAST, "javax/crypto/spec/IvParameterSpec"));
        // stack: [salt: Object/long, streamAToB: SecretKey, streamBToA: SecretKey, serverToClient: IvParameterSpec]
        sendKey.add(new VarInsnNode(Opcodes.ALOAD, 0)); // this
        sendKey.add(new FieldInsnNode(Opcodes.GETFIELD, className, fPendingIvSeeds, cPendingIvSeeds)); // pendingIvSeeds
        sendKey.add(new InsnNode(Opcodes.ICONST_1));  // clientToServer
        sendKey.add(new MethodInsnNode(Opcodes.INVOKESTATIC, className, recordReflect, recordDesc));
        sendKey.add(new TypeInsnNode(Opcodes.CHECKCAST, "javax/crypto/spec/IvParameterSpec"));
        // stack: [salt: Object/long, streamAToB: SecretKey, streamBToA: SecretKey, serverToClient: IvParameterSpec, clientToServer: IvParameterSpec]
        sendKey.add(new MethodInsnNode(Opcodes.INVOKESTATIC, className, putSalt, putSaltDesc));
        // stack cleared
        sendKey.add(sendKeysNode.instructions);
        sendKeysNode.instructions = sendKey;

        ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_FRAMES);
        injectKeyLogFileManager(className, cw);
        classNode.accept(cw);
        return cw.toByteArray();
    };

    public static TransformProvider getKeyForcingTransform(String aesKey) {
        aesKey = aesKey.toUpperCase();
        if (aesKey.length() != 32)
            throw new IllegalArgumentException("Secret Key String must be 32 characters long!");
        byte[] key = new byte[16];
        for (int i = 0; i < 16; i++) {
            int high = aesKey.charAt(i * 2);
            if (high >= '0' && high <= '9')
                high -= '0';
            else if (high >= 'A' && high <= 'F')
                high -= 'A' - 10;
            else
                throw new IllegalArgumentException("Secret Key String has illegal characters!");
            int low = aesKey.charAt(i * 2 + 1);
            if (low >= '0' && low <= '9')
                low -= '0';
            else if (low >= 'A' && low <= 'F')
                low -= 'A' - 10;
            else
                throw new IllegalArgumentException("Secret Key String has illegal characters!");
            key[i] = (byte) ((high << 4) | low);
        }
        return (classNode, className, _pool) -> {
            for (MethodNode methodNode : classNode.methods) {
                if (methodNode.desc.equals("()Ljavax/crypto/SecretKey;") && methodNode.localVariables.get(0).desc.equals("Ljavax/crypto/KeyGenerator;")) {
                    InsnList list = new InsnList();
                    list.add(new FieldInsnNode(Opcodes.GETSTATIC, "java/lang/System", "out",
                        "Ljava/io/PrintStream;"));
                    list.add(new LdcInsnNode("Override Secret Key!"));
                    list.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/io/PrintStream", "println",
                        "(Ljava/lang/String;)V"));
                    list.add(new TypeInsnNode(Opcodes.NEW, "javax/crypto/spec/SecretKeySpec"));
                    list.add(new InsnNode(Opcodes.DUP));
                    list.add(new IntInsnNode(Opcodes.BIPUSH, 16));
                    list.add(new IntInsnNode(Opcodes.NEWARRAY, Opcodes.T_BYTE));
                    for (int i = 0; i < 16; i++) {
                        list.add(new InsnNode(Opcodes.DUP));
                        list.add(new IntInsnNode(Opcodes.BIPUSH, i));
                        list.add(new IntInsnNode(Opcodes.BIPUSH, key[i]));
                        list.add(new InsnNode(Opcodes.BASTORE));
                    }
                    list.add(new LdcInsnNode("AES"));
                    list.add(new MethodInsnNode(Opcodes.INVOKESPECIAL, "javax/crypto/spec/SecretKeySpec", "<init>", "([BLjava/lang/String;)V"));
                    list.add(new InsnNode(Opcodes.ARETURN));
                    methodNode.maxLocals = 1;
                    methodNode.maxStack = 6;
                    methodNode.tryCatchBlocks.clear();
                    methodNode.exceptions.clear();
                    methodNode.localVariables.clear();
                    methodNode.instructions.clear();
                    methodNode.instructions.add(list);

                    ClassWriter writer = new ClassWriter(0);
                    classNode.accept(writer);
                    return writer.toByteArray();
                }
            }
            return null;
        };
    }
}
