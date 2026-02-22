package io.github.nickid2018.crypt;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.commons.ClassRemapper;
import org.objectweb.asm.commons.Remapper;
import org.objectweb.asm.tree.*;

public class TransformProviders {

    public static final String KEY_LOG_FILE_MANAGER_CLASS = "io/github/nickid2018/crypt/KeyLogFileManager";
    public static final String KEY_LOG_INJECTION_DESC = "(Ljavax/crypto/SecretKey;Ljava/security/PublicKey;[B)V";
    public static final String RANDOM_SUFFIX = "$$KeyLog$$" + Long.toHexString(System.nanoTime());

    public static final TransformProvider KEY_LOG_TRANSFORM = (classNode, className) -> {
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

                ClassReader injectClassReader = new ClassReader(KEY_LOG_FILE_MANAGER_CLASS);
                ClassNode injectNode = new ClassNode();
                ClassRemapper classMapper = new ClassRemapper(
                        injectNode,
                        new Remapper() {
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
                classNode.accept(cw);

                return cw.toByteArray();
            }
        }
        return null;
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
        return (classNode, className) -> {
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
