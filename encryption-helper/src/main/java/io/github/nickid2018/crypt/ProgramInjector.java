package io.github.nickid2018.crypt;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.*;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.Instrumentation;
import java.security.ProtectionDomain;

public class ProgramInjector implements ClassFileTransformer {

    private static ProgramInjector INSTANCE;

    public static void premain(String agentArgs, Instrumentation inst) {
        agentArgs = agentArgs.toUpperCase();
        if (agentArgs.length() != 32)
            throw new IllegalArgumentException("Secret Key String must be 32 characters long!");
        INSTANCE = new ProgramInjector();
        byte[] key = new byte[16];
        for (int i = 0; i < 16; i++) {
            int high = agentArgs.charAt(i * 2);
            if (high >= '0' && high <= '9')
                high -= '0';
            else if (high >= 'A' && high <= 'F')
                high -= 'A' - 10;
            else
                throw new IllegalArgumentException("Secret Key String has illegal characters!");
            int low = agentArgs.charAt(i * 2 + 1);
            if (low >= '0' && low <= '9')
                low -= '0';
            else if (low >= 'A' && low <= 'F')
                low -= 'A' - 10;
            else
                throw new IllegalArgumentException("Secret Key String has illegal characters!");
            key[i] = (byte) ((high << 4) | low);
        }
        INSTANCE.key = new SecretKeySpec(key, "AES");
        inst.addTransformer(INSTANCE);
    }

    public static SecretKey getKey() {
        System.out.println("Override Secret Key!");
        return INSTANCE.key;
    }

    private SecretKey key;
    private boolean transformed = false;

    @Override
    public byte[] transform(ClassLoader loader, String className, Class<?> classBeingRedefined,
                            ProtectionDomain protectionDomain, byte[] classfileBuffer) {
        if (transformed)
            return null;
        if (className.startsWith("java"))
            return null;
        ClassNode classNode = new ClassNode();
        ClassReader reader = new ClassReader(classfileBuffer);
        reader.accept(classNode, 0);
        for (MethodNode methodNode : classNode.methods) {
            if (methodNode.desc.equals("()Ljavax/crypto/SecretKey;") &&
                    methodNode.localVariables.get(0).desc.equals("Ljavax/crypto/KeyGenerator;")) {
                System.out.printf("Found Crypt Class, Name = %s, Method = %s%n", className, methodNode.name);
                InsnList list = new InsnList();
                list.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "io/github/nickid2018/crypt/ProgramInjector",
                        "getKey", "()Ljavax/crypto/SecretKey;"));
                list.add(new InsnNode(Opcodes.ARETURN));
                methodNode.maxLocals = 1;
                methodNode.maxStack = 1;
                methodNode.tryCatchBlocks.clear();
                methodNode.exceptions.clear();
                methodNode.localVariables.clear();
                methodNode.instructions.clear();
                methodNode.instructions.add(list);
                transformed = true;
                try {
                    ClassWriter writer = new ClassWriter(0);
                    classNode.accept(writer);
                    byte[] data = writer.toByteArray();
                    System.out.println("Class Crypt has been transformed. Key has been override with ProgramInjector.getKey() = ***!");
                    return data;
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        }
        return null;
    }
}
