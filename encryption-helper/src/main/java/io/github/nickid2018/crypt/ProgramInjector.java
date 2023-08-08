package io.github.nickid2018.crypt;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.*;

import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.Instrumentation;
import java.security.ProtectionDomain;

public class ProgramInjector implements ClassFileTransformer {

    private byte[] data;

    public static void premain(String agentArgs, Instrumentation inst) {
        agentArgs = agentArgs.toUpperCase();
        if (agentArgs.length() != 32)
            throw new IllegalArgumentException("Secret Key String must be 32 characters long!");
        ProgramInjector instance = new ProgramInjector();
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
        instance.data = key;
        inst.addTransformer(instance);
    }

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
                    list.add(new IntInsnNode(Opcodes.BIPUSH, data[i]));
                    list.add(new InsnNode(Opcodes.BASTORE));
                }
                list.add(new LdcInsnNode("AES"));
                list.add(new MethodInsnNode(Opcodes.INVOKESPECIAL, "javax/crypto/spec/SecretKeySpec", "<init>",
                        "([BLjava/lang/String;)V"));
                list.add(new InsnNode(Opcodes.ARETURN));
                methodNode.maxLocals = 1;
                methodNode.maxStack = 6;
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
                    System.out.println("Class Crypt has been transformed. Key has been override with  ***!");
                    return data;
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        }
        return null;
    }
}
