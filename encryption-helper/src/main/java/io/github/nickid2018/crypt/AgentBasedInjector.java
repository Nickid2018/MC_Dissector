package io.github.nickid2018.crypt;

import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.commons.ClassRemapper;
import org.objectweb.asm.commons.Remapper;
import org.objectweb.asm.tree.*;

import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.Instrumentation;
import java.security.ProtectionDomain;

@Slf4j
public class AgentBasedInjector implements ClassFileTransformer {

    public static final AgentBasedInjector INSTANCE = new AgentBasedInjector();
    public static final String KEY_LOG_FILE_MANAGER_CLASS = "io/github/nickid2018/crypt/KeyLogFileManager";
    public static final String RANDOM_SUFFIX = "$$KeyLog$$" + Long.toHexString(System.nanoTime());

    public static void premain(String agentArgs, Instrumentation inst) {
        inst.addTransformer(INSTANCE);
    }

    private boolean transformed = false;

    // Injection Point searching algorithm:
    // 1. Search for classes that are not in the java package.
    // 2. For each class, check its ctor.
    // 3. If a ctor with (Ljavax/crypto/SecretKey;Ljava/security/PublicKey;[B)V is found, we concern it is ServerboundKeyPacket#<init>.
    @Override
    @SneakyThrows
    public byte[] transform(ClassLoader loader, String className, Class<?> classBeingRedefined, ProtectionDomain protectionDomain, byte[] classfileBuffer) {
        if (className.startsWith("java"))
            return null;
        if (transformed)
            return null;
        ClassNode classNode = new ClassNode();
        ClassReader reader = new ClassReader(classfileBuffer);
        reader.accept(classNode, 0);

        boolean isTargetClass = false;
        for (MethodNode methodNode : classNode.methods) {
            if (!methodNode.name.equals("<init>"))
                return null;
            if (methodNode.desc.equals("(Ljavax/crypto/SecretKey;Ljava/security/PublicKey;[B)V")) {
                isTargetClass = true;
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
                break;
            }
        }

        if (isTargetClass) {
            ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_FRAMES);
            classNode.accept(cw);

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
            injectNode.methods.removeIf(methodNode -> methodNode.name.startsWith("<"));
            injectNode.version = classNode.version;
            injectNode.accept(cw);

            transformed = true;
            log.info("AgentBasedInjector: Transformed class {} to inject key logging.", className);
            return cw.toByteArray();
        }
        return null;
    }
}
