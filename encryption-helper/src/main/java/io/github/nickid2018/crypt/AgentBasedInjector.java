package io.github.nickid2018.crypt;

import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.tree.*;

import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.Instrumentation;
import java.security.ProtectionDomain;

@Slf4j
@RequiredArgsConstructor
public class AgentBasedInjector implements ClassFileTransformer {

    public static void premain(String agentArgs, Instrumentation inst) {
        inst.addTransformer(new AgentBasedInjector(
                agentArgs == null
                        ? TransformProviders.KEY_LOG_TRANSFORM
                        : TransformProviders.getKeyForcingTransform(agentArgs)
        ));
    }

    private final TransformProvider transformProvider;
    private boolean injected = false;

    @Override
    @SneakyThrows
    public byte[] transform(ClassLoader loader, String className, Class<?> classBeingRedefined, ProtectionDomain protectionDomain, byte[] classfileBuffer) {
        if (className.startsWith("java"))
            return null;
        if (injected)
            return null;

        ClassNode classNode = new ClassNode();
        ClassReader reader = new ClassReader(classfileBuffer);
        reader.accept(classNode, 0);

        byte[] transformed = transformProvider.transform(classNode, className);
        if (transformed != null) {
            injected = true;
            log.info("Transformed class {}", className);
        }
        return transformed;
    }
}
