package io.github.nickid2018.crypt;

import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.tree.*;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.Instrumentation;
import java.security.ProtectionDomain;
import java.util.HashSet;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Slf4j
@RequiredArgsConstructor
public class AgentBasedInjector implements ClassFileTransformer {

    public static void premain(String agentArgs, Instrumentation inst) {
        if (agentArgs != null && agentArgs.isEmpty()) {
            log.info("Detected key set");
            inst.addTransformer(new AgentBasedInjector(TransformProviders.getKeyForcingTransform(agentArgs)));
        } else {
            log.info("No key set");
            Set<ClassLoader> recordedLoaders = new HashSet<>();
            inst.addTransformer((classLoader, className, aClass, protectionDomain, bytes) -> {
                if (recordedLoaders.contains(classLoader)) return null;
                recordedLoaders.add(classLoader);
                log.info(classLoader.toString());
                try (BufferedReader in = new BufferedReader(new InputStreamReader(Objects.requireNonNull(classLoader.getResourceAsStream("version.json"))))) {
                    Optional<String> matchLine = in.lines().filter(str -> str.contains("protocol_version")).findFirst();
                    if (!matchLine.isPresent()) return null;
                    log.info("Match line for {}: {}", classLoader, matchLine.get());
                    Pattern extractPattern = Pattern.compile("\\s+\"protocol_version\": (\\d+),");
                    Matcher matcher = extractPattern.matcher(matchLine.get());
                    if (!matcher.find()) return null;
                    String version = matcher.group(1);
                    log.info("Checked Protocol Version = {}", version);
                    int protocol = Integer.parseInt(version);
                    if ((protocol > 777 && protocol < 10000) || protocol > 1073742166) { // >= 26.4-snapshot-5
                        inst.addTransformer(new AgentBasedInjector(TransformProviders.KEY_LOG_TRANSFORM_V2));
                    } else {
                        inst.addTransformer(new AgentBasedInjector(TransformProviders.KEY_LOG_TRANSFORM_V1));
                    }
                } catch (Exception ignored) {
                    log.info("Skip classloader {}", classLoader);
                }
                return null;
            });
        }
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
