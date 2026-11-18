package io.github.nickid2018.crypt;

import org.objectweb.asm.tree.ClassNode;

import java.util.Set;

public interface TransformProvider {

    byte[] transform(ClassNode classNode, String className, Set<String> constantPool) throws Exception;
}
