package io.github.nickid2018.crypt;

import org.objectweb.asm.tree.ClassNode;

public interface TransformProvider {

    byte[] transform(ClassNode classNode, String className) throws Exception;
}
