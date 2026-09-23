package org.liuzx.jce.api;

import org.junit.jupiter.api.Test;

import java.io.File;
import java.lang.reflect.Constructor;
import java.lang.reflect.GenericArrayType;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.lang.reflect.TypeVariable;
import java.lang.reflect.WildcardType;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 反射审计：{@code org.liuzx.jce.api} 的公开签名不得泄漏 JNA / 文件系统 / 私钥类型。
 *
 * <p>不依赖任何硬件，可在普通 {@code mvn test} 下运行。</p>
 */
class ApiSurfaceAuditTest {

    private static final String PACKAGE_NAME = "org.liuzx.jce.api";

    private static final List<String> FORBIDDEN_TYPE_NAME_PREFIXES = Arrays.asList(
            "com.sun.jna",
            "org.liuzx.jce.jna");

    private static final List<String> FORBIDDEN_EXACT_TYPES = Arrays.asList(
            "java.nio.file.Path",
            "java.io.File",
            "java.security.PrivateKey");

    @Test
    void publicSurfaceLeaksNoJnaTypes() throws Exception {
        List<Class<?>> publicTypes = loadPublicTypes();
        assertTrue(publicTypes.size() >= 5,
                "expected at least 5 public types in " + PACKAGE_NAME + ", found " + publicTypes.size());

        List<String> violations = new ArrayList<String>();
        Set<Type> visited = newIdentitySet();
        for (Class<?> type : publicTypes) {
            for (Method method : type.getMethods()) {
                checkType(violations, visited, type.getSimpleName() + "#" + method.getName(),
                        method.getGenericReturnType());
                for (Type parameterType : method.getGenericParameterTypes()) {
                    checkType(violations, visited, type.getSimpleName() + "#" + method.getName(), parameterType);
                }
            }
            for (Constructor<?> constructor : type.getConstructors()) {
                for (Type parameterType : constructor.getGenericParameterTypes()) {
                    checkType(violations, visited, type.getSimpleName() + "#<init>", parameterType);
                }
            }
        }
        assertTrue(violations.isEmpty(),
                "forbidden types leaked into org.liuzx.jce.api public surface:\n"
                        + String.join("\n", violations));
    }

    private static Set<Type> newIdentitySet() {
        return Collections.newSetFromMap(new java.util.IdentityHashMap<Type, Boolean>());
    }

    private static void checkType(List<String> violations, Set<Type> visited, String location, Type type) {
        if (type == null || !visited.add(type)) {
            return;
        }
        if (type instanceof Class) {
            Class<?> clazz = (Class<?>) type;
            if (clazz.isArray()) {
                checkType(violations, visited, location, clazz.getComponentType());
                return;
            }
            if (clazz.isPrimitive() || clazz == Void.class) {
                return;
            }
            String name = clazz.getName();
            for (String prefix : FORBIDDEN_TYPE_NAME_PREFIXES) {
                if (name.equals(prefix) || name.startsWith(prefix + ".")) {
                    violations.add(location + " -> " + name);
                    return;
                }
            }
            if (FORBIDDEN_EXACT_TYPES.contains(name)) {
                violations.add(location + " -> " + name);
                return;
            }
            if (clazz.getSimpleName().contains("Pointer")) {
                violations.add(location + " -> " + name + " (Pointer-like type)");
            }
        } else if (type instanceof ParameterizedType) {
            ParameterizedType parameterized = (ParameterizedType) type;
            checkType(violations, visited, location, parameterized.getRawType());
            for (Type argument : parameterized.getActualTypeArguments()) {
                checkType(violations, visited, location, argument);
            }
        } else if (type instanceof GenericArrayType) {
            checkType(violations, visited, location, ((GenericArrayType) type).getGenericComponentType());
        } else if (type instanceof TypeVariable) {
            for (Type bound : ((TypeVariable<?>) type).getBounds()) {
                checkType(violations, visited, location, bound);
            }
        } else if (type instanceof WildcardType) {
            WildcardType wildcard = (WildcardType) type;
            for (Type bound : wildcard.getUpperBounds()) {
                checkType(violations, visited, location, bound);
            }
            for (Type bound : wildcard.getLowerBounds()) {
                checkType(violations, visited, location, bound);
            }
        }
    }

    private static List<Class<?>> loadPublicTypes() throws Exception {
        String resourcePath = PACKAGE_NAME.replace('.', '/');
        ClassLoader classLoader = ApiSurfaceAuditTest.class.getClassLoader();
        // Always resolve from the production classes root. Looking up the package as a resource
        // can resolve to target/test-classes first, whose classes are not the public surface.
        URL codeSource = SdfErrorCategory.class.getProtectionDomain().getCodeSource().getLocation();
        File directory = new File(new File(codeSource.toURI()), resourcePath);
        List<Class<?>> publicTypes = new ArrayList<Class<?>>();
        File[] classFiles = directory.listFiles();
        if (classFiles == null) {
            return publicTypes;
        }
        for (File classFile : classFiles) {
            String fileName = classFile.getName();
            if (!fileName.endsWith(".class") || fileName.contains("$")) {
                continue;
            }
            String className = PACKAGE_NAME + "."
                    + fileName.substring(0, fileName.length() - ".class".length());
            Class<?> clazz = Class.forName(className, false, classLoader);
            if (Modifier.isPublic(clazz.getModifiers())) {
                publicTypes.add(clazz);
            }
        }
        Collections.sort(publicTypes, (a, b) -> a.getName().compareTo(b.getName()));
        return publicTypes;
    }
}
