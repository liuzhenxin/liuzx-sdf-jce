
# 开发规范指南
为保证代码质量、可维护性、安全性与可扩展性，请在开发过程中严格遵循以下规范。

## 一、用户工作目录

- **工作区路径**：`/Users/liuzhenxin/Office/Source/LiuZX/LCloud/PKI/liuzx-sdf-jce`

## 二、目录结构

```
liuzx-sdf-jce
└── src
    ├── main
    │   ├── java
    │   │   └── org
    │   │       └── liuzx
    │   │           └── jce
    │   │               ├── jna
    │   │               │   └── structure
    │   │               └── provider
    │   │                   ├── asymmetric
    │   │                   │   └── sm2
    │   │                   ├── digest
    │   │                   ├── random
    │   │                   ├── session
    │   │                   ├── symmetric
    │   │                   └── util
    │   └── resources
    └── test
        └── java
            └── org
                └── liuzx
                    └── jce
                        └── provider
                            └── test
```

## 三、技术栈要求

- **主框架**：JDK 25
- **构建工具**：Maven
- **核心依赖**：
  - `net.java.dev.jna:jna:5.10.0`
  - `com.google.code.gson:gson:2.9.0`
  - `org.junit.jupiter:junit-jupiter-api:5.8.2` (测试)
  - `org.junit.jupiter:junit-jupiter-engine:5.8.2` (测试)

## 四、代码风格规范

### 命名规范

| 类型       | 命名方式             | 示例                  |
|------------|----------------------|-----------------------|
| 类名       | UpperCamelCase       | `UserServiceImpl`     |
| 方法/变量  | lowerCamelCase       | `saveUser()`          |
| 常量       | UPPER_SNAKE_CASE     | `MAX_LOGIN_ATTEMPTS`  |

### 注释规范

- 所有类、方法、字段需添加注释。
- 注释使用中文。

### 类型命名规范（阿里巴巴风格）

| 后缀 | 用途说明                     | 示例         |
|------|------------------------------|--------------|
| DTO  | 数据传输对象                 | `UserDTO`    |
| DO   | 数据库实体对象               | `UserDO`     |
| BO   | 业务逻辑封装对象             | `UserBO`     |
| VO   | 视图展示对象                 | `UserVO`     |
| Query| 查询参数封装对象             | `UserQuery`  |

## 五、编码原则总结

| 原则       | 说明                                       |
|------------|--------------------------------------------|
| **SOLID**  | 高内聚、低耦合，增强可维护性与可扩展性     |
| **DRY**    | 避免重复代码，提高复用性                   |
| **KISS**   | 保持代码简洁易懂                           |
| **YAGNI**  | 不实现当前不需要的功能                     |
| **OWASP**  | 防范常见安全漏洞，如 SQL 注入、XSS 等      |

## 六、代码作者

- **作者**：liuzhenxin

## 七、其他说明

### 构建与打包

- 使用 `mvn clean package` 进行项目的构建与打包。
- 使用 `maven-jarsigner-plugin` 对生成的 JAR 文件进行签名，配置如下：
  - `keystore`: `${project.basedir}/keystore.jks`
  - `alias`: `dayou`
  - `storepass`: `123456`
  - `keypass`: `123456`

### 依赖信息总结

- **JNA**: 用于本地库的访问，版本为 5.10.0。
- **Gson**: 用于 JSON 的序列化和反序列化，版本为 2.9.0。
- **JUnit Jupiter**: 用于单元测试，版本为 5.8.2。
