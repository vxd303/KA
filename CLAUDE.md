# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## 项目概述

这是一个 Android 密钥认证测试应用,支持生成、保存、加载、解析和验证 Android 密钥和 ID 认证数据。该应用用于自测试,因此没有网络权限。

## 构建和测试命令

构建应用:
```bash
./gradlew assembleDebug          # 构建 debug 版本
./gradlew assembleRelease        # 构建 release 版本
```

安装应用:
```bash
./gradlew installDebug           # 安装 debug 版本到设备
```

清理构建:
```bash
./gradlew clean                  # 清理构建输出
```

## 项目结构

该项目包含两个模块:
- `app`: 主应用模块
- `stub`: 编译时依赖的存根库模块

### 核心包结构

- `io.github.vvb2060.keyattestation.attestation`: 认证核心逻辑
  - `Attestation.java`: 抽象基类,解析认证证书
  - `Asn1Attestation.java`: ASN.1 格式认证实现
  - `EatAttestation.java`: EAT(Entity Attestation Token)格式实现
  - `KnoxAttestation.java`: Samsung Knox 认证实现
  - `AuthorizationList.java`: 授权列表解析
  - `RevocationList.java`: 证书撤销列表验证

- `io.github.vvb2060.keyattestation.keystore`: Android KeyStore 交互
  - `KeyStoreManager.java`: KeyStore 管理器
  - `AndroidKeyStore.java`: 本地 KeyStore 实现
  - `RemoteProvisioning.java`: 远程配置支持

- `io.github.vvb2060.keyattestation.repository`: 数据仓库层
  - `AttestationRepository.java`: 认证数据仓库,处理证书生成和加载

- `io.github.vvb2060.keyattestation.home`: 主界面相关
  - `HomeViewModel.kt`: 主视图模型,管理认证状态和 StrongBox 选项
  - `HomeActivity.kt`: 主活动

## 技术要点

### 认证类型支持

应用支持三种认证格式:
1. ASN.1 格式 (OID: 1.3.6.1.4.1.11129.2.1.17)
2. EAT 格式 (OID: 1.3.6.1.4.1.11129.2.1.25)
3. Knox 格式 (OID: 1.3.6.1.4.1.236.11.3.23.7)

### 安全级别

- `KM_SECURITY_LEVEL_SOFTWARE = 0`: 软件实现
- `KM_SECURITY_LEVEL_TRUSTED_ENVIRONMENT = 1`: TEE 实现
- `KM_SECURITY_LEVEL_STRONG_BOX = 2`: StrongBox 实现

### 字节码转换

应用使用 ASM 进行字节码转换,通过 `ClassVisitorFactory` 重命名以 `_rename` 结尾的类。

### 依赖项

主要依赖:
- BouncyCastle (bcprov-jdk18on): 加密操作
- Guava: 通用工具
- CBOR (co.nstant.in:cbor): CBOR 格式解析
- Rikka 系列库: Material Design 组件
- Shizuku API: 系统级权限交互

## 开发注意事项

- 应用最低 SDK 版本为 24 (Android 7.0)
- 目标 SDK 版本为 35
- 使用 Java 21 和 Kotlin 2.0
- Release 构建启用混淆和资源压缩
- 应用没有网络权限,证书撤销数据嵌入在 APK 中
- 支持 Samsung 特定的 Key Attestation 功能(samsungkeystoreutils)

## 版本管理

版本代码通过 git commit 数量自动生成:
```bash
git rev-list --count HEAD
```

当前版本名: 1.8.4