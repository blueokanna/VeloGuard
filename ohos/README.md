# CatClash HarmonyOS NEXT 构建指南

## 环境要求

1. **DevEco Studio 5.0** 或更高版本
2. **HarmonyOS SDK API 12** 或更高版本
3. **Flutter OHOS 支持** (flutter_ohos)

## 项目结构

```
ohos/
├── AppScope/           # 应用级配置
│   ├── app.json5       # 应用配置
│   └── resources/      # 应用级资源
├── entry/              # 主入口模块
│   ├── src/main/
│   │   ├── ets/
│   │   │   ├── entryability/   # 主 Ability
│   │   │   ├── vpnextension/   # VPN 扩展
│   │   │   ├── plugins/        # Flutter 插件
│   │   │   └── pages/          # 页面
│   │   ├── resources/          # 模块资源
│   │   └── module.json5        # 模块配置
│   └── oh-package.json5
├── flutter_module/     # Flutter 模块
├── har/                # HAR 输出目录
│   ├── flutter.har     # Flutter 引擎 HAR
│   └── flutter_module.har  # Flutter 模块 HAR
└── build-profile.json5 # 构建配置
```

## 构建步骤

### 1. 配置 Flutter OHOS 环境

```bash
# 确保 Flutter 支持 OHOS
flutter config --enable-ohos

# 检查环境
flutter doctor
```

### 2. 构建 Flutter HAR

```bash
# 在项目根目录执行
flutter build har --release
```

这将生成：
- `ohos/har/flutter.har` - Flutter 引擎
- `ohos/har/flutter_module.har` - Flutter 应用模块

### 3. 使用 DevEco Studio 构建

1. 打开 DevEco Studio
2. 选择 `File > Open` 打开 `ohos` 目录
3. 等待项目同步完成
4. 选择 `Build > Build Hap(s)/APP(s) > Build Hap(s)`

### 4. 签名配置

在 `build-profile.json5` 中配置签名：

```json5
{
  "app": {
    "signingConfigs": [
      {
        "name": "default",
        "type": "HarmonyOS",
        "material": {
          "certpath": "path/to/certificate.cer",
          "storePassword": "your_password",
          "keyAlias": "your_alias",
          "keyPassword": "your_key_password",
          "profile": "path/to/provision.p7b",
          "signAlg": "SHA256withECDSA",
          "storeFile": "path/to/keystore.p12"
        }
      }
    ]
  }
}
```

## VPN 权限说明

CatClash 需要以下权限：

| 权限 | 说明 |
|------|------|
| `ohos.permission.INTERNET` | 网络访问 |
| `ohos.permission.GET_NETWORK_INFO` | 获取网络信息 |
| `ohos.permission.SET_NETWORK_INFO` | 设置网络信息 |
| `ohos.permission.MANAGE_VPN` | VPN 管理 |
| `ohos.permission.KEEP_BACKGROUND_RUNNING` | 后台运行 |

## 注意事项

1. **VPN 权限**: HarmonyOS NEXT 的 VPN 权限需要特殊申请，请联系华为开发者支持
2. **Rust 支持**: 需要配置 OHOS NDK 进行 Rust 交叉编译
3. **测试设备**: 建议使用 HarmonyOS NEXT 真机测试

## 常见问题

### Q: HAR 文件找不到？
A: 确保先执行 `flutter build har` 生成 HAR 文件

### Q: VPN 无法启动？
A: 检查是否已申请 VPN 权限，并在设备上授权

### Q: 编译错误？
A: 确保 DevEco Studio 和 SDK 版本匹配

## 参考链接

- [Flutter OHOS 官方文档](https://developer.huawei.com/consumer/cn/doc/harmonyos-guides-V5/flutter-overview-V5)
- [HarmonyOS VPN 开发指南](https://developer.huawei.com/consumer/cn/doc/harmonyos-guides-V5/vpn-overview-V5)
- [DevEco Studio 下载](https://developer.huawei.com/consumer/cn/deveco-studio/)
