# 逆向参考资料

这些文件只用于开发和校验，不参与 `Keep.App` 的构建。

## cssxn/UserChoiceLatestHash

- 来源：<https://github.com/cssxn/UserChoiceLatestHash>
- 许可：MIT
- 用途：Windows 11 24H2+ 的 `UserChoiceLatest` 哈希（`7D60` 流水线）公开逆向实现。
  `src/Keep.Core/Associations/UserChoiceLatestTables.cs` 由
  `tools/gen_latest_tables.py` 从 `UserChoiceLatestHashTables.inc` 生成；
  `src/Keep.Core/Associations/UserChoiceLatestHash.cs` 是其托管移植。

## 其他

- `src/Keep.Core/Associations/UserChoiceHash.cs` 的旧版哈希（V1）依据的是
  Mozilla Firefox `browser/components/shell/WindowsUserChoice.cpp`（MPL-2.0）中
  同样公开的算法说明，并未复制其代码。

## 原型

- `tools/proto/` 是验证哈希算法用的 Python 原型，可直接读取本机注册表复算
  `UserChoice` / `UserChoiceLatest`，用于反向核对。
