# .NET 属性/接口静态契约核查（dnfile，仅元数据）

## 结论先行

- 当前工作区没有提供被调查的封存插件 DLL，也没有给出目标类型、指定接口和选定属性，因此对真实插件的结论只能保留为：**无法确认，也无法否认存在外部可调用的写访问器**。这是材料缺口，不是分析失败。
- 已交付一个只读元数据分析器 `tools/dnfile_contract_audit.py`。它只调用 `dnfile.dnPE` 解析 PE、CLR 头和元数据表，不加载程序集、不启动 CLR、不使用 `System.Reflection`、不执行 IL。
- 已准备两个带重载的小样本：
  - `samples/readonly-overloads.dll`：**没有**供外部接口调用的写访问器。
  - `samples/write-overloads.dll`：**确有**供外部接口调用的写访问器；隐式实现、显式 `MethodImpl` 覆盖和继承实现三条路径都可验证。
- 关键结论：DLL 中出现名为 `set_Value` 的方法，甚至与接口 setter 同名同签名，也不能单独证明写能力。必须继续核对 `InterfaceImpl`、`MethodSemantics`、`MethodImpl`、`MethodDef` 的属主和继承链。

组合核对表：

| 样本 | 类型 | 接口 | 路由 | 外部接口写访问器 | 结论 |
|---|---|---|---|---|---|
| `readonly-overloads.dll` | `ReadOnlyFacade` | `IReadOnlyValue` | none | 否 | 只读 |
| `readonly-overloads.dll` | `ReadOnlyFacade` | `IValueWriter` | none | 否 | 未实现接口 |
| `write-overloads.dll` | `WriteFacade` | `IValueWriter` | implicit | 是 | 有写访问器 |
| `write-overloads.dll` | `ExplicitWriteFacade` | `IValueWriter` | explicit | 是 | 有写访问器 |
| `write-overloads.dll` | `InheritedWriteFacade` | `IValueWriter` | inherited-implicit | 是 | 有写访问器 |

因此，两个样本中**只有 `write-overloads.dll` 确有供外部接口调用的写访问器**。

## 材料状态与边界

已核对材料：

- `dnfile` 0.18.0 源码与虚拟环境。
- 自建的两个确定性 PE/CLR 元数据样本。
- 未提供封存插件的路径、哈希、目标类型名、接口全名或属性名。

因此本报告分为两类结论：

1. **可直接验证的样本结论**：两个样本的每一行判定都有表项证据。
2. **保留的部分结论**：对真实封存插件，只能给出可执行的核查方法与待补输入，不能把样本结论外推成插件结论。

所有表项引用格式为 `表名#RID`，括号中给出元数据 token 和该行在文件中的偏移，例如 `MethodDef#9 (0x06000009, file 0x3D0)`。

## 静态契约判定规则

对选定的 `(类型, 接口, 属性)` 组合，分析器按以下顺序取证：

1. **接口属性关联**：接口 `TypeDef -> PropertyMap -> Property -> MethodSemantics`。
   - 只有 `MethodSemantics` 标志为 `msSetter` 的 `MethodDef` 才是接口的写访问器。
   - 若接口属性只有 getter，则无论实现类里有哪些 `set` 方法，经由该接口都没有写契约。
2. **接口实现关系**：目标类型自身或某个基类必须有 `InterfaceImpl` 指向指定接口。
   - 在自身：直接实现。
   - 在基类：继承实现，需要同时给出 `TypeDef.Extends` 链。
3. **显式覆盖**：`MethodImpl` 行的 `Class` 指向实现类，`MethodDeclaration` 指向接口 setter（`MethodDef` 或 `MemberRef`），`MethodBody` 指向实现方法。
   - `MethodBody` 可以是 `private`。显式接口实现仍然可由接口调用，这正是只按可访问性判断会误判的地方。
4. **隐式实现**：实现类或基类中存在与接口 setter 同名、签名相同、非静态、`public` 且 `virtual`、非 `abstract` 的方法。
   - 若该方法还能通过 `MethodSemantics` 回连到同名 `Property`，属性关联证据完整。
   - 若只有方法匹配、没有属性语义回连，则结论保留为部分：方法级映射存在，属性级关联缺失。
5. **同名无关方法**：名称相同或前缀相同，但没有 `MethodSemantics`，也不是目标接口的 `MethodImpl` body，并且所在类型没有实现该接口。
   - 必须把重载签名一起列出，否则 `set_Value(int32)` 与 `set_Value(string)` 会被混为一谈。
6. **可外部调用**：接口 setter 存在，且上述显式或隐式实现路径成立。显式私有实现也计入，因为外部调用点是接口方法而不是类方法。

## 样本一：只读外观，存在同名 set 方法

文件：`samples/readonly-overloads.dll`

结构：

- `MetadataSamples.Contracts.IReadOnlyValue.Value` 只有 getter。
- `MetadataSamples.Contracts.IValueWriter.Value` 有 getter 和 setter，用于提供对照契约。
- `MetadataSamples.ReadOnlyFacade` 是 `sealed`，只实现 `IReadOnlyValue`。
- 该类有三个同名重载：
  - `set_Value(int32)`：public、final、virtual、newslot、specialname，签名与 `IValueWriter` setter 完全相同，但仍未绑定到任何属性或接口。
  - `set_Value(string)`：public，static。
  - `set_Value(int32, string)`：private，实例方法。

核对表：

| 类型 | 接口 | 属性 | 接口 setter | 路由 | 外部写 | 结论 |
|---|---|---|---|---|---|---|
| `MetadataSamples.ReadOnlyFacade` | `IReadOnlyValue` | `Value` | 无 | none | 否 | 接口属性本身只读 |
| `MetadataSamples.ReadOnlyFacade` | `IValueWriter` | `Value` | `MethodSemantics#3 -> MethodDef#3` | none | 否 | 类未实现该接口 |

表项证据：

- 目标类型：`TypeDef#3 (0x02000003, file 0x320)`，`Flags=0x00100101`，包含 `tdSealed`。
- 只读接口属性关联：`PropertyMap#1 -> Property#1 -> MethodSemantics#1 -> MethodDef#1`，只有 `msGetter`，没有 `msSetter`。
- 实现类属性关联：`PropertyMap#3 -> Property#3 -> MethodSemantics#4 -> MethodDef#7`，只有 getter。
- 实现关系：只有 `InterfaceImpl#1`，`Class=TypeDef#3`，`Interface=TypeDef#1 (IReadOnlyValue)`；没有指向 `IValueWriter` 的 `InterfaceImpl`。
- 对照接口 setter：`PropertyMap#2 -> Property#2 -> MethodSemantics#3 -> MethodDef#3`。
- 同名方法：
  - `MethodDef#4`：`set_Value(int32)`，`Flags=0x09E6`（public、final、virtual、newslot、specialname），没有 `MethodSemantics`，没有 `MethodImpl` 映射。
  - `MethodDef#5`：`set_Value(string)`，`Flags=0x0096`（public、static、hidebysig），没有属性关联。
  - `MethodDef#6`：`set_Value(int32,string)`，`Flags=0x0081`，没有属性关联。
- 结论：`MethodDef#4` 虽然与 `IValueWriter.set_Value(int32)` 同名同签名，甚至具有与普通属性 setter 一致的 public virtual 标志，但它不是 `IValueWriter` 的 `MethodImpl` body，也没有 `MethodSemantics` 把它连到属性；同时 `ReadOnlyFacade` 根本没有实现 `IValueWriter`。所以名称和签名都不构成写契约。

对应自动输出：`samples/readonly-audit.md`、`samples/readonly-audit.json`。

## 样本二：确有外部接口写访问器

文件：`samples/write-overloads.dll`

结构：

- `WriteFacade`：sealed，隐式实现 `IValueWriter`。
- `ExplicitWriteFacade`：sealed，通过 `MethodImpl` 显式覆盖接口 setter，实现体是 private 方法。
- `InheritedWriteFacade`：sealed，自身没有实现方法，继承 `BaseWriter` 的公开属性实现。
- 三个类型都带有同名但无关的 `set_Value(string)` 重载；`WriteFacade` 另有 `set_Value(int32,bool)` 重载。

核对表：

| 类型 | 接口 | 属性 | 接口 setter | 路由 | 实现 MethodDef | 属性关联 | 外部写 | 结论 |
|---|---|---|---|---|---|---|---|---|
| `InheritedWriteFacade` | `IValueWriter` | `Value` | `MethodSemantics#3 -> MethodDef#3` | inherited-implicit | `MethodDef#5` | 基类 `PropertyMap#3 -> Property#3 -> MethodSemantics#5` | 是 | 外部可写 |
| `WriteFacade` | `IValueWriter` | `Value` | `MethodSemantics#3 -> MethodDef#3` | implicit | `MethodDef#9` | `PropertyMap#5 -> Property#4 -> MethodSemantics#7` | 是 | 外部可写 |
| `ExplicitWriteFacade` | `IValueWriter` | `Value` | `MethodSemantics#3 -> MethodDef#3` | explicit | `MethodDef#10` | `MethodImpl#1` 直接映射，不要求类 `Property` 行 | 是 | 外部可写 |

公共接口契约证据：

- 接口类型：`TypeDef#2 (0x02000002, file 0x31A)`。
- 接口属性：`PropertyMap#2 -> Property#2`。
- 接口 getter：`MethodSemantics#2 -> MethodDef#2`。
- 接口 setter：`MethodSemantics#3 -> MethodDef#3 (0x06000003, file 0x37C)`。
- 接口 setter 签名：`instance void (int32)`。

### 路径 A：隐式实现

对象：`MetadataSamples.WriteFacade`，`TypeDef#5 (0x02000005, file 0x344)`，sealed。

- `InterfaceImpl#4`：`Class=TypeDef#5`，`Interface=TypeDef#2 (IValueWriter)`。
- 类属性：`PropertyMap#5 -> Property#4 -> MethodSemantics#7 -> MethodDef#9`。
- `MethodDef#9`：`set_Value(int32)`，`Flags=0x09E6`，即 public、final、virtual、hidebysig、newslot、specialname。
- 同名无关重载：
  - `MethodDef#6`：`set_Value(string)`，public static，签名不同，无映射。
  - `MethodDef#7`：`set_Value(int32,bool)`，private 实例，签名不同，无映射。
- 结论：接口 setter、属性关联、可见且可虚分派的方法三者齐全，外部写成立。

### 路径 B：显式覆盖

对象：`MetadataSamples.ExplicitWriteFacade`，`TypeDef#6 (0x02000006, file 0x352)`，sealed。

- `InterfaceImpl#6`：`Class=TypeDef#6`，`Interface=TypeDef#2 (IValueWriter)`。
- `MethodImpl#1 (0x19000001, file 0x48C)`：
  - `Class=TypeDef#6`
  - `MethodBody=MethodDef#10`
  - `MethodDeclaration=MemberRef#1 (0x0A000001, file 0x420)`
- `MemberRef#1`：`Class=TypeDef#2 (IValueWriter)`，`Name=set_Value`，签名 `instance void (int32)`。
- `MethodDef#10`：`set_Value(int32)`，`Flags=0x09E1`，即 private、final、virtual、hidebysig、newslot、specialname。
- 同名无关重载：`MethodDef#11`，`set_Value(string)`，public static，无映射。
- 结论：实现体虽然是 private，不能从类外部直接调用，但 `MethodImpl#1` 把它绑定到接口 setter；外部通过 `IValueWriter.set_Value` 调用时走的就是 `MethodDef#10`。因此外部写成立。

### 路径 C：继承实现

对象：`MetadataSamples.InheritedWriteFacade`，`TypeDef#4 (0x02000004, file 0x336)`，sealed。

- 继承链：`TypeDef#4.Extends -> TypeDef#3 (BaseWriter)`。
- 目标类型自身没有 `InterfaceImpl`、没有 `PropertyMap` 写属性、没有方法。
- `InterfaceImpl#2` 位于基类：`Class=TypeDef#3 (BaseWriter)`，`Interface=TypeDef#2 (IValueWriter)`。
- 基类属性：`PropertyMap#3 -> Property#3 -> MethodSemantics#5 -> MethodDef#5`。
- `MethodDef#5`：`set_Value(int32)`，`Flags=0x09E6`，public、final、virtual、newslot、specialname。
- 结论：外部对 `InheritedWriteFacade` 的接口调用会分派到基类 `MethodDef#5`；继承实现成立。

对应自动输出：`samples/write-audit.md`、`samples/write-audit.json`。

## 四类证据如何区分

| 证据类别 | 必须命中的表项 | 本报告中的例子 |
|---|---|---|
| 属性关联 | `PropertyMap -> Property -> MethodSemantics(msSetter) -> MethodDef` | `WriteFacade`: `PropertyMap#5 -> Property#4 -> MethodSemantics#7 -> MethodDef#9` |
| 显式覆盖 | `MethodImpl(Class, MethodBody, MethodDeclaration)`，必要时经 `MemberRef` | `ExplicitWriteFacade`: `MethodImpl#1 -> MemberRef#1 -> MethodDef#10` |
| 继承实现 | `TypeDef.Extends` 链 + 基类 `InterfaceImpl` + 基类 `MethodSemantics` | `InheritedWriteFacade -> BaseWriter`，`InterfaceImpl#2`，`MethodSemantics#5 -> MethodDef#5` |
| 同名无关方法 | 有 `MethodDef`，但无对应 `MethodSemantics`、无目标接口 `MethodImpl`、类型未实现接口 | `ReadOnlyFacade`: `MethodDef#4/#5/#6` |

## 对真实封存 DLL 的执行方式

补到 DLL 路径、目标类型和接口后执行：

```bash
.venv/bin/python tools/dnfile_contract_audit.py /path/to/sealed-plugin.dll \
    --type Plugin.Namespace.SealedType \
    --interface Plugin.Contracts.IReadOnlyThing \
    --property Value \
    --json-out plugin-audit.json \
    --markdown-out plugin-audit.md
```

若接口名不唯一，可重复 `--interface`；`--type` 支持全名、短名和 glob。若只想枚举某个类型实现的所有接口及其属性，可省略 `--interface` 和 `--property`。

输出中的每一行都会包含：

- 接口属性关联的 `PropertyMap`、`Property`、`MethodSemantics`、`MethodDef`。
- 实现类的 `InterfaceImpl`；若是继承，给出基类及其表项。
- 显式覆盖的 `MethodImpl`、`MemberRef` 和 body `MethodDef`。
- 同名重载的签名、标志和“是否与接口 setter 同签名”。
- 结论：`YES`、`NO` 或 `PARTIAL`。

## 保留的部分结论与限制

- **缺少封存 DLL**：当前不能对真实插件给出 YES/NO；只能确认审计路径和样本行为。
- **外部接口**：若指定接口是 `TypeRef`，其属性/访问器行不在本模块，结论保留为 `PARTIAL`。本工具不会从其他程序集补全。
- **泛型接口**：`TypeSpec` 可能无法静态还原到唯一的 `TypeDef`；结论保留为 `PARTIAL`。
- **运行时分派**：本工具证明的是元数据静态契约，不证明运行时一定成功加载；例如缺失程序集、类型加载失败、显式布局冲突等不在静态表项范围内。
- **自定义特性**：不解释 `[Obsolete]`、`[EditorBrowsable]`、条件编译等对可见性的影响；这些不改变 CLI 接口分派表项。
- **损坏元数据**：dnfile 能保留部分表；若某行缺失或索引越界，报告会保留 `PARTIAL` 和原因，不会用名称猜测补齐。
- **同名同签名仍可能无关**：只有在 `InterfaceImpl` 存在且 `MethodImpl` 或隐式匹配成立时，方法才构成接口实现。`ReadOnlyFacade` 的 `MethodDef#4` 是反例。

## 复现

```bash
.venv/bin/python tools/make_metadata_samples.py
.venv/bin/python tools/dnfile_contract_audit.py samples/readonly-overloads.dll \
    --type MetadataSamples.ReadOnlyFacade \
    --interface MetadataSamples.Contracts.IReadOnlyValue \
    --interface MetadataSamples.Contracts.IValueWriter \
    --property Value
.venv/bin/python tools/dnfile_contract_audit.py samples/write-overloads.dll \
    --type MetadataSamples.WriteFacade \
    --type MetadataSamples.ExplicitWriteFacade \
    --type MetadataSamples.InheritedWriteFacade \
    --interface MetadataSamples.Contracts.IValueWriter \
    --property Value
.venv/bin/pytest -q tests/test_contract_audit.py
```

样本生成器是确定性的：不依赖 C# 编译器、不依赖 CLR、不联网，直接写 PE 头、CLI 头、`#~`、`#Strings`、`#Blob`、`#GUID` 和所需元数据表。
