# ESE 复合次索引的归属链路分析（ese-index-provenance）

**对象**：`dissect.esedb`（本仓库 `task/400`，提交 `ea5efb8`）
**问题**：ESE 次索引的"命中"只说明找到了一条索引项；取证报告必须进一步说明它最终指向哪条主记录，以及这个结论的证据边界。
**方法**：阅读 `index.py` / `cursor.py` / `btree.py` / `page.py` / `record.py` / `table.py` / `lcmapstring.py`，并在仓库自带的 10 个数据库样本上实测（共 96 张表、152 个索引、60 个次索引、69 084 条次索引项）。

---

## 0. 结论摘要

1. **链路是两跳，且代码里的命名是反的**。`Cursor._primary` 是**本索引自己的 B 树**，`Cursor._secondary` 是**表的主记录树**（`cursor.py:30`）。次索引叶子节点的 `data` 是书签（编码后的主键），`_node()` 用它在表树里做精确查找，然后把得到的节点包装成 `Record`（`cursor.py:41-59`）。
2. **书签才是归属证据，键不是**。键只是"可见值的有损投影"，不可逆、可碰撞；书签 + 页号 + 节点号 + 页头 `objidFDP` 才构成可复核的身份。
3. **列顺序决定了能表达哪些查询**，但实现只支持**前缀**：`make_key` 在第一个缺失列处 `break`（`index.py:117-118`）。中间列缺失不会报错，会静默生成更短的键。
4. **文本等价规则是"归一化"而不是"相等"**：大小写/全半角/假名类型被折叠（`LCMapFlags=0x30401`），因此 `search(Name="stats")` 会返回 `Name="Stats"` 的记录；键不能反推出被查的字符串。ASP/西文路径还有 `str.upper().encode()`（UTF-8）而非列声明代码页的缺陷，本样本集属**潜在**缺陷（无触发样本）。
5. **截断无标记**：文本/二进制段按 `KeyMost` 硬切（`index.py:128-129`、`_encode_text:278`、`_encode_binary`），两个不同可见值可以共享同一键。本样本中有 3 个索引的键正好等于 `KeyMost`。
6. **可见值相同 ≠ 同一记录来源**。同表内可用书签区分；跨表不可用 `Record.__eq__` 区分（它只比节点键字节，实测 `MSysObjects` 与 `MSysObjectsShadow` 的 112 个键完全相同且 `==` 为真，但 `hash` 不同）；"同一键的多个成员互为版本"这一结论**没有证据**。
7. **索引里没有 = 没有记录**是错的。`RootObjects` 只有 5 条索引项对应 112 条记录，其余 107 条记录首列为 NULL 而不入索引；`search(RootFlag=None)` 抛 `KeyNotFoundError`。

---

## 1. 实测的完整归属链路

### 1.1 代码链路

```
Table.index(name) / table.indexes[i]            table.py:134-146, 237-240
  └ Index(table, catalog_record)                index.py:32-42
      ├ columns ← KeyFldIDs 每 4 字节取后 2 字节  index.py:56-70
      └ root    ← catalog 记录 ColtypOrPgnoFDP  index.py:51-54
  └ Cursor(index)                               cursor.py:24-30
      ├ _primary   = BTree(esedb, index.root)          ← 次索引自己的树
      └ _secondary = BTree(esedb, table.root)          ← 表的主记录树（仅次索引时非空）
  └ Cursor.search(**kwargs)                     cursor.py:67-91
      ├ key = index.make_key(kwargs)            index.py:107-130
      ├ _primary.search(key, exact=True)        btree.py:105-132
      └ _record() → _node() → Record(table, node)   cursor.py:41-59
            └ _secondary.search(node.data, exact=True)   ← 书签回查
```

> 命名陷阱：`_primary` / `_secondary` 这两个名字描述的是"**索引树 / 表树**"，不是"主索引 / 次索引"。写工具时若按字面理解会把回查方向搞反。

### 1.2 一个完整的实测量化样例

样本：`tests/_data/index.edb.gz`，表 `MSysObjects`，索引 `Name`（`ObjidTable, Type, Name`）。
查询：`Name="Stats"`。

| 步骤 | 实测值 |
|---|---|
| 生成的查询键 | `7f 80000002 7f 800002 7f "STATS" 00` = `7f800000027f80027f535441545300` |
| 命中索引项位置 | 逻辑页 15、tag 24、页内偏移 `0x291`、长度 22、标志 `TAG_FLAG.Version\|Compressed` |
| 该索引项文件偏移 | `(15+1)*4096 + 0x28 + 0x291 = 0x102b9`（公式见 §5.3） |
| 键的前缀/后缀压缩 | `key_prefix = 7f800000027f8002 7f 53`，`key_suffix = "TATS\0"` → `Node.key` 为二者拼接 |
| 书签（叶子 `data`） | `7f800000027f80027f80000081` → 即主键 `(ObjidTable=2, Type=2, Id=129)` |
| 索引页归属 | 页头 `objidFDP=4` = 目录表 `Type=3` 的 `Id=4`（索引 "Name"）；该索引树根页为 7 |
| 表根 | 逻辑页 4，页头 `objidFDP=2` = 目录表 `Type=1` 的 `Id=2`（MSysObjects） |
| 回查结果 | 表树节点：逻辑页 13、tag 15、文件偏移 `0xe2f7` |
| 记录内容 | `Id=129, Name='Stats', Type=2, ObjidTable=2` |
| 等价性反证 | `make_key(Name="stats")` 与 `make_key(Name="STATS")` 得到**同一键** |

**注意**：索引根页号（7）与索引页 `objidFDP`（4）是**两个不同的数**。`Index.root` 用的是目录字段 `ColtypOrPgnoFDP`（页号），`objidFDP` 指向目录里的索引对象 Id（对象号）。两者量纲不同：把 `objidFDP` 当页号去 `esedb.page()` 会读到完全无关的页，把 `ColtypOrPgnoFDP` 当对象 Id 去目录里查会查不到记录。

### 1.3 书签的两种形态（必须逐表判定）

| 表类型 | 书签形态 | 实测样本 |
|---|---|---|
| 有 `IDBFLAG.Primary` 索引 | 编码后的**主键**（多段） | `MSysObjects.Name`：13 字节 `7f800000027f80027f80000081` |
| 无 Primary 标志（UAL 类） | **4 字节大端记录号** | `Current.mdb` 的 `CLIENTS`/`DNS`/`ROLE_ACCESS`：`00000001`、`00000013` 等 |

`Current.mdb` 中 `CLIENTS`、`DNS`、`ROLE_ACCESS`、`VIRTUALMACHINES` 四张表**没有** `IDBFLAG.Primary` 索引：`table.primary_index` 为 `None`，`table.cursor()` 返回 `None`，`table.search(...)` 抛 `AttributeError: 'NoneType' object has no attribute 'search'`，但三张表的次索引 `index.search(...)` / `Cursor` 都正常工作。所以**不能假设"书签一定等于编码主键"**，也不能假设"表一定有主索引"。

---

## 2. 索引键编码：实际做了什么

`encode_key`（`index.py:140-200`）对每个段先写 1 字节段前缀，再写载荷：

| 类型 | 编码 | 实测键片段 |
|---|---|---|
| NULL | `0x00`（`bPrefixNull`） | `make_key(RootFlag=None) = 00` |
| Bit | `0x7f` + `FF`/`00` | `7f00`（False） |
| Short/Long/Currency/LongLong | `0x7f` + 大端，最高位取反 | `Long=-13371337 → 7f7f33f837` |
| IEEESingle/Double、DateTime | `0x7f` + 位翻转 | 见 `test_index.py` |
| UnsignedLong/UnsignedShort | `0x7f` + 大端原值 | — |
| GUID | `0x7f` + `bytes_le` 重排 | `3f360af1-… → 7f0dacf295c2a19af2dc466667f10a363f` |
| 定长二进制 | `0x7f` + 原字节（超长直接切） | — |
| 变长二进制 | `0x7f` + 8 字节块 + 块头 | `…0961 7269 2064 6174 6108` |
| 空串/空二进制 | `0x40`（`bPrefixZeroLength`） | — |
| 西文/ASCII 文本 | `0x7f` + `str.upper()` + `0x00` | `"Simple ASCII text" → 7f53494d504c45…54585400` |
| Unicode 文本 | `0x7f` + LCMapString 排序键 | `"Simple Unicode text 🦊" → 7f0e91…` |

未被使用的常量：`bPrefixNullHigh (0xC0)`、`bSentinel (0xFF)` 声明后从未使用（`index.py:135-137`）。若后续实现对 0xFF 语义有依赖，当前代码不匹配。

另有两条"无载荷"路径：`JET_coltyp.Nil` 与 `JET_coltyp.SLV` 不落入任何分支，`encode_key` 只返回前缀字节 `7f`，即**任何值都编成同一个键**。本样本集中未出现这两类列参与索引，属未验证风险。

---

## 3. 列顺序如何影响命中与扫描范围

### 3.1 列顺序 = 段顺序，前缀性质是硬约束

`column_ids` 按 `KeyFldIDs` 的**字节顺序**解析（`index.py:56-65`），`make_key` 按此顺序逐段编码（`index.py:116-126`）。

- 只给出前缀列 → 键更短；`search(exact=True)` 必然失败（键不可能等于完整键）。
  - 实测：`Name` 索引 `search(ObjidTable=2)` → `KeyNotFoundError: b'\x7f\x80\x00\x00\x02'`；`search(ObjidTable=2, Type=1)` 同样失败。
- **跳过中间列不会报错**：`make_key({ObjidTable, Name})` 在 `Type` 处 `break`，结果为 `7f80000002`（等于只查 `ObjidTable`）。查询被静默收窄。
- 只给非首列 → 键为空串 `b''`。`seek()` 会落到树的最左节点（实测落到 `MSysObjects`），`search()` 抛 `KeyNotFoundError`。**空键不会报"参数非法"，只会给出一个看似正常的错误位置。**
- 完全无关的列（`Id`）同理：`make_key(Id=6) = b''`，`seek(Id=6)` 静默落到第一条记录。

### 3.2 扫描范围必须由调用方自己加边界

`BTree.search(key, exact=False)` 的语义是**下界（ceil）**：返回第一个 `node.key >= key` 的节点（`btree.py:135-166`）。因此：

- `seek(prefix)` 是"从该前缀处开始"的正确起点；
- 但**没有任何上界 API**。实测：`seek(ObjidTable=2, Type=1)` 之后连续 `next()`，共走过 112 条（整棵索引），其中只有 1 条真正匹配前缀。
- 正确用法是逐条比较 `node.key.startswith(prefix)`（Python 的 bytes 比较与 ESE 键比较一致，`btree.py:150-151` 有明确注释）。实测按此边界走 `ObjidTable=8, Type=3` 得到 19 条，与全量扫描一致。
- 前缀不存在时，`seek` 会落到下一个组的键上且不报错：`seek(ObjidTable=4)` 落到 `ObjidTable=6` 的 `MSysObjids`（目录中没有 4、5 号对象）。**因此"seek 到某值"不能作为"该值存在"的证据，必须检查前缀。**

### 3.3 分支页键是非包含上界

`find_node` 在分支页遇到精确相等时，会移到**下一个**节点（`btree.py:154-160`）；注释说明分支键是"非包含上界"。实测页 7 的两个分支：节点 0 键 `…7f495855` 指向子页 15，而子页 15 实际最大键为 `…7f49585348…`（更小），节点 1（空键）指向子页 16。取证时若把分支键当作"子页最小键"会算错范围。

### 3.4 列顺序还会改变"后列是否参与"

`make_key` 用同一个 `KeyMost` 预算顺序扣减（`index.py:114-126`）：前面的段越长，后面的段越可能被整个挤掉。实测（合成）：`CLIENTS` 的 `(AuthenticatedUserName, RoleGuid, TenantId)`，当用户名长 300 字符时，键长 255 且**不包含任何 RoleGuid/TenantId 字节**，仅 GUID 不同的两条记录得到**完全相同**的键。列顺序决定了哪一列"有权被索引"。

### 3.5 `find_index` 与 `search` 脱节

`Table.find_index` 用"前缀匹配列数"挑索引（`table.py:148-168`），但 `Table.search`/`Index.search` 从不调用它。实测 `find_index(["Address"])` 返回 `Address_index`，而真正执行 `table.search` 走的是 `table.cursor()`（需要主索引），在 UAL 表上直接 `AttributeError`。报告里若写"按某索引查询"，必须以实际传入的 `Index` 对象为准，不能以 `find_index` 的返回为准。

---

## 4. 文本等价规则如何影响命中与扫描范围

### 4.1 Unicode 路径：有损排序键（大小写/宽窄/假名折叠）

`_encode_text`（`index.py:261-280`）对非 ASCII/西文列调用 `map_string`（`lcmapstring.py:85-209`），生成 WC 排序键。样本中 149/152 个索引的 `LCMapFlags = 0x30401`（`LCMAP_SORTKEY | NORM_IGNORECASE | NORM_IGNOREWIDTH | NORM_IGNOREKANATYPE`）。

实测后果：

| 查询 | 结果 |
|---|---|
| `search(ObjidTable=2, Type=2, Name="stats")` | 返回记录，其 `Name='Stats'`（**与查询串不等**） |
| `make_key("Stats")` vs `make_key("stats")` vs `make_key("STATS")` | 完全相同的键 |
| `map_string("Straße İi", 0x401, locale)`，locale 取 `en-US/tr-TR/de-DE/ja-JP` | 四个结果完全相同 → **locale 被忽略** |
| `"AB"` / `"A­B"`（软连字符） | 相同键（`UNSORTABLE` 字符被丢弃） |
| `"A-B"` | `NotImplementedError(SCRIPT.PUNCTUATION)` |

含义：**键不能反解出"用户查的是哪个字符串"**；同一键可能来自多个可见值；而某些可见值（含数字、部分标点）**根本无法生成键**，也就无法通过"值查询"命中——即使索引项确实存在。

### 4.2 西文/ASCII 路径：`str.upper()` + UTF-8，而非列声明的代码页

`index.py:267-272`：

```python
if len(value) + 1 > max_size:
    value = value[:max_size]
key += value.upper().encode()      # 默认 UTF-8
key.append(0)
```

实测：

| 值 | 本实现键载荷 | 列声明代码页（cp1252）应为 |
|---|---|---|
| `Simple ASCII text é` | `…20 c3 89 00` | `…20 c9 00` |
| `straße` | `…53 54 52 41 53 53 45 00`（`SS`） | 同（`ß→SS` 恰好一致） |
| `ÿ` | `…c5 b8 00`（UTF-8） | `ff` |

对本仓库 10 个样本：**未发现任何非 ASCII 值进入西文/ASCII 文本索引列**（逐值扫描，命中 0），因此 112/112（`index.edb`）、894/894（`Windows.edb`）等键都能由 `key_from_record` 复现。结论应表述为：**该缺陷在当前样本上不可证伪，但对真实含重音/变音符号的数据库（如用户名、文件名）会导致键与 ESE 实际写入的键不一致**，进而"按值搜索失败"或"匹配到错误记录"。这是潜在的、非样本内可证的问题。

另有一个已实测的**真实**不一致：`Windows.edb` 的 `CatalogStorageManager.CatalogManagerIdx`（主索引，列 `CatalogName` 声明为 `JET_coltyp.Text` + locale 1252），记录里存的是 UTF-16LE 字节（`S\0y\0s\0t\0e\0m\0I\0n\0d\0e\0x\0`），而索引键是 `7f 53 00 7f80000001`（只有字符 `S`）。即**目录元数据与记录内容/实际建键所用的值三者不一致**。此处唯一可信的是落盘键本身；从记录值重建的键必然不等（1/1 失败）。

### 4.3 `LINGUISTIC_IGNORECASE` 未实现 → 真实键不可复现

`Windows.edb` 的 3 个索引使用 `LCMapFlags = 0x410`（`LCMAP_SORTKEY | LINGUISTIC_IGNORECASE`），例如 `SystemIndex_Gthr.indexUrl`（`ScopeID, FileName`，`KeyMost=2000`）：

- 1184 条索引项中，`key_from_record` 复现失败 **1078** 条（612 条不匹配 + 466 条抛异常）。
- 失败原因可精确定位：`map_string` 只检查 `NORM_IGNORECASE (0x1)` 来屏蔽 case 权重（`lcmapstring.py:109`），不认 `LINGUISTIC_IGNORECASE (0x10)`，因此末尾多出 `0x12` 段。
- 反证：对 `FileName="Users"`，把 flags 强制加上 `NORM_IGNORECASE` 后，生成的键与落盘键**逐字节相等**（`7f000000057f0e9f0e910e210e8a0e910101010100`）。
- 后果：这 3 个索引**不能按值搜索**（实测抛 `KeyNotFoundError`），但书签回查仍然有效。

### 4.4 截断：无标记、可碰撞、跨段

| 位置 | 行为 | 实测 |
|---|---|---|
| `make_key` 总长 | 超预算后 `key[:KeyMost]` 硬切（`index.py:128-129`） | `IxASCII` 400×`A` vs 400×`A`+`B` → 键完全相同，长度 255 |
| 文本段内 | `value[:max_size]` 先按**字符**切，再 `upper().encode()`，再 `+0x00`，实际可到 `max_size+2` | `_encode_text(max_size=255)` 对 400 字符 ASCII 返回 256 字节 |
| Unicode 段内 | `segment[:max_size]` 按**字节**切 | 切点落在排序键权重中间（`…0e020e02`，无 `0x00` 终止） |
| 二进制段内 | 8 字节块 + 块头，按剩余预算切 | `IxLongBinary` 键长 255，末字节 `0x61`（数据中间） |

证据性后果：

- **键长度达到 `KeyMost` 本身是截断征兆**，但不是充分条件（`IxId` 的 `KeyMost=5` 恰好等于自然长度，`TimeStamp+AutoIncId` 的 14 字节也常常恰好填满）。实测本仓库有 3 个次索引的键正好等于 255：`IxLongBinary`、`IxLongASCII`、`IxLongUnicode`。
- `"0x00 终止符缺失"` 只能检测文本段被截断；二进制段本身无终止符。
- 截断冲突的搜索结果会返回**落盘记录的真实值**（更长），与查询值不同：`search(LongASCII=1043 字符)` 返回 1040 字符的记录。因此"命中即匹配查询值"不成立，必须读记录后再比对。

### 4.5 NULL 与"不入索引"

`encode_key(None) → 0x00`。但 ESE 会根据索引标志决定是否**跳过**某些记录。实测 `MSysObjects.RootObjects`（`Unique|AllowSomeNulls`）：

- 112 条记录，索引只有 **5** 条；107 条记录 `RootFlag IS NULL` 完全不在索引里；
- 5 条索引键以 `7f ff` 开头（`RootFlag=True`），**没有任何键以 `0x00` 开头**；
- `search(RootFlag=None)` 生成 `b'\x00'` 后抛 `KeyNotFoundError`。

规则（本样本内一致）：`NoNullSeg`（`MSysObjects.Name`）→ 该列不允许 NULL，实测 112/112 全入索引；`AllowSomeNulls`/`AllowAllNulls`/`AllowFirstNull` → 全 NULL 记录被跳过。但代码**不读取**这些标志（`index.py:39-40` 只保存，未使用），所以"为什么某记录不在索引里"只能靠上述经验规则解释，属**部分证据**。

---

## 5. 可复核的归属判据

以下判据在 10 个样本上全部通过，且每条都可独立重算。

### 5.1 四级身份（缺一不可）

| 级别 | 字段 | 用途 | 实测校验 |
|---|---|---|---|
| L1 索引项 | 逻辑页号 + tag 号 + 页内偏移 + 长度 + `TAG_FLAG` | 物理定位 | 152/152 可定位 |
| L2 键/书签 | `Node.key`（前缀+后缀拼接）、`Node.data` | 值投影 + 主键 | 全部可复原 |
| L3 索引页归属 | 页头 `objidFDP` → 目录 `Type=3, Id==objidFDP` → `ObjidTable` → `Type=1` 表记录 | 证明"这个索引项属于哪个索引、哪张表" | 152/152 通过；`ColtypOrPgnoFDP == 索引根页号` 152/152 |
| L4 记录归属 | 回查节点的页头 `objidFDP` → 目录 `Type=1, Id==objidFDP` | 证明"这条记录属于哪张表" | 96/96 通过 |
| L5 复现 | `index.key_from_record(record) == Node.key` | 证明"该索引项由该记录生成" | 见 §5.2 |

L3 是关键：**索引页的 `objidFDP` 是索引对象 Id，不是表 Id**。表页的 `objidFDP` 才是表 Id。实测 `MSysObjects.Name`：根页 7、`objidFDP=4`（索引 Id 4）、目录 `ObjidTable=2`（表 Id 2）。只要按 `Id==objidFDP` 去目录里找 `Type=3` 记录，就能唯一确定归属；本样本集中没有歧义。

### 5.2 L5 复现校验（必须做，且必须给出失败原因）

| 类别 | 结果 |
|---|---|
| 单列索引（`index.edb` 的 19 个、`SRUDB`、`Windows` 的 `indexDocID` 等） | 全部逐字节相等 |
| `MSysObjects.Name` / `RootObjects`（西文文本） | 112/112、5/5、894/894、467/467、161/161、102/102、87/87 全等 |
| `SruDbIdMapTable.IdTypeIdBlob`（复合，二进制） | 106/106 全等 |
| `CLIENTS.Username_RoleGuid_TenantId_index` / `Address_Username_RoleGuid_TenantId_index` | 各 10 条全等；各 9 条因值含 `-`/`$` 抛 `NotImplementedError(6)` |
| `DNS.Address_index` | 12/12 抛 `NotImplementedError(13)`（值含数字） |
| `Windows.SystemIndex_Gthr.indexUrl` | 106 等、612 不等、466 异常（`LINGUISTIC_IGNORECASE` + 数字/标点） |
| `CatalogStorageManager` | 1/1 不等（元数据与数据编码冲突） |

结论：**L5 失败不是"索引不可信"，而是"当前实现无法重建该键"**。报告里必须区分"键由落盘数据直接给出"（可信）与"键由记录值重建"（仅在 L5 通过时可作为交叉证据）。

### 5.3 物理位置复算

```
文件偏移 = (逻辑页号 + 1) * 页大小 + 页头长度 + tag.offset
页头长度 = sizeof(PGHDR)=40 + (小页? 0 : sizeof(PGHDR2)=40)
逻辑页号 n 的物理读取位置 = read_page(n+2) → (n+1)*page_size   （esedb.py:92-102）
```

实测校验（`index.edb` 4 KiB 页、`Windows.edb` 32 KiB 页）：页 4/7/15/16/31/2/3/200/400 的 tag1 数据与文件字节**全部一致**。`tag(0)` 是页内键前缀，不是节点；`node(i)` 对应 `tag(i+1)`（`page.py:114-131`），实测 `tag_count = node_count + 1`（页 15：108 = 107+1）。

### 5.4 书签有效性

对每条次索引项，用其 `data` 在**表树**（`table.root`，当存在主索引时等于主索引根，实测 92/92 一致）中做精确查找：

- `index` / `multi` / `SRUDB` / `Windows` / `large`：书签**全部**能在表树中解析（0 个孤儿）；
- `Current.mdb`：三张无主索引的表，书签为 4 字节记录号，同样全部解析；19 条记录被 3 个次索引**共同引用且书签一致**（书签是记录属性，不是索引属性）。

> 补充：`Windows.SystemIndex_Gthr.indexUrl` 这类 `KeyMost=2000` 的大页索引，书签长度为 17–253 字节，全部与主键集合逐字节相同（1184/1184），可作为"书签 = 编码主键"的直接证据。

### 5.5 判据清单（可直接执行）

```python
# 1) 索引项身份
entry = (page.num, node.tag.num, node.tag.offset, node.tag.size, bytes(node.key), bytes(node.data))

# 2) 索引 → 目录 → 表
idx_rec = catalog_by_id[node.tag.page.header.objidFDP]      # Type == 3
assert idx_rec["ColtypOrPgnoFDP"] == index.root.num
table_rec = catalog_by_id[idx_rec["ObjidTable"]]            # Type == 1
assert table_rec["Name"] == index.table.name

# 3) 书签 → 记录
rec_node = BTree(esedb, table.root).search(bytes(node.data), exact=True)
assert rec_node.tag.page.header.objidFDP == table_rec["Id"]

# 4) 复现校验（失败必须记录原因，而不是丢弃）
try:
    assert index.key_from_record(Record(table, rec_node)) == bytes(node.key)
    reproduces = "yes"
except NotImplementedError as e:
    reproduces = f"unsupported:{e}"        # 数字/标点/语言学大小写
except AssertionError:
    reproduces = "mismatch"                # 截断 / 编码 / 元数据冲突

# 5) 记录状态与物理位置
deleted = bool(rec_node.tag.flags & TAG_FLAG.Deleted)
abs_offset = (rec_node.tag.page.num + 1) * esedb.page_size + 0x28 + rec_node.tag.offset
```

---

## 6. 可见值相同时：哪些来源身份仍可区分

### 6.1 可区分（有落盘证据）

| 场景 | 可区分依据 | 实测证据 |
|---|---|---|
| 同表、同值、多条记录 | **书签不同**（编码主键不同） | `CLIENTS` 12 个重复键组（31 条项）、`DNS` 2 组（10 条项），组内书签互异；如 `{:00000001, :00000013}` |
| 同上，物理位置 | 页号/tag 号/页内偏移 | 组内成员分布在不同 tag（本样本 14 个重复组均落在单页内，未观察到跨页组；跨页分组的处理未经样本验证） |
| 索引项属于哪个索引 | 索引页 `objidFDP` → 目录 `Type=3` | 152/152 |
| 记录属于哪张表 | 记录页 `objidFDP` → 目录 `Type=1` | 96/96 |
| 同一记录被多个索引引用 | 书签**相同** | `CLIENTS` 三个索引的书签集合完全相同（19/19） |
| 跨页扫描连续性 | `pgnoNext`/`pgnoPrev` | `MSysObjects.Name` 页 15 ↔ 16 双向链、112 条项 |

### 6.2 不可区分 / 现有结论缺证据

| 结论 | 为什么缺证据 | 实测 |
|---|---|---|
| "两条 `Record` 相等 ⇒ 同一记录" | `__eq__`/`__ne__` 只比较 `self._node.key`（`record.py:63-73`），不含表身份；`__hash__` 却是 `hash((table, node))`（`record.py:51-52`），而 `Node` 按对象身份哈希 | ① 跨表：`MSysObjects` 与 `MSysObjectsShadow` 112 个主键完全相同 → `==` 为真、`hash` 不等；UAL 三表首键都是 `00000001`。② **同表内**：为同一条记录新建一个 `Node`（如页缓存被换出后重读）→ `==` 为真但 `hash` 不等。`set`/`dict` 去重结果不可依赖 |
| "`record != 'x'` 为真" | 非 `Record` 时 `__ne__` 返回 `False`（不是 `True`） | 实测 `r != "x" → False`；`r < "x" → False`；`r >= "x" → False` |
| "`search()` 命中的是组内第一条/最新一条" | `find_node` 返回的组内位置由二分路径决定，既不取最小书签也无语义保证 | 14 个重复组中 10 组可复算（另 4 组的值含 `-`/`$`，键生成抛 `NotImplementedError`）；可算组的位置分布：`(size2,pos1)×4`、`(size2,pos0)×3`、`(size3,pos2)`、`(size3,pos1)`、`(size5,pos3)`。同一组多次查询稳定，但"哪一条"无业务含义 |
| "同一键的多条记录是同一条记录的新旧版本" | 两者标志同为 `TAG_FLAG.Version`，无版本号/时间戳排序，索引也不携带时间 | `CLIENTS` `{:00000001, :00000013}` 是两条独立记录（`TotalAccesses` 2529 vs 2、用户不同），不是版本链 |
| "索引项存在 ⇒ 记录可见/未删除" | 代码从未读取 `TAG_FLAG.Deleted`（全仓库仅枚举定义处出现） | `Windows.SystemIndex_PropertyStore` 有 1 个 `Version\|Deleted\|Compressed` 节点，`records()` 仍返回 1183 条（含该条） |
| "索引项缺失 ⇒ 记录不存在" | 首列 NULL 的记录不入索引；`AllowSomeNulls` 等标志未被读取 | `RootObjects` 5 条 vs 112 条记录 |
| "键字节 ⇒ 用户查询的原值" | 排序键有损（大小写/宽窄/符号）、截断无标记、GUID 重排 | `stats`/`STATS` 同键；400×`A` 与 400×`A`+`B` 同键 |
| "记录值 ⇒ 索引键"（L5） | 数字/标点/语言学大小写/西文非 ASCII 四类已知失败 | 见 §5.2 |
| "页内容 = 磁盘快照一致" | 页校验和（`XECHECKSUM`/`rgChecksum`）只被解析，**从未校验**（全仓库无校验和比对） | grep 仅命中结构定义 |
| "遍历页树 = 覆盖全部索引项" | `iter_leaf_nodes` 对脏库有额外启发式（根页最后一个叶子的 `next_page` 也解析，`page.py:150-162`），可能跨出分支树 | 本样本净树无差异，但脏页未覆盖 |
| 多值索引的段编码 | `encode_key` 对 list 直接 `TypeError`；`IDBFLAG.Multivalued` 的样本索引 0 条项 | `Windows.SystemIndex_Gthr.indexRecovery`（`RequiredSIDs`，Multivalued）entries=0 |

---

## 7. 对报告写作的直接约束

1. 不要写"索引命中 X"。写：
   > 在索引 `<table>.<index>`（目录 Id=`<idx_id>`，根页 `<root_pgno>`）中，位于页 `<pgno>`/tag `<tag>`（文件偏移 `0x<off>`）的索引项，键为 `<key hex>`、书签为 `<bm hex>`；该书签在表 `<table>`（目录 Id=`<tbl_id>`，根页 `<root_pgno>`）的树中解析为页 `<pgno>`/tag `<tag>` 的记录；该记录 `col=值`；用该记录重建的键与落盘键一致/不一致（原因）。
2. 同值多记录时，必须**列出全部组内书签**，并明确"`search()` 只返回其中之一，不能代表全体"；需要全体时用 `find_all` 或自行按前缀游走。
3. 键到达 `KeyMost` 时必须标注"可能截断"，并给出该索引的 `KeyMost`、实际键长、末字节；不要用键反推原值。
4. 文本索引的命中必须回读记录值并显式比较，因为查询串与存储值可能只在大小写上不同。
5. 任何"删除/最新/覆盖"结论，必须给出 `TAG_FLAG.Deleted` 或独立时间字段；仅凭索引项不得下结论。
6. 表无 `IDBFLAG.Primary` 时，书签形态要单独声明为"记录号"，不要套用"编码主键"的解读。

---

## 8. 附带发现（影响证据采集，不影响上面的判据）

1. **未搜索就用 `for rec in Cursor(index)` 会产出假数据或异常**。`__iter__` 直接从当前节点取 `_record()`，而 `BTree` 初始停在根节点；若根是分支页：
   - 主索引：把分支节点的 4 字节子页号当书签/键解析，静默产出"记录"——`names=[None, None, None]` 这种假数据（`index.edb` 3 条、`SRUDB` 4 条、`Current` 9 条，条数 = 根页分支数）；
   - 次索引：把子页号当书签回查，抛 `KeyNotFoundError` 或 `IndexError`（`Windows` 多个索引）。
   
   正确做法：先 `search`/`seek`，或用 `Page.iter_leaf_nodes()` / `table.records()`。**这条最容易在自动化报告工具里造成"每条索引都只有 N 条记录"的静默错误。**
2. `Index.search_key` 的返回类型注释写 `Node`，实际返回 `Record`（`index.py:87-96`）；`Cursor._node` 的 docstring 说"resolves the secondary index"，实际解析的是**表树**。
3. `search()` 会**静默丢弃**不在索引里的过滤条件：`search(ObjidTable=2, Type=2, Name="FLAGS", Id=999999)` 返回 `Id=6` 的记录。需要过滤时用 `find()/find_all()`。
4. `find_all()` 要求 kwargs **包含索引的全部列**，否则 `KeyError`（实测缺 `Name`/`Type` 均报错）；分组判定用"完整键相等"，因此不支持前缀分组。
5. `Record.__hash__` 与 `__eq__` 不一致（见 §6.2），把 `Record` 放进 `set`/`dict` 后跨表去重会得到反直觉结果。
6. 页校验和不校验（§6.2），且 `iter_leaf_nodes` 有脏库启发式；对"脏关闭"镜像做完整性结论时要另行说明。
7. `Index.column_ids` 只在 `len(KeyFldIDs) % 4 == 0` 时解析（`index.py:61`），畸形值会得到空列表 → `columns=[]` → `make_key` 返回 `b''` → 所有查询落到树最左端。当前样本全部为 `IDXFLAG.ExtendedColumns`（152/152），若遇到非扩展索引（FID 而非 COLUMNID），现有解析会把 FID 当列号查表，可能命中错误列；这条**未在样本中验证**。

---

## 附录 A：样本与规模

| 样本 | 页大小 | 格式 | 表 | 索引 | 次索引 | 多列次索引 | 次索引项 |
|---|---|---|---|---|---|---|---|
| basic / binary / text / multi / default / index | 4 KiB | 20.0 | 5 each | 7 / 7 / 7 / 7 / 7 / 25 | 2 each（index 为 20） | 2 each | 92 / 92 / 107 / 102 / 98 / 135 |
| large | 32 KiB | 20.0 | 5 | 7 | 2 | 2 | 65 073 |
| SRUDB.dat | 4 KiB | 20.0 | 12 | 28 | 16 | 10 | 719 |
| Current.mdb (UAL) | 4 KiB | 20.0 | 8 | 12 | 8 | 5 | 547 |
| Windows.edb | 32 KiB | 110.240 | 41 | 45 | 4 | 2 | 2 119 |
| **合计** | | | **96** | **152** | **60** | **31** | **69 084** |

全局不变量：索引页 `objidFDP` → 目录 `Type=3` 记录 **152/152** 命中；表页 `objidFDP` → 目录 `Type=1` 记录 **96/96** 命中；有主索引的表其 `table.root_page == primary_index.root` **92/92**；`TAG_FLAG.Deleted` 节点共 **1** 个（`Windows.SystemIndex_PropertyStore`）。

## 附录 B：复核命令

在仓库根目录执行（依赖已安装的 `dissect.cstruct`/`dissect.util`）：

```bash
python3 -m pytest tests -q          # 基线：17 passed
```

```python
import gzip
from dissect.esedb.esedb import EseDB
from dissect.esedb.btree import BTree
from dissect.esedb.cursor import Cursor
from dissect.esedb.c_esedb import SYSOBJ, TAG_FLAG, c_esedb

db = EseDB(gzip.open("tests/_data/index.edb.gz"))
t, ix = db.table("MSysObjects"), db.table("MSysObjects").index("Name")

# 归属链
cur = ix.cursor()
rec = cur.search(ObjidTable=2, Type=2, Name="Stats")
n = cur._primary.node()                       # 索引项（注意：_primary 是索引树）
print("index entry", n.tag.page.num, n.tag.num, hex(n.tag.offset), n.key.hex(), n.data.hex())
print("index page objidFDP", n.tag.page.header.objidFDP)
print("bookmark ->", rec._node.tag.page.num, rec._node.tag.num, rec.get("Id"), rec.get("Name"))
print("reproduces:", ix.key_from_record(rec) == bytes(n.key))

# 大小写等价
assert ix.make_key({"ObjidTable": 2, "Type": 2, "Name": "stats"}) == \
       ix.make_key({"ObjidTable": 2, "Type": 2, "Name": "STATS"})

# 截断碰撞
lib = db.table("index")
a, b = lib.index("IxLongASCII"), lib.index("IxLongBinary")
assert a.make_key({"LongASCII": "A"*400}) == a.make_key({"LongASCII": "A"*400 + "B"})
assert b.make_key({"LongBinary": b"x"*300}) == b.make_key({"LongBinary": b"x"*300 + b"Y"})

# NULL 不入索引
ro = t.index("RootObjects")
assert sum(1 for _ in ro.root.iter_leaf_nodes()) == 5
assert sum(1 for r in t.records() if r.get("RootFlag") is None) == 107
```

---

**证据等级说明**：凡标注"实测"者，均在本仓库 10 个样本上由上述脚本逐一复算；凡标注"未验证"者，样本集中不存在触发条件（多值索引、非扩展索引、`Nil`/`SLV` 索引列、西文非 ASCII 索引值、脏页树），不得据本文推断其在真实库上的行为。
