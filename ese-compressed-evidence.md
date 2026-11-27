# ESE 压缩标记与声明长度取证分析

分析对象：本仓库 `dissect.esedb`（分支 `task/410`，提交 `ea5efb8`）实际解码与列读取代码，
以及随仓库测试数据库（`tests/_data/*.edb.gz`，含离线 Windows Search 的 `Windows.edb`、`SRUDB.dat`、`Current.mdb`）。

结论先行：**在当前实现中，"声明长度"与"实际恢复字节"并不能互相印证。**

- 7-bit ASCII/Unicode 的声明长度公式 **系统性偏大 2 或 4 字节**（19,813 个样本无一相等），但恢复出的字节本身完整；
- XPRESS 的声明长度字段（`buf[1:3]`）**未被读取校验**，且现有的 `decompress_size()` 对它取 `buf[1:2]` 会直接抛 `struct.error`；
- 分离长值（separated long value）多块时，`get_long_value()` 的偏移累加逻辑有误，**会把未压缩块当作压缩块解码**，导致内容被放大/篡改或抛异常；
- 解码层**从不校验恢复长度是否等于声明长度**，因此截断、未知压缩方案、缺块都会被"成功解码"掩盖。

因此：**压缩层的成功不能替代整列内容完整性的结论。** 下面逐层说明边界与证据含义。

---

## 1. 读取链路与压缩发生的边界

列读取入口在 `dissect/esedb/record.py:198` 的 `RecordData.get()`，按列标识符分三条路径：

| 列类型 | 判定 | 读取函数 | 是否有压缩 | 边界由谁决定 |
|---|---|---|---|---|
| 固定列 | `identifier <= 127` | `_get_fixed()` (`record.py:335`) | **否** | 记录头 + 固定列布局/空位图 |
| 可变列 | `128 <= identifier <= 255` | `_get_variable()` (`record.py:354`) | **否** | 2 字节偏移数组 |
| 标签列 | `identifier > 255` | `_get_tagged()` (`record.py:380`) | **是（内联）** | 下一个 `TAGFLD` 偏移 |
| 分离长值 | 标签列且 `TAGFLD_HEADER.Separated` | `Table.get_long_value()` (`table.py:186`) | **是（分块）** | LV B 树节点键偏移 + LV 头声明总长 |

关键区别（决定"能证明什么"）：

- **普通列（固定/可变）根本不经过压缩路径。** 其字节数由列 schema（`Column.size`/`SpaceUsage`）或
  记录内偏移数组唯一确定，不存在"声明长度 vs 恢复长度"的不一致，只要记录结构完整，字节数即等于列定义。
- **标签列内的压缩值**：`_get_tagged()` 用"下一个标签字段偏移"限定原始字节范围（`record.py:392`），
  然后 `_parse_value()` 中若 `TAGFLD_HEADER.Compressed` 则调用 `compression.decompress()`（`record.py:289-291`）。
  该范围**与压缩头里任何声明长度无关**。
- **分离长值**：记录里只存一个 4 字节 LV 键（`record.py:287-288`），真正内容在 LongValue B 树上按块存放，
  每块是否压缩由"存储长度 vs 槽位长度"推断（`table.py:217-222`），总长来自 LV 头节点数据的前 8 字节（`table.py:196`）。

注意区分两个"Compressed"：

- `TAG_FLAG.Compressed`（`c_esedb.py:377-381`）用于**页节点键前缀压缩**（`page.py:233`），是 B 树键的压缩，
  与列值压缩无关；
- `TAGFLD_HEADER.Compressed`（`c_esedb.py:396-405`，值 `0x02`）才是**列值压缩**标记。
  两者不可混淆。

压缩方案编码在压缩缓冲首字节高 5 位（`compression.py:19` 的 `identifier = buf[0] >> 3`，`c_esedb.py:26-34` 的 `COMPRESSION_SCHEME` 枚举）。
低 3 位**仅被 `decompress_size()` 当作"剩余位计数"使用**（`compression.py:43-45`），而 `decompress()` 与 `sevenbit.decompress()` 不使用它——这是第 2.1 节长度偏差的根源之一。
（注：本节及下文关于头部语义的表述均据本仓库代码与实测样本推断，未依赖外部规范文档。）

---

## 2. 三个"声明长度"来源及其可信度

### 2.1 7-bit ASCII / Unicode —— 声明公式错误（系统性偏大）

`compression.decompress_size()`（`compression.py:42-45`）：

```python
if identifier == COMPRESSION_SCHEME.COMPRESS_7BITASCII:
    return ((buf[0] & 7) + (8 * len(buf))) // 7          # 注意 len(buf) 含方案字节
if identifier == COMPRESSION_SCHEME.COMPRESS_7BITUNICODE:
    return 2 * (((buf[0] & 7) + (8 * len(buf))) // 7)
```

而真正解码的 `compression.decompress()`（`compression.py:20-23`）调用 `sevenbit.decompress(buf[1:])`，
输出长度为 `n + n // 7`（n = 负载字节数，宽字符再乘 2），**完全忽略低 3 位**。

实测（`tests/_data/Windows.edb.gz`，全部内联压缩标签值）：

| 方案 | 样本数 | 声明 − 实际 = +4 | 声明 − 实际 = +2 | 相等 |
|---|---|---|---|---|
| `COMPRESS_7BITUNICODE` | 19,748 | 16,533 | 3,215 | 0 |
| `COMPRESS_7BITASCII` | 65 | 0 | 65 | 0 |
| 合计 | 19,813 | 16,533 | 3,280 | **0** |

对 `text.edb` 的 `MaxLongCompressedASCII`（方案 1）：原始 838 字节，声明 958，实际解码 956；
而该值真实文本长度恰为 956（测试 `tests/test_esedb.py:158` 断言完整串并通过）。
即**恢复字节完整，错的是声明值**。可将偏差归因于公式把方案字节当成完整 8 位负载计入、又叠加低 3 位剩余计数，导致约 +1 字符（宽字符 ×2）；该归因与全部样本的 +2/+4 分布一致，但属于对错误公式的解读，不影响"声明值不可信、恢复字节可用"的结论。

> 结论：7-bit 的"声明长度"不可作为完整性上界；但当前样本中"恢复字节"与真实内容一致。

### 2.2 XPRESS —— 声明字段有效，但代码读错且不校验

方案 3 的头部为 `[方案字节][2 字节小端原始长度]`，`decompress()` 正确跳过 3 字节（`compression.py:25`），
但 `decompress_size()` 写成 `struct.unpack("<H", buf[1:2])`（`compression.py:47`）——**只取 1 字节，必然抛
`struct.error: unpack requires a buffer of 2 bytes`**。正确应为 `buf[1:3]`。

实测：

- `binary.edb` 的 `LongCompressedBinary` 长值单块：方案 3，`buf[1:3]` = 1033，恢复 1033，LV 头总长 1033，三者一致；
- `Windows.edb` 的 309 个压缩 LV 块中 300 个为 XPRESS，`buf[1:3]` 与槽位长度 **300/300 完全一致**；
- 另 9 个为 7-bit，槽位长度与恢复长度 **9/9 一致**。

> 结论：XPRESS 的 2 字节声明长度是可信的，可用于完整性校验；但当前既读不到（`decompress_size` 崩），
> `decompress()` 也从不拿它比对恢复结果。

### 2.3 分离长值 —— LV 头总长 + 分块键偏移

LV 根数据节点前 8 字节为 `<2I`：`(特征值, 未压缩总长)`（`table.py:196`）。
每块的"起始偏移"存放在该块节点键的最后 4 字节（大端，`table.py:210`）。
块是否压缩由 `len(chunk) != 槽位长度` 推断，其中槽位长度应为 `本块起始偏移的下一个起点 − 本块起点`
（最后一块用总长）。

实测 `Windows.edb` 中 ≥3 块的分离长值 65 个：用**正确的绝对起点模型**重建，65/65 与头声明总长完全一致；
说明 LV 头总长是可信的整列长度声明。

---

## 3. `get_long_value()` 的多块偏移缺陷（可恢复，但当前实现会产出错误字节）

`dissect/esedb/table.py:213-224`：

```python
chunk_offsets.append(size)          # 末尾追加总长
...
chunk_offset = 0
for chunk, next_chunk_offset in zip(chunks, chunk_offsets[1:], strict=False):
    if len(chunk) != next_chunk_offset - chunk_offset:
        chunk = compression.decompress(chunk)
    buf.append(chunk)
    chunk_offset += next_chunk_offset        # ← 错误：应为 chunk_offset = next_chunk_offset
```

键里的偏移是**绝对起点**，但代码把绝对偏移**累加**进 `chunk_offset`。对 `SystemIndex_1_Properties`
的键 `0c00008000000080`（10 块，起点 `[0, 8150, 16300, 24450, …, 73350]`，总长 74384）逐块跟踪：

| 块 | 存储长度 | 代码算出的槽位 | 应得槽位 | 代码动作 |
|---|---|---|---|---|
| 0 | 8150 | 8150 | 8150 | 保留 ✓ |
| 1 | 8150 | 8150 | 8150 | 保留 ✓ |
| 2 | 8150 | **0** | 8150 | 误判需解压 → 把未压缩块送进 `decompress` |
| 3 | 8150 | −16300 | 8150 | 误判需解压 |
| … | … | … | … | 同上，一直错误 |

从第 2 块起，`chunk_offset` 累计为 `8150+16300=24450`（应为 16300），槽位变为 0/负数，
于是**每个未压缩块都被当作压缩块**送入 `compression.decompress()`。
而 `decompress()` 只看块首字节高 5 位当方案：

- 首字节 `<0x08`（方案 0）→ "未压缩"原样返回，长度碰巧正确（这也是多数样本"侥幸正确"的原因）；
- 首字节落在 7-bit 方案（`0x08–0x1F`）→ 整块被 `sevenbit.decompress` 重构，长度/内容改变；
- 首字节落在 XPRESS9/10（`0x28–0x37`）→ 抛 `NotImplementedError`；
- 其余 → 原样返回。

实测 65 个多块长值：

| 结果 | 数量 | 说明 |
|---|---|---|
| 与正确重建逐字节相同 | 55 | 后续块首字节恰为 0，侥幸未被破坏 |
| 长度错误（内容被破坏） | 7 | 例如 74384→75547（+1163）、75744→86332（+10476） |
| 抛 `NotImplementedError` | 3 | 后续块首字节被误读为 XPRESS9/10 |

这是**当前工具的输出缺陷，不是磁盘数据缺失**：用绝对起点模型可从同一批页/键完整、正确地重建全部 65 个值。
但只要直接信任库返回，就会把**被放大、混入错误字节的内容当作原文**——这正是取证上最危险的一类不一致。

修复仅需把累加改为赋值：`chunk_offset = next_chunk_offset`。

---

## 4. 不一致的分类：可恢复内容 vs 证据缺口

| 不一致 | 性质 | 判定 |
|---|---|---|
| 7-bit 声明长度比实际大 2/4 字节 | 声明公式错误，恢复字节完整 | **可恢复内容**；不可用声明值当上界 |
| XPRESS `decompress_size` 崩溃 | 访问器 bug，字段本身正确 | **可恢复**；修复为 `buf[1:3]` |
| XPRESS 恢复长度与声明不符（若发生） | 若真有则说明截断/损坏 | 目前样本 300/300 一致；规则上可作校验 |
| 多块 LV 偏移累加 | 工具算法 bug，磁盘数据完整 | **可恢复内容**（修正算法即可），但当前输出不可信 |
| 多块 LV 中某块缺页/被截断 | `btree.next()` 静默停止，返回更短的拼接 | **证据缺口**：无长度比对，会静默"成功" |
| 压缩方案字节损坏为未知值（含 `COMPRESS_SCRUB=4`） | `decompress()` 落到 `return buf`（`compression.py:29`） | **证据缺口**：未知方案被当作"未压缩"原样返回 |
| 文本尾部 NUL 被 `rstrip("\x00")`、非法字节被 `backslashreplace` | 展示层规整 | 展示文本不能证明原始字节；需回到 raw |

补充方法论陷阱：`BTree` 是**有状态**的（`btree.py:12-35` 文档明确说明，`search()` 从当前页而非根开始）。
若用同一个 `BTree` 实例连续查多个键，会得到"键不存在"的假阴性。核查分离长值完整性时，必须**每个键新建
`BTree`（或 `reset()`）**；我在初次审计中即因此出现 173 个假"未解析"，改用每键新建后只剩 3 个真实异常
（均为上面的多块缺陷所致）。

---

## 5. 展示文本与原始字节各自能证明什么

- `Record.get(name)`（默认）返回**解析后的展示值**；文本经 `decode_text`（`c_esedb.py:496-507`）：
  - 用列编码（`CODEPAGE`）解码；
  - 奇数长度 Unicode 补 `\x00`；
  - **`.rstrip("\x00")` 去掉尾部 NUL**；
  - 默认 `errors="backslashreplace"`，非法字节显示为 `\xNN` 而非原始字节。
  因此展示文本能证明的是"在编码 X、错误处理模式 Y 下得到这样一个字符串"，**不能**证明磁盘字节即如此，
  也**不能**证明尾部无内容（NUL 可能被裁掉）。
- `Record.get(name, raw=True)`（`record.py:226-229`）返回**记录内原始字节**：对**内联压缩标签列**是
  *压缩后*的字节；对**分离长值**只是那个 4 字节 LV 键。它**不是**"解压后的原文"，需再解压/跟随 LV。
- 库中**没有任何 API 同时返回"恢复字节 + 声明长度 + 是否完整"**，也没有把"解压成功"与"长度相符"绑定。

因此有三种明确不同的主张，不可混用：

1. **解压成功**：只能证明该缓冲被解码器接受并产出了某些字节；
2. **声明长度相符**：才能支撑"恢复了声称的全部字节"；
3. **整列完整**：还需记录结构（tag 边界/偏移数组/LV 头总长）自洽且各块齐全。

当前实现只保证 (1)，(2)(3) 均未强制。

---

## 6. 保留正常数据库兼容性的处理建议

以下改动都应**默认不改变现有返回类型/行为**，只在检测到不一致时提供显式信号，避免影响正常库：

1. **修正 `compression.decompress_size()`（`compression.py:32-50`）**
   - 7-bit：镜像解码器输出长度，仅按负载计：ASCII `n + n//7`、Unicode `2*(n + n//7)`（`n = len(buf)-1`）。
     不再把方案字节当 8 位负载、不再叠加低 3 位。
   - XPRESS：`struct.unpack("<H", buf[1:3])[0]`。
   - 对未知方案返回 `None`（保持现状语义），但不要与"确实未压缩"混淆——见第 5 条。

2. **在解码处增加可选校验，默认关闭**
   - 新增 `decompress_checked(buf) -> (data, declared, recovered)` 或 `strict` 关键字；
     仅当 `declared is not None and declared != len(data)` 时抛专用异常/返回标志。
   - 对 7-bit 因公式已修，`declared` 与恢复长度天然一致；XPRESS 用可信字段校验。
   - 保持 `decompress()` 旧行为，确保 17 个现有测试与真实库不受影响。

3. **修正 `Table.get_long_value()`（`table.py:186-224`）**
   - 把 `chunk_offset += next_chunk_offset` 改为 `chunk_offset = next_chunk_offset`（一处即可复现全对）。
   - 仅在**所有块齐全**时用绝对起点算槽位：`slot_i = (start[i+1] if i+1<n else total) - start[i]`。
   - 组装后与 LV 头声明总长 `size` 比对；不一致时（默认）仍返回字节以兼容，但提供 `strict=True`
     或返回 `(data, declared)`，让取证调用方能判定"是否完整"。

4. **分离长值增加"声明 vs 恢复"双输出**
   - 保留 `get_long_value(key) -> bytes` 默认签名；
   - 新增 `get_long_value_checked()` 或轻量 dataclass（`data/declared/recovered/chunks/complete`），
     供报告层区分"可恢复"与"证据缺口"，而不破坏现有消费者。

5. **明确未知/异常压缩方案**
   - `decompress()` 当前对方案 0、4 及任意未知值一律 `return buf`（`compression.py:28-29`）。
     建议把"方案 0=确实未压缩"与"方案未知/损坏"区分：后者在 `strict` 模式下报错，避免把损坏当原文。

6. **展示层与证据层分离（文档层面）**
   - 文本 `rstrip("\x00")` 与 `backslashreplace` 保持不变以兼容；
   - 但在文档/报告指引中要求：任何作为证据的文本，都必须同时给出 `raw=True` 的原始（或解压后）字节、
     所用编码与错误处理模式；二进制列不得套用文本的 NUL 裁剪规则。

7. **测试补强**
   - 现有 fixtures（`text/binary/multi.edb`）的分离长值均只有 1 块，因此多块偏移缺陷**未被测试覆盖**
     （当前 `17 passed`）。建议加入 `Windows.edb` 中 10 块的 `SystemIndex_1_Properties.Property`
     作为回归用例，断言恢复长度等于 LV 头总长且逐字节等于绝对起点模型的重建结果。

---

## 7. 复现要点

- 内联 7-bit 差异：对 `Windows.edb` 遍历标签列，`declared=decompress_size(raw)`，`actual=len(decompress(raw))`，
  统计 `declared-actual` 得 `{+4: 16533, +2: 3280}`，相等 0。
- XPRESS 字段：`binary.edb` 的 `LongCompressedBinary` 长值块，`buf[1:3]`=1033=`decompress` 长度=LV 头总长；
  `decompress_size()` 抛 `struct.error`。
- 多块 LV：`SystemIndex_1_Properties` 键 `0c00008000000080`，按 `get_long_value` 逻辑跟踪槽位得
  `8150/8150/0/-16300/…`；正确重建总长 74384，库返回 75547。

> 全部数据来自仓库自带的脱敏测试库；上述结论均可用仓库内代码与 `tests/_data` 复现，无需外部网络或容器。
