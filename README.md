# jianying-video-decode

解密剪映 / CapCut 草稿缓存中被 **BDVE（ByteDance Video Encryption）** 周期性 XOR 混淆的 MP4 文件，还原为可直接播放的明文视频。

> 已在 **剪映专业版 11.5.3** 生成的草稿缓存上实测验证。
>
> **v1.1.0**：在 4 个额外真实文件（5–88 MB、152–2577 帧）上端到端验证，修正了 v1.0.0 的两个问题——`moov` 可能被加密、样本加密状态改用 4 字节 NAL 长度前缀判定。

## ⚠️ 声明

本项目为**试验性（experimental）项目**，目的仅在于**生成与恢复个人视频**——即还原用户本人拍摄、本人导入剪映的本地草稿素材，以便在剪映工程之外正常播放和归档。

- **仅限个人使用**：不得用于解密、传播或商用你不拥有版权的内容（包括但不限于剪映素材库中的受版权保护片段）。
- **BDVE 是轻量混淆而非强 DRM**：本工具不绕过任何需要在线授权或硬件绑定的数字版权管理机制。
- **责任自负**：使用者需自行确保其行为符合所在地法律法规及剪映用户协议；作者不对任何滥用行为承担责任。

## 它能做什么

剪映专业版在编辑过程中会把复合片段（combination）或素材缓存写到本地，部分 `*_video.mp4` 文件并非标准 MP4——文件尾追加了 68 字节的 BDVE 加密信息头，文件体则按"每 `step` 字节、前 `length` 字节"的网格与单字节 `key` 做 XOR。直接用 ffprobe/ffmpeg 打开会报 `Invalid data found when processing input`。

本工具通过解析尾部的 `bdve`/`crpt` 结构，利用其中的 **SHA-256 参数摘要**确定性地反推出 `(step, length, key)`，从而精确还原明文 MP4。

**注意**：大多数 `*.alpha.mp4` 侧车文件本身就是明文，无需解密，直接复制即可。

## 快速开始

### 环境要求

- Python 3.8+（无第三方依赖）
- [FFmpeg](https://ffmpeg.org/)（用于校验输出，可选但推荐）

### 使用

```bash
python scripts/decrypt_bdve.py <输入加密.mp4> <输出明文.mp4>
```

示例：

```bash
python scripts/decrypt_bdve.py \
  "C:\Users\kev\AppData\Local\JianyingPro\User Data\Projects\com.lveditor.draft\金地门锁 10月5日\Resources\combination\AB7A021D-..._video.mp4" \
  "D:\output\decrypted.mp4"
```

查看版本：

```bash
python scripts/decrypt_bdve.py --version
# decrypt_bdve 1.1.0 (tested on 剪映专业版 11.5.3)
```

## 工作原理

### 尾部结构（最后 68 字节）

```
[ u32 size=0x44 ] 'bdve'
[ u32 size=0x30 ] 'crpt' [ u32 cryptor_type=1 ] [ u32 version ] [ 32B SHA256 ]
[ u32 size=0x0c ] 'size' [ u32 size=0x44 ]
```

- `key` = 文件第 1 个字节（ftyp 长度高字节 `0x00` 与密文异或的结果）。**不是固定值**，实测出现过 `0x25 / 0x4D / 0x5F / 0xBE / 0x8B`，始终从文件读取。
- 32 字节摘要是 `SHA256( BE32(step) || BE32(length) || u8(key) )` 的完整值，**不是** salt+digest 拆分。

### 解密规则

剥掉 68 字节尾部，对每个 `step` 对齐的块，仅 XOR 其前 `length` 字节。脚本使用 256 字节查表（`bytes.translate`）而非逐字节循环，88 MB 文件秒级完成：

```python
for i in range(0, n, step):
    out[i:i+length] = payload[i:i+length].translate(XOR_TABLE)
```

### 参数发现

公开脚本里的默认 profile（`1022554/311610`、`102303/89230`）往往与真实文件不符。`decrypt_bdve.py` 通过以下步骤确定性求解：

1. 定位 `moov` box 并重建视频 sample 的 `(pos, size)` 表（通过 `hdlr=vide` 选中视频轨，支持 `stco`/`co64`）。**moov 既可能是明文，也可能落在 XOR 窗口内被加密**——先在原始数据中按"标记 + 尺寸合法 + 含 trak/stsz/stco"校验查找，找不到再对整份数据 XOR 后查找。
2. 构造"加密 / 明文"观察点：
   - **主判据——4 字节 AVCC NAL 长度前缀（v1.1.0 新增）**：每个 sample 开头的大端长度必须满足 `0 < len < sample_size`。原始值合法即为明文，XOR 后合法即为密文，两者都合法/都不合法则跳过该样本（不强行下结论）。实测每个文件都能据此得到 50–1900 个两侧锚点。
   - **备用判据——H.264 NAL 合法性打分**：仅当长度判据锚点过少时，对模糊样本按 NAL 类型（1/5/6/7/8/9 为佳）打分。不能只依赖打分——曾有真实文件全部样本打分打平而被误判为加密，导致零明文锚点。
   - 加上 `ftyp`/`mdat`/`moov` 标记的密文/明文位置。
3. 模约束：加密点 `p` 要求 `length > p % step`，明点 `p` 要求 `length <= p % step`。
4. 在 `[1, 5,000,000]` 内枚举可行的 `(step, length)`（锚点商区间优化 + 全量线性兜底），用尾部 SHA-256 摘要做唯一匹配。

### 实测参数集（回归参考）

| key | step | length | 分辨率 | 视频帧数 | moov 状态 |
|-----|------|--------|--------|----------|-----------|
| 0x4D | 259978 | 182696 | 1660×1246 | 152 | 加密 |
| 0x5F | 663483 | 523369 | 720×1280 | 2426 | 加密 |
| 0xBE | 691030 | 381312 | 720×1280 | 2426 | 加密 |
| 0x8B | 505727 | 285731 | 720×1280 | 2577 | 明文 |

v1.1.0 脚本对这 4 个文件的输出与先前人工验证的解密结果逐字节一致（SHA-256 相同）。

## 校验方法

`ffmpeg -f null` 的错误计数**不可靠**——`length` 偏差几百字节仍可能零错误，但画面下半部出现条纹。务必：

1. `ffmpeg -v error -i out.mp4 -f null -`（Windows 用 `NUL`）应无错误
2. `ffprobe` 的流信息与帧数应正常，包数应与 `stsz`/`stsc` 表一致
3. 渲染首帧与尾帧 PNG，肉眼确认无横向条纹

## 项目结构

```
jianying-video-decode/
├── README.md                 # 本文件
├── SKILL.md                  # Trae Skill 规格说明（含算法细节与踩坑）
└── scripts/
    └── decrypt_bdve.py       # 解密器入口（无第三方依赖）
```

## 兼容性

| 项目 | 版本 |
|------|------|
| 剪映专业版 (Jianying Pro) | 11.5.3（实测） |
| BDVE cryptor_type | 1（周期性 XOR） |

未来剪映版本若改动尾部结构或 `cryptor_type`，需重新检查样本最后 68+ 字节后再调整算法。

## 许可证

MIT
