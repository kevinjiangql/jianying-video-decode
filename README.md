# jianying-video-decode

解密剪映 / CapCut 草稿缓存中被 **BDVE（ByteDance Video Encryption）** 周期性 XOR 混淆的 MP4 文件，还原为可直接播放的明文视频。

> 已在 **剪映专业版 11.5.3** 生成的草稿缓存上实测验证。

## 它能做什么

剪映专业版在编辑过程中会把复合片段（combination）或素材缓存写到本地，部分 `*_video.mp4` 文件并非标准 MP4——文件尾追加了 68 字节的 BDVE 加密信息头，文件体则按"每 `step` 字节、前 `length` 字节"的网格与单字节 `key` 做 XOR。直接用 ffprobe/ffmpeg 打开会报 `Invalid data found when processing input`。

本工具通过解析尾部的 `bdve`/`crpt` 结构，利用其中的 **SHA-256 参数摘要**确定性地反推出 `(step, length, key)`，从而精确还原明文 MP4。

**注意**：大多数 `*.alpha.mp4` 侧车文件本身就是明文，无需解密，直接复制即可。

## 快速开始

### 环境要求

- Python 3.8+
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
# decrypt_bdve 1.0.0 (tested on 剪映专业版 11.5.3)
```

## 工作原理

### 尾部结构（最后 68 字节）

```
[ u32 size=0x44 ] 'bdve'
[ u32 size=0x30 ] 'crpt' [ u32 cryptor_type=1 ] [ u32 version ] [ 32B SHA256 ]
[ u32 size=0x0c ] 'size' [ u32 size=0x44 ]
```

- `key` = 文件第 1 个字节（ftyp 长度高字节 `0x00` 与密文异或的结果，通常为 `0x25`）
- 32 字节摘要是 `SHA256( BE32(step) || BE32(length) || u8(key) )` 的完整值，**不是** salt+digest 拆分

### 解密规则

剥掉 68 字节尾部，对每个 `step` 对齐的块，仅 XOR 其前 `length` 字节：

```python
for i in range(0, n, step):
    for j in range(i, min(i + length, n)):
        out[j] ^= key
```

### 参数发现

公开脚本里的默认 profile（`1022554/311610`、`102303/89230`）往往与真实文件不符。`decrypt_bdve.py` 通过以下步骤确定性求解：

1. 解析位于文件尾部的明文 `moov`，重建视频 sample 的 `(pos, size)` 表
2. 用 H.264 NAL 合法性打分，对前约 260 个 sample 起点判定"加密 / 明文"
3. 结合 `ftyp`/`mdat`/`moov` 标记的密文/明文位置，构造模约束：加密点 `p` 要求 `length > p % step`，明点 `p` 要求 `length <= p % step`
4. 枚举可行的 `(step, length)`，用尾部 SHA-256 摘要做唯一匹配

## 校验方法

`ffmpeg -f null` 的错误计数**不可靠**——`length` 偏差几百字节仍可能零错误，但画面下半部出现条纹。务必：

1. `ffmpeg -v warning -i out.mp4 -f null -` 应无错误
2. `ffprobe -count_packets` 的包数应与 `stsz`/`stsc` 表一致
3. 渲染首帧与尾帧 PNG，肉眼确认无横向条纹

## 项目结构

```
jianying-video-decode/
├── README.md                 # 本文件
├── SKILL.md                  # Trae Skill 规格说明（含算法细节与踩坑）
└── scripts/
    └── decrypt_bdve.py       # 解密器入口
```

## 兼容性

| 项目 | 版本 |
|------|------|
| 剪映专业版 (Jianying Pro) | 11.5.3（实测） |
| BDVE cryptor_type | 1（周期性 XOR） |

未来剪映版本若改动尾部结构或 `cryptor_type`，需重新检查样本最后 68+ 字节后再调整算法。

## 许可证

MIT
