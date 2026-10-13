# 密码学与数据块编码模块

`src/cryptfs_crypto.c` 实现 `src/cryptfs_crypto.h` 声明的接口。模块使用 libsodium 提供随机字节、Argon2id13、XChaCha20-Poly1305、crypto_kdf、SHA-256、HMAC-SHA-256 和安全清零；zstd 用于独立数据块压缩。

## 密钥与密码规则

- 使用模块前调用 `cf_crypto_init()`。其他辅助函数也会以防御性方式初始化 libsodium。`cf_random()` 的返回类型为 void；如果库初始化失败，它会清零请求的缓冲区后返回。因此，创建或更新容器前，调用方必须先成功初始化库，并将初始化失败视为致命错误。
- 密码必须为 1 至 1024 字节的有效 UTF-8。拒绝 NUL、CR 和 LF 字节。调用 libsodium 前，`cf_password_key()` 会检查 Argon2id13 参数：操作次数 1–6，内存 64–512 MiB。创建容器使用头部格式约定的 3 次操作和 256 MiB。
- `cf_keys_derive()` 从随机主密钥派生三个不同的 32 字节子密钥，使用独立的 libsodium KDF ID 和固定的 8 字节上下文 `cfrec001`、`cfwal001`、`cfhdr001`。
- 所有 AEAD 调用均使用 XChaCha20-Poly1305-IETF 和调用方生成的随机 24 字节 nonce。模块的 encrypt/decrypt 函数不会自行生成 nonce；容器代码必须将 nonce 与密文一起持久化，并确保同一密钥下不重复使用。
- `cf_decrypt()` 会先解密到临时缓冲区，只有认证成功后才复制明文。任何失败都会清零完整的目标容量，并将输出长度置零。调用方必须保证所声明的整个目标容量都是有效可写内存。AEAD 输入和输出区间不得重叠，因为验证/解密前会先清零目标区间。
- 数据块 codec 的输入缓冲区和输出缓冲区必须互不重叠。容器数据路径使用独立缓冲区；固定数组 API 不承诺支持原地操作。

## 数据块 codec 规则

输入块和解码后的块都必须恰好为 65536 字节。`cf_block_encode()` 接受 zstd 支持的压缩等级范围，按指定等级写入单个 zstd frame，并将窗口上限设为 64 KiB。只有完整 frame 严格小于 65536 字节时才选择 codec 1；否则以 codec 0 保存原始数据。

`cf_block_decode()` 会拒绝未知 codec、错误的原始长度、超过 `ZSTD_compressBound(65536)` 的压缩长度、格式错误或截断的 frame、串接的多个 frame、尾随字节、未知或不匹配的 frame 内容长度、超过 64 KiB 的窗口，以及解码长度不是恰好 65536 字节的结果。解码失败会清零整个输出块。

释放前会清零由应用程序拥有的临时压缩及解码缓冲区。zstd API 不保证安全擦除其内部上下文分配；这些内存保存 codec 状态，也可能包含历史数据字节。如果威胁模型要求验证库内部压缩内存被擦除，应单独评估 zstd allocator/API，而不能假定释放上下文就会清零。

## 与 memfs 的关系

依赖和构建选择遵循现有 `D:\work\fs\memfs` 核心：两者都通过 vcpkg 静态链接 libsodium（`unofficial-sodium::sodium`）和 zstd（`zstd::libzstd`），并使用静态 CRT。复用这些经过验证的基础密码学原语可保持项目一致，同时不照搬 memfs 的存储策略。

memfs 是易失性文件系统，在随机的每次挂载前缀下使用进程本地单调 nonce 序列；持久化 CryptFS 则为每段密文保存新生成的随机 nonce，使 nonce 唯一性不依赖崩溃后的计数器恢复。memfs 会根据观测到的压缩效果自适应地跳过部分压缩尝试，并要求页面至少节省 32 字节。CryptFS 固定采用互相独立的 64 KiB 数据块格式，始终编码每个块，且只有 frame 严格变小时才选择 zstd，符合其磁盘 codec 格式约定。

## 测试覆盖

`tests/test_crypto.c` 包含公开 XChaCha20-Poly1305 draft 向量、SHA-256 和 HMAC-SHA-256 已知答案；AEAD 篡改/AAD 和失败后清零检查；密码验证和 KDF 参数边界；密钥分离；随机 nonce 唯一性抽样和 AEAD 往返；原始/压缩数据块往返；以及对畸形 frame、长度、codec 和压缩等级的拒绝测试。基础密码测试中的 KDF 使用读取端允许的最低参数，避免重复承担创建容器所需的计算成本。
