# csdo - 命令执行守护进程

`csdo` 是一个轻量级、安全的命令执行系统，设计用于在类 Unix 系统上以指定用户身份（默认 `root`）运行命令，并利用 `sudoers` 配置实现权限提升。它包括客户端（`csdo`）和守护进程（`csdod`），通过 Unix 域套接字（`/var/run/csdod.sock`）通信。系统支持交互式命令（如 `vim`、`top`）使用伪终端（PTY）以及非交互式命令（如 `ls`、`whoami`）使用管道或套接字对。

## 功能

- **特权执行**：以 `root` 或指定用户（`-u <用户名>`）运行命令，对 `sudo` 或 `wheel` 组用户利用 `sudoers` 配置。
- **交互与非交互模式**：
  - 交互模式（默认，PTY）：支持 `vim`、`top` 等命令，提供完整终端交互。
  - 非交互模式（`-n`，管道/套接字对）：适合 `ls` 或脚本等无需终端输入的命令。
- **安全性**：
  - 套接字权限限制为 `root:sudo` 或 `root:wheel`。
  - 用户验证和基于组的访问控制。
  - 安全的 `setuid` 或 `sudo` 执行，包含错误处理。
- **日志**：客户端错误通过 `stderr`（`fprintf`），服务端通过 `syslog` 记录调试和监控信息。
- **可靠通信**：通过 Unix 域套接字处理 `stdin`、`stdout` 和 `stderr`。

## 安装

### 依赖
- **操作系统**：在 Fedora 和 Ubuntu 上测试通过。
- **依赖项**：
  - GCC（`gcc`）
  - GNU Make（`make`）
  - POSIX 线程（`pthread`）
  - `sudo` 包
  - 标准 C 库
- **权限**：
  - 用户必须在 `sudo` 或 `wheel` 组。
  - 配置 `/etc/sudoers.d/<用户名>` 以支持特权执行（如 `NOPASSWD: ALL`）。

### 编译
项目提供 `Makefile` 用于构建客户端（`csdo`）和守护进程（`csdod`）。

```bash
make
```

清理对象文件和二进制文件：
```bash
make clean
```

完全清理：
```bash
make distclean
```

### 配置
1. **设置权限**：
   ```bash
   sudo chown root:wheel csdod  # Ubuntu 上为 root:sudo
   sudo chmod u+s csdod        # 启用 setuid 位
   ```
2. **配置 sudoers**（以用户 `nginx` 为例）：
   ```bash
   echo "Defaults:nginx !env_reset" | sudo tee /etc/sudoers.d/nginx
   echo "nginx ALL=(ALL) NOPASSWD: ALL" | sudo tee -a /etc/sudoers.d/nginx
   sudo visudo -c -f /etc/sudoers.d/nginx
   ```
3. **运行守护进程**：
   ```bash
   sudo ./csdod
   ```
   - 检查套接字：`ls -l /var/run/csdod.sock`（应显示 `srw-rw---- root:wheel` 或 `root:sudo`）。

## 使用方法

### 语法
```bash
csdo [-u <用户名>] [-n] <命令> [参数...]
```
- `-u <用户名>`：以指定用户运行（默认：`root`）。
- `-n`：非交互模式（使用管道/套接字对而非 PTY）。
- `<命令> [参数...]`：要执行的命令（如 `touch /file`、`vim`、`ls`）。

### 示例
1. **以 root 身份运行（交互式）**：
   ```bash
   ./csdo vim /tmp/testfile
   ```
   - 打开 `vim`，保存内容到 `/tmp/testfile`。
2. **以指定用户运行（非交互式）**：
   ```bash
   ./csdo -u nginx -n ls
   ```
   - 以 `nginx` 用户列出目录，无 PTY。
3. **使用 sudo 权限创建文件**：
   ```bash
   ./csdo -u nginx touch /testfile
   ```
   - 使用 `sudo` 创建 `/testfile`（需 `sudoers` 配置）。
4. **以用户身份运行交互命令**：
   ```bash
   ./csdo -u nginx top
   ```
   - 以 `nginx` 用户运行 `top`，使用 PTY。

## 测试

### 设置测试用户
```bash
sudo useradd -m testuser
sudo usermod -aG wheel testuser  # Ubuntu 上为 sudo
echo "Defaults:testuser !env_reset" | sudo tee /etc/sudoers.d/testuser
echo "testuser ALL=(ALL) NOPASSWD: ALL" | sudo tee -a /etc/sudoers.d/testuser
```

### 测试用例
1. **交互命令（vim）**：
   ```bash
   su - testuser -c "./csdo -u testuser vim /tmp/testfile"
   ```
   - 输入：`i`，`test content`，`:wq`，Enter
   - 预期：`/tmp/testfile` 包含 `test content`
2. **非交互命令（ls）**：
   ```bash
   su - testuser -c "./csdo -u testuser -n ls"
   ```
   - 预期：列出目录内容
3. **特权执行**：
   ```bash
   su - testuser -c "./csdo -u testuser touch /testfile"
   ```
   - 预期：创建 `/testfile` 文件
4. **无效用户**：
   ```bash
   su - testuser -c "./csdo -u invaliduser ls"
   ```
   - 预期（stderr）：`Invalid user: invaliduser`
5. **权限拒绝**：
   ```bash
   useradd -m nouser
   su - nouser -c "./csdo ls"
   ```
   - 预期（stderr）：`Permission denied: user not in sudo or wheel group`

### 检查日志
```bash
tail -f /var/log/messages  # Ubuntu 上为 /var/log/syslog
```
- 预期：命令参数（`LOG_DEBUG`）、错误（`LOG_ERR`）。

### 内存检查
```bash
valgrind ./csdo -u testuser vim /tmp/testfile
valgrind ./csdod
```
- 预期：无内存泄漏。

## 注意事项
- **终端环境**：交互命令（如 `vim`、`top`）需设置 `TERM=xterm`。
- **sudoers 配置**：确保 `/etc/sudoers.d/<用户名>` 有效（使用 `visudo -c` 检查）。
- **套接字路径**：`/var/run/csdod.sock` 需 `sudo` 或 `wheel` 组可访问。
- **USE_PIPES**：在 `Makefile` 中添加 `CFLAGS += -DUSE_PIPES` 以使用管道而非套接字对（非交互模式）。

## 贡献指南
1. Fork 本仓库。
2. 创建功能分支（`git checkout -b feature-branch`）。
3. 提交更改（`git commit -m "添加功能"`）。
4. 推送到分支（`git push origin feature-branch`）。
5. 提交 Pull Request。

## 许可证
版权 © 2024-2025 vgfree omstor，基于 MIT 许可证。
