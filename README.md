# csdo - Command Execution Daemon

`csdo` is a lightweight, secure command execution system designed to run commands as a specified user (defaulting to `root`) on Unix-like systems, leveraging `sudoers` for privilege escalation. It consists of a client (`csdo`) and a daemon (`csdod`), communicating via a Unix domain socket (`/var/run/csdod.sock`). The system supports both interactive commands (e.g., `vim`, `top`) with pseudo-terminals (PTY) and non-interactive commands (e.g., `ls`, `whoami`) with pipes or socketpairs.

## Features

- **Privileged Execution**: Run commands as `root` or a specified user (`-u <username>`), utilizing `sudoers` for users in `sudo` or `wheel` groups.
- **Interactive and Non-Interactive Modes**:
  - Interactive mode (default, PTY): Supports commands like `vim` and `top` with full terminal interaction.
  - Non-interactive mode (`-n`, pipes/socketpairs): Ideal for commands like `ls` or scripts without terminal input.
- **Security**:
  - Socket permissions restricted to `root:sudo` or `root:wheel`.
  - User validation and group-based access control.
  - Safe `setuid` or `sudo` execution with proper error handling.
- **Logging**: Client errors via `stderr` (`fprintf`), server logs via `syslog` for debugging and monitoring.
- **Robust Communication**: Handles `stdin`, `stdout`, and `stderr` over Unix domain sockets.

## Installation

### Prerequisites
- **OS**: Tested on Fedora and Ubuntu.
- **Dependencies**:
  - GCC (`gcc`)
  - GNU Make (`make`)
  - POSIX threads (`pthread`)
  - `sudo` package
  - Standard C libraries
- **Permissions**:
  - User must be in `sudo` or `wheel` group.
  - `/etc/sudoers.d/<username>` configured for privileged execution (e.g., `NOPASSWD: ALL`).

### Build
The project includes a `Makefile` for building the client (`csdo`) and daemon (`csdod`).

```bash
make
```

To clean up object files and binaries:
```bash
make clean
```

To perform a full cleanup:
```bash
make distclean
```

### Setup
1. **Set Permissions**:
   ```bash
   sudo chown root:wheel csdod  # Or root:sudo on Ubuntu
   sudo chmod u+s csdod        # Enable setuid bit
   ```
2. **Configure sudoers** (e.g., for user `nginx`):
   ```bash
   echo "Defaults:nginx !env_reset" | sudo tee /etc/sudoers.d/nginx
   echo "nginx ALL=(ALL) NOPASSWD: ALL" | sudo tee -a /etc/sudoers.d/nginx
   sudo visudo -c -f /etc/sudoers.d/nginx
   ```
3. **Run Daemon**:
   ```bash
   sudo ./csdod
   ```
   - Verify socket: `ls -l /var/run/csdod.sock` (should show `srw-rw---- root:wheel` or `root:sudo`).

## Usage

### Syntax
```bash
csdo [-u <username>] [-n] <command> [args...]
```
- `-u <username>`: Run as specified user (default: `root`).
- `-n`: Non-interactive mode (uses pipes/socketpairs instead of PTY).
- `<command> [args...]`: Command to execute (e.g., `touch /file`, `vim`, `ls`).

### Examples
1. **Run as root (interactive)**:
   ```bash
   ./csdo vim /tmp/testfile
   ```
   - Opens `vim` in a PTY, saves content to `/tmp/testfile`.
2. **Run as specific user (non-interactive)**:
   ```bash
   ./csdo -u nginx -n ls
   ```
   - Lists directory as `nginx` user without PTY.
3. **Create file with sudo privileges**:
   ```bash
   ./csdo -u nginx touch /testfile
   ```
   - Creates `/testfile` using `sudo` (requires `sudoers` configuration).
4. **Interactive command as user**:
   ```bash
   ./csdo -u nginx top
   ```
   - Runs `top` in a PTY as `nginx`.

## Testing

### Setup Test User
```bash
sudo useradd -m testuser
sudo usermod -aG wheel testuser  # Or sudo on Ubuntu
echo "Defaults:testuser !env_reset" | sudo tee /etc/sudoers.d/testuser
echo "testuser ALL=(ALL) NOPASSWD: ALL" | sudo tee -a /etc/sudoers.d/testuser
```

### Test Cases
1. **Interactive Command (vim)**:
   ```bash
   su - testuser -c "./csdo -u testuser vim /tmp/testfile"
   ```
   - Input: `i`, `test content`, `:wq`, Enter
   - Expected: `/tmp/testfile` contains `test content`
2. **Non-Interactive Command (ls)**:
   ```bash
   su - testuser -c "./csdo -u testuser -n ls"
   ```
   - Expected: Lists directory contents
3. **Privileged Execution**:
   ```bash
   su - testuser -c "./csdo -u testuser touch /testfile"
   ```
   - Expected: File `/testfile` created
4. **Invalid User**:
   ```bash
   su - testuser -c "./csdo -u invaliduser ls"
   ```
   - Expected (stderr): `Invalid user: invaliduser`
5. **Permission Denied**:
   ```bash
   useradd -m nouser
   su - nouser -c "./csdo ls"
   ```
   - Expected (stderr): `Permission denied: user not in sudo or wheel group`

### Verify Logs
```bash
tail -f /var/log/messages  # Or /var/log/syslog on Ubuntu
```
- Expected: Command arguments (`LOG_DEBUG`), errors (`LOG_ERR`).

### Memory Check
```bash
valgrind ./csdo -u testuser vim /tmp/testfile
valgrind ./csdod
```
- Expected: No memory leaks.

## Notes
- **Terminal Environment**: Set `TERM=xterm` for interactive commands (`vim`, `top`).
- **sudoers**: Ensure `/etc/sudoers.d/<username>` is valid (`visudo -c`).
- **Socket Path**: `/var/run/csdod.sock` must be accessible by `sudo`/`wheel` group.
- **USE_PIPES**: Define `USE_PIPES` in `Makefile` (e.g., `CFLAGS += -DUSE_PIPES`) to use pipes instead of socketpairs for non-interactive mode.

## Contributing
1. Fork the repository.
2. Create a feature branch (`git checkout -b feature-branch`).
3. Commit changes (`git commit -m "Add feature"`).
4. Push to the branch (`git push origin feature-branch`).
5. Open a pull request.

## License
Copyright © 2024-2025 vgfree omstor. Licensed under the MIT License.
