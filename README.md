# libcas

该软件是一套后门程序，用以在低权限的上下文中自动提升权限。  
用户应该合理使用并评估带来的风险问题，  
推荐添加白名单和输入源检测等多种方式来提升安全。  

## 特性

- 简单易用。
- 支持并发。

## 示例

```bash
systemctl start csdod
csdo echo "hello world!"
```


### 使用 Git 克隆项目

```bash
git clone https://github.com/vgfree/csdo.git
cd csdo
make all
```

### 贡献

我们欢迎任何形式的贡献，欢迎提交 issue 或 pull request！
