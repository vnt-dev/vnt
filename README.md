# switch
Virtual Network Tools

将不同网络下的设备虚拟到一个局域网下


### 示例：

- 在一台mac设备上运行，获取到ip 10.13.0.2：

<img width="506" alt="图片" src="https://user-images.githubusercontent.com/49143209/210379090-a3f21007-5a12-44d3-81d6-a69495209ea7.png">

- 在另一台windows上运行，获取到ip 10.13.0.3：

![图片](https://user-images.githubusercontent.com/49143209/210380063-d02c5b46-8fef-4e21-aa9b-6c2defcb1412.png)

- 此时这两个设备之间就能用ip相互访问了

<img width="437" alt="图片" src="https://user-images.githubusercontent.com/49143209/210380969-4a7c0f23-1e88-4ab6-9cc2-0c0f086848ac.png">

- token的作用是标识一个虚拟局域网，当使用公共服务器时，建议使用一个唯一值当token(比如uuid)，否则有可能连接到其他人创建的虚拟局域网中
- 公共服务器目前的配置是2核4G 4Mbps，有需要再扩展~
### 支持平台
- Mac
- Linux
- Windows
  - 依赖 wintun.dll(https://www.wintun.net/)

### 特性
- IP层数据转发
- Nat穿透

### Todo
- 数据加密
