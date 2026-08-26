export const navItems = [
  {
    to: "/",
    label: "网络总览",
    shortLabel: "总览",
    subtitle: "组网状态与实例管理",
    icon: "M4 4h6v6H4V4Zm10 0h6v6h-6V4ZM4 14h6v6H4v-6Zm10 0h6v6h-6v-6Z",
  },
  {
    to: "/peers",
    label: "在线设备",
    shortLabel: "设备",
    subtitle: "查看网络中的对端设备",
    icon: "M15 19a6 6 0 0 0-12 0m18 0a5 5 0 0 0-5-5m-7-3a4 4 0 1 0 0-8 4 4 0 0 0 0 8Zm8 0a3 3 0 1 0 0-6",
  },
  {
    to: "/routes",
    label: "路由表",
    shortLabel: "路由",
    subtitle: "虚拟网络路由信息",
    icon: "M6 8a2 2 0 1 0 0-4 2 2 0 0 0 0 4Zm12 12a2 2 0 1 0 0-4 2 2 0 0 0 0 4ZM8 6h6a4 4 0 0 1 4 4v2m-3-3 3 3 3-3M16 18h-6a4 4 0 0 1-4-4v-2",
  },
  {
    to: "/config",
    label: "组网配置",
    shortLabel: "配置",
    subtitle: "管理组网配置文件",
    icon: "M12 15.5a3.5 3.5 0 1 0 0-7 3.5 3.5 0 0 0 0 7Zm7.4-.5a1.7 1.7 0 0 0 .3 1.9l.1.1-2.8 2.8-.1-.1a1.7 1.7 0 0 0-1.9-.3A1.7 1.7 0 0 0 14 21v.2h-4V21a1.7 1.7 0 0 0-1-1.6 1.7 1.7 0 0 0-1.9.3l-.1.1L4.2 17l.1-.1a1.7 1.7 0 0 0 .3-1.9A1.7 1.7 0 0 0 3 14h-.2v-4H3a1.7 1.7 0 0 0 1.6-1 1.7 1.7 0 0 0-.3-1.9L4.2 7 7 4.2l.1.1A1.7 1.7 0 0 0 9 4.6 1.7 1.7 0 0 0 10 3v-.2h4V3a1.7 1.7 0 0 0 1 1.6 1.7 1.7 0 0 0 1.9-.3l.1-.1L19.8 7l-.1.1a1.7 1.7 0 0 0-.3 1.9 1.7 1.7 0 0 0 1.6 1h.2v4H21a1.7 1.7 0 0 0-1.6-1Z",
  },
  {
    to: "/settings",
    label: "设置",
    shortLabel: "设置",
    subtitle: "内核、服务与访问设置",
    desktopOnly: true,
    icon: "M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18Zm0 0c-2.2-2.5 3.3-5.5 3.3-9S14.2 5.5 12 3m0 18c-2.2-2.5-3.3-5.5-3.3-9S9.8 5.5 12 3M3.5 9h17m-17 6h17",
  },
  {
    to: "/about",
    label: "关于",
    shortLabel: "关于",
    subtitle: "版本与更新",
    icon: "M12 17v-6m0-4h.01M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0Z",
  },
];

export const visibleNavItems = () =>
  navItems.filter((item) => !item.desktopOnly || globalThis.__VNT_DESKTOP__);
