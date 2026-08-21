import { createRouter, createWebHashHistory } from "vue-router";
import DashboardView from "../views/DashboardView.vue";
import ConfigView from "../views/ConfigView.vue";
import PeersView from "../views/PeersView.vue";
import RoutesView from "../views/RoutesView.vue";
import WebAccessView from "../views/WebAccessView.vue";
import AboutView from "../views/AboutView.vue";

const routes = [
  { path: "/", component: DashboardView },
  // 兼容旧路由：实例管理已并入网络总览
  { path: "/instances", redirect: "/" },
  { path: "/general", redirect: "/" },
  { path: "/config", component: ConfigView },
  { path: "/peers", component: PeersView },
  { path: "/routes", component: RoutesView },
  { path: "/web-access", component: WebAccessView },
  { path: "/about", component: AboutView },
];

export default createRouter({
  history: createWebHashHistory(),
  routes,
});
