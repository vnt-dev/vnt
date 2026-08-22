import { createRouter, createWebHashHistory } from "vue-router";
import DashboardView from "../views/DashboardView.vue";
import InstancesView from "../views/InstancesView.vue";
import ConfigView from "../views/ConfigView.vue";
import PeersView from "../views/PeersView.vue";
import RoutesView from "../views/RoutesView.vue";
import WebAccessView from "../views/WebAccessView.vue";
import AboutView from "../views/AboutView.vue";

const routes = [
  { path: "/", component: DashboardView },
  { path: "/instances", component: InstancesView },
  // 兼容旧路由
  { path: "/general", redirect: "/instances" },
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
