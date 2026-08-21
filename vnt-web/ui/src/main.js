import { createApp } from "vue";
import { createPinia } from "pinia";
import App from "./App.vue";
import router from "./router";
import vntIcon from "./assets/vnt-icon.png";
import "./style.css";

const favicon = document.querySelector('link[rel~="icon"]') || document.createElement("link");
favicon.rel = "icon";
favicon.type = "image/png";
favicon.href = vntIcon;
document.head.appendChild(favicon);

createApp(App).use(createPinia()).use(router).mount("#app");
