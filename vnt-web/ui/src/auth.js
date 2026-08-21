import { ref } from "vue";

const STORAGE_KEY = "vnt-web-access-token";
export const isDesktop = Boolean(globalThis.__VNT_DESKTOP__);

const url = new URL(window.location.href);
const tokenFromUrl = url.searchParams.get("token") || "";
if (tokenFromUrl) {
  localStorage.setItem(STORAGE_KEY, tokenFromUrl);
  url.searchParams.delete("token");
  window.history.replaceState({}, "", `${url.pathname}${url.search}${url.hash}`);
}

export const accessToken = ref(
  isDesktop ? "" : tokenFromUrl || localStorage.getItem(STORAGE_KEY) || "",
);
export const authorized = ref(isDesktop || Boolean(accessToken.value));

export const getAccessToken = () => accessToken.value;

export const saveAccessToken = (token) => {
  const normalized = token.trim();
  localStorage.setItem(STORAGE_KEY, normalized);
  accessToken.value = normalized;
  authorized.value = Boolean(normalized);
};

export const clearAccessToken = () => {
  localStorage.removeItem(STORAGE_KEY);
  accessToken.value = "";
  authorized.value = false;
};
