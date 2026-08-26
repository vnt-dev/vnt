!macro NSIS_HOOK_PREUNINSTALL
  ; 服务程序位于安装目录内，必须先删除服务，才能安全移除 sidecar。
  nsExec::ExecToStack '"$SYSDIR\sc.exe" query "VntWeb"'
  Pop $0
  Pop $1
  StrCmp $0 "0" vnt_web_service_installed vnt_web_service_removed

vnt_web_service_installed:
  DetailPrint "正在卸载 VNT Web Windows 服务..."
  ClearErrors
  ExecShellWait "runas" "$INSTDIR\vnt-desktop.exe" '--vnt-service-control uninstall --desktop-config "$APPDATA\com.vnt.desktop\web_access.toml"' SW_HIDE
  IfErrors vnt_web_service_remove_failed

  nsExec::ExecToStack '"$SYSDIR\sc.exe" query "VntWeb"'
  Pop $0
  Pop $1
  StrCmp $0 "0" vnt_web_service_remove_failed vnt_web_service_removed

vnt_web_service_remove_failed:
  MessageBox MB_OK|MB_ICONSTOP "无法卸载 VNT Web Windows 服务。请允许管理员授权后重试，或先在 VNT Desktop 设置中卸载服务。"
  Abort

vnt_web_service_removed:
!macroend
