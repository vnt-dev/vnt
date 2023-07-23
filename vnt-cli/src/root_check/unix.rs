pub fn is_app_elevated() -> bool {
    sudo::RunningAs::Root == sudo::check()
}