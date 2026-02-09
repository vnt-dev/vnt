mod service_http;

pub use service_http::run_http_server;

struct ScopeGuard<F: FnOnce()>(Option<F>);

impl<F: FnOnce()> Drop for ScopeGuard<F> {
    fn drop(&mut self) {
        if let Some(f) = self.0.take() {
            f();
        }
    }
}

fn defer<F: FnOnce()>(f: F) -> ScopeGuard<F> {
    ScopeGuard(Some(f))
}
