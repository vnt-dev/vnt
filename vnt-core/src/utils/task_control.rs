use parking_lot::Mutex;
use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, Weak};
use tokio::sync::Notify;
use tokio::task::{Id, JoinHandle};

struct TaskGroupState {
    stopped: bool,
    tasks: HashMap<Id, JoinHandle<()>>,
}

struct TaskGroupInner {
    state: Mutex<TaskGroupState>,
    all_stopped_notify: Notify,
}

impl TaskGroupInner {
    fn new() -> Self {
        Self {
            state: Mutex::new(TaskGroupState {
                stopped: false,
                tasks: HashMap::new(),
            }),
            all_stopped_notify: Notify::new(),
        }
    }

    fn spawn<F>(self: &Arc<Self>, f: F) -> Option<Id>
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        let mut state = self.state.lock();
        if state.stopped {
            return None;
        }

        let guard = TaskGuard {
            inner: Arc::downgrade(self),
        };

        let handle = tokio::spawn(async move {
            let _guard = guard;
            f.await;
        });

        let task_id = handle.id();
        state.tasks.insert(task_id, handle);
        Some(task_id)
    }

    fn stop(&self) {
        let mut state = self.state.lock();
        state.stopped = true;
        for (_, handle) in state.tasks.drain() {
            handle.abort();
        }
    }

    fn is_stopped(&self) -> bool {
        self.state.lock().stopped
    }

    fn remove_task(&self, task_id: Id) {
        let all_stopped = {
            let mut state = self.state.lock();
            state.tasks.remove(&task_id);
            if state.tasks.is_empty() {
                state.stopped = true;
                true
            } else {
                false
            }
        };
        if all_stopped {
            self.all_stopped_notify.notify_waiters();
        }
    }

    async fn abort_task(&self, task_id: Id) {
        let handle = self.state.lock().tasks.remove(&task_id);
        if let Some(handle) = handle {
            handle.abort();
            _ = handle.await;
        }
    }

    async fn join_all(&self) {
        let tasks = std::mem::take(&mut self.state.lock().tasks);
        for (_, h) in tasks {
            let _ = h.await;
        }
    }

    fn all_tasks_stopped(&self) -> bool {
        let state = self.state.lock();
        state.stopped && state.tasks.is_empty()
    }
}

impl Drop for TaskGroupInner {
    fn drop(&mut self) {
        self.stop();
    }
}

struct TaskGuard {
    inner: Weak<TaskGroupInner>,
}

impl Drop for TaskGuard {
    fn drop(&mut self) {
        if let Some(inner) = self.inner.upgrade() {
            let task_id = tokio::task::id();
            inner.remove_task(task_id);
        }
    }
}

#[derive(Clone)]
pub struct TaskGroup {
    inner: Arc<TaskGroupInner>,
}

impl TaskGroup {
    fn new() -> Self {
        Self {
            inner: Arc::new(TaskGroupInner::new()),
        }
    }

    pub fn stop(&self) {
        self.inner.stop();
    }

    pub fn is_stopped(&self) -> bool {
        self.inner.is_stopped()
    }

    pub fn spawn<F>(&self, f: F) -> SubTask
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        match self.inner.spawn(f) {
            Some(task_id) => SubTask::new(task_id, Arc::downgrade(&self.inner)),
            None => SubTask::empty(),
        }
    }

    pub async fn join_all(&self) {
        self.inner.join_all().await;
    }

    pub async fn wait_all_stopped(&self) {
        loop {
            if self.inner.all_tasks_stopped() {
                return;
            }
            self.inner.all_stopped_notify.notified().await;
        }
    }
}

pub struct SubTask {
    task_id: Option<Id>,
    inner: Weak<TaskGroupInner>,
}

impl SubTask {
    fn new(task_id: Id, inner: Weak<TaskGroupInner>) -> Self {
        Self {
            task_id: Some(task_id),
            inner,
        }
    }

    fn empty() -> Self {
        Self {
            task_id: None,
            inner: Weak::new(),
        }
    }

    pub async fn stop(&self) {
        if let Some(task_id) = self.task_id
            && let Some(inner) = self.inner.upgrade()
        {
            inner.abort_task(task_id).await;
        }
    }

    pub fn is_running(&self) -> bool {
        if let Some(task_id) = self.task_id
            && let Some(inner) = self.inner.upgrade()
        {
            return inner.state.lock().tasks.contains_key(&task_id);
        }
        false
    }

    pub fn id(&self) -> Option<Id> {
        self.task_id
    }
}
#[derive(Clone, Default)]
pub struct TaskGroupManager {
    task_group: Arc<Mutex<Option<TaskGroup>>>,
}

impl TaskGroupManager {
    pub fn new() -> Self {
        TaskGroupManager::default()
    }

    pub fn is_running(&self) -> bool {
        self.task_group.lock().is_some()
    }

    pub fn is_stopped(&self) -> bool {
        self.task_group.lock().is_none()
    }

    pub fn create_task(&self) -> anyhow::Result<(TaskGroup, TaskGroupGuard)> {
        let mut guard = self.task_group.lock();
        if guard.is_some() {
            anyhow::bail!("运行中")
        }

        let task_group = TaskGroup::new();
        guard.replace(task_group.clone());
        let stop_guard = TaskGroupGuard {
            task_group: self.task_group.clone(),
        };
        Ok((task_group, stop_guard))
    }

    pub fn stop(&self) {
        let option = self.task_group.lock();
        if let Some(task_group) = option.as_ref() {
            task_group.stop();
        }
    }
}
pub struct TaskGroupGuard {
    task_group: Arc<Mutex<Option<TaskGroup>>>,
}
impl Drop for TaskGroupGuard {
    fn drop(&mut self) {
        if let Some(task_group) = self.task_group.lock().take() {
            task_group.stop();
        }
    }
}
