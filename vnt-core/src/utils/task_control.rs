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
        self.spawn_inner(f, false, false)
    }

    fn spawn_stop_all<F>(self: &Arc<Self>, f: F) -> Option<Id>
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        self.spawn_inner(f, true, false)
    }

    fn spawn_restartable<F>(self: &Arc<Self>, f: F) -> Option<Id>
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        self.spawn_inner(f, false, true)
    }

    fn spawn_inner<F>(
        self: &Arc<Self>,
        f: F,
        stop_all_on_exit: bool,
        keep_group_alive_on_exit: bool,
    ) -> Option<Id>
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        let mut state = self.state.lock();
        if state.stopped {
            return None;
        }

        let weak = Arc::downgrade(self);
        let handle = tokio::spawn(async move {
            // 在任务上下文内获取自身 id 存入 guard；
            // 不能延迟到 Drop 里调 tokio::task::id()：
            // abort 路径下 future 可能在非任务上下文被销毁（panic），
            // 在调用方任务上下文被销毁时又会拿到错误的 id 误删条目
            let _guard = TaskGuard {
                inner: weak,
                task_id: tokio::task::id(),
                stop_all_on_exit,
                keep_group_alive_on_exit,
            };
            f.await;
        });

        let task_id = handle.id();
        state.tasks.insert(task_id, handle);
        Some(task_id)
    }

    fn stop(&self) {
        {
            let mut state = self.state.lock();
            state.stopped = true;
            for (_, handle) in state.tasks.drain() {
                handle.abort();
            }
        }
        // `spawn_restartable` 允许任务组在暂停期暂时为空，此时没有 TaskGuard
        // 会负责发送通知，因此 stop 本身必须唤醒等待者。
        self.all_stopped_notify.notify_waiters();
    }

    fn is_stopped(&self) -> bool {
        self.state.lock().stopped
    }

    fn remove_task(&self, task_id: Id, keep_group_alive_on_exit: bool) {
        let all_stopped = {
            let mut state = self.state.lock();
            state.tasks.remove(&task_id);
            if state.tasks.is_empty() && !keep_group_alive_on_exit {
                state.stopped = true;
            }
            state.stopped && state.tasks.is_empty()
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
    /// 创建时（任务上下文内）获取的自身任务 id
    task_id: Id,
    /// 当前任务结束（包括 panic 或 abort）时停止组内所有任务
    stop_all_on_exit: bool,
    /// 该任务可以被有意停止后重新创建；它单独耗尽时不结束任务组。
    keep_group_alive_on_exit: bool,
}

impl Drop for TaskGuard {
    fn drop(&mut self) {
        if let Some(inner) = self.inner.upgrade() {
            if self.stop_all_on_exit {
                inner.stop();
            }
            inner.remove_task(self.task_id, self.keep_group_alive_on_exit);
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

    /// 启动一个任务；该任务一旦结束，就停止组内所有任务。
    pub fn spawn_stop_all<F>(&self, f: F) -> SubTask
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        match self.inner.spawn_stop_all(f) {
            Some(task_id) => SubTask::new(task_id, Arc::downgrade(&self.inner)),
            None => SubTask::empty(),
        }
    }

    /// 启动可重建的子任务。该任务结束时不会仅因任务组暂时为空而把组永久关闭；
    /// 任务若非预期退出，应在任务体内显式调用 `TaskGroup::stop`。
    pub fn spawn_restartable<F>(&self, f: F) -> SubTask
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        match self.inner.spawn_restartable(f) {
            Some(task_id) => SubTask::new(task_id, Arc::downgrade(&self.inner)),
            None => SubTask::empty(),
        }
    }

    pub async fn join_all(&self) {
        self.inner.join_all().await;
    }

    pub async fn wait_all_stopped(&self) {
        loop {
            // 先注册等待再检查条件，避免在检查与等待之间丢失唤醒
            let notified = self.inner.all_stopped_notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.inner.all_tasks_stopped() {
                return;
            }
            notified.await;
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::pending;

    /// 所有任务自然结束后 wait_all_stopped 必须返回。
    /// 覆盖两个关键点：任务自然耗尽时 remove_task 置 stopped 并唤醒；
    /// 等待方先注册再检查，不会因竞态错过唤醒而永久挂起。
    #[tokio::test]
    async fn test_wait_all_stopped_after_natural_completion() {
        let manager = TaskGroupManager::new();
        let (group, _guard) = manager.create_task().unwrap();

        let waiter = {
            let group = group.clone();
            tokio::spawn(async move { group.wait_all_stopped().await })
        };
        // 让 waiter 先进入等待
        tokio::task::yield_now().await;

        let _sub = group.spawn(async {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        });

        tokio::time::timeout(std::time::Duration::from_secs(2), waiter)
            .await
            .expect("wait_all_stopped should return after all tasks complete")
            .unwrap();
    }

    /// abort 路径：任务被 stop() 终止后，TaskGuard 必须用创建时保存的 id
    /// 注销自身；若在 Drop 里调 tokio::task::id()，在非任务上下文会 panic，
    /// 在调用方任务上下文则会误删调用方的条目。
    #[tokio::test]
    async fn test_abort_task_keeps_caller_bookkeeping() {
        let manager = TaskGroupManager::new();
        let (group, _guard) = manager.create_task().unwrap();

        let victim = group.spawn(async {
            tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
        });

        // observer 在同组任务内 abort victim，随后挂起等待放行
        let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();
        let (exit_tx, exit_rx) = tokio::sync::oneshot::channel::<()>();
        let observer = group.spawn(async move {
            victim.stop().await;
            let _ = done_tx.send(());
            let _ = exit_rx.await;
        });

        done_rx.await.unwrap();
        // victim 的 guard 注销不得误删 observer 的条目
        assert!(
            observer.is_running(),
            "aborting victim must not remove the caller's task entry"
        );

        let _ = exit_tx.send(());
        tokio::time::timeout(std::time::Duration::from_secs(2), group.wait_all_stopped())
            .await
            .expect("wait_all_stopped should return after observer exits");
    }

    /// spawn_stop_all 的任务结束后必须终止同组的其他任务。
    #[tokio::test]
    async fn test_spawn_stop_all_stops_sibling_tasks() {
        let manager = TaskGroupManager::new();
        let (group, _guard) = manager.create_task().unwrap();

        let (alive_tx, alive_rx) = tokio::sync::oneshot::channel::<()>();
        let sibling = group.spawn(async move {
            let _alive_tx = alive_tx;
            pending::<()>().await;
        });
        assert!(sibling.is_running());

        group.spawn_stop_all(async {});

        tokio::time::timeout(std::time::Duration::from_secs(2), group.wait_all_stopped())
            .await
            .expect("task group should stop when spawn_stop_all task exits");
        tokio::time::timeout(std::time::Duration::from_secs(2), alive_rx)
            .await
            .expect("sibling task should be aborted")
            .expect_err("sibling task must not complete normally");
        assert!(group.is_stopped());
        assert!(!sibling.is_running());
    }

    #[tokio::test]
    async fn test_restartable_task_can_be_stopped_and_started_again() {
        let manager = TaskGroupManager::new();
        let (group, _guard) = manager.create_task().unwrap();

        let first = group.spawn_restartable(std::future::pending::<()>());
        first.stop().await;
        assert!(!group.is_stopped());

        let second = group.spawn_restartable(std::future::pending::<()>());
        assert!(second.is_running());
        group.stop();
    }

    #[tokio::test]
    async fn test_stopping_empty_restartable_group_wakes_waiter() {
        let manager = TaskGroupManager::new();
        let (group, _guard) = manager.create_task().unwrap();
        let task = group.spawn_restartable(std::future::pending::<()>());
        task.stop().await;

        let waiter = {
            let group = group.clone();
            tokio::spawn(async move { group.wait_all_stopped().await })
        };
        tokio::task::yield_now().await;
        group.stop();
        tokio::time::timeout(std::time::Duration::from_secs(2), waiter)
            .await
            .expect("stopping a suspended group must wake its waiter")
            .unwrap();
    }
}
