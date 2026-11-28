use super::RouteBackend;
use std::ffi::{CStr, OsString};
use std::fmt;
use std::io;
use std::net::IpAddr;
use std::os::unix::ffi::OsStringExt;
use std::process::{Command, Output};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Route {
    destination: IpAddr,
    prefix: u8,
    gateway: Option<IpAddr>,
    if_index: u32,
}

impl Route {
    pub(super) fn new(destination: IpAddr, prefix: u8) -> Self {
        Self {
            destination,
            prefix,
            gateway: None,
            if_index: 0,
        }
    }

    pub(super) fn with_gateway(mut self, gateway: IpAddr) -> Self {
        self.gateway = Some(gateway);
        self
    }

    pub(super) fn with_if_index(mut self, if_index: u32) -> Self {
        self.if_index = if_index;
        self
    }

    fn ip_command(&self, operation: &str) -> Command {
        let family = if self.destination.is_ipv4() {
            "-4"
        } else {
            "-6"
        };
        let mut command = Command::new("ip");
        command
            .env("LC_ALL", "C")
            .args([family, "route", operation]);
        command
    }

    fn prefix(&self) -> String {
        format!("{}/{}", self.destination, self.prefix)
    }

    fn device_name(&self) -> io::Result<OsString> {
        let mut name = [0; libc::IF_NAMESIZE];
        // SAFETY: if_indextoname writes at most IF_NAMESIZE bytes, including the terminator.
        if unsafe { libc::if_indextoname(self.if_index, name.as_mut_ptr()) }.is_null() {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: a successful call filled the buffer with a NUL-terminated name.
        let name = unsafe { CStr::from_ptr(name.as_ptr()) };
        Ok(OsString::from_vec(name.to_bytes().to_vec()))
    }
}

impl fmt::Display for Route {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.destination, self.prefix)?;
        if let Some(gateway) = self.gateway {
            write!(f, " via {gateway}")?;
        }
        write!(f, " ifindex {}", self.if_index)
    }
}

pub(crate) struct SystemRouteBackend;

impl SystemRouteBackend {
    pub(super) fn new() -> io::Result<Self> {
        Ok(Self)
    }

    fn modify(&mut self, operation: &str, route: &Route) -> io::Result<()> {
        let mut command = route.ip_command(operation);
        command.arg(route.prefix());
        if let Some(gateway) = route.gateway {
            command.arg("via").arg(gateway.to_string());
        }
        command.arg("dev").arg(route.device_name()?);
        run_ip(&mut command, operation)?;
        Ok(())
    }
}

impl RouteBackend for SystemRouteBackend {
    fn contains(&mut self, route: &Route) -> io::Result<bool> {
        let mut command = route.ip_command("show");
        command
            .arg("exact")
            .arg(route.prefix())
            .arg("dev")
            .arg(route.device_name()?);
        let output = run_ip(&mut command, "show")?;
        Ok(!output.stdout.iter().all(u8::is_ascii_whitespace))
    }

    fn add(&mut self, route: &Route) -> io::Result<()> {
        self.modify("add", route)
    }

    fn delete(&mut self, route: &Route) -> io::Result<()> {
        self.modify("del", route)
    }
}

fn run_ip(command: &mut Command, operation: &str) -> io::Result<Output> {
    let output = command.output().map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("cannot run ip route {operation}: {error}"),
        )
    })?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let error = if operation == "add" && stderr.contains("File exists") {
            io::ErrorKind::AlreadyExists
        } else {
            io::ErrorKind::Other
        };
        return Err(io::Error::new(
            error,
            format!(
                "ip route {operation} failed ({}): {}",
                output.status,
                stderr.trim()
            ),
        ));
    }
    Ok(output)
}
