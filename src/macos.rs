use std::ffi::CStr;
use std::io;

use libproc::libproc::file_info::{ListFDs, ProcFDType};
use libproc::libproc::file_info::pidfdinfo;
use libproc::libproc::net_info::{SocketFDInfo, SocketInfoKind};
use libproc::libproc::proc_pid::{listpidinfo, pidinfo};
use libproc::libproc::task_info::TaskAllInfo;
use libproc::processes::{pids_by_type, ProcFilter};
use log::{debug, warn};
use nix::sys::signal::{self, Signal};
use nix::unistd::Pid;

use crate::KillPortSignalOptions;

/// Collect information about all processes.
///
/// # Returns
///
/// A vector containing the information of all processes.
fn collect_proc() -> Vec<TaskAllInfo> {
    let mut base_procs = Vec::new();

    if let Ok(procs) = pids_by_type(ProcFilter::All) {
        for p in procs {
            if let Ok(task) = pidinfo::<TaskAllInfo>(p as i32, 0) {
                base_procs.push(task);
            }
        }
    }

    base_procs
}

/// Kill processes listening on the specified port.
///
/// # Arguments
///
/// * `port` - The port number to kill processes listening on.
/// * `signal` - A enum value representing the signal type.
///
/// # Returns
///
/// A `Result` containing a boolean value. If true, at least one process was killed; otherwise, false.
pub fn kill_processes_by_port(port: u16, signal: KillPortSignalOptions, execute: bool) -> Result<bool, io::Error> {
    let process_infos = collect_proc();
    let mut killed = false;

    for task in process_infos {
        let pid = task.pbsd.pbi_pid as i32;

        let kill_process = is_target_to_kill(port, &task, pid);
        if !kill_process {
            continue;
        }

        debug!("Found process with PID {}", pid);
        let pid = Pid::from_raw(pid);
        let cmd = unsafe {
            CStr::from_ptr(task.pbsd.pbi_comm.as_ptr())
                .to_string_lossy()
                .into_owned()
        };

        if !execute {
            println!("Found pid: {} command: {}", pid, cmd);
            continue;
        }

        if cmd.starts_with("com.docker") {
            warn!("Warning: Found Docker. You might need to stop the container manually.");
            continue;
        }

        let system_signal = match signal {
            KillPortSignalOptions::SIGKILL => Signal::SIGKILL,
            KillPortSignalOptions::SIGTERM => Signal::SIGTERM,
        };
        match signal::kill(pid, system_signal) {
            Ok(_) => {
                killed = true;
                println!("Killed pid: {} command: {}", pid, cmd);
            }
            Err(e) => {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("Failed to kill process {}: {}", pid, e),
                ));
            }
        }
    }

    Ok(killed)
}

fn is_target_to_kill(port: u16, task: &TaskAllInfo, pid: i32) -> bool {
    let fds = listpidinfo::<ListFDs>(pid, task.pbsd.pbi_nfiles as usize);
    if let Ok(fds) = fds {
        for fd in fds {
            if let ProcFDType::Socket = fd.proc_fdtype.into() {
                if let Ok(socket) = pidfdinfo::<SocketFDInfo>(pid, fd.proc_fd) {
                    match socket.psi.soi_kind.into() {
                        SocketInfoKind::In => {
                            if socket.psi.soi_protocol == libc::IPPROTO_UDP {
                                let info = unsafe { socket.psi.soi_proto.pri_in };
                                let local_port = u16::from_be(info.insi_lport as u16);
                                if local_port == port {
                                    return true;
                                }
                            }
                        }
                        SocketInfoKind::Tcp => {
                            let info = unsafe { socket.psi.soi_proto.pri_tcp };
                            let local_port = u16::from_be(info.tcpsi_ini.insi_lport as u16);
                            if local_port == port {
                                return true;
                            }
                        }
                        _ => (),
                    }
                }
            }
        }
    }

    return false;
}
