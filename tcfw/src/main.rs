use aya::programs::{tc, tc::qdisc_detach_program, SchedClassifier, TcAttachType};
use aya::{include_bytes_aligned, Bpf};
use std::{
    convert::TryInto,
    sync::atomic::{AtomicBool, Ordering},
    sync::Arc,
    thread,
    time::Duration,
};
use structopt::StructOpt;

fn main() {
    if let Err(e) = try_main() {
        eprintln!("error: {:#}", e);
    }
}

#[derive(Debug, StructOpt)]
struct Opt {
    #[structopt(short, long, default_value = "eth0")]
    iface: String,
}

fn try_main() -> Result<(), anyhow::Error> {
    let opt = Opt::from_args();
    // This will include youe eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/tcfw"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/tcfw"
    ))?;
    if let Err(e) = tc::qdisc_add_clsact(&opt.iface) {
        eprintln!(
            "INFO: error attaching clsact to interface {}, possibly already exists \
		 and safe to ignore: {}. \
		 \nYou can run 'sudo tc qdisc del dev {} clsact' to clean up and avoid this harmless error.\n",
            opt.iface, e, opt.iface
        );
    }
    let program: &mut SchedClassifier = bpf.program_mut("tcfw").unwrap().try_into()?;
    program.load()?;
    program.attach(&opt.iface, TcAttachType::Ingress)?;

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })
    .expect("Error setting Ctrl-C handler");

    println!("Waiting for Ctrl-C...");
    while running.load(Ordering::SeqCst) {
        thread::sleep(Duration::from_millis(500))
    }
    println!("Cleaning up...");
    if let Err(e) = qdisc_detach_program(&opt.iface, TcAttachType::Ingress, "tcfw") {
        println!(
            "Error in qdisc_detach_program for interface {}: {}",
            opt.iface, e
        );
    }
    println!("Exiting...");

    Ok(())
}
