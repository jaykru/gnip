use clap::{Arg, App};
use packet::builder::Builder;
use packet::Packet;
use packet::icmp;
use packet::ip;
use std::net::IpAddr;
use dns_lookup::lookup_host;
use std::collections::HashMap;
use std::time::{Duration, Instant};
use nix::sys::socket;
use libc;
use signal_hook;
use std::sync::{Mutex, Arc};
use std::thread;

fn main() {
    let matches = App::new("gnip ICMP echo requester")
        .version("1.0")
        .author("Jay Kruer <j@dank.systems>")
        .about("pings stuff")
        .arg(Arg::with_name("ttl")
	     .short("t")
	     .long("ttl")
	     .value_name("TTL (in hops)")
             .help("Time-to-live (in hops) for request packets")
	     .takes_value(true))
	.arg(Arg::with_name("ip_or_host")
	     .value_name("IP or hostname")
	     .required(true)
	     .takes_value(true)
	     .help("The IP or name of the host to ping"))
	.arg(Arg::with_name("interval")
             .short("i")
             .long("interval")
             .value_name("INTERVAL")
             .help("Interval at which to send ICMP echo requests (in ms), defaults to 1 second.")
             .takes_value(true))
        .get_matches();

    // Gets a value for interface name if supplied by user, otherwise
    // defaults to "any" which is special-cased later
    let ttl = matches.value_of("ttl").unwrap_or("54").parse::<u64>().unwrap();
    let host_or_ip = matches.value_of("ip_or_host").unwrap();
    let interval = matches.value_of("interval").unwrap_or("1000").parse::<u64>().unwrap(); // default to 1 second interval
    
    
    let	target_ip: IpAddr = if let Ok(parsed_ip) = host_or_ip.parse::<IpAddr>() {
	parsed_ip
    } else {
	let ips: Vec<std::net::IpAddr> = lookup_host(host_or_ip).unwrap().into_iter().filter(|ip| ip.is_ipv4()).collect();
	assert!(ips.len() > 0, "Name or service not known");
	ips[0]
    };

    assert!(target_ip.is_ipv4(), "IPv6 is not supported by this version of gnip");
    let std_socket_addr = std::net::SocketAddr::new(target_ip, 0);
    let out_in_times: Arc<Mutex<HashMap<u16, (Instant, Option<Instant>)>>> = Arc::new(Mutex::new(HashMap::new()));
    let log = Arc::new(Mutex::new((0,0))); // sent, received

    let log_handler = Arc::clone(&log);
    let _ = unsafe { signal_hook::register(signal_hook::SIGINT, move ||
						{
						    let log = log_handler.lock().unwrap();
						    let pct_loss: f64 = ((log.0 as f64 - log.1 as f64) / log.0 as f64)* 100.0;
						    println!("\n{:.1} packet(s) dropped; total packet loss: {}%", log.0 - log.1, pct_loss);
						    std::process::exit(0); 
						})};
    unsafe {

	let sock = libc::socket(libc::AF_INET,
				libc::SOCK_RAW,
				(*libc::getprotobyname(std::ffi::CString::new("icmp").unwrap().into_raw())).p_proto);
	// N.b.: no kernel-level icmp support will result in a fatal
	// error here, which seems fine to me for this prototype.
	libc::setsockopt(sock, libc::IPPROTO_IP, libc::IP_TTL, ttl as *const libc::c_void, 4);
	libc::setsockopt(sock, libc::IPPROTO_IP, libc::SO_RCVTIMEO, 10 as *const libc::c_void, 4); // set recvmsg timeout to 10ms

	let out_in_times_ping = Arc::clone(&out_in_times);
	let log_ping = Arc::clone(&log);
	let pinger = thread::spawn(move || {
	    let nix_addr = socket::SockAddr::new_inet(socket::InetAddr::from_std(&std_socket_addr));
	    let sockaddr_pair = socket::SockAddr::as_ffi_pair(&nix_addr);
	    
	    let mut seq_num: u16 = 1;
	    loop {
		let packet = packet::icmp::Builder::default()
		    .echo().unwrap().request().unwrap()
		    .identifier(0).unwrap()
		    .sequence(seq_num).unwrap()
		    .build().unwrap();
 		let res = libc::sendto(sock, (&packet).as_ptr() as *const core::ffi::c_void, packet.len(), 0, sockaddr_pair.0, sockaddr_pair.1);
		let when = Instant::now();
		let mut out_in_times = out_in_times_ping.lock().unwrap();
		let mut log = log_ping.lock().unwrap();
		log.0 = log.0 + 1;
		out_in_times.insert(seq_num,
					 (when,
					  None));
		println!("Sent {} bytes for packet #{}", res, seq_num);
		seq_num += 1;
		
		thread::sleep(Duration::from_millis(interval));
	    }
	});

	let out_in_times_pong = Arc::clone(&out_in_times);
	let log_pong = Arc::clone(&log);
	let ponger = thread::spawn(move || {
	    let nix_addr = socket::SockAddr::new_inet(socket::InetAddr::from_std(&std_socket_addr));
	    let sockaddr_pair = socket::SockAddr::as_ffi_pair(&nix_addr);
	    let mut sockaddr = *sockaddr_pair.0;
	    let mut sockaddr_len = sockaddr_pair.1;
	    
	    loop {
		// can fit largest ICMP packet + IP header + Ethernet header
		let mut buf: [u8; 1500] = [0; 1500];
		let bytes_rec = libc::recvfrom(sock, buf.as_mut_ptr() as *mut core::ffi::c_void, 1500, 0, &mut sockaddr as *mut libc::sockaddr, &mut sockaddr_len as *mut u32
		);
		let when = Instant::now();
		if bytes_rec > 0 {
		    if let Ok(ip_packet) = ip::Packet::new(&buf[..]) {
			let payload = ip_packet.payload();
			if let Ok(icmp_packet) = icmp::echo::Packet::new(payload) {
			    if icmp_packet.is_reply() {
				let out_in_times = out_in_times_pong.lock().unwrap();
				let mut log = log_pong.lock().unwrap();
				log.1 = log.1 + 1;
				println!("Reply for #{}; RTT: {}ms", icmp_packet.sequence(), (when - out_in_times.get(&icmp_packet.sequence()).unwrap().0).as_millis());
			    }
			}
		    }
		} 
	    }
	});
	
	let _ = pinger.join();
	let _ = ponger.join();
    }
}
