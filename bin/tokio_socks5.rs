extern crate clap;
extern crate env_logger;
extern crate tokio_socks5;

use std::io::{self, Write};
use std::net::SocketAddr;
use std::process;

use clap::{App, ArgMatches, Arg};

use tokio_socks5::server::Builder;

fn main() {
    match run_main(parser().get_matches()) {
        Ok(()) => process::exit(0),
        Err(e) => {
            writeln!(&mut io::stderr(), "{:?}", e).unwrap();
            process::exit(1);
        }
    }
}

fn run_main(matches: ArgMatches) -> io::Result<()> {
    let _ = env_logger::try_init();
    let server = Builder::new()
        .local_address(matches.value_of("bind").unwrap().parse().unwrap())
        .dns_address(matches.value_of("dns").unwrap().parse().unwrap())
        .build()?;
    server.serve()
}

fn socket_addr_validator(v: String) -> Result<(), String> {
    v.parse::<SocketAddr>()
        .map(|_| ())
        .map_err(|_| format!("{} is not a valid socket address", v))
}

fn parser<'a, 'b>() -> App<'a, 'b> {
    App::new("boots-server")
        .version(env!("CARGO_PKG_VERSION"))
        .about("SOCKS server")
        .arg(
            Arg::with_name("dns")
                .help("DNS server")
                .long("dns")
                .takes_value(true)
                .default_value("9.9.9.9:53")
                .validator(socket_addr_validator)
        )
        .arg(
            Arg::with_name("bind")
                .help("Address to bind to")
                .long("bind")
                .takes_value(true)
                .default_value("127.0.0.1:8000")
                .validator(socket_addr_validator)
        )
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn check_parser() {
        let _ = parser();
    }
}
