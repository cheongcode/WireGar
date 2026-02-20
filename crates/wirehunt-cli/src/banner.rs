use colored::Colorize;

const BANNER: &str = r#"
 ██╗    ██╗██╗██████╗ ███████╗██╗  ██╗██╗   ██╗███╗   ██╗████████╗
 ██║    ██║██║██╔══██╗██╔════╝██║  ██║██║   ██║████╗  ██║╚══██╔══╝
 ██║ █╗ ██║██║██████╔╝█████╗  ███████║██║   ██║██╔██╗ ██║   ██║
 ██║███╗██║██║██╔══██╗██╔══╝  ██╔══██║██║   ██║██║╚██╗██║   ██║
 ╚███╔███╔╝██║██║  ██║███████╗██║  ██║╚██████╔╝██║ ╚████║   ██║
  ╚══╝╚══╝ ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝
"#;

pub fn print_banner() {
    let version = wirehunt_core::VERSION;
    eprintln!("{}", BANNER.bright_cyan());
    eprintln!(
        "  {} {} {} {}\n",
        "v".bright_white().dimmed(),
        version.bright_white().bold(),
        "//".bright_black(),
        "network forensic engine".bright_black().italic(),
    );
}
