use std::env;

mod aes;
mod set1;
mod set2;
mod util;

fn init_logger() {
    let subscriber = tracing_subscriber::FmtSubscriber::builder()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .finish();
    tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");
}

fn main() {
    init_logger();
    let mut skip_slow_challenges = false;

    env::args().skip(1).for_each(|arg| {
        tracing::info!("Running {}", arg);
        if arg == "--fast" {
            skip_slow_challenges = true;
        }
    });

    set1::run();
    set2::run(skip_slow_challenges);

    println!("All done!")
}
