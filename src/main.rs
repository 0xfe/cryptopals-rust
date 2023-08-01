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

    set1::run();
    set2::run();

    println!("All done!")
}
