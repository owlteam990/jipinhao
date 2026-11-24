//! TRON 极品号碰撞器入口：多线程暴力搜索吉利后缀地址

mod matcher;
mod tron;

use std::fs::OpenOptions;
use std::io::Write;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use clap::Parser;
use matcher::{MatchConfig, DEFAULT_CHARSET};
use rand::rngs::ThreadRng;
use rand::RngCore;
use secp256k1::{Secp256k1, SecretKey};
use tron::private_key_to_address;

/// TRON 极品号碰撞器
#[derive(Parser, Debug)]
#[command(name = "jipinhao", about = "本地暴力搜索带吉利后缀的 TRON 地址（极品号）")]
struct Cli {
    /// 连续位数（默认 7）
    #[arg(short = 'n', long, default_value_t = 7)]
    length: usize,

    /// 吉利字符集（默认 689A）
    #[arg(short = 'c', long, default_value = DEFAULT_CHARSET)]
    charset: String,

    /// 要求后缀每一位都相同（豹子号，难度远高于默认模式）
    #[arg(long, default_value_t = false)]
    same: bool,

    /// 工作线程数（默认 = CPU 逻辑核数）
    #[arg(short = 't', long)]
    threads: Option<usize>,

    /// 命中结果追加写入的文件路径
    #[arg(short = 'o', long, default_value = "found.txt")]
    output: String,

    /// 找到多少个后退出（0 表示一直跑，直到 Ctrl+C）
    #[arg(short = 'm', long, default_value_t = 1)]
    max_find: u64,

    /// 仅校验一条私钥能否推导出地址（不碰撞）
    #[arg(long)]
    verify: Option<String>,
}

/// 碰撞命中结果
struct Hit {
    address: String,
    private_key_hex: String,
    thread_id: usize,
}

fn main() {
    let cli = Cli::parse();

    // 校验模式：只做私钥 → 地址推导
    if let Some(hex_key) = cli.verify.as_ref() {
        match tron::address_from_hex(hex_key.trim()) {
            Some(addr) => {
                println!("私钥: {}", hex_key.trim());
                println!("地址: {}", addr);
            }
            None => {
                eprintln!("私钥非法，请提供 64 位十六进制私钥");
                std::process::exit(1);
            }
        }
        return;
    }

    let config = match MatchConfig::new(cli.length, &cli.charset, cli.same) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("参数错误: {}", e);
            std::process::exit(1);
        }
    };

    let thread_count = cli.threads.unwrap_or_else(num_cpus::get).max(1);
    let stop = Arc::new(AtomicBool::new(false));
    let attempts = Arc::new(AtomicU64::new(0));
    let found_count = Arc::new(AtomicU64::new(0));

    // Ctrl+C 优雅停机
    {
        let stop = Arc::clone(&stop);
        ctrlc::set_handler(move || {
            eprintln!("\n收到中断信号，正在停止...");
            stop.store(true, Ordering::SeqCst);
        })
        .expect("无法注册 Ctrl+C 处理");
    }

    let (tx, rx) = std::sync::mpsc::channel::<Hit>();

    println!("规则      : {}", config.describe());
    println!("近似概率  : {:.3e} / 次", config.hit_probability());
    println!("线程数    : {}", thread_count);
    println!("输出文件  : {}", cli.output);
    println!("目标数量  : {}", if cli.max_find == 0 { "无限".to_string() } else { cli.max_find.to_string() });
    println!("开始碰撞，按 Ctrl+C 停止...\n");

    let started = Instant::now();

    // 启动工作线程
    let mut handles = Vec::with_capacity(thread_count);
    for thread_id in 0..thread_count {
        let stop = Arc::clone(&stop);
        let attempts = Arc::clone(&attempts);
        let config = config.clone();
        let tx = tx.clone();

        handles.push(thread::spawn(move || {
            worker_loop(thread_id, config, stop, attempts, tx);
        }));
    }
    drop(tx);

    // 主线程接收命中并落盘；另起进度打印
    let stop_progress = Arc::clone(&stop);
    let attempts_progress = Arc::clone(&attempts);
    let progress = thread::spawn(move || {
        print_progress(stop_progress, attempts_progress, started);
    });

    let mut saved = 0u64;
    while let Ok(hit) = rx.recv() {
        // 二次校验，防止实现错误写出脏数据
        match tron::address_from_hex(&hit.private_key_hex) {
            Some(addr) if addr == hit.address => {}
            _ => {
                eprintln!("警告：命中结果校验失败，已丢弃 thread={}", hit.thread_id);
                continue;
            }
        }

        let line = format!(
            "address={}\tprivate_key={}\tthread={}\n",
            hit.address, hit.private_key_hex, hit.thread_id
        );

        if let Err(e) = append_line(&cli.output, &line) {
            eprintln!("写入文件失败: {}", e);
        }

        let total = found_count.fetch_add(1, Ordering::SeqCst) + 1;
        saved += 1;

        println!(
            "\n[命中 #{}] {}\n私钥: {}\n已写入 {}\n",
            total, hit.address, hit.private_key_hex, cli.output
        );

        if cli.max_find > 0 && saved >= cli.max_find {
            stop.store(true, Ordering::SeqCst);
            break;
        }
    }

    // 排空通道中残留命中（停机后 worker 可能还塞了几条）
    while let Ok(hit) = rx.try_recv() {
        if let Some(addr) = tron::address_from_hex(&hit.private_key_hex) {
            if addr == hit.address {
                let line = format!(
                    "address={}\tprivate_key={}\tthread={}\n",
                    hit.address, hit.private_key_hex, hit.thread_id
                );
                let _ = append_line(&cli.output, &line);
                let total = found_count.fetch_add(1, Ordering::SeqCst) + 1;
                println!(
                    "\n[命中 #{}] {}\n私钥: {}\n已写入 {}\n",
                    total, hit.address, hit.private_key_hex, cli.output
                );
            }
        }
    }

    for handle in handles {
        let _ = handle.join();
    }
    let _ = progress.join();

    let elapsed = started.elapsed().as_secs_f64().max(0.001);
    let total_attempts = attempts.load(Ordering::Relaxed);
    println!(
        "结束：尝试 {} 次，用时 {:.1}s，速度 {:.0} keys/s，命中 {}",
        total_attempts,
        elapsed,
        total_attempts as f64 / elapsed,
        found_count.load(Ordering::Relaxed)
    );
}

/// 单个工作线程的碰撞循环
///
/// # Arguments
/// * `thread_id` - 线程编号
/// * `config` - 匹配规则
/// * `stop` - 全局停机标志
/// * `attempts` - 全局尝试计数
/// * `tx` - 命中结果发送端
fn worker_loop(
    thread_id: usize,
    config: MatchConfig,
    stop: Arc<AtomicBool>,
    attempts: Arc<AtomicU64>,
    tx: std::sync::mpsc::Sender<Hit>,
) {
    let secp = Secp256k1::new();
    let mut rng = ThreadRng::default();
    let mut local_count = 0u64;
    // 复用缓冲区，减少堆分配
    let mut sk_bytes = [0u8; 32];

    while !stop.load(Ordering::Relaxed) {
        // 1. 线程本地 CSPRNG 生成私钥（比每次系统调用 OsRng 快）
        loop {
            rng.fill_bytes(&mut sk_bytes);
            if let Ok(secret_key) = SecretKey::from_slice(&sk_bytes) {
                // 2. 推导 TRON 地址
                let address = private_key_to_address(&secp, &secret_key);

                local_count += 1;
                // 批量上报计数，降低原子操作开销
                if local_count >= 1024 {
                    attempts.fetch_add(local_count, Ordering::Relaxed);
                    local_count = 0;
                }

                // 3. 判断后缀是否命中
                if config.matches(&address) {
                    let private_key_hex = hex::encode(secret_key.secret_bytes());
                    let _ = tx.send(Hit {
                        address,
                        private_key_hex,
                        thread_id,
                    });
                }
                break;
            }
        }
    }

    if local_count > 0 {
        attempts.fetch_add(local_count, Ordering::Relaxed);
    }
}

/// 定时打印速度与预估剩余时间
fn print_progress(stop: Arc<AtomicBool>, attempts: Arc<AtomicU64>, started: Instant) {
    let mut last_attempts = 0u64;
    let mut last_instant = Instant::now();

    while !stop.load(Ordering::Relaxed) {
        thread::sleep(Duration::from_secs(2));
        if stop.load(Ordering::Relaxed) {
            break;
        }

        let now = Instant::now();
        let total = attempts.load(Ordering::Relaxed);
        let dt = now.duration_since(last_instant).as_secs_f64().max(0.001);
        let instant_rate = (total - last_attempts) as f64 / dt;
        let overall_rate = total as f64 / started.elapsed().as_secs_f64().max(0.001);

        eprint!(
            "\r已尝试 {:12} | 瞬时 {:>10.0} keys/s | 平均 {:>10.0} keys/s",
            total, instant_rate, overall_rate
        );
        let _ = std::io::stderr().flush();

        last_attempts = total;
        last_instant = now;
    }
    eprintln!();
}

/// 追加一行到结果文件
fn append_line(path: &str, line: &str) -> std::io::Result<()> {
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    file.write_all(line.as_bytes())?;
    file.flush()?;
    Ok(())
}
