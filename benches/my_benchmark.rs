
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use vats::signing;

pub fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("keygen 5,5", |b| b.iter(|| signing::key_dealer::dealer(black_box(5), black_box(5))));
    // c.bench_function("fib 20", |b| b.iter(|| fibonacci(black_box(20))));
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);