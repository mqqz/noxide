#[path = "src/search/build.rs"]
mod search_build;

fn main() {
    search_build::verify();
}
