// Owned test payload: no UI/network. The installer launches it without arguments.
fn main() {
    let executable = std::env::current_exe().unwrap();
    std::fs::write(executable.with_extension("updated"), b"new payload started").unwrap();
}
