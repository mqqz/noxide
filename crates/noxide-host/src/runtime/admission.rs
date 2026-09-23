use anyhow::{Result, ensure};

pub(super) fn check(bytes: &[u8]) -> Result<()> {
    ensure!(
        bytes.starts_with(b"\0asm\x0d\0\x01\0") && bytes.len() <= 2 * 1024 * 1024,
        "not an admitted portable component"
    );
    let mut functions = 0u32;
    let mut operators = 0usize;
    for payload in wasmparser::Parser::new(0).parse_all(bytes) {
        let payload = payload?;
        match payload {
            wasmparser::Payload::FunctionSection(s) => {
                functions = functions
                    .checked_add(s.count())
                    .ok_or_else(|| anyhow::anyhow!("function limit"))?;
                ensure!(functions <= 4096, "function limit");
            }
            wasmparser::Payload::CodeSectionEntry(body) => {
                let reader = body.get_operators_reader()?;
                for op in reader {
                    op?;
                    operators += 1;
                    ensure!(operators <= 500_000, "code limit");
                }
            }
            wasmparser::Payload::ComponentCanonicalSection(section) => {
                for function in section {
                    match function? {
                        wasmparser::CanonicalFunction::Lift { options, .. }
                        | wasmparser::CanonicalFunction::Lower { options, .. } => {
                            ensure!(
                                !options.iter().any(|o| matches!(
                                    o,
                                    wasmparser::CanonicalOption::PostReturn(_)
                                        | wasmparser::CanonicalOption::Async
                                        | wasmparser::CanonicalOption::Callback(_)
                                        | wasmparser::CanonicalOption::Gc
                                )),
                                "unsupported canonical cleanup or concurrency"
                            );
                        }
                        _ => anyhow::bail!("unsupported canonical resource or concurrency"),
                    }
                }
            }
            _ => {}
        }
    }
    Ok(())
}
