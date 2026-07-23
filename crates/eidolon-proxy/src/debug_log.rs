use std::{
    fs::{File, OpenOptions},
    io::{self, BufWriter, Write},
    path::{Path, PathBuf},
};

use serde_json::Value;

use crate::event_log::{
    repair_jsonl_tail, report_jsonl_tail_repair, rotate_log_if_oversized, rotate_log_now,
    JsonlTailRepairOutcome, LOG_ROTATE_BYTES,
};

pub type FileDebugLogWriter = DebugLogWriter<BufWriter<File>>;

pub struct DebugLogWriter<W> {
    sink: W,
    reopen: Option<Box<dyn Fn() -> io::Result<W> + Send + Sync>>,
    path: Option<PathBuf>,
    current_len: u64,
    startup_tail_repair: JsonlTailRepairOutcome,
}

impl FileDebugLogWriter {
    pub fn open(path: impl AsRef<Path>) -> io::Result<Self> {
        let startup_tail_repair = repair_jsonl_tail(path.as_ref())?;
        report_jsonl_tail_repair("debug", path.as_ref(), startup_tail_repair);

        if let Some(archive) = rotate_log_if_oversized(path.as_ref())? {
            eprintln!(
                "eidolon log rotation: archived oversized debug log to {}",
                archive.display()
            );
        }

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path.as_ref())?;

        #[cfg(unix)]
        {
            use std::{fs, os::unix::fs::PermissionsExt};

            file.set_permissions(fs::Permissions::from_mode(0o600))?;
        }

        let current_len = std::fs::metadata(path.as_ref())
            .map(|metadata| metadata.len())
            .unwrap_or(0);
        let path = path.as_ref().to_path_buf();
        let reopen_path = path.clone();

        Ok(Self {
            sink: BufWriter::new(file),
            reopen: Some(Box::new(move || {
                let file = OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&reopen_path)?;

                #[cfg(unix)]
                {
                    use std::{fs, os::unix::fs::PermissionsExt};

                    file.set_permissions(fs::Permissions::from_mode(0o600))?;
                }

                Ok(BufWriter::new(file))
            })),
            path: Some(path),
            current_len,
            startup_tail_repair,
        })
    }
}

impl<W: Write> DebugLogWriter<W> {
    pub fn new(sink: W) -> Self {
        Self {
            sink,
            reopen: None,
            path: None,
            current_len: 0,
            startup_tail_repair: JsonlTailRepairOutcome::NotNeeded,
        }
    }

    pub fn startup_tail_repair(&self) -> JsonlTailRepairOutcome {
        self.startup_tail_repair
    }

    pub fn write_record(&mut self, record: &Value) -> io::Result<()> {
        let serialized = serde_json::to_vec(record).map_err(|err| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("failed to serialize debug record as JSON: {err}"),
            )
        })?;

        self.rotate_if_needed(serialized.len() as u64 + 1)?;
        self.sink.write_all(&serialized)?;
        self.sink.write_all(b"\n")?;
        self.current_len += serialized.len() as u64 + 1;
        self.sink.flush()
    }

    fn rotate_if_needed(&mut self, incoming: u64) -> io::Result<()> {
        let (Some(path), Some(reopen)) = (self.path.clone(), self.reopen.as_ref()) else {
            return Ok(());
        };
        if self.current_len + incoming <= LOG_ROTATE_BYTES {
            return Ok(());
        }

        self.sink.flush()?;
        let archive = rotate_log_now(&path)?;
        eprintln!(
            "eidolon log rotation: archived debug log to {}",
            archive.display()
        );

        self.sink = reopen()?;
        self.current_len = 0;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::io::{self, Write};

    use serde_json::{json, Value};

    use super::DebugLogWriter;

    #[test]
    fn writes_one_record_per_jsonl_line() {
        let mut output = Vec::new();
        let mut writer = DebugLogWriter::new(&mut output);
        writer
            .write_record(&json!({"a": 1}))
            .expect("first record should write");
        writer
            .write_record(&json!({"b": 2}))
            .expect("second record should write");
        drop(writer);

        let rendered = String::from_utf8(output).expect("output should be utf8");
        let lines: Vec<Value> = rendered
            .lines()
            .map(|line| serde_json::from_str(line).expect("line should parse"))
            .collect();
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0]["a"], 1);
        assert_eq!(lines[1]["b"], 2);
    }

    #[test]
    fn write_errors_propagate() {
        struct FailingWriter;
        impl Write for FailingWriter {
            fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
                Err(io::Error::other("write failed"))
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }

        let mut writer = DebugLogWriter::new(FailingWriter);
        let error = writer
            .write_record(&json!({"a": 1}))
            .expect_err("write failure should propagate");
        assert_eq!(error.to_string(), "write failed");
    }

    #[test]
    fn debug_log_repairs_invalid_tail_before_append() {
        use std::fs;

        let path = unique_debug_temp_path("invalid-tail.jsonl");
        fs::write(&path, b"{\"first\":true}\n{\"partial\":").expect("torn debug log should write");

        let mut writer = super::FileDebugLogWriter::open(&path).expect("debug log should repair");
        assert!(matches!(
            writer.startup_tail_repair(),
            crate::event_log::JsonlTailRepairOutcome::Truncated { .. }
        ));
        writer
            .write_record(&json!({"second": true}))
            .expect("record should append");
        drop(writer);

        let lines = fs::read_to_string(&path)
            .expect("debug log should read")
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).expect("line should be valid JSON"))
            .collect::<Vec<_>>();
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0]["first"], true);
        assert_eq!(lines[1]["second"], true);

        fs::remove_file(path).expect("debug log should remove");
    }

    #[test]
    fn oversized_debug_log_rotates_on_open() {
        use std::fs;

        let path = unique_debug_temp_path("oversized.jsonl");
        let oversized = vec![b'x'; (crate::event_log::LOG_ROTATE_BYTES + 1) as usize];
        fs::write(&path, &oversized).expect("oversized log should write");

        let _writer = super::FileDebugLogWriter::open(&path).expect("debug log should open");

        let active = fs::metadata(&path)
            .expect("active log metadata should read")
            .len();
        assert_eq!(active, 0, "oversized log must rotate to a fresh segment");

        std::fs::remove_file(&path).expect("active log should remove");
        let prefix = format!("{}.", path.display());
        for archive in std::fs::read_dir(path.parent().expect("temp dir"))
            .expect("temp dir should read")
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.path())
            .filter(|candidate| candidate.to_string_lossy().starts_with(&prefix))
        {
            std::fs::remove_file(archive).expect("archive should remove");
        }
    }

    #[test]
    fn write_beyond_budget_rotates_mid_run_and_keeps_appending() {
        use std::fs;

        let path = unique_debug_temp_path("mid-run-rotate.jsonl");
        let mut writer = super::FileDebugLogWriter::open(&path).expect("debug log should open");
        writer.current_len = crate::event_log::LOG_ROTATE_BYTES;

        writer
            .write_record(&json!({"rotation": "first"}))
            .expect("record should write and rotate");
        writer
            .write_record(&json!({"rotation": "second"}))
            .expect("record should append after rotation");

        let active_content = fs::read_to_string(&path).expect("active log should read");
        assert!(active_content.contains("first"));
        assert!(active_content.contains("second"));

        let prefix = format!("{}.", path.display());
        let archives: Vec<_> = fs::read_dir(path.parent().expect("temp dir"))
            .expect("temp dir should read")
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.path())
            .filter(|candidate| {
                candidate.to_string_lossy().starts_with(&prefix) && candidate != &path
            })
            .collect();
        assert_eq!(archives.len(), 1, "one rotated archive must exist");

        fs::remove_file(&path).expect("active log should remove");
        fs::remove_file(&archives[0]).expect("archive should remove");
    }

    #[test]
    fn current_len_tracks_written_bytes_and_resets_on_rotation() {
        use std::fs;

        let mut output = Vec::new();
        let mut writer = DebugLogWriter::new(&mut output);
        assert_eq!(writer.current_len, 0);

        writer
            .write_record(&json!({"a": 1}))
            .expect("record should write");
        let first_len = writer.current_len;
        assert_eq!(
            first_len, 8,
            "one 7-byte record plus its newline must be tracked exactly"
        );
        writer
            .write_record(&json!({"b": 2}))
            .expect("record should write");
        assert_eq!(writer.current_len, 16);
        drop(writer);

        let path = unique_debug_temp_path("bookkeeping.jsonl");
        let writer = super::FileDebugLogWriter::open(&path).expect("debug log should open");
        assert_eq!(
            writer.current_len, 0,
            "a fresh log must start at zero bytes tracked"
        );

        let mut writer = super::FileDebugLogWriter::open(&path).expect("debug log should open");
        writer.current_len = crate::event_log::LOG_ROTATE_BYTES;
        writer
            .write_record(&json!({"rotate": true}))
            .expect("record should write and rotate");
        assert_eq!(
            writer.current_len, 16,
            "rotation must reset the byte counter to exactly the fresh write's size"
        );

        fs::remove_file(&path).expect("active log should remove");
        let prefix = format!("{}.", path.display());
        for archive in fs::read_dir(path.parent().expect("temp dir"))
            .expect("temp dir should read")
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.path())
            .filter(|candidate| candidate.to_string_lossy().starts_with(&prefix))
        {
            fs::remove_file(archive).expect("archive should remove");
        }
    }

    fn unique_debug_temp_path(label: &str) -> std::path::PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock should be after epoch")
            .as_nanos();

        std::env::temp_dir().join(format!(
            "eidolon-debug-log-{label}-{}-{nanos}.jsonl",
            std::process::id()
        ))
    }
}
