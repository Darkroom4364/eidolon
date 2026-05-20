use std::{
    fs::{File, OpenOptions},
    io::{self, BufWriter, Write},
    path::Path,
};

use serde_json::Value;

pub type FileDebugLogWriter = DebugLogWriter<BufWriter<File>>;

pub struct DebugLogWriter<W> {
    sink: W,
}

impl FileDebugLogWriter {
    pub fn open(path: impl AsRef<Path>) -> io::Result<Self> {
        let file = OpenOptions::new().create(true).append(true).open(path)?;

        #[cfg(unix)]
        {
            use std::{fs, os::unix::fs::PermissionsExt};

            file.set_permissions(fs::Permissions::from_mode(0o600))?;
        }

        Ok(Self::new(BufWriter::new(file)))
    }
}

impl<W: Write> DebugLogWriter<W> {
    pub fn new(sink: W) -> Self {
        Self { sink }
    }

    pub fn write_record(&mut self, record: &Value) -> io::Result<()> {
        let serialized = serde_json::to_vec(record).map_err(|err| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("failed to serialize debug record as JSON: {err}"),
            )
        })?;

        self.sink.write_all(&serialized)?;
        self.sink.write_all(b"\n")?;
        self.sink.flush()
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
            .write_record(&json!({"event": "request_received"}))
            .expect("record should write");
        writer
            .write_record(&json!({"event": "response_served"}))
            .expect("record should write");

        let rendered = String::from_utf8(output).expect("output should be utf8");
        let lines = rendered.lines().collect::<Vec<_>>();
        assert_eq!(lines.len(), 2);

        let first: Value = serde_json::from_str(lines[0]).expect("first line should be json");
        let second: Value = serde_json::from_str(lines[1]).expect("second line should be json");
        assert_eq!(first["event"], "request_received");
        assert_eq!(second["event"], "response_served");
    }

    #[test]
    fn write_errors_propagate() {
        let mut writer = DebugLogWriter::new(FailingSink);

        let error = writer
            .write_record(&json!({"event": "request_received"}))
            .expect_err("sink error should propagate");

        assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
        assert_eq!(error.to_string(), "sink closed");
    }

    struct FailingSink;

    impl Write for FailingSink {
        fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
            Err(io::Error::new(io::ErrorKind::BrokenPipe, "sink closed"))
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
}
