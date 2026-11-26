//! The Prometheus text exposition format, version 0.0.4.

use std::time::Duration;

/// Builds an exposition, one metric family at a time.
#[derive(Default)]
pub(super) struct Encoder {
    out: String,
}

/// A metric family whose HELP and TYPE lines are written; its samples follow.
pub(super) struct Family<'a> {
    out: &'a mut String,
    name: &'static str,
}

/// A sample's value.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(super) enum Value {
    Int(u64),
    Float(f64),
}

impl Encoder {
    /// Start a counter family; its name ends in `_total`.
    pub(super) fn counter(&mut self, name: &'static str, help: &str) -> Family<'_> {
        self.family(name, "counter", help)
    }

    /// Start a gauge family.
    pub(super) fn gauge(&mut self, name: &'static str, help: &str) -> Family<'_> {
        self.family(name, "gauge", help)
    }

    fn family(&mut self, name: &'static str, kind: &str, help: &str) -> Family<'_> {
        for (line, text) in [("# HELP ", escape_help(help)), ("# TYPE ", kind.to_owned())] {
            self.out.push_str(line);
            self.out.push_str(name);
            self.out.push(' ');
            self.out.push_str(&text);
            self.out.push('\n');
        }
        Family { out: &mut self.out, name }
    }

    /// The finished exposition.
    pub(super) fn finish(self) -> String {
        self.out
    }
}

impl Family<'_> {
    /// Write the family's one unlabelled sample.
    pub(super) fn value(&mut self, value: impl Into<Value>) -> &mut Self {
        self.sample(&[], value)
    }

    /// Write one sample with these labels.
    pub(super) fn sample(&mut self, labels: &[(&str, &str)], value: impl Into<Value>) -> &mut Self {
        self.out.push_str(self.name);
        if !labels.is_empty() {
            self.out.push('{');
            for (i, (name, value)) in labels.iter().enumerate() {
                if i > 0 {
                    self.out.push(',');
                }
                self.out.push_str(name);
                self.out.push_str("=\"");
                push_label_value(self.out, value);
                self.out.push('"');
            }
            self.out.push('}');
        }
        self.out.push(' ');
        self.out.push_str(&value.into().to_string());
        self.out.push('\n');
        self
    }
}

/// HELP text escapes backslashes and line feeds.
fn escape_help(help: &str) -> String {
    help.replace('\\', "\\\\").replace('\n', "\\n")
}

/// Label values escape backslashes, double quotes and line feeds.
fn push_label_value(out: &mut String, value: &str) {
    for c in value.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            c => out.push(c),
        }
    }
}

impl std::fmt::Display for Value {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Value::Int(n) => write!(f, "{n}"),
            Value::Float(x) if x.is_nan() => f.write_str("NaN"),
            Value::Float(x) if x.is_infinite() => {
                f.write_str(if x > 0.0 { "+Inf" } else { "-Inf" })
            }
            Value::Float(x) => write!(f, "{x}"),
        }
    }
}

impl From<u64> for Value {
    fn from(n: u64) -> Self {
        Value::Int(n)
    }
}

impl From<usize> for Value {
    fn from(n: usize) -> Self {
        Value::Int(n as u64)
    }
}

impl From<bool> for Value {
    fn from(b: bool) -> Self {
        Value::Int(u64::from(b))
    }
}

impl From<f64> for Value {
    fn from(x: f64) -> Self {
        Value::Float(x)
    }
}

/// A duration, or a timestamp as the time since the Unix epoch, in seconds.
impl From<Duration> for Value {
    fn from(d: Duration) -> Self {
        Value::Float(d.as_secs_f64())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_help_type_and_samples_exactly() {
        let mut enc = Encoder::default();
        enc.counter("x_total", "Things done.\nBy \\ kind.")
            .sample(&[("kind", "a\"b"), ("peer", "c\\d\ne")], 3u64)
            .sample(&[("kind", "plain"), ("peer", "p")], 0u64);
        enc.gauge("y_seconds", "Some time.")
            .value(Duration::from_millis(1500))
            .value(true)
            .value(f64::INFINITY)
            .value(f64::NAN)
            .value(1_764_158_400.0);
        assert_eq!(
            enc.finish(),
            "# HELP x_total Things done.\\nBy \\\\ kind.\n\
             # TYPE x_total counter\n\
             x_total{kind=\"a\\\"b\",peer=\"c\\\\d\\ne\"} 3\n\
             x_total{kind=\"plain\",peer=\"p\"} 0\n\
             # HELP y_seconds Some time.\n\
             # TYPE y_seconds gauge\n\
             y_seconds 1.5\n\
             y_seconds 1\n\
             y_seconds +Inf\n\
             y_seconds NaN\n\
             y_seconds 1764158400\n"
        );
    }
}
