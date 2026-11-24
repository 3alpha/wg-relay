use std::fmt;
use std::str::FromStr;

use serde::Deserialize;

use super::error::RateError;

/// Events per second, written "<n>/s" or "<n>/m" in the config.
#[derive(Debug, Clone, Copy, PartialEq, Deserialize)]
#[serde(try_from = "String")]
pub struct Rate {
    per_sec: f64,
}

impl Rate {
    pub fn per_sec(self) -> f64 {
        self.per_sec
    }
}

impl Default for Rate {
    fn default() -> Self {
        Rate { per_sec: 10.0 }
    }
}

impl FromStr for Rate {
    type Err = RateError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (n, unit) = s.trim().split_once('/').ok_or(RateError::MissingUnit)?;
        let n: f64 = n.trim().parse().map_err(|_| RateError::Number(n.trim().to_owned()))?;
        let secs = match unit.trim() {
            "s" => 1.0,
            "m" => 60.0,
            other => return Err(RateError::Unit(other.to_owned())),
        };
        if !(n.is_finite() && n > 0.0) {
            return Err(RateError::NotPositive);
        }
        Ok(Rate { per_sec: n / secs })
    }
}

impl TryFrom<String> for Rate {
    type Error = RateError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        s.parse()
    }
}

impl fmt::Display for Rate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/s", self.per_sec)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn per_sec(s: &str) -> Result<f64, RateError> {
        s.parse::<Rate>().map(Rate::per_sec)
    }

    #[test]
    fn parses_per_second_and_per_minute() {
        assert_eq!(per_sec("10/s"), Ok(10.0));
        assert_eq!(per_sec(" 120 / m "), Ok(2.0));
    }

    #[test]
    fn rejects_missing_unit_instead_of_defaulting() {
        assert_eq!(per_sec("10"), Err(RateError::MissingUnit));
    }

    #[test]
    fn rejects_bad_numbers_units_and_non_positive_rates() {
        assert_eq!(per_sec("0/s"), Err(RateError::NotPositive));
        assert_eq!(per_sec("-1/s"), Err(RateError::NotPositive));
        assert_eq!(per_sec("inf/s"), Err(RateError::NotPositive));
        assert_eq!(per_sec("x/s"), Err(RateError::Number("x".into())));
        assert_eq!(per_sec("10/h"), Err(RateError::Unit("h".into())));
    }
}
