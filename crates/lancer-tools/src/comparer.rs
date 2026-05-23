//! Word + byte diff (Comparer). Full implementation comes in commit 2.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiffMode {
    Bytes,
    Words,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiffOp {
    Equal(String),
    Insert(String),
    Delete(String),
}

pub struct Comparer;

impl Comparer {
    pub fn diff(a: &str, b: &str, mode: DiffMode) -> Vec<DiffOp> {
        match mode {
            DiffMode::Bytes => Self::diff_bytes(a, b),
            DiffMode::Words => Self::diff_words(a, b),
        }
    }

    fn diff_bytes(a: &str, b: &str) -> Vec<DiffOp> {
        Self::lcs_diff(&a.chars().map(|c| c.to_string()).collect::<Vec<_>>(),
                      &b.chars().map(|c| c.to_string()).collect::<Vec<_>>())
    }

    fn diff_words(a: &str, b: &str) -> Vec<DiffOp> {
        Self::lcs_diff(
            &a.split_whitespace().map(|s| s.to_string()).collect::<Vec<_>>(),
            &b.split_whitespace().map(|s| s.to_string()).collect::<Vec<_>>(),
        )
    }

    fn lcs_diff(a: &[String], b: &[String]) -> Vec<DiffOp> {
        let n = a.len();
        let m = b.len();
        let mut dp = vec![vec![0u32; m + 1]; n + 1];
        for i in 0..n {
            for j in 0..m {
                dp[i + 1][j + 1] = if a[i] == b[j] {
                    dp[i][j] + 1
                } else {
                    dp[i + 1][j].max(dp[i][j + 1])
                };
            }
        }
        let mut out = Vec::new();
        let mut i = n;
        let mut j = m;
        while i > 0 && j > 0 {
            if a[i - 1] == b[j - 1] {
                out.push(DiffOp::Equal(a[i - 1].clone()));
                i -= 1;
                j -= 1;
            } else if dp[i - 1][j] >= dp[i][j - 1] {
                out.push(DiffOp::Delete(a[i - 1].clone()));
                i -= 1;
            } else {
                out.push(DiffOp::Insert(b[j - 1].clone()));
                j -= 1;
            }
        }
        while i > 0 {
            out.push(DiffOp::Delete(a[i - 1].clone()));
            i -= 1;
        }
        while j > 0 {
            out.push(DiffOp::Insert(b[j - 1].clone()));
            j -= 1;
        }
        out.reverse();
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn word_diff() {
        let d = Comparer::diff("the quick brown fox", "the slow brown fox", DiffMode::Words);
        assert!(d.iter().any(|op| matches!(op, DiffOp::Delete(s) if s == "quick")));
        assert!(d.iter().any(|op| matches!(op, DiffOp::Insert(s) if s == "slow")));
    }
}
