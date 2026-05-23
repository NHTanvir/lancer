//! Tiny cron-style scheduler.
//!
//! Supports a simplified 5-field cron expression (min, hour, dom, mon, dow)
//! and runs registered jobs at next-match resolution of one minute.

use std::sync::Arc;

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use chrono::{DateTime, Datelike, TimeZone, Timelike, Utc};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[async_trait]
pub trait Job: Send + Sync {
    async fn run(&self) -> Result<()>;
    fn name(&self) -> &str;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScheduledJob {
    pub id: Uuid,
    pub name: String,
    pub cron: String,
}

#[derive(Default)]
pub struct Scheduler {
    jobs: Arc<RwLock<Vec<(ScheduledJob, Arc<dyn Job>)>>>,
}

impl Scheduler {
    pub fn new() -> Self { Self::default() }

    pub fn register(&self, cron: impl Into<String>, job: Arc<dyn Job>) -> Uuid {
        let sj = ScheduledJob { id: Uuid::new_v4(), name: job.name().to_string(), cron: cron.into() };
        let id = sj.id;
        self.jobs.write().push((sj, job));
        id
    }

    pub fn list(&self) -> Vec<ScheduledJob> {
        self.jobs.read().iter().map(|(sj, _)| sj.clone()).collect()
    }

    /// Run forever; uses 60-second tick alignment.
    pub async fn run_forever(self) {
        let mut last_minute: Option<DateTime<Utc>> = None;
        loop {
            let now = Utc::now();
            let this_min = Utc.with_ymd_and_hms(now.year(), now.month(), now.day(), now.hour(), now.minute(), 0).unwrap();
            if Some(this_min) != last_minute {
                last_minute = Some(this_min);
                let snapshot = self.jobs.read().clone();
                for (sj, job) in snapshot {
                    if let Ok(true) = matches_cron(&sj.cron, this_min) {
                        let job = job.clone();
                        let name = sj.name.clone();
                        tokio::spawn(async move {
                            if let Err(e) = job.run().await {
                                tracing::warn!("scheduled job `{name}` failed: {e}");
                            }
                        });
                    }
                }
            }
            tokio::time::sleep(std::time::Duration::from_secs(20)).await;
        }
    }
}

/// Returns true iff `t` matches the cron expression. Fields:
/// minute (0-59), hour (0-23), day-of-month (1-31), month (1-12), day-of-week (0-6, Sun=0).
/// Supports `*`, lists `1,2,3`, ranges `1-5`, and step `*/15`.
pub fn matches_cron(expr: &str, t: DateTime<Utc>) -> Result<bool> {
    let fields: Vec<&str> = expr.split_whitespace().collect();
    if fields.len() != 5 {
        return Err(anyhow!("cron needs 5 fields"));
    }
    Ok(matches_field(fields[0], t.minute() as u32, 0, 59)?
        && matches_field(fields[1], t.hour() as u32, 0, 23)?
        && matches_field(fields[2], t.day() as u32, 1, 31)?
        && matches_field(fields[3], t.month() as u32, 1, 12)?
        && matches_field(fields[4], t.weekday().num_days_from_sunday(), 0, 6)?)
}

fn matches_field(spec: &str, v: u32, lo: u32, hi: u32) -> Result<bool> {
    for piece in spec.split(',') {
        let (range, step) = match piece.split_once('/') {
            Some((r, s)) => (r, s.parse::<u32>().unwrap_or(1).max(1)),
            None => (piece, 1),
        };
        let (start, end) = if range == "*" {
            (lo, hi)
        } else if let Some((a, b)) = range.split_once('-') {
            (a.parse()?, b.parse()?)
        } else {
            let n: u32 = range.parse()?;
            (n, n)
        };
        if v >= start && v <= end && (v - start) % step == 0 {
            return Ok(true);
        }
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cron_minute_match() {
        let t = Utc.with_ymd_and_hms(2026, 1, 5, 10, 15, 0).unwrap(); // Mon
        assert!(matches_cron("15 10 * * *", t).unwrap());
        assert!(matches_cron("*/15 * * * *", t).unwrap());
        assert!(matches_cron("0 10 * * *", t).unwrap() == false);
        assert!(matches_cron("* * * * 1", t).unwrap()); // Monday
    }
}
