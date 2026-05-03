-- H6: per-version batch metrics for B1/E1 analysis.
ALTER TABLE batch_jobs ADD COLUMN method_duration_sec REAL;
ALTER TABLE batch_jobs ADD COLUMN relocate_max_outlier_delta INTEGER;
