-- =============================================================================
-- Google Earth Web Security Sampling - Incident Investigation SQL Queries
-- Skema disesuaikan dengan dataset simulasi: data/simulated_earth_logs.csv
-- =============================================================================

-- 1. Definisi Tabel Log (PostgreSQL / Standard ANSI SQL)
CREATE TABLE IF NOT EXISTS earth_security_logs (
    event_id        INT PRIMARY KEY,
    event_timestamp TIMESTAMP NOT NULL,
    user_email      VARCHAR(255) NOT NULL,
    source_ip       VARCHAR(45) NOT NULL,
    action          VARCHAR(100) NOT NULL
);

-- 2. Deteksi Anomali: Ekspor KML Massal & Perubahan Izin di Luar Jam Kerja (00:00-05:00)
SELECT
    user_email,
    source_ip,
    action,
    COUNT(event_id) AS total_actions,
    MIN(event_timestamp) AS first_seen,
    MAX(event_timestamp) AS last_seen
FROM
    earth_security_logs
WHERE
    action IN ('EXPORT_KML', 'CHANGE_SHARE_PERMISSION')
    AND EXTRACT(HOUR FROM event_timestamp) BETWEEN 0 AND 5
GROUP BY
    user_email,
    source_ip,
    action
HAVING
    COUNT(event_id) >= 5
ORDER BY
    total_actions DESC;

-- 3. Rekonstruksi Lini Masa (Timeline) untuk Aktor Mencurigakan
SELECT
    event_id,
    event_timestamp,
    user_email,
    source_ip,
    action
FROM
    earth_security_logs
WHERE
    source_ip = '203.0.113.45'
ORDER BY
    event_timestamp ASC;