CREATE TABLE IF NOT EXISTS popular_packages (
    ecosystem      TEXT NOT NULL,
    name           TEXT NOT NULL,
    rank           INTEGER NOT NULL,
    download_count INTEGER,
    last_updated   TIMESTAMP WITH TIME ZONE NOT NULL,
    PRIMARY KEY (ecosystem, name)
);

CREATE INDEX IF NOT EXISTS idx_popular_packages_ecosystem ON popular_packages(ecosystem, rank);
