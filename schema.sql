CREATE TABLE IF NOT EXISTS profiles (
  owner_id TEXT NOT NULL,
  profile_id TEXT NOT NULL,
  name TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (owner_id, profile_id)
);

CREATE TABLE IF NOT EXISTS profile_data (
  owner_id TEXT NOT NULL,
  profile_id TEXT NOT NULL,
  json TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (owner_id, profile_id)
);

CREATE INDEX IF NOT EXISTS idx_profiles_owner_updated
ON profiles(owner_id, updated_at);
