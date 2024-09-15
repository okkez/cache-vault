create table if not exists entries (
  id integer primary key autoincrement not null
  , namespace text not null
  , key_name text not null
  , nonce blob not null
  , encrypted_value blob not null
  , created_at timestamp not null
  , updated_at timestamp not null
  , expired_at timestamp
);
