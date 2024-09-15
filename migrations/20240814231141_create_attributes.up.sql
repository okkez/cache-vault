create table if not exists attributes (
  id integer primary key autoincrement not null
  , entry_id integer not null references entries(id)
  , name text not null
  , nonce blob not null
  , encrypted_value blob not null
  , hashed_value blob not null
  , created_at timestamp not null
  , updated_at timestamp not null
);
