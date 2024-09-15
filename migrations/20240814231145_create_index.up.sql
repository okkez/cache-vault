create index if not exists index_namespace_on_entries on entries (namespace);
create unique index if not exists index_ns_kn_on_entries on entries (namespace, key_name);
create index if not exists index_expired_at_on_entries on entries (expired_at);

create index if not exists index_entry_id_on_attributes on attributes (entry_id);
create unique index if not exists index_entry_id_name_on_attributes on attributes (entry_id, name);
create index if not exists index_name_and_encrypted_value_on_attributes on attributes (name, encrypted_value);

