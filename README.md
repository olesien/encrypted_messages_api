```sql
CREATE TABLE users (
    id SERIAL NOT NULL PRIMARY KEY,
    name VARCHAR(250) NOT NULL,
    email VARCHAR(250) NOT NULL,
    password TEXT NOT NULL
);
CREATE TABLE encrypted_messages (
    id SERIAL NOT NULL PRIMARY KEY,
    userid INT NOT NULL REFERENCES users(id),
    message TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
ALTER TABLE encrypted_messages ADD COLUMN title TEXT NOT NULL; 
```
