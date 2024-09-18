# kerberos-simple

A simple Kerberos implementation

## Steps to run example:

### Step 1

Open new terminal

```bash
cd kerberos_app_srv
cargo run
```

### Step 2

Open new terminal

```bash
cd kerberos_kdc
cargo run
```

### Step 3

Open new terminal

```bash
cd client_ui
cargo run -- get-ticket --target-principal "MYREALM.COM" --transport tcp --target-realm "MYREALM.COM" --as-server-address "127.0.0.1:8088" --tgs-server-address "127.0.0.1:8089" --password 'uJV4sOr09XwCdIIjKjB7CV3zZdBmWVRt'
```

### Step 4

In `client_ui`, run:

```bash
cargo run -- send-ap-req --server-address '127.0.0.1:8080'
```
