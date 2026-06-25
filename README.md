# Passmngr

A custom terminal-based password manager.

To use it on Linux or Windows, compile the project and copy the application folder to a location of your choice. Then, create an environment variable named PASSMNGR that points to the application's directory.

Once configured, you can run the commands shown above directly from your terminal by replacing 'cargo run' with 'passmngr'.

## Commands

Initialize and create vault.json encrypted with master password:

```bash
cargo run init
```

Add an entry (interactive prompts):

```bash
cargo run add <name>
```

Show an entry:

```bash
cargo run get <name>
```

List all entries:

```bash
cargo run list
```

Delete an entry:

```bash
cargo run delete <name>
```

Update an entry (interactive with defaults):

```bash
cargo run update <name>
```

## Usage

Run this command to see usage:

```bash
cargo run -- --help
```
