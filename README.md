# OpenPAVE Mailchimp Skill

Access Mailchimp Marketing API for email campaigns, lists, and subscribers using the PAVE secure token system.

## Installation

```bash
pave install openpave-mailchimp
```

## Token Configuration

Add your Mailchimp API key to `~/.pave/tokens.yaml`:

```yaml
MAILCHIMP_API_KEY: "your-api-key-us21"
```

The token configuration should be in `~/.pave/permissions.yaml`:

```yaml
tokens:
  mailchimp:
    env: MAILCHIMP_API_KEY
    type: api_key
    domains:
      - "*.api.mailchimp.com"
    placement:
      type: header
      name: Authorization
      format: "Bearer {token}"
```

**Note:** The Mailchimp API key format is `key-datacenter` (e.g., `abc123def456-us21`). You need to pass the datacenter using `--dc` flag.

## Usage

All commands require the `--dc` flag to specify your Mailchimp datacenter.

### Account Info

```bash
# Verify API key and get account info
mailchimp ping --dc us21 --summary
```

### Lists/Audiences

```bash
# List all audiences
mailchimp lists --dc us21 --summary

# Get specific list details
mailchimp list b4cd77f0a4 --dc us21 --summary

# List with pagination
mailchimp lists --dc us21 --count 20 --offset 0 --summary
```

### Members/Subscribers

```bash
# List members in a list
mailchimp members b4cd77f0a4 --dc us21 --summary

# Filter by status
mailchimp members b4cd77f0a4 --dc us21 --status subscribed --count 50

# Get specific member by email
mailchimp member b4cd77f0a4 user@example.com --dc us21 --summary

# Search members across all lists
mailchimp search "john@example.com" --dc us21 --summary

# Add a new member
mailchimp add-member b4cd77f0a4 new@example.com --dc us21 --fname John --lname Doe --tags "newsletter,vip"
```

### Campaigns

```bash
# List campaigns
mailchimp campaigns --dc us21 --summary

# Filter by status
mailchimp campaigns --dc us21 --status sent --count 20

# Get campaign details
mailchimp campaign abc123 --dc us21 --summary

# Get campaign with HTML content
mailchimp campaign abc123 --dc us21 --content --summary
```

### Reports/Analytics

```bash
# Get campaign report
mailchimp report abc123 --dc us21 --summary

# Include click and open details
mailchimp report abc123 --dc us21 --clicks --opens --summary
```

### Tags

```bash
# List tags for a list
mailchimp tags b4cd77f0a4 --dc us21 --summary
```

### Automations

```bash
# List all automations
mailchimp automations --dc us21 --summary
```

## Command Reference

| Command | Description |
|---------|-------------|
| `ping` | Verify API key and get account info |
| `lists` | List all audiences/lists |
| `list <listId>` | Get a specific list/audience details |
| `members <listId>` | List members/subscribers of a list |
| `member <listId> <email>` | Get a specific member by email |
| `add-member <listId> <email>` | Add a new member to a list |
| `search <query>` | Search members across all lists |
| `campaigns` | List campaigns |
| `campaign <campaignId>` | Get a specific campaign |
| `report <campaignId>` | Get campaign report/analytics |
| `tags <listId>` | List tags for a list |
| `automations` | List all automations |

## Options

### Global Options

| Option | Description |
|--------|-------------|
| `--dc <datacenter>` | Mailchimp datacenter (required, e.g., us21) |
| `--json` | Raw JSON output |
| `--summary` | Human-readable summary (default) |

### List/Member Options

| Option | Description |
|--------|-------------|
| `-n, --count <number>` | Number of records to return (default: 10) |
| `--offset <number>` | Number of records to skip (default: 0) |
| `-s, --status <status>` | Filter by status |

### Campaign Options

| Option | Description |
|--------|-------------|
| `-s, --status <status>` | Filter by status: save, paused, schedule, sending, sent |
| `-t, --type <type>` | Filter by type: regular, plaintext, absplit, rss, variate |
| `--since <date>` | Filter by create date (ISO 8601) |
| `--before <date>` | Filter by create date (ISO 8601) |
| `--content` | Include campaign HTML content |

### Report Options

| Option | Description |
|--------|-------------|
| `--clicks` | Include click details |
| `--opens` | Include open details |

### Add-Member Options

| Option | Description |
|--------|-------------|
| `-s, --status <status>` | Status: subscribed, unsubscribed, pending |
| `--fname <name>` | First name |
| `--lname <name>` | Last name |
| `--tags <tags>` | Tags (comma-separated) |

## Member Status Values

| Status | Description |
|--------|-------------|
| `subscribed` | Active subscriber |
| `unsubscribed` | Opted out |
| `cleaned` | Hard bounce (invalid email) |
| `pending` | Awaiting confirmation |
| `transactional` | Transactional emails only |

## Campaign Status Values

| Status | Description |
|--------|-------------|
| `save` | Draft |
| `paused` | Paused |
| `schedule` | Scheduled |
| `sending` | Currently sending |
| `sent` | Completed |

## Finding Your Datacenter

Your datacenter is the last part of your API key, after the hyphen.

For example, if your API key is `abc123def456-us21`, your datacenter is `us21`.

## License

MIT
