# Tic Tac Toe Database

This directory contains migration/setup scripts for the Tic Tac Toe backend.

### Database Schema Overview

- **users**: Stores user info and password hashes for authentication.
- **game_sessions**: One row per game. Tracks players (X/O), status, and winner.
- **moves**: Lists all moves made in each game by move order and board position.
- **player_statistics**: Aggregated stats (played/won/lost/drawn) per user for leaderboards.

### How to Set Up

To initialize the database, run the SQL script:

```bash
psql -U <username> -d <dbname> -f tic_tac_toe_database/init.sql
```

Replace `<username>` and `<dbname>` as appropriate for your setup.

### Backend Integration

- The FastAPI backend should use this schema for login, registration, game play, fetching game histories, and updating player stats.
- Foreign key constraints ensure referential integrity, and indexing is provided for query efficiency.

---
