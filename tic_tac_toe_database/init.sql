-- Tic Tac Toe Database Schema Initialization

-- USERS TABLE: Stores user account information and authentication credentials.
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(64) UNIQUE NOT NULL,
    password_hash VARCHAR(128) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP
);

-- GAME SESSIONS: Each row represents an active/completed game between two players.
CREATE TABLE IF NOT EXISTS game_sessions (
    id SERIAL PRIMARY KEY,
    player_x_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    player_o_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    status VARCHAR(16) NOT NULL CHECK (status IN ('in_progress', 'completed', 'abandoned')),
    winner_id INTEGER REFERENCES users(id),
    started_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    ended_at TIMESTAMP
);

-- MOVE HISTORY: Stores every move made (one per row) in each game.
CREATE TABLE IF NOT EXISTS moves (
    id SERIAL PRIMARY KEY,
    game_session_id INTEGER NOT NULL REFERENCES game_sessions(id) ON DELETE CASCADE,
    player_id INTEGER NOT NULL REFERENCES users(id),
    move_num INTEGER NOT NULL,
    position_x INTEGER NOT NULL CHECK (position_x >= 0 AND position_x <= 2),
    position_y INTEGER NOT NULL CHECK (position_y >= 0 AND position_y <= 2),
    value CHAR(1) NOT NULL CHECK (value IN ('X', 'O')),
    move_time TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(game_session_id, move_num)
);

-- PLAYER STATISTICS: Aggregated stats for each player.
CREATE TABLE IF NOT EXISTS player_statistics (
    user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    games_played INTEGER NOT NULL DEFAULT 0,
    games_won INTEGER NOT NULL DEFAULT 0,
    games_lost INTEGER NOT NULL DEFAULT 0,
    games_drawn INTEGER NOT NULL DEFAULT 0
);

-- INDEXES FOR PERFORMANCE
CREATE INDEX IF NOT EXISTS idx_moves_game ON moves(game_session_id);
CREATE INDEX IF NOT EXISTS idx_game_sessions_status ON game_sessions(status);
