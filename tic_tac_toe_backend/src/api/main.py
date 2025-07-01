import os
from fastapi import (
    FastAPI, Depends, HTTPException, status, WebSocket, WebSocketDisconnect
)
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from datetime import datetime, timedelta
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy import (
    create_engine, Column, Integer, String, DateTime, ForeignKey, CHAR,
    UniqueConstraint
)
from sqlalchemy.orm import sessionmaker, scoped_session, relationship, declarative_base
from typing import Optional, List, Dict, Any
import enum

# Setup for environment/config
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./test.db")
SECRET_KEY = os.getenv("SECRET_KEY", "tic-tac-toe-secret")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

Base = declarative_base()
engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {}
)
SessionLocal = scoped_session(
    sessionmaker(autocommit=False, autoflush=False, bind=engine)
)


class GameStatusEnum(str, enum.Enum):
    in_progress = "in_progress"
    completed = "completed"
    abandoned = "abandoned"


# --- SQLAlchemy ORM Models matching DB schema --- #


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    username = Column(String(64), unique=True, nullable=False)
    password_hash = Column(String(128), nullable=False)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    last_login = Column(DateTime)

    games_x = relationship("GameSession", foreign_keys="GameSession.player_x_id")
    games_o = relationship("GameSession", foreign_keys="GameSession.player_o_id")
    moves = relationship("Move", back_populates="player")
    stats = relationship(
        "PlayerStatistic", uselist=False, back_populates="user"
    )


class GameSession(Base):
    __tablename__ = "game_sessions"

    id = Column(Integer, primary_key=True)
    player_x_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    player_o_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    status = Column(String(16), nullable=False)
    winner_id = Column(Integer, ForeignKey("users.id"))
    started_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    ended_at = Column(DateTime)
    moves = relationship(
        "Move", back_populates="game", order_by="Move.move_num"
    )


class Move(Base):
    __tablename__ = "moves"
    __table_args__ = (
        UniqueConstraint('game_session_id', 'move_num', name='_game_move_uc'),
    )

    id = Column(Integer, primary_key=True)
    game_session_id = Column(Integer, ForeignKey("game_sessions.id"), nullable=False)
    player_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    move_num = Column(Integer, nullable=False)
    position_x = Column(Integer, nullable=False)
    position_y = Column(Integer, nullable=False)
    value = Column(CHAR(1), nullable=False)
    move_time = Column(DateTime, nullable=False, default=datetime.utcnow)

    player = relationship("User", back_populates="moves")
    game = relationship("GameSession", back_populates="moves")


class PlayerStatistic(Base):
    __tablename__ = "player_statistics"

    user_id = Column(Integer, ForeignKey("users.id"), primary_key=True)
    games_played = Column(Integer, nullable=False, default=0)
    games_won = Column(Integer, nullable=False, default=0)
    games_lost = Column(Integer, nullable=False, default=0)
    games_drawn = Column(Integer, nullable=False, default=0)

    user = relationship("User", back_populates="stats")


# --- Pydantic Schemas --- #
class UserCreate(BaseModel):
    username: str = Field(..., max_length=64)
    password: str = Field(..., min_length=5, max_length=128)


class UserLogin(UserCreate):
    pass


class UserPublic(BaseModel):
    id: int
    username: str

    class Config:
        orm_mode = True


class Token(BaseModel):
    access_token: str
    token_type: str


class GameCreate(BaseModel):
    opponent_username: str


class GamePublic(BaseModel):
    id: int
    player_x: UserPublic
    player_o: UserPublic
    status: GameStatusEnum
    winner: Optional[UserPublic]
    started_at: datetime
    ended_at: Optional[datetime]

    class Config:
        orm_mode = True


class MoveCreate(BaseModel):
    position_x: int = Field(..., ge=0, le=2)
    position_y: int = Field(..., ge=0, le=2)


class MovePublic(BaseModel):
    move_num: int
    position_x: int
    position_y: int
    value: str
    player_id: int
    move_time: datetime

    class Config:
        orm_mode = True


class GameState(BaseModel):
    id: int
    status: GameStatusEnum
    moves: List[MovePublic]
    next_turn_value: str
    winner: Optional[UserPublic] = None


class StatsPublic(BaseModel):
    games_played: int
    games_won: int
    games_lost: int
    games_drawn: int


# --- JWT / AUTH --- #
# PUBLIC_INTERFACE
def verify_password(plain_password, hashed_password):
    """Verifies a password against a hash."""
    return pwd_context.verify(plain_password, hashed_password)


# PUBLIC_INTERFACE
def get_password_hash(password):
    """Hashes a plaintext password."""
    return pwd_context.hash(password)


# PUBLIC_INTERFACE
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    """Creates a JWT access token."""
    to_encode = data.copy()
    expire = datetime.utcnow() + (
        expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


# PUBLIC_INTERFACE
def get_user_by_username(db, username: str) -> Optional[User]:
    """Fetch a user by username."""
    return db.query(User).filter(User.username == username).first()


# PUBLIC_INTERFACE
def authenticate_user(db, username: str, password: str):
    """Authenticate user credentials."""
    user = get_user_by_username(db, username)
    if user and verify_password(password, user.password_hash):
        return user
    return None


# PUBLIC_INTERFACE
def get_current_user(
    token: str = Depends(oauth2_scheme), db=Depends(lambda: SessionLocal())
):
    """Get the user from JWT token or raise 401."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials.",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = get_user_by_username(db, username=username)
    if user is None:
        raise credentials_exception
    return user


# -- CORS & FastAPI App -- #
openapi_tags = [
    {"name": "auth", "description": "Registration, login, user info"},
    {"name": "game", "description": "Game creation, moves, game state"},
    {"name": "stats", "description": "Player statistics, leaderboards"},
    {"name": "ws", "description": "WebSockets for real-time game updates"},
]

app = FastAPI(
    title="Tic Tac Toe Backend API",
    description=(
        "Backend API for a fullstack Tic Tac Toe game including registration, "
        "login, play, game state, and realtime updates."
    ),
    version="1.0.0",
    openapi_tags=openapi_tags,
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# --- DB Init --- #
def init_db():
    Base.metadata.create_all(bind=engine)


# --- Game Logic --- #
WINNING_PATTERNS = [
    [(0, 0), (0, 1), (0, 2)],
    [(1, 0), (1, 1), (1, 2)],
    [(2, 0), (2, 1), (2, 2)],
    [(0, 0), (1, 0), (2, 0)],
    [(0, 1), (1, 1), (2, 1)],
    [(0, 2), (1, 2), (2, 2)],
    [(0, 0), (1, 1), (2, 2)],
    [(0, 2), (1, 1), (2, 0)],
]


# PUBLIC_INTERFACE
def check_winner(moves: List[Move]):
    """Checks the list of moves for a winner."""
    board = [['' for _ in range(3)] for _ in range(3)]
    for mv in moves:
        board[mv.position_x][mv.position_y] = mv.value
    for pattern in WINNING_PATTERNS:
        values = [board[x][y] for x, y in pattern]
        if values[0] and all(val == values[0] for val in values):
            return values[0]  # 'X' or 'O'
    return None


def get_next_value(moves: List[Move]):
    """Determine whose turn next; X always first."""
    if len(moves) % 2 == 0:
        return 'X'
    else:
        return 'O'


def moves_to_schema(moves: List[Move]) -> List[MovePublic]:
    return [
        MovePublic(
            move_num=m.move_num,
            position_x=m.position_x,
            position_y=m.position_y,
            value=m.value,
            player_id=m.player_id,
            move_time=m.move_time,
        ) for m in moves
    ]


# --- WebSocket Management for Realtime Updates --- #
class ConnectionManager:
    """Keeps track of WebSocket connections for each game session."""

    def __init__(self):
        self.active_connections: Dict[int, List[WebSocket]] = {}

    async def connect(self, game_id: int, ws: WebSocket):
        await ws.accept()
        if game_id not in self.active_connections:
            self.active_connections[game_id] = []
        self.active_connections[game_id].append(ws)

    def disconnect(self, game_id: int, ws: WebSocket):
        self.active_connections[game_id].remove(ws)
        if not self.active_connections[game_id]:
            del self.active_connections[game_id]

    async def broadcast(self, game_id: int, message: Dict[str, Any]):
        for ws in self.active_connections.get(game_id, []):
            await ws.send_json(message)


manager = ConnectionManager()


# --- API Endpoints --- #
@app.on_event("startup")
def startup_event():
    """Initialize the DB on server startup."""
    init_db()


@app.get("/", summary="Healthcheck", tags=["health"])
def health_check():
    """Health check endpoint."""
    return {"status": "ok"}


# ----------- AUTH -----------
@app.post("/register", response_model=UserPublic, tags=["auth"])
def register(user: UserCreate):
    """Register a new user with username and password."""
    db = SessionLocal()
    try:
        if get_user_by_username(db, user.username):
            raise HTTPException(409, "Username already exists.")
        user_obj = User(
            username=user.username,
            password_hash=get_password_hash(user.password),
        )
        db.add(user_obj)
        db.commit()
        db.refresh(user_obj)
        stats = PlayerStatistic(user_id=user_obj.id)
        db.add(stats)
        db.commit()
        return UserPublic(id=user_obj.id, username=user_obj.username)
    finally:
        db.close()


@app.post("/token", response_model=Token, tags=["auth"])
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    """Log in user and return JWT."""
    db = SessionLocal()
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        db.close()
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    access_token = create_access_token({"sub": user.username})
    user.last_login = datetime.utcnow()
    db.commit()
    db.close()
    return Token(access_token=access_token, token_type="bearer")


@app.get("/me", response_model=UserPublic, tags=["auth"])
def get_me(current_user: User = Depends(get_current_user)):
    """Get current user info."""
    return UserPublic(id=current_user.id, username=current_user.username)


# ----------- GAME -----------
@app.post("/games", response_model=GamePublic, tags=["game"])
def start_game(game: GameCreate, current_user: User = Depends(get_current_user)):
    """
    Start a new game session vs another registered user.
    """
    db = SessionLocal()
    try:
        opponent = get_user_by_username(db, game.opponent_username)
        if not opponent or opponent.id == current_user.id:
            raise HTTPException(404, "Opponent not found or invalid.")
        game_sess = GameSession(
            player_x_id=current_user.id,
            player_o_id=opponent.id,
            status="in_progress"
        )
        db.add(game_sess)
        db.commit()
        db.refresh(game_sess)
        return GamePublic(
            id=game_sess.id,
            player_x=UserPublic(
                id=game_sess.player_x_id,
                username=current_user.username
            ),
            player_o=UserPublic(
                id=game_sess.player_o_id,
                username=opponent.username
            ),
            status=game_sess.status,
            winner=None,
            started_at=game_sess.started_at,
            ended_at=game_sess.ended_at,
        )
    finally:
        db.close()


@app.get("/games/{game_id}", response_model=GameState, tags=["game"])
def get_game(game_id: int, current_user: User = Depends(get_current_user)):
    """
    Get current state of a game (moves, whose turn, winner).
    """
    db = SessionLocal()
    try:
        game = db.query(GameSession).filter(GameSession.id == game_id).first()
        if not game:
            raise HTTPException(404, "Game not found")
        if current_user.id not in [game.player_x_id, game.player_o_id]:
            raise HTTPException(403, "Not a player of this game")
        moves = game.moves
        winner_val = check_winner(moves)
        winner_user = None
        if winner_val:
            winning_id = (
                game.player_x_id if winner_val == 'X' else game.player_o_id
            )
            winning_user = db.query(User).filter(
                User.id == winning_id
            ).first()
            winner_user = UserPublic(
                id=winning_id,
                username=winning_user.username if winning_user else ""
            )
        return GameState(
            id=game.id,
            status=game.status,
            moves=moves_to_schema(moves),
            next_turn_value=get_next_value(moves),
            winner=winner_user
        )
    finally:
        db.close()


@app.post("/games/{game_id}/move", response_model=GameState, tags=["game"])
def make_move(
    game_id: int, move: MoveCreate, current_user: User = Depends(get_current_user)
):
    """
    Make a move in a game; validates move legality and updates state.
    """
    db = SessionLocal()
    try:
        game = db.query(GameSession).filter(GameSession.id == game_id).first()
        if not game:
            raise HTTPException(404, "Game not found")
        if game.status != "in_progress":
            raise HTTPException(400, "Game already completed")
        if current_user.id not in [game.player_x_id, game.player_o_id]:
            raise HTTPException(403, "Not a player of this game")
        moves = game.moves
        next_value = get_next_value(moves)
        expected_player_id = (
            game.player_x_id if next_value == 'X' else game.player_o_id
        )
        if current_user.id != expected_player_id:
            raise HTTPException(400, "Not your turn")
        if any(
            m.position_x == move.position_x and m.position_y == move.position_y
            for m in moves
        ):
            raise HTTPException(400, "Cell already filled")
        if not (0 <= move.position_x <= 2 and 0 <= move.position_y <= 2):
            raise HTTPException(400, "Invalid board position")
        move_obj = Move(
            game_session_id=game.id,
            player_id=current_user.id,
            move_num=len(moves) + 1,
            position_x=move.position_x,
            position_y=move.position_y,
            value=next_value,
        )
        db.add(move_obj)
        db.commit()
        db.refresh(move_obj)

        updated_moves = game.moves
        winner_val = check_winner(updated_moves)
        if winner_val:
            game.status = "completed"
            game.ended_at = datetime.utcnow()
            winner_id = game.player_x_id if winner_val == 'X' else game.player_o_id
            game.winner_id = winner_id
            db.commit()
            for player, stat_change in [
                (winner_id, ('games_played', 1, 'games_won', 1)),
                (
                    game.player_x_id if winner_id != game.player_x_id
                    else game.player_o_id,
                    ('games_played', 1, 'games_lost', 1)
                )
            ]:
                stat = db.query(PlayerStatistic).filter(
                    PlayerStatistic.user_id == player
                ).first()
                if stat:
                    setattr(
                        stat, stat_change[0],
                        getattr(stat, stat_change[0]) + stat_change[1]
                    )
                    setattr(
                        stat, stat_change[2],
                        getattr(stat, stat_change[2]) + stat_change[3]
                    )
            db.commit()
        elif len(updated_moves) == 9:
            game.status = "completed"
            game.ended_at = datetime.utcnow()
            game.winner_id = None
            stat_1 = db.query(PlayerStatistic).filter(
                PlayerStatistic.user_id == game.player_x_id
            ).first()
            stat_2 = db.query(PlayerStatistic).filter(
                PlayerStatistic.user_id == game.player_o_id
            ).first()
            if stat_1:
                stat_1.games_played += 1
                stat_1.games_drawn += 1
            if stat_2:
                stat_2.games_played += 1
                stat_2.games_drawn += 1
            db.commit()
        try:
            import asyncio
            ws_payload = {
                "event": "move",
                "game_id": game.id,
                "state": GameState(
                    id=game.id,
                    status=game.status,
                    moves=moves_to_schema(updated_moves),
                    next_turn_value=get_next_value(updated_moves),
                    winner=None,
                ).dict(),
            }
            asyncio.create_task(manager.broadcast(game.id, ws_payload))
        except Exception:
            pass
        winner_user = None
        if winner_val:
            winning_id = (
                game.player_x_id if winner_val == 'X' else game.player_o_id
            )
            winning_user = db.query(User).filter(
                User.id == winning_id
            ).first()
            winner_user = UserPublic(
                id=winning_id,
                username=winning_user.username if winning_user else ""
            )
        return GameState(
            id=game.id,
            status=game.status,
            moves=moves_to_schema(updated_moves),
            next_turn_value=get_next_value(updated_moves),
            winner=winner_user
        )
    finally:
        db.close()


@app.get("/me/games", response_model=List[GamePublic], tags=["game"])
def my_games(current_user: User = Depends(get_current_user)):
    """List user's recent games."""
    db = SessionLocal()
    try:
        games = db.query(GameSession).filter(
            (GameSession.player_x_id == current_user.id)
            | (GameSession.player_o_id == current_user.id)
        ).order_by(GameSession.started_at.desc()).limit(20).all()
        result = []
        for game in games:
            result.append(
                GamePublic(
                    id=game.id,
                    player_x=UserPublic(
                        id=game.player_x_id,
                        username=db.query(User)
                        .filter(User.id == game.player_x_id)
                        .first().username
                    ),
                    player_o=UserPublic(
                        id=game.player_o_id,
                        username=db.query(User)
                        .filter(User.id == game.player_o_id)
                        .first().username
                    ),
                    status=game.status,
                    winner=(
                        UserPublic(
                            id=game.winner_id,
                            username=db.query(User)
                            .filter(User.id == game.winner_id)
                            .first().username,
                        )
                        if game.winner_id else None
                    ),
                    started_at=game.started_at,
                    ended_at=game.ended_at,
                )
            )
        return result
    finally:
        db.close()


# ----------- STATS -----------
@app.get("/me/stats", response_model=StatsPublic, tags=["stats"])
def get_my_stats(current_user: User = Depends(get_current_user)):
    """Get the current user's stats."""
    db = SessionLocal()
    try:
        stats = db.query(PlayerStatistic).filter(
            PlayerStatistic.user_id == current_user.id
        ).first()
        if not stats:
            raise HTTPException(404, "Stats not found")
        return StatsPublic(
            games_played=stats.games_played,
            games_won=stats.games_won,
            games_lost=stats.games_lost,
            games_drawn=stats.games_drawn
        )
    finally:
        db.close()


@app.get("/stats/leaderboard", tags=["stats"])
def leaderboard(limit: int = 10):
    """Get top players by games won."""
    db = SessionLocal()
    try:
        result = db.query(PlayerStatistic, User).join(User).order_by(
            PlayerStatistic.games_won.desc()
        ).limit(limit).all()
        return [
            {
                "username": user.username,
                "games_won": stats.games_won,
                "games_played": stats.games_played,
                "games_lost": stats.games_lost,
                "games_drawn": stats.games_drawn,
            }
            for stats, user in result
        ]
    finally:
        db.close()


# ----------- HISTORY -----------
@app.get(
    "/games/{game_id}/history",
    response_model=List[MovePublic],
    tags=["game"]
)
def move_history(game_id: int, current_user: User = Depends(get_current_user)):
    """
    Fetch the move history for a game for replay.
    """
    db = SessionLocal()
    try:
        game = db.query(GameSession).filter(
            GameSession.id == game_id
        ).first()
        if not game or current_user.id not in [game.player_x_id, game.player_o_id]:
            raise HTTPException(403, "Forbidden")
        return moves_to_schema(game.moves)
    finally:
        db.close()


# ----------- REALTIME: WEBSOCKET -----------
@app.websocket("/ws/game/{game_id}")
async def websocket_endpoint(websocket: WebSocket, game_id: int):
    """
    WebSocket endpoint for real-time game state for a particular game.

    - Connect as a player or spectator.
    - Receives JSON payloads after every move.
    - Usage: `wss://<host>/ws/game/{game_id}`
    """
    await manager.connect(game_id, websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(game_id, websocket)


@app.get("/websockets", tags=["ws"])
def websocket_usage():
    """WebSocket API usage information.

    - Connect to /ws/game/{game_id} for real-time updates.
    - See /docs for full request/response shape.
    """
    return {
        "instructions": [
            "Use WebSocket: ws(s)://<host>/ws/game/{game_id}",
            "Receive updates after moves in real-time.",
            "Payload: {event: 'move', game_id: <int>, state: {...}}",
        ]
    }
