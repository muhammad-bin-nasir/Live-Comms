import os
import json
import hashlib
import secrets
import asyncio
import threading # Used for SQLite database lock and periodic cleanup
import time
from datetime import datetime, timedelta
import sqlite3
from contextlib import contextmanager

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse

app = FastAPI()

# --- Global variables for SQLite DB Setup ---
DB_DIR = 'db'
DB_FILE = 'users.db'
DB_PATH = os.path.join(DB_DIR, DB_FILE)

# Thread-local storage for database connections
thread_local = threading.local()
db_lock = threading.Lock() # Thread-safe database operations

def get_db_connection():
    """Get thread-local database connection"""
    if not hasattr(thread_local, 'connection'):
        os.makedirs(DB_DIR, exist_ok=True) # Ensure the directory exists
        thread_local.connection = sqlite3.connect(DB_PATH, check_same_thread=False)
        thread_local.connection.execute("PRAGMA foreign_keys = ON")
    return thread_local.connection

@contextmanager
def get_db_cursor():
    """Context manager for database operations"""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        yield cursor
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        cursor.close()

def init_database():
    """Initialize the database with proper schema"""
    with get_db_cursor() as cursor:
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP
        )
        """)
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS login_attempts (
            ip_address TEXT,
            username TEXT,
            attempt_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            success BOOLEAN
        )
        """)
    print("[i] Database initialized successfully.")

def cleanup_old_login_attempts():
    """Clean up old login attempts (run periodically)"""
    try:
        with get_db_cursor() as cursor:
            cursor.execute("""
            DELETE FROM login_attempts 
            WHERE datetime(attempt_time) < datetime('now', '-1 day')
            """)
            deleted_count = cursor.rowcount
            if deleted_count > 0:
                print(f"[i] Cleaned up {deleted_count} old login attempts.")
    except Exception as e:
        print(f"[!] Error during cleanup: {e}")

# --- Authentication Logic ---
def generate_salt():
    """Generate a random salt for password hashing"""
    return secrets.token_hex(32)

def hash_password_with_salt(password, salt):
    """Hash password with salt using PBKDF2 (more secure than simple SHA256)"""
    return hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000).hex()

def verify_password(password, stored_hash, salt):
    """Verify password against stored hash"""
    return hash_password_with_salt(password, salt) == stored_hash

def check_rate_limit(ip_address, username):
    """Check if user/IP has exceeded login attempts"""
    try:
        with get_db_cursor() as cursor:
            # Check failed attempts in last 15 minutes
            cursor.execute("""
            SELECT COUNT(*) FROM login_attempts 
            WHERE (ip_address = ? OR username = ?) 
            AND success = 0 
            AND datetime(attempt_time) > datetime('now', '-15 minutes')
            """, (ip_address, username))
            failed_attempts = cursor.fetchone()[0]
            return failed_attempts < 5  # Allow max 5 failed attempts per 15 minutes
    except Exception as e:
        print(f"[!] Error checking rate limit: {e}")
        return True  # Allow on error to avoid blocking legitimate users

def log_login_attempt(ip_address, username, success):
    """Log login attempt for rate limiting"""
    try:
        with get_db_cursor() as cursor:
            cursor.execute("""
            INSERT INTO login_attempts (ip_address, username, success) 
            VALUES (?, ?, ?)
            """, (ip_address, username, success)) # Corrected: parameters as a tuple
    except Exception as e:
        print(f"[!] Error logging login attempt: {e}")

def authenticate_user(username, password, ip_address):
    """
    Authenticate user credentials.
    Returns: (success: bool, message: str, is_new_user: bool)
    """
    # Check rate limiting first
    if not check_rate_limit(ip_address, username):
        return False, "Too many failed attempts. Try again later.", False

    # Input validation
    if not username or not password:
        return False, "Username and password required.", False
    if len(username) > 50 or len(password) > 128:
        return False, "Username or password too long.", False
    if not username.replace('_', '').replace('-', '').isalnum():
        return False, "Username can only contain letters, numbers, underscores, and hyphens.", False

    with db_lock: # Use threading.Lock for SQLite operations
        try:
            with get_db_cursor() as cursor:
                # Check if user exists
                cursor.execute("SELECT password_hash, salt FROM users WHERE username = ?", (username,))
                row = cursor.fetchone()

                if row:
                    # Existing user - verify password
                    stored_hash, salt = row
                    if verify_password(password, stored_hash, salt):
                        # Update last login time
                        cursor.execute("""
                        UPDATE users SET last_login = CURRENT_TIMESTAMP 
                        WHERE username = ?
                        """, (username,))
                        log_login_attempt(ip_address, username, True)
                        return True, "Login successful.", False
                    else:
                        log_login_attempt(ip_address, username, False)
                        return False, "Invalid password.", False
                else:
                    # New user - create account
                    salt = generate_salt()
                    password_hash = hash_password_with_salt(password, salt)

                    cursor.execute("""
                    INSERT INTO users (username, password_hash, salt) 
                    VALUES (?, ?, ?)
                    """, (username, password_hash, salt)) # Corrected: parameters as a tuple
                    log_login_attempt(ip_address, username, True)
                    return True, "Account created successfully.", True

        except sqlite3.IntegrityError:
            # Handle race condition where user was created between check and insert
            log_login_attempt(ip_address, username, False)
            return False, "Username already exists.", False
        except Exception as e:
            print(f"[!] Database error during authentication: {e}")
            return False, "Database error occurred.", False

# --- WebSocket Connection Manager ---
class ConnectionManager:
    def __init__(self):
        self.active_connections: dict[str, WebSocket] = {} # username: websocket
        self.public_keys: dict[str, str] = {} # username: public_key
        self._manager_lock = asyncio.Lock() # For async-safe access to active_connections and public_keys

    async def connect(self, websocket: WebSocket, username: str, public_key: str):
        # Removed websocket.accept() from here
        async with self._manager_lock:
            self.active_connections[username] = websocket
            self.public_keys[username] = public_key
        print(f"[+] {username} connected.")
        await self.broadcast_peer_list()

    async def disconnect(self, username: str):
        async with self._manager_lock:
            if username in self.active_connections:
                del self.active_connections[username]
            if username in self.public_keys:
                del self.public_keys[username]
        print(f"[-] {username} disconnected.")
        # Schedule broadcast after a short delay to ensure disconnect is processed
        asyncio.create_task(self.broadcast_peer_list())

    async def send_personal_message(self, message: str, websocket: WebSocket):
        await websocket.send_text(message)

    async def broadcast(self, message: str, exclude_username: str = None):
        disconnected_users = []
        async with self._manager_lock:
            for username, connection in list(self.active_connections.items()):
                if username == exclude_username:
                    continue
                try:
                    await connection.send_text(message)
                except WebSocketDisconnect:
                    disconnected_users.append(username)
                except Exception as e:
                    print(f"[!] Failed to relay message to {username}: {e}")
                    disconnected_users.append(username)
        
        for user in disconnected_users:
            await self.disconnect(user) # This will also trigger a peer list broadcast

    async def broadcast_peer_list(self):
        async with self._manager_lock:
            payload = {
                "type": "peer_list",
                "peers": [
                    {"username": user, "public_key": key}
                    for user, key in self.public_keys.items()
                ]
            }
        message = json.dumps(payload)
        print(f"[i] Broadcasting peer list: {payload['peers']}")
        await self.broadcast(message)

manager = ConnectionManager()

# --- FastAPI App Events ---
@app.on_event("startup")
async def startup_event():
    """Initializes database and starts periodic cleanup."""
    # SQLite init is synchronous, so it's fine to call directly
    init_database() 
    asyncio.create_task(periodic_cleanup_task())
    print("[i] Periodic cleanup task scheduled.")

async def periodic_cleanup_task():
    """Task to run cleanup periodically."""
    while True:
        await asyncio.sleep(3600) # Wait 1 hour
        # SQLite cleanup is synchronous, run in a thread pool executor to not block event loop
        await asyncio.to_thread(cleanup_old_login_attempts)

@app.get("/")
async def get():
    """Root endpoint for health check."""
    return HTMLResponse("<h1>Secure Chat Server (FastAPI/WebSockets)</h1><p>WebSocket endpoint: /ws</p>")

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """Handles WebSocket connections."""
    username = None
    ip_address = websocket.client.host 

    # IMPORTANT: Accept the WebSocket connection immediately
    await websocket.accept() 

    try:
        # First message is for authentication
        auth_data = await websocket.receive_text()
        auth_payload = json.loads(auth_data)

        username = auth_payload.get("username", "").strip()
        password = auth_payload.get("auth", "")
        public_key = auth_payload.get("public_key", "")

        if not all([username, password, public_key]):
            await websocket.send_text(json.dumps({
                "type": "auth_result",
                "status": "error",
                "message": "Missing required fields"
            }))
            return

        # Check if username is already connected
        async with manager._manager_lock:
            if username in manager.active_connections:
                await websocket.send_text(json.dumps({
                    "type": "auth_result",
                    "status": "error",
                    "message": "User already connected"
                }))
                return

        # Authenticate user (synchronous call, run in thread pool)
        success, message, is_new_user = await asyncio.to_thread(authenticate_user, username, password, ip_address)

        if success:
            status = "new_user" if is_new_user else "success"
            response = {
                "type": "auth_result",
                "status": status,
                "message": message
            }
            await websocket.send_text(json.dumps(response))

            await manager.connect(websocket, username, public_key)

            try:
                while True:
                    data = await websocket.receive_text()
                    # Relay message to all other clients
                    await manager.broadcast(data, exclude_username=username)
            except WebSocketDisconnect:
                print(f"[!] WebSocket disconnected for {username}")
            except Exception as e:
                print(f"[!] Error receiving message from {username}: {e}")
        else:
            response = {
                "type": "auth_result",
                "status": "fail",
                "message": message
            }
            await websocket.send_text(json.dumps(response))
            print(f"[!] Authentication failed for {username} from {ip_address}: {message}")

    except json.JSONDecodeError:
        print(f"[!] Invalid JSON from {ip_address}")
        try:
            await websocket.send_text(json.dumps({
                "type": "auth_result",
                "status": "error",
                "message": "Invalid data format"
            }))
        except:
            pass # Client might have already disconnected
    except WebSocketDisconnect:
        print(f"[!] Initial WebSocket connection closed for {ip_address}")
    except Exception as e:
        print(f"[!] Error during WebSocket connection for {ip_address}: {e}")
    finally:
        if username:
            await manager.disconnect(username)
        else:
            # If authentication failed, username might not be set
            print(f"[-] Unauthenticated client from {ip_address} disconnected.")