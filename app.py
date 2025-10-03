
import os, sqlite3, uuid
from urllib.parse import urlencode
from flask import Flask, redirect, url_for, session, request, render_template, flash, send_from_directory, abort
import git
import requests
from dotenv import load_dotenv

load_dotenv()

GITHUB_CLIENT_ID = os.getenv("GITHUB_CLIENT_ID")
GITHUB_CLIENT_SECRET = os.getenv("GITHUB_CLIENT_SECRET")
SECRET_KEY = os.getenv("SECRET_KEY", "change_this_secret")
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
SITES_DIR = os.path.join(BASE_DIR, "sites")
DB_FILE = os.path.join(BASE_DIR, "mini_vercel.db")

os.makedirs(SITES_DIR, exist_ok=True)

app = Flask(__name__)
app.secret_key = SECRET_KEY

# Initialize DB
def init_db():
    con = sqlite3.connect(DB_FILE)
    cur = con.cursor()
    cur.execute("""CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        github_id TEXT UNIQUE,
        username TEXT,
        access_token TEXT,
        is_admin INTEGER DEFAULT 0
    )""")
    cur.execute("""CREATE TABLE IF NOT EXISTS projects (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        name TEXT,
        repo_url TEXT,
        UNIQUE(user_id, name)
    )""")
    # create default admin user (local admin) if none exists
    cur.execute("SELECT COUNT(*) FROM users WHERE is_admin=1")
    if cur.fetchone()[0] == 0:
        cur.execute("INSERT OR IGNORE INTO users (github_id, username, access_token, is_admin) VALUES (?,?,?,1)", ("local-admin","admin",""))
    con.commit()
    con.close()

init_db()

# ---- Helper DB funcs ----
def db_get_user_by_github_id(gid):
    con = sqlite3.connect(DB_FILE)
    cur = con.cursor()
    cur.execute("SELECT id, github_id, username, access_token, is_admin FROM users WHERE github_id=?", (gid,))
    r = cur.fetchone()
    con.close()
    return r

def db_upsert_user(gid, username, access_token):
    con = sqlite3.connect(DB_FILE)
    cur = con.cursor()
    cur.execute("INSERT OR REPLACE INTO users (github_id, username, access_token, is_admin) VALUES (?,?,?, COALESCE((SELECT is_admin FROM users WHERE github_id=?), 0))", (gid, username, access_token, gid))
    con.commit()
    con.close()

def db_add_project(user_id, name, repo_url):
    con = sqlite3.connect(DB_FILE)
    cur = con.cursor()
    cur.execute("INSERT OR IGNORE INTO projects (user_id, name, repo_url) VALUES (?,?,?)", (user_id, name, repo_url))
    con.commit()
    con.close()

def db_list_projects(user_id=None):
    con = sqlite3.connect(DB_FILE)
    cur = con.cursor()
    if user_id:
        cur.execute("SELECT id, user_id, name, repo_url FROM projects WHERE user_id=?", (user_id,))
    else:
        cur.execute("SELECT id, user_id, name, repo_url FROM projects")
    rows = cur.fetchall()
    con.close()
    return rows

# ---- Routes ----
@app.route("/")
def index():
    user = session.get("user")
    if not user:
        return render_template("landing.html")
    # show dashboard
    projects = db_list_projects(user_id=user["id"])  # each row: (id,user_id,name,repo_url)
    return render_template("dashboard.html", user=user, projects=projects)

@app.route("/login")
def login():
    # start GitHub OAuth flow
    if not GITHUB_CLIENT_ID or not GITHUB_CLIENT_SECRET:
        return "GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET are required (set .env)"
    params = {
        "client_id": GITHUB_CLIENT_ID,
        "redirect_uri": url_for("oauth_callback", _external=True),
        "scope": "read:user",
        "state": str(uuid.uuid4())
    }
    session["oauth_state"] = params["state"]
    auth_url = "https://github.com/login/oauth/authorize?" + urlencode(params)
    return redirect(auth_url)

@app.route("/oauth/callback")
def oauth_callback():
    code = request.args.get("code")
    state = request.args.get("state")
    if not code or state != session.get("oauth_state"):
        return "Invalid OAuth response", 400
    # exchange code for access token
    token_url = "https://github.com/login/oauth/access_token"
    payload = {
        "client_id": GITHUB_CLIENT_ID,
        "client_secret": GITHUB_CLIENT_SECRET,
        "code": code,
        "redirect_uri": url_for("oauth_callback", _external=True),
        "state": state
    }
    headers = {"Accept": "application/json"}
    resp = requests.post(token_url, json=payload, headers=headers)
    data = resp.json()
    access_token = data.get("access_token")
    if not access_token:
        return "Failed to obtain access token", 400
    # fetch user
    user_resp = requests.get("https://api.github.com/user", headers={"Authorization": f"token {access_token}"})
    user_json = user_resp.json()
    github_id = str(user_json.get("id"))
    username = user_json.get("login")
    # upsert user
    db_upsert_user(github_id, username, access_token)
    user_row = db_get_user_by_github_id(github_id)
    # set session
    session["user"] = {"id": user_row[0], "github_id": user_row[1], "username": user_row[2], "is_admin": user_row[4]}
    return redirect(url_for("index"))

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))

@app.route("/deploy", methods=["POST"])
def deploy():
    user = session.get("user")
    if not user:
        return redirect(url_for("index"))
    repo = request.form.get("repo_url", "").strip()
    if not repo:
        flash("Repo URL required")
        return redirect(url_for("index"))
    # parse project name
    name = repo.rstrip("/").split("/")[-1].replace(".git", "")
    path = os.path.join(SITES_DIR, name)
    # clone or update
    try:
        if os.path.exists(path):
            # pull latest
            repo_obj = git.Repo(path)
            origin = repo_obj.remotes.origin
            origin.pull()
        else:
            git.Repo.clone_from(repo, path)
    except Exception as e:
        flash(f"Deploy failed: {e}")
        return redirect(url_for("index"))
    db_add_project(user["id"], name, repo)
    flash("Deployed "+name)
    return redirect(url_for("index"))

@app.route("/redeploy/<name>")
def redeploy(name):
    user = session.get("user")
    if not user:
        return redirect(url_for("index"))
    path = os.path.join(SITES_DIR, name)
    if not os.path.exists(path):
        flash("Project not found")
        return redirect(url_for("index"))
    try:
        repo_obj = git.Repo(path)
        origin = repo_obj.remotes.origin
        origin.pull()
    except Exception as e:
        flash("Redeploy failed: "+str(e))
    return redirect(url_for("index"))

@app.route("/sites/<name>/<path:filename>")
def serve_site_file(name, filename):
    path = os.path.join(SITES_DIR, name)
    if not os.path.exists(path):
        abort(404)
    return send_from_directory(path, filename)

@app.route("/sites/<name>/")
def serve_site_index(name):
    path = os.path.join(SITES_DIR, name)
    if not os.path.exists(path):
        abort(404)
    # prefer index.html
    for f in ["index.html","Index.html","INDEX.html"]:
        p = os.path.join(path, f)
        if os.path.exists(p):
            return send_from_directory(path, f)
    # otherwise list files
    files = os.listdir(path)
    return "<pre>"+("\n".join(files))+"</pre>"

# Admin routes
@app.route("/admin")
def admin_panel():
    user = session.get("user")
    if not user or not user.get("is_admin"):
        return "Forbidden", 403
    projects = db_list_projects()
    con = sqlite3.connect(DB_FILE)
    users = con.execute("SELECT id, github_id, username, is_admin FROM users").fetchall()
    con.close()
    return render_template("admin.html", users=users, projects=projects)

if __name__ == '__main__':
    app.run(debug=True, port=5000)
