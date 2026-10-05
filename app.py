# ============================================================
# MINT - AI Based Mutual Fund Performance Analyzer
# Complete Flask Application
# ============================================================

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    flash,
    Response,
    jsonify,
)

import psycopg2
from psycopg2.extras import RealDictCursor

from werkzeug.security import generate_password_hash, check_password_hash

import requests
import os
import csv

from io import StringIO, BytesIO
from datetime import datetime
from functools import wraps

# ============================================================
# FLASK APPLICATION
# ============================================================

app = Flask(__name__)

app.secret_key = os.getenv("SECRET_KEY", "mint-mutual-fund-secret-key")


# ============================================================
# DATABASE CONFIGURATION
# ============================================================

DB_HOST = "localhost"
DB_NAME = "mint_db"
DB_USER = "postgres"
DB_PASSWORD = "1234"
DB_PORT = "5432"


# ============================================================
# MFAPI
# ============================================================

MFAPI_BASE = "https://api.mfapi.in"


# ============================================================
# DATABASE CONNECTION
# ============================================================


def get_db_connection():

    return psycopg2.connect(
        host=DB_HOST, database=DB_NAME, user=DB_USER, password=DB_PASSWORD, port=DB_PORT
    )


# Some old functions use get_db()
def get_db():
    return get_db_connection()


# ============================================================
# LOGIN REQUIRED DECORATOR
# ============================================================


def login_required(f):

    @wraps(f)
    def decorated_function(*args, **kwargs):

        if "user_id" not in session:

            flash("Please login first.", "warning")

            return redirect(url_for("login"))

        return f(*args, **kwargs)

    return decorated_function


# ============================================================
# ADMIN REQUIRED DECORATOR
# ============================================================


def admin_required(f):

    @wraps(f)
    def decorated_function(*args, **kwargs):

        if "user_id" not in session:

            flash("Please login first.", "warning")

            return redirect(url_for("login"))

        if session.get("role") != "admin":

            flash("Admin access required.", "error")

            return redirect(url_for("dashboard"))

        return f(*args, **kwargs)

    return decorated_function


# ============================================================
# DATABASE HELPER - FETCH ALL
# ============================================================


def fetch_all(query, params=()):

    conn = get_db()

    try:

        with conn.cursor(cursor_factory=RealDictCursor) as cur:

            cur.execute(query, params)

            return cur.fetchall()

    finally:

        conn.close()


# ============================================================
# DATABASE HELPER - FETCH ONE
# ============================================================


def fetch_one(query, params=()):

    conn = get_db()

    try:

        with conn.cursor(cursor_factory=RealDictCursor) as cur:

            cur.execute(query, params)

            return cur.fetchone()

    finally:

        conn.close()


# ============================================================
# DATABASE HELPER - EXECUTE
# ============================================================


def execute_query(query, params=(), fetch=False):

    conn = get_db()

    try:

        with conn.cursor(cursor_factory=RealDictCursor) as cur:

            cur.execute(query, params)

            result = None

            if fetch:

                result = cur.fetchone()

            conn.commit()

            return result

    except Exception:

        conn.rollback()

        raise

    finally:

        conn.close()


# ============================================================
# ACTIVITY LOG
# ============================================================


def add_log(user_id, action, description=""):

    try:

        execute_query(
            """
            INSERT INTO activity_logs
            (
                user_id,
                action,
                description
            )
            VALUES (%s, %s, %s)
            """,
            (user_id, action, description),
        )

    except Exception:

        # Logging should never crash the main application
        pass


# ============================================================
# HOME / INDEX
# ============================================================


@app.route("/")
def index():

    return render_template("index.html")


# ============================================================
# LOGIN
# ============================================================


@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form.get("username", "").strip()

        password = request.form.get("password", "")

        role = request.form.get("role", "user")

        if not username or not password:

            flash("Please enter username and password.", "error")

            return redirect(url_for("login"))

        connection = None
        cursor = None

        try:

            connection = get_db_connection()

            cursor = connection.cursor()

            cursor.execute(
                """
                SELECT
                    id,
                    full_name,
                    username,
                    email,
                    password,
                    role
                FROM users
                WHERE username = %s
                AND role = %s
                """,
                (username, role),
            )

            user = cursor.fetchone()

        except Exception as e:

            print("LOGIN DATABASE ERROR:", e)

            flash("Database connection error.", "error")

            return redirect(url_for("login"))

        finally:

            if cursor:

                cursor.close()

            if connection:

                connection.close()

        if user:

            user_id = user[0]
            full_name = user[1]
            db_username = user[2]
            db_password = user[4]
            db_role = user[5]

            try:

                password_correct = check_password_hash(db_password, password)

            except Exception:

                password_correct = False

            if password_correct:

                session["user_id"] = user_id
                session["username"] = db_username
                session["full_name"] = full_name
                session["role"] = db_role

                add_log(user_id, "Login", "User logged in")

                flash("Login successful!", "success")

                if db_role == "admin":

                    return redirect(url_for("admin"))

                return redirect(url_for("dashboard"))

            else:

                flash("Incorrect password.", "error")

        else:

            flash("Username or role not found. Please register first.", "error")

    return render_template("login.html")


# ============================================================
# REGISTER
# ============================================================


@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        full_name = request.form.get("full_name", "").strip()

        username = request.form.get("username", "").strip()

        email = request.form.get("email", "").strip()

        password = request.form.get("password", "")

        confirm_password = request.form.get("confirm_password", "")

        role = request.form.get("role", "user")

        if not full_name or not username or not email:

            flash("Please fill all required fields.", "error")

            return redirect(url_for("register"))

        # Users should normally register as user.
        if role not in ["user", "admin"]:

            role = "user"

        if password != confirm_password:

            flash("Passwords do not match.", "error")

            return redirect(url_for("register"))

        if len(password) < 6:

            flash("Password must contain at least 6 characters.", "error")

            return redirect(url_for("register"))

        connection = None
        cursor = None

        try:

            connection = get_db_connection()

            cursor = connection.cursor()

            cursor.execute(
                """
                SELECT id
                FROM users
                WHERE username = %s
                OR email = %s
                """,
                (username, email),
            )

            existing_user = cursor.fetchone()

            if existing_user:

                flash("Username or email already exists.", "error")

                return redirect(url_for("register"))

            hashed_password = generate_password_hash(password)

            cursor.execute(
                """
                INSERT INTO users
                (
                    full_name,
                    username,
                    email,
                    password,
                    role
                )
                VALUES
                (%s, %s, %s, %s, %s)
                """,
                (full_name, username, email, hashed_password, role),
            )

            connection.commit()

        except Exception as e:

            if connection:

                connection.rollback()

            print("REGISTER ERROR:", e)

            flash("Registration failed. Please check database.", "error")

            return redirect(url_for("register"))

        finally:

            if cursor:

                cursor.close()

            if connection:

                connection.close()

        flash("Registration successful! Please login.", "success")

        return redirect(url_for("login"))

    return render_template("register.html")


# ============================================================
# LOGOUT
# ============================================================


@app.route("/logout")
def logout():

    user_id = session.get("user_id")

    if user_id:

        add_log(user_id, "Logout", "User logged out")

    session.clear()

    flash("You have been logged out.", "success")

    return redirect(url_for("index"))


# ============================================================
# MFAPI - SEARCH FUNDS
# ============================================================


def search_funds(keyword):

    try:

        response = requests.get(
            f"{MFAPI_BASE}/mf/search", params={"q": keyword}, timeout=10
        )

        if response.status_code == 200:

            return response.json()

    except Exception as e:

        print("MF SEARCH ERROR:", e)

    return []


# ============================================================
# MFAPI - GET FUND
# ============================================================


def get_fund(code):

    try:

        response = requests.get(f"{MFAPI_BASE}/mf/{code}", timeout=10)

        if response.status_code == 200:

            return response.json()

    except Exception as e:

        print("MFAPI ERROR:", e)

    return None


# ============================================================
# MFAPI - LATEST NAV
# ============================================================


def get_latest_nav(code):

    data = get_fund(code)

    if not data:

        return None

    meta = data.get("meta", {})

    nav_data = data.get("data", [])

    if not nav_data:

        return None

    latest = nav_data[0]

    try:

        nav_value = float(latest.get("nav", 0))

    except (ValueError, TypeError):

        nav_value = 0

    return {
        "scheme_code": code,
        "scheme_name": meta.get("scheme_name", ""),
        "fund_house": meta.get("fund_house", ""),
        "scheme_type": meta.get("scheme_type", ""),
        "scheme_category": meta.get("scheme_category", ""),
        "nav": nav_value,
        "date": latest.get("date"),
    }


# ============================================================
# USER DASHBOARD
# ============================================================


@app.route("/dashboard")
@login_required
def dashboard():

    uid = session["user_id"]

    portfolio = fetch_all(
        """
        SELECT *
        FROM portfolio
        WHERE user_id = %s
        """,
        (uid,),
    )

    transactions = fetch_all(
        """
        SELECT *
        FROM transactions
        WHERE user_id = %s
        ORDER BY created_at DESC
        LIMIT 10
        """,
        (uid,),
    )

    watch_count = fetch_one(
        """
        SELECT COUNT(*) AS count
        FROM watchlist
        WHERE user_id = %s
        """,
        (uid,),
    )

    invested = sum(float(row.get("invested_amount") or 0) for row in portfolio)

    current = 0

    for row in portfolio:

        nav = get_latest_nav(row["scheme_code"])

        if nav:

            current += float(row.get("units") or 0) * nav["nav"]

    pnl = current - invested

    return render_template(
        "dashboard.html",
        holdings=portfolio,
        recent=transactions,
        invested=invested,
        current=current,
        pnl=pnl,
        watch_count=(watch_count["count"] if watch_count else 0),
    )


# ============================================================
# MUTUAL FUND SEARCH
# ============================================================


@app.route("/funds")
@login_required
def funds():

    keyword = request.args.get("q", "").strip()

    results = []

    if keyword:

        results = search_funds(keyword)

    return render_template("funds.html", funds=results, keyword=keyword)


# ============================================================
# FUND API
# ============================================================


@app.route("/api/fund/<int:code>")
@login_required
def fund_api(code):

    data = get_fund(code)

    if not data:

        return jsonify({"error": "Fund not found"}), 404

    return jsonify(data)


# ============================================================
# MARKET
# ============================================================


@app.route("/market")
@login_required
def market():

    code = request.args.get("code", "")

    data = None

    if code:

        data = get_fund(code)

    return render_template("market.html", data=data, code=code)


# ============================================================
# PERFORMANCE
# ============================================================


@app.route("/performance")
@login_required
def performance():

    code = request.args.get("code", "")

    data = None

    if code:

        data = get_fund(code)

    return render_template("performance.html", data=data, code=code)


# ============================================================
# FUND COMPARISON
# ============================================================


@app.route("/compare", methods=["GET", "POST"])
@login_required
def compare():

    funds_list = []

    codes = request.form.getlist("codes")

    if not codes:

        codes = request.args.getlist("code")

    for code in codes[:5]:

        if code:

            data = get_fund(code)

            if data:

                funds_list.append(data)

    return render_template("compare.html", funds=funds_list)


# ============================================================
# RECOMMENDATION
# ============================================================


@app.route("/recommendation", methods=["GET", "POST"])
@login_required
def recommendation():

    results = []

    keyword = ""

    if request.method == "POST":

        keyword = request.form.get("keyword", "").strip()

        if keyword:

            results = search_funds(keyword)

    return render_template("recommendation.html", results=results, keyword=keyword)


# ============================================================
# AI INSIGHTS
# ============================================================


@app.route("/insights")
@login_required
def insights():

    uid = session["user_id"]

    portfolio = fetch_all(
        """
        SELECT *
        FROM portfolio
        WHERE user_id = %s
        """,
        (uid,),
    )

    insights_data = []

    if portfolio:

        insights_data.append("Your portfolio contains active mutual fund holdings.")

        if len(portfolio) >= 5:

            insights_data.append("Your portfolio contains multiple schemes.")

        else:

            insights_data.append("Portfolio diversification can be reviewed.")

    else:

        insights_data.append("No portfolio holdings are available yet.")

    return render_template("insights.html", insights=insights_data)


# ============================================================
# RISK ANALYSIS
# ============================================================


@app.route("/risk")
@login_required
def risk():

    uid = session["user_id"]

    holdings = fetch_all(
        """
        SELECT *
        FROM portfolio
        WHERE user_id = %s
        """,
        (uid,),
    )

    return render_template("risk.html", holdings=holdings)


# ============================================================
# SIP
# ============================================================


@app.route("/sip", methods=["GET", "POST"])
@login_required
def sip():

    if request.method == "POST":

        scheme_code = request.form.get("scheme_code")

        amount = request.form.get("amount")

        frequency = request.form.get("frequency", "Monthly")

        start_date = request.form.get("start_date")

        if scheme_code and amount:

            try:

                execute_query(
                    """
                    INSERT INTO sip_plans
                    (
                        user_id,
                        scheme_code,
                        amount,
                        frequency,
                        start_date,
                        status
                    )
                    VALUES
                    (
                        %s,
                        %s,
                        %s,
                        %s,
                        %s,
                        'Active'
                    )
                    """,
                    (session["user_id"], scheme_code, amount, frequency, start_date),
                )

                add_log(
                    session["user_id"], "SIP Created", f"SIP created for {scheme_code}"
                )

                flash("SIP plan created successfully.", "success")

            except Exception as e:

                print("SIP ERROR:", e)

                flash("Unable to create SIP.", "error")

    sips = fetch_all(
        """
        SELECT *
        FROM sip_plans
        WHERE user_id = %s
        ORDER BY created_at DESC
        """,
        (session["user_id"],),
    )

    return render_template("sip.html", sips=sips)


# ============================================================
# INVEST
# ============================================================


@app.route("/invest", methods=["GET", "POST"])
@login_required
def invest():

    code = request.args.get("code", "")

    if request.method == "POST":

        code = request.form.get("scheme_code", "").strip()

        try:

            amount = float(request.form.get("amount", 0))

        except (ValueError, TypeError):

            amount = 0

        if not code or amount <= 0:

            flash("Please enter a valid fund and amount.", "error")

            return redirect(url_for("invest", code=code))

        nav_data = get_latest_nav(code)

        if not nav_data:

            flash("Invalid fund or live NAV unavailable.", "error")

            return redirect(url_for("invest", code=code))

        nav = nav_data["nav"]

        if nav <= 0:

            flash("Invalid NAV.", "error")

            return redirect(url_for("invest", code=code))

        units = amount / nav

        existing = fetch_one(
            """
            SELECT *
            FROM portfolio
            WHERE user_id = %s
            AND scheme_code = %s
            """,
            (session["user_id"], code),
        )

        if existing:

            new_units = float(existing["units"]) + units

            new_amount = float(existing["invested_amount"]) + amount

            execute_query(
                """
                UPDATE portfolio
                SET
                    units = %s,
                    invested_amount = %s,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = %s
                """,
                (new_units, new_amount, existing["id"]),
            )

        else:

            execute_query(
                """
                INSERT INTO portfolio
                (
                    user_id,
                    scheme_code,
                    scheme_name,
                    units,
                    invested_amount
                )
                VALUES
                (
                    %s,
                    %s,
                    %s,
                    %s,
                    %s
                )
                """,
                (session["user_id"], code, nav_data["scheme_name"], units, amount),
            )

        execute_query(
            """
            INSERT INTO transactions
            (
                user_id,
                scheme_code,
                scheme_name,
                transaction_type,
                amount,
                units,
                nav
            )
            VALUES
            (
                %s,
                %s,
                %s,
                'BUY',
                %s,
                %s,
                %s
            )
            """,
            (session["user_id"], code, nav_data["scheme_name"], amount, units, nav),
        )

        add_log(session["user_id"], "Investment Added", f"Investment added in {code}")

        flash("Investment added successfully.", "success")

        return redirect(url_for("portfolio"))

    return render_template("invest.html", code=code)


# ============================================================
# PORTFOLIO
# ============================================================


@app.route("/portfolio")
@login_required
def portfolio():

    holdings = fetch_all(
        """
        SELECT *
        FROM portfolio
        WHERE user_id = %s
        ORDER BY updated_at DESC
        """,
        (session["user_id"],),
    )

    for holding in holdings:

        nav = get_latest_nav(holding["scheme_code"])

        if nav:

            holding["current_nav"] = nav["nav"]

            holding["current_value"] = float(holding.get("units") or 0) * nav["nav"]

            holding["profit_loss"] = holding["current_value"] - float(
                holding.get("invested_amount") or 0
            )

        else:

            holding["current_nav"] = 0

            holding["current_value"] = 0

            holding["profit_loss"] = -float(holding.get("invested_amount") or 0)

    return render_template("portfolio.html", holdings=holdings)


# ============================================================
# WATCHLIST
# ============================================================


@app.route("/watchlist")
@login_required
def watchlist():

    items = fetch_all(
        """
        SELECT *
        FROM watchlist
        WHERE user_id = %s
        ORDER BY created_at DESC
        """,
        (session["user_id"],),
    )

    return render_template("watchlist.html", watchlist=items)


# ============================================================
# ADD WATCHLIST
# ============================================================


@app.route("/watchlist/add/<int:code>")
@login_required
def watchlist_add(code):

    fund = get_latest_nav(code)

    if fund:

        existing = fetch_one(
            """
            SELECT id
            FROM watchlist
            WHERE user_id = %s
            AND scheme_code = %s
            """,
            (session["user_id"], code),
        )

        if not existing:

            execute_query(
                """
                INSERT INTO watchlist
                (
                    user_id,
                    scheme_code,
                    scheme_name
                )
                VALUES
                (
                    %s,
                    %s,
                    %s
                )
                """,
                (session["user_id"], code, fund["scheme_name"]),
            )

            flash("Fund added to watchlist.", "success")

    return redirect(url_for("watchlist"))


# ============================================================
# DELETE WATCHLIST
# ============================================================


@app.route("/watchlist/delete/<int:code>")
@login_required
def watchlist_delete(code):

    execute_query(
        """
        DELETE FROM watchlist
        WHERE user_id = %s
        AND scheme_code = %s
        """,
        (session["user_id"], code),
    )

    flash("Fund removed from watchlist.", "success")

    return redirect(url_for("watchlist"))


# ============================================================
# TRANSACTIONS
# ============================================================


@app.route("/transactions")
@login_required
def transactions():

    rows = fetch_all(
        """
        SELECT *
        FROM transactions
        WHERE user_id = %s
        ORDER BY created_at DESC
        """,
        (session["user_id"],),
    )

    return render_template("transactions.html", transactions=rows)


# ============================================================
# REPORTS
# ============================================================


@app.route("/reports")
@login_required
def reports():

    return render_template("reports.html")


# ============================================================
# AMC
# ============================================================


@app.route("/amc")
@login_required
def amc():

    funds = fetch_all("""
        SELECT DISTINCT scheme_name
        FROM portfolio
        WHERE scheme_name IS NOT NULL
        ORDER BY scheme_name
        """)

    return render_template("amc.html", amcs=funds)


# ============================================================
# ADMIN DASHBOARD
# ============================================================


@app.route("/admin")
@admin_required
def admin():

    users = fetch_one("""
        SELECT COUNT(*) AS count
        FROM users
        """)

    transactions_count = fetch_one("""
        SELECT COUNT(*) AS count
        FROM transactions
        """)

    holdings = fetch_one("""
        SELECT COUNT(*) AS count
        FROM portfolio
        """)

    watchlist_count = fetch_one("""
        SELECT COUNT(*) AS count
        FROM watchlist
        """)

    sip_count = fetch_one("""
        SELECT COUNT(*) AS count
        FROM sip_plans
        """)

    funds = fetch_one("""
        SELECT COUNT(DISTINCT scheme_code) AS count
        FROM portfolio
        """)

    stats = {
        "users": users["count"] if users else 0,
        "transactions": (transactions_count["count"] if transactions_count else 0),
        "holdings": (holdings["count"] if holdings else 0),
        "watchlist": (watchlist_count["count"] if watchlist_count else 0),
        "sip": (sip_count["count"] if sip_count else 0),
        "funds": (funds["count"] if funds else 0),
    }

    try:

        logs = fetch_all("""
            SELECT
                l.*,
                u.full_name AS user_name
            FROM activity_logs l
            LEFT JOIN users u
            ON u.id = l.user_id
            ORDER BY l.created_at DESC
            LIMIT 10
            """)

    except Exception:

        logs = []

    return render_template("admin.html", stats=stats, logs=logs)


# ============================================================
# ADMIN USER MANAGEMENT
# ============================================================


@app.route("/admin/users")
@admin_required
def admin_users():

    users = fetch_all("""
        SELECT
            id,
            full_name,
            username,
            email,
            role
        FROM users
        ORDER BY id DESC
        """)

    return render_template("admin_users.html", users=users)


# ============================================================
# ADMIN USER ROLE
# ============================================================


@app.route("/admin/user/<int:uid>/role", methods=["POST"])
@admin_required
def admin_user_role(uid):

    new_role = request.form.get("role")

    if new_role not in ["user", "admin"]:

        existing = fetch_one(
            """
            SELECT role
            FROM users
            WHERE id = %s
            """,
            (uid,),
        )

        if not existing:

            return redirect(url_for("admin_users"))

        if existing["role"] == "admin":

            new_role = "user"

        else:

            new_role = "admin"

    execute_query(
        """
        UPDATE users
        SET role = %s
        WHERE id = %s
        """,
        (new_role, uid),
    )

    add_log(
        session["user_id"], "User Role Updated", f"User ID {uid} changed to {new_role}"
    )

    flash("User role updated.", "success")

    return redirect(url_for("admin_users"))


# ============================================================
# ADMIN FUND MANAGEMENT
# ============================================================


@app.route("/admin/funds")
@admin_required
def admin_funds():

    funds = fetch_all("""
        SELECT
            scheme_code,
            scheme_name,
            COUNT(*) AS holdings
        FROM portfolio
        GROUP BY
            scheme_code,
            scheme_name
        ORDER BY scheme_name
        """)

    for fund in funds:

        latest = get_latest_nav(fund["scheme_code"])

        if latest:

            fund["nav"] = latest["nav"]

            fund["fund_house"] = latest.get("fund_house", "")

            fund["category"] = latest.get("scheme_category", "")

        else:

            fund["nav"] = None

            fund["fund_house"] = ""

            fund["category"] = ""

    return render_template("admin_funds.html", funds=funds)


# ============================================================
# ADMIN TRANSACTIONS
# ============================================================


@app.route("/admin/transactions")
@admin_required
def admin_transactions():

    rows = fetch_all("""
        SELECT
            t.*,
            u.full_name AS user_name
        FROM transactions t
        JOIN users u
        ON u.id = t.user_id
        ORDER BY t.created_at DESC
        """)

    return render_template("admin_transactions.html", transactions=rows)


# ============================================================
# ADMIN HOLDINGS
# ============================================================


@app.route("/admin/holdings")
@admin_required
def admin_holdings():

    rows = fetch_all("""
        SELECT
            p.*,
            u.full_name AS user_name
        FROM portfolio p
        JOIN users u
        ON u.id = p.user_id
        ORDER BY p.updated_at DESC
        """)

    for row in rows:

        latest = get_latest_nav(row["scheme_code"])

        if latest:

            row["current_nav"] = latest["nav"]

            row["current_value"] = float(row.get("units") or 0) * latest["nav"]

        else:

            row["current_nav"] = 0

            row["current_value"] = 0

    return render_template("admin_holdings.html", holdings=rows)


# ============================================================
# ADMIN WATCHLIST
# ============================================================


@app.route("/admin/watchlist")
@admin_required
def admin_watchlist():

    rows = fetch_all("""
        SELECT
            w.*,
            u.full_name AS user_name
        FROM watchlist w
        JOIN users u
        ON u.id = w.user_id
        ORDER BY w.created_at DESC
        """)

    return render_template("admin_watchlist.html", watchlist=rows)


# ============================================================
# ADMIN SIP
# ============================================================


@app.route("/admin/sip")
@admin_required
def admin_sip():

    rows = fetch_all("""
        SELECT
            s.*,
            u.full_name AS user_name
        FROM sip_plans s
        JOIN users u
        ON u.id = s.user_id
        ORDER BY s.created_at DESC
        """)

    for row in rows:

        latest = get_latest_nav(row["scheme_code"])

        if latest:

            row["scheme_name"] = latest["scheme_name"]

        else:

            row["scheme_name"] = str(row["scheme_code"])

    return render_template("admin_sip.html", sips=rows)


# ============================================================
# ADMIN REPORTS
# ============================================================


@app.route("/admin/reports")
@admin_required
def admin_reports():

    total_users = fetch_one("""
        SELECT COUNT(*) AS count
        FROM users
        """)["count"]

    total_transactions = fetch_one("""
        SELECT COUNT(*) AS count
        FROM transactions
        """)["count"]

    total_investment = fetch_one("""
        SELECT COALESCE(
            SUM(amount),
            0
        ) AS total
        FROM transactions
        WHERE transaction_type = 'BUY'
        """)["total"]

    return render_template(
        "admin_reports.html",
        total_users=total_users,
        total_transactions=total_transactions,
        total_investment=total_investment,
    )


# ============================================================
# ADMIN AMC
# ============================================================


@app.route("/admin/amc")
@admin_required
def admin_amc():

    funds = fetch_all("""
        SELECT DISTINCT
            scheme_code,
            scheme_name
        FROM portfolio
        WHERE scheme_name IS NOT NULL
        ORDER BY scheme_name
        """)

    amcs = []

    seen = set()

    for fund in funds:

        latest = get_latest_nav(fund["scheme_code"])

        if latest:

            house = latest.get("fund_house", "")

            if house and house not in seen:

                seen.add(house)

                amcs.append({"name": house})

    return render_template("admin_amc.html", amcs=amcs)


# ============================================================
# ADMIN ACTIVITY LOGS
# ============================================================


@app.route("/admin/logs")
@admin_required
def admin_logs():

    logs = fetch_all("""
        SELECT
            l.*,
            u.full_name AS user_name
        FROM activity_logs l
        LEFT JOIN users u
        ON u.id = l.user_id
        ORDER BY l.created_at DESC
        """)

    return render_template("admin_logs.html", logs=logs)


# ============================================================
# ADMIN MARKET / API MONITORING
# ============================================================


@app.route("/admin/market")
@admin_required
def admin_market():

    try:

        api_logs = fetch_all("""
            SELECT *
            FROM api_logs
            ORDER BY created_at DESC
            LIMIT 50
            """)

    except Exception:

        api_logs = []

    return render_template("admin_market.html", api_logs=api_logs)


# ============================================================
# TRANSACTION CSV REPORT
# ============================================================


@app.route("/reports/transactions.csv")
@login_required
def transaction_csv():

    user_id = session["user_id"]

    rows = fetch_all(
        """
        SELECT
            transaction_type,
            scheme_code,
            scheme_name,
            amount,
            units,
            nav,
            created_at
        FROM transactions
        WHERE user_id = %s
        ORDER BY created_at DESC
        """,
        (user_id,),
    )

    output = StringIO()

    writer = csv.writer(output)

    writer.writerow(
        [
            "Transaction Type",
            "Scheme Code",
            "Scheme Name",
            "Amount",
            "Units",
            "NAV",
            "Date",
        ]
    )

    for row in rows:

        writer.writerow(
            [
                row["transaction_type"],
                row["scheme_code"],
                row["scheme_name"],
                row["amount"],
                row["units"],
                row["nav"],
                row["created_at"],
            ]
        )

    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=transactions.csv"},
    )


# ============================================================
# PORTFOLIO PDF REPORT
# ============================================================


@app.route("/reports/portfolio.pdf")
@login_required
def portfolio_pdf():

    try:

        from reportlab.lib.pagesizes import A4

        from reportlab.platypus import (
            SimpleDocTemplate,
            Paragraph,
            Spacer,
            Table,
            TableStyle,
        )

        from reportlab.lib import colors

        from reportlab.lib.styles import getSampleStyleSheet

    except ImportError:

        return "ReportLab is not installed. " "Install it using: pip install reportlab"

    user_id = session["user_id"]

    rows = fetch_all(
        """
        SELECT
            scheme_code,
            scheme_name,
            units,
            invested_amount
        FROM portfolio
        WHERE user_id = %s
        """,
        (user_id,),
    )

    buffer = BytesIO()

    document = SimpleDocTemplate(buffer, pagesize=A4)

    styles = getSampleStyleSheet()

    elements = []

    elements.append(Paragraph("MINT - Portfolio Report", styles["Title"]))

    elements.append(Spacer(1, 20))

    table_data = [["Scheme Code", "Scheme Name", "Units", "Invested"]]

    for row in rows:

        table_data.append(
            [
                str(row["scheme_code"]),
                str(row["scheme_name"] or ""),
                str(row["units"]),
                "Rs. " + str(row["invested_amount"]),
            ]
        )

    table = Table(table_data)

    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("PADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )

    elements.append(table)

    document.build(elements)

    buffer.seek(0)

    return Response(
        buffer.getvalue(),
        mimetype="application/pdf",
        headers={"Content-Disposition": "attachment; filename=portfolio_report.pdf"},
    )


# ============================================================
# FAVICON
# ============================================================


@app.route("/favicon.ico")
def favicon():

    return "", 204


# ============================================================
# 404 ERROR
# ============================================================


@app.errorhandler(404)
def page_not_found(error):

    try:

        return render_template("error.html", error="Page not found"), 404

    except Exception:

        return ("<h1>404 - Page Not Found</h1>" "<a href='/'>Go Home</a>"), 404


# ============================================================
# 500 ERROR
# ============================================================


@app.errorhandler(500)
def internal_error(error):

    try:

        return render_template("error.html", error="Internal server error"), 500

    except Exception:

        return ("<h1>500 - Internal Server Error</h1>" "<a href='/'>Go Home</a>"), 500


# ============================================================
# RUN APPLICATION
# ============================================================

if __name__ == "__main__":

    app.run(host="127.0.0.1", port=5000, debug=True)
