import os
from io import BytesIO

import mysql.connector
from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    send_file,
    session
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from dotenv import load_dotenv

from azure.storage.blob import BlobServiceClient


# --------------------------------------------------
# LOAD ENVIRONMENT VARIABLES
# --------------------------------------------------

load_dotenv()


# --------------------------------------------------
# FLASK APPLICATION
# --------------------------------------------------

app = Flask(__name__)

app.secret_key = os.getenv(
    "FLASK_SECRET_KEY",
    "change-this-secret-key"
)


# --------------------------------------------------
# ALLOWED FILE TYPES
# --------------------------------------------------

ALLOWED_EXTENSIONS = {
    "txt",
    "pdf",
    "png",
    "jpg",
    "jpeg",
    "gif",
    "doc",
    "docx",
    "xls",
    "xlsx",
    "csv",
    "zip"
}


def allowed_file(filename):
    return (
        "." in filename
        and filename.rsplit(".", 1)[1].lower()
        in ALLOWED_EXTENSIONS
    )


# --------------------------------------------------
# MYSQL DATABASE CONNECTION
# --------------------------------------------------

def get_db_connection():

    return mysql.connector.connect(
        host=os.getenv("MYSQL_HOST", "localhost"),
        user=os.getenv("MYSQL_USER", "root"),
        password=os.getenv("MYSQL_PASSWORD", ""),
        database=os.getenv(
            "MYSQL_DATABASE",
            "cloud_file_storage"
        )
    )


# --------------------------------------------------
# AZURE BLOB STORAGE CONNECTION
# --------------------------------------------------

AZURE_CONNECTION_STRING = os.getenv(
    "AZURE_STORAGE_CONNECTION_STRING"
)

AZURE_CONTAINER_NAME = os.getenv(
    "AZURE_CONTAINER_NAME",
    "project-files"
)


blob_service_client = BlobServiceClient.from_connection_string(
    AZURE_CONNECTION_STRING
)

container_client = blob_service_client.get_container_client(
    AZURE_CONTAINER_NAME
)


# --------------------------------------------------
# HOME
# --------------------------------------------------

@app.route("/")
def home():

    if "user_id" in session:
        return redirect(url_for("upload"))

    return redirect(url_for("login"))


# --------------------------------------------------
# REGISTER
# --------------------------------------------------

@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm_password = request.form.get(
            "confirm_password",
            ""
        )

        if not username or not password:

            flash("Username and password are required.")

            return redirect(url_for("register"))

        if password != confirm_password:

            flash("Passwords do not match.")

            return redirect(url_for("register"))

        try:

            connection = get_db_connection()

            cursor = connection.cursor()

            # Check whether username already exists
            cursor.execute(
                "SELECT id FROM users WHERE username = %s",
                (username,)
            )

            existing_user = cursor.fetchone()

            if existing_user:

                flash("Username already exists.")

                cursor.close()
                connection.close()

                return redirect(url_for("register"))

            # Hash password
            password_hash = generate_password_hash(password)

            cursor.execute(
                """
                INSERT INTO users (username, password)
                VALUES (%s, %s)
                """,
                (username, password_hash)
            )

            connection.commit()

            cursor.close()
            connection.close()

            flash("Registration successful. Please login.")

            return redirect(url_for("login"))

        except Exception as e:

            flash(
                f"Registration failed: {str(e)}"
            )

            return redirect(url_for("register"))

    return render_template("register.html")


# --------------------------------------------------
# LOGIN
# --------------------------------------------------

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form.get(
            "username",
            ""
        ).strip()

        password = request.form.get(
            "password",
            ""
        )

        try:

            connection = get_db_connection()

            cursor = connection.cursor(
                dictionary=True
            )

            cursor.execute(
                """
                SELECT id, username, password
                FROM users
                WHERE username = %s
                """,
                (username,)
            )

            user = cursor.fetchone()

            cursor.close()
            connection.close()

            if user and check_password_hash(
                user["password"],
                password
            ):

                session["user_id"] = user["id"]
                session["username"] = user["username"]

                flash("Login successful.")

                return redirect(
                    url_for("upload")
                )

            flash("Invalid username or password.")

        except Exception as e:

            flash(
                f"Login failed: {str(e)}"
            )

    return render_template("login.html")


# --------------------------------------------------
# LOGOUT
# --------------------------------------------------

@app.route("/logout")
def logout():

    session.clear()

    flash("You have been logged out.")

    return redirect(url_for("login"))


# --------------------------------------------------
# UPLOAD PAGE
# --------------------------------------------------

@app.route("/upload")
def upload():

    if "user_id" not in session:

        flash("Please login first.")

        return redirect(url_for("login"))

    return render_template("upload.html")


# --------------------------------------------------
# UPLOAD FILE
# --------------------------------------------------

@app.route("/upload", methods=["POST"])
def upload_file():

    if "user_id" not in session:

        flash("Please login first.")

        return redirect(url_for("login"))

    if "file" not in request.files:

        flash("No file selected.")

        return redirect(url_for("upload"))

    file = request.files["file"]

    if file.filename == "":

        flash("No file selected.")

        return redirect(url_for("upload"))

    if not allowed_file(file.filename):

        flash("File type is not allowed.")

        return redirect(url_for("upload"))

    filename = secure_filename(
        file.filename
    )

    try:

        blob_client = container_client.get_blob_client(
            filename
        )

        blob_client.upload_blob(
            file.stream,
            overwrite=True
        )

        flash(
            f"File '{filename}' uploaded successfully."
        )

    except Exception as e:

        flash(
            f"Upload failed: {str(e)}"
        )

    return redirect(url_for("list_files"))


# --------------------------------------------------
# LIST FILES
# --------------------------------------------------

@app.route("/files")
def list_files():

    if "user_id" not in session:

        flash("Please login first.")

        return redirect(url_for("login"))

    try:

        blobs = container_client.list_blobs()

        files = []

        for blob in blobs:

            files.append(blob.name)

        return render_template(
            "files.html",
            files=files
        )

    except Exception as e:

        flash(
            f"Unable to load files: {str(e)}"
        )

        return redirect(url_for("upload"))


# --------------------------------------------------
# DOWNLOAD FILE
# --------------------------------------------------

@app.route("/download/<path:filename>")
def download_file(filename):

    if "user_id" not in session:

        flash("Please login first.")

        return redirect(url_for("login"))

    try:

        blob_client = container_client.get_blob_client(
            filename
        )

        download_stream = blob_client.download_blob()

        file_data = download_stream.readall()

        return send_file(
            BytesIO(file_data),
            download_name=filename,
            as_attachment=True
        )

    except Exception as e:

        flash(
            f"Download failed: {str(e)}"
        )

        return redirect(
            url_for("list_files")
        )


# --------------------------------------------------
# DELETE FILE
# --------------------------------------------------

@app.route(
    "/delete/<path:filename>",
    methods=["POST"]
)
def delete_file(filename):

    if "user_id" not in session:

        flash("Please login first.")

        return redirect(url_for("login"))

    try:

        blob_client = container_client.get_blob_client(
            filename
        )

        blob_client.delete_blob()

        flash(
            f"File '{filename}' deleted successfully."
        )

    except Exception as e:

        flash(
            f"Delete failed: {str(e)}"
        )

    return redirect(
        url_for("list_files")
    )


# --------------------------------------------------
# RUN APPLICATION
# --------------------------------------------------

if __name__ == "__main__":

    app.run(
        debug=True,
        host="0.0.0.0",
        port=5000
    )
