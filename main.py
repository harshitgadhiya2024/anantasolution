"""
    In this file handling all flask api route and maintain all of operation and sessions
"""

from flask import (flash, Flask, redirect, render_template, request,
                   session, url_for, send_file, jsonify)
import os
from flask_cors import CORS
import jwt
import uuid
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from operations.mongo_connection import MongoOperations
from datetime import datetime, timedelta
from operations.common_func import CommonOpertion

secreat_id = uuid.uuid4().hex

app = Flask(__name__)

# Apply cors policy in our app instance
CORS(app)

client = MongoOperations().mongo_connect(app)

# setup all config variable
app.config["enviroment"] = "qa"
app.config["SECRET_KEY"] = secreat_id
app.config["mapping_user_dict"] = {}
app.config["mapping_admin_dict"] = {}
app.config["mapping_client_upload_folder"] = {}
app.config["mapping_user_folder"] = {}

# handling our application secure type like http or https
secure_type = "http"

ALLOWED_EXTENSIONS = {'jpg', 'jpeg', 'png', 'webp'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def token_required(func):
    # decorator factory which invoks update_wrapper() method and passes decorated function as an argument
    @wraps(func)
    def decorated(*args, **kwargs):
        login_dict = session.get("login_dict", {})
        token = app.config["mapping_user_dict"].get(login_dict.get("username", "nothing"), {}).get("token", False)
        if not token:
            flash("Please login first...", "danger")
            return redirect(url_for('login', _external=True, _scheme=secure_type))
        return func(*args, **kwargs)
    return decorated

def token_admin_required(func):
    # decorator factory which invoks update_wrapper() method and passes decorated function as an argument
    @wraps(func)
    def decorated(*args, **kwargs):
        admin_login_dict = session.get("admin_login_dict", {})
        token = app.config["mapping_admin_dict"].get(admin_login_dict.get("username", "nothing"), {}).get("token", False)
        if not token:
            flash("Please login first...", "danger")
            return redirect(url_for('admin_login', _external=True, _scheme=secure_type))
        return func(*args, **kwargs)
    return decorated


@app.route("/", methods=["GET", "POST"])
def login():
    """
    In this route we can handling login process
    :return: login template
    """
    try:
        login_dict = session.get("login_dict", "nothing")
        if login_dict != "nothing":
            return redirect(url_for('dashboard', _external=True, _scheme=secure_type))

        db = client["prod_ananta_solution"]
        if request.method == "POST":
            email = request.form["username_text"]
            password = request.form["password"]

            di = {"username": email}
            di_email = {"email": email}
            user_data = MongoOperations().find_spec_data(app, db, "user_data", di)
            email_data = MongoOperations().find_spec_data(app, db, "user_data", di_email)
            user_data = list(user_data)
            email_data = list(email_data)

            if len(user_data) == 0 and len(email_data) == 0:
                flash("Please use correct credential..", "danger")
                return redirect(url_for('login', _external=True, _scheme=secure_type))
            elif len(user_data)>0:
                user_data = user_data[0]
                if user_data["password"] == password:
                    username = user_data["username"]

                    token = jwt.encode({
                        'user': username,
                        'expiration': str(datetime.now() + timedelta(seconds=14400))
                    }, app.config['SECRET_KEY'])

                    app.config["mapping_user_dict"][username] = {"token": "token_data"}
                    session["login_dict"] = {"username": username}

                    try:
                        folder_path = app.config["mapping_client_upload_folder"][username]
                        folder_count = app.config["mapping_user_folder"][username]
                    except:
                        folder_path = f"static/data/{username}"
                        try:
                            os.makedirs(folder_path, exist_ok=True)
                        except OSError as e:
                            print(f"Error: {e}")

                        app.config["mapping_client_upload_folder"][username] = folder_path
                        app.config["mapping_user_folder"][username] = 1

                    flash("Login Successfully...", "success")
                    return redirect(url_for('dashboard', _external=True, _scheme=secure_type))
                else:
                    flash("Please use correct credential..", "danger")
                    return redirect(url_for('login', _external=True, _scheme=secure_type))
            else:
                email_data = email_data[0]
                if email_data["password"] == password:
                    username = email_data["username"]

                    token = jwt.encode({
                        'user': username,
                        'expiration': str(datetime.now() + timedelta(seconds=14400))
                    }, app.config['SECRET_KEY'])

                    app.config["mapping_user_dict"][username] = {"token": "token_data"}
                    session["login_dict"] = {"username": username}
                    flash("Login Successfully...", "success")
                    return redirect(url_for('dashboard', _external=True, _scheme=secure_type))
                else:
                    flash("Please use correct credential..", "danger")
                    return redirect(url_for('login', _external=True, _scheme=secure_type))

        else:
            return render_template("login.html")

    except Exception as e:
        print(e)
        app.logger.debug(f"Error in login route: {e}")
        flash("Please try again...", "danger")
        return redirect(url_for('login', _external=True, _scheme=secure_type))

@app.route("/admin_login", methods=["GET", "POST"])
def admin_login():
    """
    In this route we can handling login process
    :return: login template
    """
    try:
        db = client["prod_ananta_solution"]
        if request.method == "POST":
            email = request.form["username_text"]
            password = request.form["password"]

            di = {"username": email}
            user_data = MongoOperations().find_spec_data(app, db, "admin_data", di)
            user_data = list(user_data)

            if len(user_data) == 0:
                flash("Please use correct credential..", "danger")
                return redirect(url_for('admin_login', _external=True, _scheme=secure_type))

            elif len(user_data)>0:
                user_data = user_data[0]
                if user_data["password"] == password:
                    username = user_data["username"]

                    token = jwt.encode({
                        'user': username,
                        'expiration': str(datetime.now() + timedelta(seconds=14400))
                    }, app.config['SECRET_KEY'])

                    app.config["mapping_admin_dict"][username] = {"token": "token_data"}
                    session["admin_login_dict"] = {"username": username}
                    flash("Login Successfully...", "success")
                    return redirect(url_for('admin_dashboard', _external=True, _scheme=secure_type))
                else:
                    flash("Please use correct credential..", "danger")
                    return redirect(url_for('admin_login', _external=True, _scheme=secure_type))

        else:
            return render_template("admin_login.html")

    except Exception as e:
        print(e)
        app.logger.debug(f"Error in admin_login route: {e}")
        flash("Please try again...", "danger")
        return redirect(url_for('admin_login', _external=True, _scheme=secure_type))

@app.route("/dashboard", methods=["GET", "POST"])
@token_required
def dashboard():
    """
    In this route we can handling main dashboard process
    :return: dashboard template
    """
    try:
        login_dict = session["login_dict"]
        username = login_dict["username"]
        return render_template("index.html")

    except Exception as e:
        print(e)
        app.logger.debug(f"Error in dashboard route: {e}")
        flash("Please try again...", "danger")
        return redirect(url_for('dashboard', _external=True, _scheme=secure_type))

@app.route("/admin_dashboard", methods=["GET", "POST"])
@token_admin_required
def admin_dashboard():
    """
    In this route we can handling main dashboard process
    :return: dashboard template
    """
    try:
        login_dict = session["admin_login_dict"]
        username = login_dict["username"]
        return render_template("admin_dashboard.html")

    except Exception as e:
        print(e)
        app.logger.debug(f"Error in admin_dashboard route: {e}")
        flash("Please try again...", "danger")
        return redirect(url_for('admin_dashboard', _external=True, _scheme=secure_type))

@app.route("/admin_client_data", methods=["GET", "POST"])
@token_admin_required
def admin_client_data():
    """
    In this route we can handling main dashboard process
    :return: dashboard template
    """
    try:
        login_dict = session["admin_login_dict"]
        username = login_dict["username"]
        db = client["prod_ananta_solution"]
        developers = ["harshit", "jay", "ravi", "naman", "ajay", "ajesh", "keval", "divya", "meet"]
        all_users = MongoOperations().find_all_data(app, db, "user_data")
        all_users_list = []
        for user_info in all_users:
            user_info_list = [user_info["username"],user_info["company"],user_info["email"],user_info["phone"],user_info["developer"]]
            all_users_list.append(user_info_list)
        if request.method=="POST":
            username = request.form.get("username", "")
            company = request.form.get("company", "")
            email = request.form.get("email", "")
            phone = request.form.get("phone", "")
            developer = request.form.get("developer", "")
            city = request.form.get("city", "")
            state = request.form.get("state", "")
            country = request.form.get("country", "")
            password = "X7yhF12Oj6"

            if username and company and email and phone and developer:
                mapping_dict = {"username": username, "company": company, "email": email, "phone": phone,
                                "developer": developer, "city": city, "state": state, "country": country,
                                "password": password, "inserted_on": datetime.now()}

                change_password_link = f"http://64.181.227.59/change_password?username={username}"
                html_body = f"""
                    <html>
                      <body style="font-family: Arial, sans-serif; background-color: #f4f4f4; margin: 0; padding: 0;">
                        <table align="center" border="0" cellpadding="0" cellspacing="0" width="600" style="border-collapse: collapse; background-color: #ffffff;">
                          <tr>
                            <td align="center" bgcolor="#4CAF50" style="padding: 40px 0 30px 0; color: white; font-size: 24px; font-weight: bold;">
                              Welcome to Ananta Solution!
                            </td>
                          </tr>
                          <tr>
                            <td style="padding: 40px 30px 40px 30px;">
                              <table border="0" cellpadding="0" cellspacing="0" width="100%">
                                <tr>
                                  <td style="color: #333333; font-size: 18px; font-weight: bold;">
                                    Hi, {username}!
                                  </td>
                                </tr>
                                <tr>
                                  <td style="padding: 20px 0 30px 0; color: #333333; font-size: 16px;">
                                    We're excited to have you on board. Here are your login details to get started:
                                  </td>
                                </tr>
                                <tr>
                                  <td style="color: #333333; font-size: 16px;">
                                    <b>Username:</b> {username}<br>
                                    <b>Temporary Password:</b> {password}<br>
                                  </td>
                                </tr>
                                <tr>
                                  <td style="padding: 30px 0; color: #333333; font-size: 16px;">
                                    Please change your password immediately by clicking the link below:
                                  </td>
                                </tr>
                                <tr>
                                  <td align="center">
                                    <a href="{change_password_link}" style="background-color: #4CAF50; color: white; padding: 10px 20px; text-decoration: none; font-size: 16px;">
                                      Change My Password
                                    </a>
                                  </td>
                                </tr>
                                <tr>
                                  <td style="padding: 40px 0 0 0; color: #333333; font-size: 16px;">
                                    Thank you,<br>
                                    Ananta Solution Team
                                  </td>
                                </tr>
                              </table>
                            </td>
                          </tr>
                          <tr>
                            <td bgcolor="#4CAF50" style="padding: 20px 30px 20px 30px; color: white; font-size: 12px; text-align: center;">
                              © 2024 Ananta Solutions. All rights reserved.
                            </td>
                          </tr>
                        </table>
                      </body>
                    </html>
                """
                CommonOpertion().send_mail(email, "[Ananta Solution] Registration Successfully", html_body)
                MongoOperations().data_added(app, db, "user_data", mapping_dict)
                folder_path = f"static/data/{username}"
                try:
                    os.makedirs(folder_path, exist_ok=True)
                except OSError as e:
                    print(f"Error: {e}")
                app.config["mapping_client_upload_folder"][username] = folder_path
                app.config["mapping_user_folder"][username] = 1
                flash("Your Data Saved Successfully...", "success")
                return redirect(url_for('admin_client_data', _external=True, _scheme=secure_type))
            else:
                flash("Please fill details..", "danger")
                return redirect(url_for('admin_client_data', _external=True, _scheme=secure_type))

        else:
            return render_template("admin_client_data.html", developers=developers, all_users_list=all_users_list)

    except Exception as e:
        print(e)
        app.logger.debug(f"Error in admin_client_data route: {e}")
        flash("Please try again...", "danger")
        return redirect(url_for('admin_client_data', _external=True, _scheme=secure_type))

@app.route("/admin_admin_data", methods=["GET", "POST"])
@token_admin_required
def admin_admin_data():
    """
    In this route we can handling main dashboard process
    :return: dashboard template
    """
    try:
        login_dict = session["admin_login_dict"]
        username = login_dict["username"]
        db = client["prod_ananta_solution"]
        all_users = MongoOperations().find_all_data(app, db, "admin_data")
        all_admin_list = []
        for user_info in all_users:
            user_info_list = [user_info["username"],user_info["password"]]
            all_admin_list.append(user_info_list)
        if request.method=="POST":
            username = request.form.get("username", "")
            password = request.form.get("password", "")
            if username and password:
                mapping_dict = {"username": username, "password": password, "inserted_on": datetime.now()}
                MongoOperations().data_added(app, db, "admin_data", mapping_dict)
                flash("Your Data Saved Successfully...", "success")
                return redirect(url_for('admin_admin_data', _external=True, _scheme=secure_type))
            else:
                flash("Please fill details..", "danger")
                return redirect(url_for('admin_admin_data', _external=True, _scheme=secure_type))

        else:
            return render_template("admin_admin_data.html", all_admin_list=all_admin_list)

    except Exception as e:
        print(e)
        app.logger.debug(f"Error in admin_admin_data route: {e}")
        flash("Please try again...", "danger")
        return redirect(url_for('admin_admin_data', _external=True, _scheme=secure_type))

@app.route("/delete_data", methods=["GET", "POST"])
@token_admin_required
def delete_data():
    """
    In this route we can handling main dashboard process
    :return: dashboard template
    """
    try:
        db = client["prod_ananta_solution"]
        username = request.args.get("username")
        type = request.args.get("type")
        if type=="client_data":
            MongoOperations().delete_data(app, db, "user_data", {"username": username})
            return redirect(url_for('admin_client_data', _external=True, _scheme=secure_type))
        elif type=="admin_data":
            MongoOperations().delete_data(app, db, "admin_data", {"username": username})
            return redirect(url_for('admin_admin_data', _external=True, _scheme=secure_type))

    except Exception as e:
        print(e)
        app.logger.debug(f"Error in delete_data route: {e}")
        flash("Please try again...", "danger")
        return redirect(url_for('delete_data', _external=True, _scheme=secure_type))

@app.route("/change_password", methods=["GET", "POST"])
def change_password():
    """
    In this route we can handling main dashboard process
    :return: dashboard template
    """
    try:
        username = request.args.get("username", "")
        db = client["prod_ananta_solution"]
        if request.method=="POST":
            old_password = request.form.get("old_password")
            new_password = request.form.get("new_password")
            user_data = MongoOperations().find_spec_data(app, db, "user_data", {"username": username})
            user_data = list(user_data)
            if user_data:
                password = user_data[0]["password"]
                if password==old_password:
                    MongoOperations().update_mongo_data(app, db, "user_data", {"username": username}, {"password": new_password})
                    return redirect(url_for('login', _external=True, _scheme=secure_type))
                else:
                    flash("Your old password does not match...", "danger")
                    return redirect(url_for('login', _external=True, _scheme=secure_type))
            else:
                flash("Your account does not exits, please check....", "danger")
                return redirect(url_for('login', _external=True, _scheme=secure_type))
        else:
            return render_template("change_password.html", username=username)

    except Exception as e:
        print(e)
        app.logger.debug(f"Error in admin_client_data route: {e}")
        flash("Please try again...", "danger")
        return redirect(url_for('admin_client_data', _external=True, _scheme=secure_type))

@app.route('/logout', methods=['GET', 'POST'])
def logout():
    """
    That funcation was logout session and clear user session
    """

    try:
        username = session["login_dict"]["username"]
        del app.config["mapping_user_dict"][username]["token"]
        session.clear()
        return redirect(url_for('login', _external=True, _scheme=secure_type))

    except Exception as e:
        print(e)
        flash("Please try again...", "danger")
        return redirect(url_for('login', _external=True, _scheme=secure_type))

@app.route("/upload_garment", methods=["GET", "POST"])
@token_required
def upload_garment():
    """
    In this route we can handling main dashboard process
    :return: dashboard template
    """
    try:
        login_dict = session["login_dict"]
        username = login_dict["username"]
        path = f"static/data/{username}"
        data_set = []
        all_folders = CommonOpertion().get_folders(path)
        for folder in all_folders[:4]:
            all_files = CommonOpertion().get_files(path+f"/{folder}/")
            for var in all_files:
                if "garment" in var:
                    garment_path = f"static/data/{username}/{folder}/{var}"
                    data_set.append([garment_path, folder])

        if request.method=="POST":
            if 'file' not in request.files:
                flash("No file selected...", "danger")
                return redirect(url_for('upload_garment', _external=True, _scheme=secure_type))

            files = request.files.getlist('file')
            for file in files:
                if file.filename == '':
                    flash('No selected file', "danger")
                    return redirect(url_for('upload_garment', _external=True, _scheme=secure_type))
                if file and allowed_file(file.filename):
                    pass
                else:
                    flash(f'File {file.filename} is not allowed! Only .jpg, .jpeg, .png, .webp files are accepted.', "danger")
                    return redirect(url_for('upload_garment', _external=True, _scheme=secure_type))

            for file in files:
                folder_type_name = f"photoshoot_{app.config['mapping_user_folder'][username]}"
                folder_path = f"static/data/{username}/{folder_type_name}"
                CommonOpertion().create_folder_path(folder_path)
                filaname = file.filename
                new_file_name = f"garment.{filaname.split('.')[-1]}"
                file_path = os.path.join(folder_path, new_file_name)
                file.save(file_path)
                app.config['mapping_user_folder'][username] = app.config['mapping_user_folder'][username]+1

            return redirect(url_for('upload_garment', _external=True, _scheme=secure_type))
        else:
            return render_template("upload_garment.html", data_set=data_set, username=username)

    except Exception as e:
        print(e)
        app.logger.debug(f"Error in upload_garment route: {e}")
        flash("Please try again...", "danger")
        return redirect(url_for('upload_garment', _external=True, _scheme=secure_type))

@app.route("/photoshoot", methods=["GET", "POST"])
@token_required
def photoshoot():
    """
    In this route we can handling main dashboard process
    :return: dashboard template
    """
    try:
        login_dict = session["login_dict"]
        username = login_dict["username"]
        path = f"static/data/{username}"
        data_set = []
        all_folders = CommonOpertion().get_folders(path)
        for folder in all_folders:
            all_files = CommonOpertion().get_files(path+f"/{folder}/")
            for var in all_files:
                if "garment" in var:
                    garment_path = f"static/data/{username}/{folder}/{var}"
                    data_set.append([garment_path, folder])

        return render_template("photoshoot.html", data_set=data_set, username=username)

    except Exception as e:
        print(e)
        app.logger.debug(f"Error in photoshoot route: {e}")
        flash("Please try again...", "danger")
        return redirect(url_for('photoshoot', _external=True, _scheme=secure_type))


@app.route("/open_photoshoot", methods=["GET", "POST"])
@token_required
def open_photoshoot():
    """
    In this route we can handling main dashboard process
    :return: dashboard template
    """
    try:
        login_dict = session["login_dict"]
        username = request.args.get("username")
        folder_name = request.args.get("folder_name")
        type = request.args.get("type")
        path = f"static/data/{username}/{folder_name}"
        data_set = []
        all_files = CommonOpertion().get_files(path)
        for var in all_files:
            image_path = f"static/data/{username}/{folder_name}/{var}"
            data_set.append([image_path, var])

        return render_template("open_photoshoot.html",type=type, data_set=data_set, username=username)

    except Exception as e:
        print(e)
        app.logger.debug(f"Error in open_photoshoot route: {e}")
        flash("Please try again...", "danger")
        return redirect(url_for('open_photoshoot', _external=True, _scheme=secure_type))


if __name__ == '__main__':
    app.run(host="0.0.0.0", port=80)
