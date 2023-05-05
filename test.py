import os
from flask import Flask, send_file

app = Flask(__name__)

@app.route("/download")
def download_file():
    folder_name = "my_folder"
    zip_filename = f"{folder_name}.zip"
    folder_path = os.path.join(os.getcwd(), folder_name)

    # Create the zip file
    with zipfile.ZipFile(zip_filename, "w", zipfile.ZIP_DEFLATED) as zip:
        for root, dirs, files in os.walk(folder_path):
            for file in files:
                file_path = os.path.join(root, file)
                zip.write(file_path, os.path.relpath(file_path, folder_path))

    return send_file(zip_filename, as_attachment=True)

if __name__ == "__main__":
    app.run()
