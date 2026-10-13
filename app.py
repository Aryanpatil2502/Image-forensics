import hashlib
import io
import os
import re
import uuid
from datetime import datetime

from flask import (Flask, Response, abort, flash, redirect, render_template,
                   request, send_from_directory, url_for)
from PIL import ExifTags, Image, UnidentifiedImageError
from werkzeug.utils import secure_filename

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
ALLOWED_EXTENSIONS = {"jpg", "jpeg", "png"}      
ALLOWED_FORMATS = {"JPEG", "PNG"}                
MAX_UPLOAD_MB = 5


FORMAT_TO_EXT = {"JPEG": "jpg", "PNG": "png"}

STORED_NAME_PATTERN = re.compile(r"^[0-9a-f]{32}\.(jpg|png)$")

Image.MAX_IMAGE_PIXELS = 50_000_000

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_MB * 1024 * 1024  # size limit
app.secret_key = os.environ.get("SECRET_KEY", "change-this-for-real-use")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


def has_allowed_extension(filename):
    """Check that the filename ends with .jpg, .jpeg or .png."""
    return "." in filename and \
        filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def validate_image(data):
   
    try:
        with Image.open(io.BytesIO(data)) as img:
            detected = img.format
            img.verify()  
    except (UnidentifiedImageError, Image.DecompressionBombError):
        raise ValueError("The file is not a valid or supported image.")
    except Exception:
        raise ValueError("The image appears to be corrupted.")

    if detected not in ALLOWED_FORMATS:
        raise ValueError("Only real JPG and PNG images are accepted.")
    return detected


def human_size(num_bytes):
    """Convert a size in bytes to a readable string, e.g. '2.31 MB'."""
    size = float(num_bytes)
    for unit in ("bytes", "KB", "MB"):
        if size < 1024 or unit == "MB":
            return f"{int(size)} bytes" if unit == "bytes" else f"{size:.2f} {unit}"
        size /= 1024


def compute_hashes(path):
    """Read the file in small chunks and compute MD5 and SHA-256 together."""
    md5 = hashlib.md5()
    sha256 = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            md5.update(chunk)
            sha256.update(chunk)
    return md5.hexdigest(), sha256.hexdigest()


def clean_value(value):
    """Turn any EXIF value into a short, printable string."""
    if isinstance(value, bytes):
        return f"<binary data, {len(value)} bytes>"
    text = str(value).replace("\x00", "").strip()
    return text[:200] + "..." if len(text) > 200 else text


def extract_exif(img):
   
    metadata = {}
    try:
        exif = img.getexif()
      
        for tag_id, value in exif.items():
            name = ExifTags.TAGS.get(tag_id, f"Tag {tag_id}")
            metadata[name] = clean_value(value)
     
        for tag_id, value in exif.get_ifd(0x8769).items():
            name = ExifTags.TAGS.get(tag_id, f"Tag {tag_id}")
            metadata[name] = clean_value(value)
        
        if exif.get_ifd(0x8825):
            metadata["GPS Information"] = "Present (coordinates not displayed)"
    except Exception:
        pass 
    return metadata


def analyze_image(path, original_name):
    """Collect everything we want to show about one stored image."""
    with Image.open(path) as img:
        width, height = img.size
        image_format = img.format
        exif = extract_exif(img)

    md5_hash, sha256_hash = compute_hashes(path)
    size_bytes = os.path.getsize(path)

    
    summary = {
        "Camera Make": exif.get("Make", "Not available"),
        "Camera Model": exif.get("Model", "Not available"),
        "Date/Time Taken": exif.get("DateTimeOriginal",
                                    exif.get("DateTime", "Not available")),
    }

    return {
        "filename": original_name,
        "format": image_format,
        "size_bytes": size_bytes,
        "size_readable": human_size(size_bytes),
        "width": width,
        "height": height,
        "summary": summary,
        "exif": exif,
        "md5": md5_hash,
        "sha256": sha256_hash,
    }


def get_stored_path(stored_name):
    """Validate a stored filename and return its full path (or stop with 404)."""
    if not STORED_NAME_PATTERN.match(stored_name):
        abort(404)
    path = os.path.join(UPLOAD_FOLDER, stored_name)
    if not os.path.isfile(path):
        abort(404)
    return path


def build_report(info):
    """Create the plain-text report as one string."""
    lines = [
        "=" * 60,
        "DIGITAL FORENSICS TOOL FOR IMAGES - ANALYSIS REPORT",
        "=" * 60,
        f"Report generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "",
        "1. IMAGE INFORMATION",
        "-" * 60,
        f"File name   : {info['filename']}",
        f"Format      : {info['format']}",
        f"File size   : {info['size_readable']}"
        + (f" ({info['size_bytes']} bytes)" if info["size_bytes"] >= 1024 else ""),
        f"Dimensions  : {info['width']} x {info['height']} pixels",
        "",
        "2. METADATA (EXIF)",
        "-" * 60,
    ]
    if info["exif"]:
        for key, value in info["exif"].items():
            lines.append(f"{key}: {value}")
    else:
        lines.append("No EXIF metadata available in this image.")
    lines += [
        "",
        "3. FILE HASHES",
        "-" * 60,
        f"MD5     : {info['md5']}",
        f"SHA-256 : {info['sha256']}",
        "",
        "NOTE",
        "-" * 60,
        "Hashes help verify file integrity (the file has not changed).",
        "Neither hashes nor metadata prove that an image is genuine,",
        "because metadata can be edited or removed.",
        "",
    ]
    return "\n".join(lines)


def friendly_original_name(raw_name):
    """Make the name from the URL safe to show and to put in a report."""
    return secure_filename(raw_name or "")[:100] or "unknown_file"


@app.route("/")
def index():
    """Homepage with the upload form."""
    return render_template("index.html", max_mb=MAX_UPLOAD_MB)


@app.route("/upload", methods=["POST"])
def upload():
    """Receive the file, validate it, save it safely, then show results."""

    file = request.files.get("image")
    if file is None or file.filename == "":
        flash("Please choose an image file before clicking Analyze.")
        return redirect(url_for("index"))


    if not has_allowed_extension(file.filename):
        flash("Unsupported file type. Please upload a JPG, JPEG or PNG image.")
        return redirect(url_for("index"))

    data = file.read()
    if not data:
        flash("The uploaded file is empty.")
        return redirect(url_for("index"))
    try:
        detected_format = validate_image(data)
    except ValueError as error:
        flash(str(error))
        return redirect(url_for("index"))

    stored_name = f"{uuid.uuid4().hex}.{FORMAT_TO_EXT[detected_format]}"
    with open(os.path.join(UPLOAD_FOLDER, stored_name), "wb") as f:
        f.write(data)

    original_name = friendly_original_name(file.filename)
    return redirect(url_for("results", stored_name=stored_name,
                            name=original_name))


@app.route("/results/<stored_name>")
def results(stored_name):
    """Analyze the stored image and show the results page."""
    path = get_stored_path(stored_name)
    original_name = friendly_original_name(request.args.get("name"))
    try:
        info = analyze_image(path, original_name)
    except Exception:
        flash("Could not analyze this image. Please try another file.")
        return redirect(url_for("index"))
    return render_template("results.html", info=info, stored_name=stored_name)


@app.route("/uploads/<stored_name>")
def uploaded_file(stored_name):
    """Serve the uploaded image so it can be previewed on the results page."""
    get_stored_path(stored_name)  # validates the name
    return send_from_directory(UPLOAD_FOLDER, stored_name)


@app.route("/report/<stored_name>")
def report(stored_name):
    """Download the analysis as a .txt file."""
    path = get_stored_path(stored_name)
    original_name = friendly_original_name(request.args.get("name"))
    info = analyze_image(path, original_name)
    text = build_report(info)
    download_name = f"report_{os.path.splitext(original_name)[0]}.txt"
    return Response(
        text,
        mimetype="text/plain",
        headers={"Content-Disposition": f'attachment; filename="{download_name}"'},
    )

@app.errorhandler(413)
def file_too_large(error):
    flash(f"File is too large. The maximum allowed size is {MAX_UPLOAD_MB} MB.")
    return redirect(url_for("index"))


@app.errorhandler(404)
def not_found(error):
    flash("That page or file was not found.")
    return redirect(url_for("index"))


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
