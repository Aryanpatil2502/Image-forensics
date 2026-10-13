# Image Forensics Tool

A simple Flask web application for basic digital forensic analysis of images. It extracts image details, displays available EXIF metadata, generates MD5 and SHA-256 hashes, and provides a downloadable text report.

## Features
- Upload JPG, JPEG, and PNG images.
- View image details and EXIF metadata.
- Generate MD5 and SHA-256 hashes.
- Download a forensic report.

## Requirements
- Python 3.10+
- [uv](https://docs.astral.sh/uv/)
- Flask and Pillow

## Run the Project

```bash

sudo pacman -S uv


cd image-forensics

uv sync

uv run app.py
```

Open http://127.0.0.1:5000 in your browser.

Press `Ctrl+C` to stop the server.