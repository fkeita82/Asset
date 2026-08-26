@echo off
if not exist venv\Scripts\python.exe (
    echo Setting up virtual environment...
    "C:\Users\FacinetKeita\AppData\Local\Programs\Python\Python312\python.exe" -m venv venv
    call venv\Scripts\activate.bat
    pip install -r requirements.txt
) else (
    call venv\Scripts\activate.bat
)
python app.py
pause
