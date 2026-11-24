@echo off
echo ==========================================
echo             NETWATCH STARTUP
echo ==========================================
echo.
echo Open TWO terminals in this project folder.
echo.
echo BACKEND:
echo   cd backend
echo   py -m venv .venv
echo   .venv\Scripts\activate
echo   pip install -r requirements.txt
echo   python app.py
echo.
echo FRONTEND (second terminal):
echo   cd frontend
echo   npm install
echo   npm run dev
echo.
echo Open http://localhost:5173
echo ==========================================
pause
