# FastAPI, Django, Flask

- **Django.** `DEBUG = True` in a deployed settings module exposes settings,
  environment, and a traceback console. `ALLOWED_HOSTS = ["*"]` disables host
  validation. A `SECRET_KEY` literal in settings is a session-forgery key.
- **FastAPI.** `allow_origins=["*"]` with `allow_credentials=True` is the CORS
  hole. Dependencies are per-route: a missing `Depends(get_current_user)` is an
  open endpoint, and it looks identical to a protected one at a glance.
- **Flask.** `app.run(debug=True)` exposes the Werkzeug console, which is remote
  code execution by design.
- Pydantic models validate what they declare. `Dict[str, Any]` or a bare `dict`
  body annotation validates nothing.
- ORM queries built with f-strings are injectable. `.raw()` and `.execute()`
  take parameters for a reason.
- `except Exception: pass` is the Python spelling of a swallowed error.
