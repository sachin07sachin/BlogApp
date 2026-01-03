web: flask --app main db upgrade && gunicorn --bind 0.0.0.0:$PORT main:app --workers 2 --threads 4 --timeout 120
