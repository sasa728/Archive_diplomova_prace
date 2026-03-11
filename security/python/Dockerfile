FROM python:3.11-slim
# Tato promenna zajisti, ze uvidime logy hned
ENV PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
# Spoustime primo soubor v rootu app slozky
CMD ["python", "main.py"]