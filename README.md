# Chat4Chatting

run:
```bash
pip3 install -r requirements.txt
python3 app.py
```

The database tables will be created automatically on the first run. If you want
to initialize them manually, run `python3 init_db.py`.

Private chats are available via `/private/<username>` or by visiting the direct
link `/p/<id>`.
