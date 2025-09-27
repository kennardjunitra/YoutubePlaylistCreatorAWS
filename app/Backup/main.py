from flask import Flask, request, jsonify, send_from_directory
from youtube_service import handle_auth_code, create_playlist_for_user

app = Flask(__name__, static_folder='../static')

@app.route('/')
def index():
    return send_from_directory(app.static_folder, 'index.html')

@app.route('/exchange_code', methods=['POST'])
def exchange_code():
    data = request.get_json()
    code = data.get('code')
    creds = handle_auth_code(code)
    return jsonify({
        'access_token': creds.token,
        'refresh_token': creds.refresh_token
    })

@app.route('/create_playlist', methods=['POST'])
def create_playlist():
    data = request.get_json()
    access_token = data.get('access_token')
    refresh_token = data.get('refresh_token')
    query = data.get('query')
    title = data.get('playlist_title')

    try:
        result = create_playlist_for_user(access_token, refresh_token, query, title)
        return jsonify({ 'message': result })
    except Exception as e:
        return jsonify({ 'error': str(e) }), 500