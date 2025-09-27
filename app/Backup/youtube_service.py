from google_auth_oauthlib.flow import Flow
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from google.cloud import secretmanager
import os

CLIENT_SECRET_FILE = 'client_secret.json'
SCOPES = ['https://www.googleapis.com/auth/youtube']
REDIRECT_URI = 'http://localhost:8080/'  # local
#REDIRECT_URI = 'https://youtubeplaylistcreatorv2-117353943789.asia-southeast1.run.app/'  # actual


def load_all_secrets(secret_names):
    client = secretmanager.SecretManagerServiceClient()
    secrets = {}
    for name in secret_names:
        resource_name = f"projects/{project_id}/secrets/{name}/versions/latest"
        response = client.access_secret_version(name=resource_name)
        secrets[name] = response.payload.data.decode("UTF-8")
    return secrets


def handle_auth_code(code):
    flow = Flow.from_client_secrets_file(
        CLIENT_SECRET_FILE,
        scopes=SCOPES,
        redirect_uri=REDIRECT_URI
    )
    flow.fetch_token(code=code)
    return flow.credentials


def create_playlist_for_user(access_token, refresh_token, query, title):
    client_id = get_secret("YoutubePlaylistCreatorClientID")
    client_secret = get_secret("YoutubePlaylistCreatorClientSecret")
    creds = Credentials(
        token=access_token,
        refresh_token=refresh_token,
        token_uri='https://oauth2.googleapis.com/token',
        client_id=os.environ.get('CLIENT_ID'),
        client_secret=os.environ.get('CLIENT_SECRET'),
        scopes=SCOPES
    )
    if not creds.valid and creds.expired and creds.refresh_token:
        creds.refresh(Request())

    youtube = build('youtube', 'v3', credentials=creds)

    playlist = youtube.playlists().insert(
        part='snippet,status',
        body={
            'snippet': {
                'title': title,
                'description': f'Playlist for query: {query}'
            },
            'status': {'privacyStatus': 'private'}
        }
    ).execute()

    # Dummy example: Normally you'd search for real video IDs
    video_ids = ['dQw4w9WgXcQ', '3JZ_D3ELwOQ']

    for vid in video_ids:
        youtube.playlistItems().insert(
            part='snippet',
            body={
                'snippet': {
                    'playlistId': playlist['id'],
                    'resourceId': {
                        'kind': 'youtube#video',
                        'videoId': vid
                    }
                }
            }
        ).execute()

    return f"Created playlist '{title}' with {len(video_ids)} videos."
