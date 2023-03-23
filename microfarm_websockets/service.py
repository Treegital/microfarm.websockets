import jwt
import asyncio
import websockets
import typing as t
import json
from pathlib import Path
from aiozmq import rpc
from minicli import run, cli


logger = logging.getLogger('microfarm_websockets')


class UserData(t.TypedDict):
    id: str
    email: str


class WebsocketServer(rpc.AttrHandler):

    def __init__(self, public_key: bytes):
        self.public_key = public_key
        self.connections = {}

    @rpc.method
    async def send_message(self, user: str, message: str) -> dict:
        if (websocket := self.connections.get(user)) is not None:
            await websocket.send(message)
            return True
        return {"err": "user is offline"}

    @rpc.method
    def broadcast(self, message: str) -> bool:
        websockets.broadcast(self.connections.values(), message)
        return True

    def decode_jwt(self, token: str) -> dict:
        try:
            return jwt.decode(token, self.public_key, algorithms=["RS256"])

    async def __call__(self, websocket):
        token = await asyncio.wait_for(websocket.recv(), timeout=2)
        try:
            userdata = jwt.decode(
                token, self.public_key, algorithms=["RS256"])
        except jwt.ExpiredSignatureError:
            # specific error => token expired.
            await websocket.send(json.dumps(
                {"err": "Authentication failed."}
            ))
        except jwt.exceptions.InvalidTokenError:
            await websocket.send(json.dumps(
                {"err": "Authentication failed."}
            ))
        else:
            self.connections[userdata['email']] = websocket
            try:
                await websocket.wait_closed()
            finally:
                del self.connections[userdata['email']]


@cli
async def serve(config: Path, public_key: Path):
    import tomli
    import logging.config

    assert config.is_file()
    assert public_key.is_file()

    with config.open("rb") as f:
        settings = tomli.load(f)

    with public_key.open("rb") as f:
        public_key_pem = f.read()

    if logconf := settings.get('logging'):
        logging.config.dictConfigClass(logconf).configure()

    service = WebsocketServer(public_key_pem)
    server = await rpc.serve_rpc(service, bind=settings['rpc']['bind'])
    async with websockets.serve(
            service, settings['ws']['host'], settings['ws']['port']):
        await server.wait_closed()


if __name__ == '__main__':
    run()
