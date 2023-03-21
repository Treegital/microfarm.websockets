import asyncio
import websockets
import typing as t
from aiozmq import rpc
from minicli import run, cli


class UserData(t.TypedDict):
    id: str
    email: str


class WebsocketServer(rpc.AttrHandler):

    def __init__(self, jwt_service: str = 'tcp://127.0.0.1:5555'):
        self.jwt_service = jwt_service
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

    async def __call__(self, websocket):
        jwt = await asyncio.wait_for(websocket.recv(), timeout=2)
        service = await rpc.connect_rpc(connect=self.jwt_service)
        userdata: UserData = await service.call.verify_token(jwt)

        self.connections[userdata['email']] = websocket
        try:
            await websocket.wait_closed()
        finally:
            del self.connections[userdata['email']]


@cli
async def serve():
    service = WebsocketServer()
    zeroserver = await rpc.serve_rpc(service, bind=f'tcp://127.0.0.1:6000')
    async with websockets.serve(service, "", 6001):
        await zeroserver.wait_closed()


if __name__ == '__main__':
    run()
