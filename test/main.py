import asyncio
from tor_py_client import TorClient

class TorChanMgr:
    def __init__(self):
        self.tor_client = TorClient()

    async def init(self):
        self.tor_client.init()
    
    async def connect(self, relay_ip: str, relay_port: int, rsa_id: str, target_ip: str, target_port: int):
        try:
            await self.tor_client.connect(relay_ip, relay_port, rsa_id, target_ip, target_port)
        except Exception as e:
            print(e)
            return

# This is a test function
async def test():
    tor_chan_mgr = TorChanMgr()
    
    try:
        await tor_chan_mgr.init()
        await tor_chan_mgr.connect(
            "116.202.55.100",
            9001,
            "C3DFB7BD40B072EB6D46578F1BE021FDD9D60713",
            "https://example.com",
            80
        )
            
    except Exception as e:
        print(e)
        return

if __name__ == "__main__":
    asyncio.run(test())