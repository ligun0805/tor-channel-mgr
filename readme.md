# Tor Channel Manager

This is a Python library that provides a simple interface for managing Tor channels.

## Installation

To install the library, run the following command:

```bash
pip install tor-channel-mgr
```

## Usage

Here's an example of how to use the library:

```python
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
            relay_ip,
            replay_port,
            rsa_id,
            target_url,
            target_port
        )
            
    except Exception as e:
        print(e)
        return

if __name__ == "__main__":
    asyncio.run(test())
```