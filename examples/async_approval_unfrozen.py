import asyncio

from approval_flow import check_approval
from approval_flow import publish


async def release(topic, payload):
    approved = check_approval(topic)
    await asyncio.sleep(0)
    if approved:
        publish(topic, payload)


async def release_with_cleanup(topic, payload):
    approved = check_approval(topic)
    try:
        await asyncio.sleep(0)
    finally:
        pass
    if approved:
        publish(topic, payload)
