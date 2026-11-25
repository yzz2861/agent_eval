import asyncio

from approval_flow import check_approval
from approval_flow import publish


async def release_all(topics, payload):
    approved = check_approval("bulk")
    for topic in topics:
        await asyncio.sleep(0)
    if approved:
        publish("bulk", payload)


async def maybe_release(topic, payload, flush):
    approved = check_approval(topic)
    if flush:
        await asyncio.sleep(0)
    if approved:
        publish(topic, payload)
