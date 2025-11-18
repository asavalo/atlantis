import asyncio


async def async_process_run_and_exit(
    p, timeout: int, wait_time: int = 1
) -> tuple[int, bytes, bytes]:
    try:
        stdout, stderr = await asyncio.wait_for(p.communicate(), timeout=timeout)
        return (p.returncode, stdout, stderr)
    except TimeoutError as e:
        p.terminate()
        try:
            await asyncio.wait_for(p.wait(), timeout=wait_time)
        except TimeoutError as e:
            p.kill()
            raise e
        raise e
