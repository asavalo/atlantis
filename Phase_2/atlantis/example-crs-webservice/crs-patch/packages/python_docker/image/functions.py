import docker
import docker.errors


def docker_image_exists(image_name: str) -> bool:
    client = docker.from_env()

    try:
        client.images.get(image_name)
        return True
    except docker.errors.ImageNotFound:
        return False


def pull_docker_image(image_name: str):
    client = docker.from_env()

    return client.images.pull(image_name)


def _check_container_status(container_name: str, status: str) -> bool:
    client = docker.from_env()
    try:
        container = client.containers.get(container_name)
        return container.status == status
    except docker.errors.NotFound:
        return False


def is_running(container_name: str) -> bool:
    return _check_container_status(container_name, "running")


def is_exited(container_name: str) -> bool:
    return _check_container_status(container_name, "exited")


def get_running_containers() -> set[str]:
    client = docker.from_env()
    return {container.name for container in client.containers.list()}  # type: ignore


def destroy_container(container_name: str):
    client = docker.from_env()
    container = client.containers.get(container_name)
    container.stop()
    try:
        container.remove()
    except docker.errors.APIError:
        # Container is already being removed, we can ignore this
        pass


def get_exposed_port(container_name: str, container_port: int) -> int:
    client = docker.from_env()
    container = client.containers.get(container_name)
    ports = container.attrs["NetworkSettings"]["Ports"]

    if f"{container_port}/tcp" in ports and ports[f"{container_port}/tcp"]:
        host_port = ports[f"{container_port}/tcp"][0]["HostPort"]
        return int(host_port)
    else:
        raise ValueError(f"No host mapping found for port {container_port}")
