import docker


def run_docker_container():
    client = docker.from_env()
    container = client.containers.get("6721d0570f13ec831c1d8581187e69a632caf47a5b1cc8f7f42c084f94d11c71")
    container.start()
    exit_code, output = container.exec_run("uname -a")
    print(output.decode("utf-8"))
    return container
